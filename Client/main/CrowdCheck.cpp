#include <iostream>
#include <set>
#include <string>
#include <mutex>
#include <cstdio>
#include <cstring>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "nvs_flash.h"

#include "host/ble_hs.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

// ==========================================
// 설정(Configuration) 매크로
// ==========================================
#define ENABLE_LIVE_RSSI_MONITOR 1    // 1로 설정하면 1초에 1번씩 현재 가장 강하게 잡히는 기기의 RSSI를 실시간 출력 (거리 튜닝용)

#define RSSI_THRESHOLD -65            // 카페 내부 체류자 측정용 (창밖 행인 무시)
#define SCAN_DURATION_SEC 60          // 60초 단위 안정적 데이터 집계 (중복 방지를 위해 60초 필수)
#define WIFI_SNIFF_DURATION_MS 2000    
#define BLE_SCAN_DURATION_MS 2000      

static const char* TAG = "CrowdCheck";

// 비트맵 최적화를 통한 고유 MAC 식별 (ESP32-Paxcounter 방식)
// 65536 비트 = 2048 * 32비트 (총 8KB 메모리 사용)
uint32_t seen_ids_map[2048] = {0}; 

// 프로토콜별 기기 스캔 카운트
int wifi_count = 0;
int ble_count = 0;
int filtered_wifi_count = 0;
int filtered_ble_count = 0;
int dropped_apple_packet_count = 0;

std::mutex mac_mutex;

// 비트맵 조작 헬퍼 함수
#define WORD_OFFSET(b) ((b) / 32)
#define BIT_OFFSET(b) ((b) % 32)

bool is_mac_seen(uint16_t id) {
    return (seen_ids_map[WORD_OFFSET(id)] & (1UL << BIT_OFFSET(id))) != 0;
}

void mark_mac_seen(uint16_t id) {
    seen_ids_map[WORD_OFFSET(id)] |= (1UL << BIT_OFFSET(id));
}
SemaphoreHandle_t ble_sync_sem;

// ==========================================
// Wi-Fi 스니퍼 로직
// ==========================================
void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    // Management Frame만 취급합니다.
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    int rssi = pkt->rx_ctrl.rssi;
    
#if ENABLE_LIVE_RSSI_MONITOR
    static uint32_t last_wifi_log = 0;
    uint32_t now = xTaskGetTickCount() * portTICK_PERIOD_MS;
    if (now - last_wifi_log > 1000) { // 1초에 1번만 출력 (Watchdog 방지)
        last_wifi_log = now;
        ESP_LOGI(TAG, "📡 [실시간 Wi-Fi] 주변 기기 RSSI: %d (임계값 %d %s)", 
                 rssi, RSSI_THRESHOLD, rssi >= RSSI_THRESHOLD ? "✔ 통과(카운트됨)" : "❌ 차단(문 밖)");
    }
#endif

    // RSSI 임계값 미만인 경우 무시
    if (rssi < RSSI_THRESHOLD) return;

    uint8_t *frame = pkt->payload;
    
    // Frame Control: byte 0
    uint8_t frame_control = frame[0];
    uint8_t type_val = (frame_control & 0x0C) >> 2;
    uint8_t subtype_val = (frame_control & 0xF0) >> 4;

    // Type 0 (Management) & Subtype 4 (Probe Request)
    if (type_val == 0 && subtype_val == 4) {
        uint8_t *mac = frame + 10; // Probe Request 프레임에서 Source Address 위치

        bool is_random = (mac[0] & 0x02) != 0;
        
        // 로컬 관리(Random) 주소인지 확인. (첫 번째 바이트의 b1 비트가 1이어야 함)
        // Public MAC(공유기, 스마트TV 등 고정 기기)은 필터링하여 제외합니다.
        // [테스트] 현재는 모든 장치를 확인하기 위해 필터링을 임시로 주석 처리합니다.
        // if (!is_random) return;

        // MAC 주소의 마지막 2바이트를 추출하여 16비트 ID로 변환
        uint16_t id = (mac[4] << 8) | mac[5];
        
        std::lock_guard<std::mutex> lock(mac_mutex);
        if (!is_mac_seen(id)) {
            mark_mac_seen(id);
            wifi_count++;
        } else {
            // 이미 이번 윈도우에서 탐지된 기기인 경우 중복 카운트 증가
            filtered_wifi_count++;
        }
    }
}

// ==========================================
// BLE 페이로드 필터링 (Apple 기기 중복 카운트 방지)
// ==========================================
bool is_valid_ble_payload(const uint8_t *data, uint8_t len) {
    int offset = 0;
    while (offset < len) {
        uint8_t ad_len = data[offset];
        if (ad_len == 0 || offset + 1 + ad_len > len) break;
        
        uint8_t ad_type = data[offset + 1];
        // Manufacturer Specific Data (0xFF)
        if (ad_type == 0xFF && ad_len >= 4) {
            const uint8_t *mfg_data = &data[offset + 2];
            // Apple의 Company ID는 0x004C (Little Endian으로 0x4C 0x00)
            if (mfg_data[0] == 0x4C && mfg_data[1] == 0x00) {
                uint8_t apple_type = mfg_data[2];
                // 애플 기기라면, 오직 'Find My (0x12)' 패킷만 허용!
                // Nearby(0x10), Action(0x0F) 등은 한 기기가 중복 생성하므로 무시(Drop)
                if (apple_type != 0x12) {
                    return false; 
                }
            }
        }
        offset += ad_len + 1;
    }
    // 애플 기기가 아니거나(Android 등), 애플이더라도 0x12 패킷이면 통과
    return true; 
}

// ==========================================
// BLE(NimBLE) 스캐너 로직
// ==========================================
static int ble_gap_event_cb(struct ble_gap_event *event, void *arg) {
    // 디바이스가 탐색(Discovery)되었을 때
    if (event->type == BLE_GAP_EVENT_DISC) {
        int rssi = event->disc.rssi;

#if ENABLE_LIVE_RSSI_MONITOR
        static uint32_t last_ble_log = 0;
        uint32_t now = xTaskGetTickCount() * portTICK_PERIOD_MS;
        if (now - last_ble_log > 1000) { // 1초에 1번만 출력
            last_ble_log = now;
            ESP_LOGI(TAG, "🔵 [실시간 BLE] 주변 기기 RSSI: %d (임계값 %d %s)", 
                     rssi, RSSI_THRESHOLD, rssi >= RSSI_THRESHOLD ? "✔ 통과(카운트됨)" : "❌ 차단(문 밖)");
        }
#endif

        if (rssi < RSSI_THRESHOLD) return 0;
        
        const uint8_t *mac = event->disc.addr.val;
        int addr_type = event->disc.addr.type;
        
        const char *type_str = "Unknown";
        if (addr_type == BLE_ADDR_PUBLIC) type_str = "Public (Fixed)";
        else if (addr_type == BLE_ADDR_RANDOM) type_str = "Random";
        else if (addr_type == BLE_ADDR_PUBLIC_ID) type_str = "Public ID";
        else if (addr_type == BLE_ADDR_RANDOM_ID) type_str = "Random ID";

        // 랜덤 주소(Random Address)인지 확인하여 고정 기기를 필터링합니다.
        // [테스트] 현재는 모든 장치를 확인하기 위해 필터링을 임시로 주석 처리합니다.
        // if (addr_type != BLE_ADDR_RANDOM && addr_type != BLE_ADDR_RANDOM_ID) return 0;
        
        // 애플 기기의 동시다발적 MAC 주소 뻥튀기 방지 필터 통과 여부 확인
        if (!is_valid_ble_payload(event->disc.data, event->disc.length_data)) {
            std::lock_guard<std::mutex> lock(mac_mutex);
            dropped_apple_packet_count++;
            return 0; // 조건에 맞지 않는 애플의 다른 찌꺼기 패킷들은 즉시 버림(Drop)
        }

        // NimBLE의 주소는 Little-endian이므로 mac[0], mac[1]이 가장 오른쪽(마지막) 2바이트입니다.
        // 이를 16비트 ID로 변환합니다.
        uint16_t id = (mac[1] << 8) | mac[0];

        std::lock_guard<std::mutex> lock(mac_mutex);
        if (!is_mac_seen(id)) {
            mark_mac_seen(id);
            ble_count++;
        } else {
            // 이미 이번 윈도우에서 탐지된 기기인 경우 중복 카운트 증가
            filtered_ble_count++;
        }
    }
    return 0;
}

// NimBLE 호스트 태스크
void ble_host_task(void *param) {
    ESP_LOGI(TAG, "BLE Host Task Started");
    nimble_port_run();
    nimble_port_freertos_deinit();
}

// 스택 동기화 완료 콜백
static void ble_on_sync(void) {
    xSemaphoreGive(ble_sync_sem);
}

void start_ble_scan() {
    struct ble_gap_disc_params disc_params;
    memset(&disc_params, 0, sizeof(disc_params));
    disc_params.passive = 1;      // 패시브 스캔
    disc_params.filter_duplicates = 1;

    // 무한히 스캔 시작 (이후 cancel로 제어)
    ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, ble_gap_event_cb, NULL);
}

void stop_ble_scan() {
    ble_gap_disc_cancel();
}

// ==========================================
// 메인 어플리케이션 엔트리 포인트
// ==========================================
extern "C" void app_main() {
    ESP_LOGI(TAG, "CrowdCheck System Starting...");

    // 1. NVS 초기화 (Wi-Fi 및 BLE 스택의 내부 상태 저장을 위해 필수)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    esp_netif_init();
    esp_event_loop_create_default();

    // 2. BLE (NimBLE) 초기화
    ble_sync_sem = xSemaphoreCreateBinary();
    nimble_port_init();
    ble_hs_cfg.sync_cb = ble_on_sync;
    nimble_port_freertos_init(ble_host_task);

    // 스택이 완전히 동기화될 때까지 대기
    xSemaphoreTake(ble_sync_sem, portMAX_DELAY);
    ESP_LOGI(TAG, "NimBLE Stack Synchronized.");

    // 3. Wi-Fi 초기화 (초기 상태: Station 모드 진입 전)
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Wi-Fi Stack Initialized.");

    // 4. 메인 루프 (120초 스캔 -> 5초 전송 반복)
    while (true) {
        ESP_LOGI(TAG, "=== 스캔 윈도우 시작 (%d초) ===", SCAN_DURATION_SEC);
        uint32_t start_time = xTaskGetTickCount() * portTICK_PERIOD_MS;
        
        while ((xTaskGetTickCount() * portTICK_PERIOD_MS) - start_time < (SCAN_DURATION_SEC * 1000)) {
            
            // --- Wi-Fi 스니핑 페이즈 ---
            ESP_LOGD(TAG, "Wi-Fi Sniffing On");
            ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_cb));
            ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
            
            vTaskDelay(pdMS_TO_TICKS(WIFI_SNIFF_DURATION_MS));
            
            ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
            
            // --- BLE 스캐닝 페이즈 ---
            ESP_LOGD(TAG, "BLE Scanning On");
            start_ble_scan();
            
            vTaskDelay(pdMS_TO_TICKS(BLE_SCAN_DURATION_MS));
            
            stop_ble_scan();
        }

        // --- 전송 윈도우 페이즈 ---
        ESP_LOGI(TAG, "=== 전송 윈도우 진입 ===");
        
        mac_mutex.lock();
        int current_wifi = wifi_count;
        int current_ble = ble_count;
        int current_filtered_wifi = filtered_wifi_count;
        int current_filtered_ble = filtered_ble_count;
        int current_dropped_apple = dropped_apple_packet_count;
        
        // 데이터 초기화
        memset(seen_ids_map, 0, sizeof(seen_ids_map));
        wifi_count = 0;
        ble_count = 0;
        filtered_wifi_count = 0;
        filtered_ble_count = 0;
        dropped_apple_packet_count = 0;
        mac_mutex.unlock();

        ESP_LOGI(TAG, ">> 수집된 고유 Wi-Fi 기기 수: %d (중복 필터링됨: %d건)", current_wifi, current_filtered_wifi);
        ESP_LOGI(TAG, ">> 수집된 고유 BLE 기기 수: %d (중복 필터링됨: %d건, 뻥튀기 방지로 버려진 애플 패킷: %d건)", current_ble, current_filtered_ble, current_dropped_apple);
        ESP_LOGI(TAG, ">> 혼잡도 데이터 서버로 HTTP POST 전송 중... (Dummy)");
        
        // TODO: 정상적인 AP(공유기) 연결 및 HTTP 전송 로직 구현 공간
        // esp_wifi_connect();
        // vTaskDelay(pdMS_TO_TICKS(5000));
        // send_http_post(current_wifi, current_ble);
        // esp_wifi_disconnect();
        
        // 서버 전송 및 연결을 위한 5초 대기 시뮬레이션
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
