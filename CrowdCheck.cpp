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
#define RSSI_THRESHOLD -100            // RSSI 필터링 임계값 (원하는 값으로 튜닝하세요)
#define SCAN_DURATION_SEC 120          // 총 스캔 윈도우 시간 (초)
#define WIFI_SNIFF_DURATION_MS 5000    // 1회 Wi-Fi 스니핑 유지 시간 (밀리초)
#define BLE_SCAN_DURATION_MS 5000      // 1회 BLE 스캐닝 유지 시간 (밀리초)

static const char* TAG = "CrowdCheck";

// MAC 주소를 고유하게 저장하기 위한 컨테이너 및 뮤텍스
std::set<std::string> discovered_macs;
std::mutex mac_mutex;
SemaphoreHandle_t ble_sync_sem;

// ==========================================
// Wi-Fi 스니퍼 로직
// ==========================================
void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    // Management Frame만 취급합니다.
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    int rssi = pkt->rx_ctrl.rssi;
    
    // RSSI 임계값 미만인 경우 무시
    if (rssi < RSSI_THRESHOLD) return;

    uint8_t *frame = pkt->payload;
    
    // Frame Control: byte 0
    uint8_t frame_control = frame[0];
    uint8_t type_val = (frame_control & 0x0C) >> 2;
    uint8_t subtype_val = (frame_control & 0xF0) >> 4;

    // Type 0 (Management) & Subtype 4 (Probe Request)
    if (type_val == 0 && subtype_val == 4) {
        char mac_str[18];
        uint8_t *mac = frame + 10; // Probe Request 프레임에서 Source Address 위치

        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        
        std::lock_guard<std::mutex> lock(mac_mutex);
        discovered_macs.insert(std::string(mac_str));
    }
}

// ==========================================
// BLE(NimBLE) 스캐너 로직
// ==========================================
static int ble_gap_event_cb(struct ble_gap_event *event, void *arg) {
    // 디바이스가 탐색(Discovery)되었을 때
    if (event->type == BLE_GAP_EVENT_DISC) {
        if (event->disc.rssi < RSSI_THRESHOLD) return 0;
        
        char mac_str[18];
        const uint8_t *mac = event->disc.addr.val;
        
        // NimBLE의 주소는 Little-endian으로 들어오므로 뒤집어서 출력합니다.
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);

        std::lock_guard<std::mutex> lock(mac_mutex);
        discovered_macs.insert(std::string(mac_str));
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
        int crowd_count = discovered_macs.size();
        discovered_macs.clear();
        mac_mutex.unlock();

        ESP_LOGI(TAG, ">> 수집된 주변 유효 기기(사람) 수: %d", crowd_count);
        ESP_LOGI(TAG, ">> 서버로 HTTP POST 전송 중... (Dummy)");
        
        // TODO: 정상적인 AP(공유기) 연결 및 HTTP 전송 로직 구현 공간
        // esp_wifi_connect();
        // vTaskDelay(pdMS_TO_TICKS(5000));
        // send_http_post(crowd_count);
        // esp_wifi_disconnect();
        
        // 서버 전송 및 연결을 위한 5초 대기 시뮬레이션
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
