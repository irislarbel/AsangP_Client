#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include <set>
#include <string>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "host/ble_hs.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "esp_nimble_hci.h"

#if __has_include("esp_eap_client.h")
#include "esp_eap_client.h"
#else
#include "esp_wpa2.h"
#define esp_eap_client_set_identity esp_wifi_sta_wpa2_ent_set_identity
#define esp_eap_client_set_username esp_wifi_sta_wpa2_ent_set_username
#define esp_eap_client_set_password esp_wifi_sta_wpa2_ent_set_password
#define esp_eap_client_set_ca_cert esp_wifi_sta_wpa2_ent_set_ca_cert
#define esp_eap_client_set_ttls_phase2_method esp_wifi_sta_wpa2_ent_set_ttls_phase2_method
#define esp_wifi_sta_enterprise_enable esp_wifi_sta_wpa2_ent_enable
#define ESP_EAP_TTLS_PHASE2_PAP WPA2_ENT_TTLS_PAP
#endif

// ==========================================
// 설정(Configuration) 매크로
// ==========================================
#define ENABLE_LIVE_RSSI_MONITOR 0 // 실시간 출력 비활성화 (프로덕션 모드)

#define SCAN_DURATION_SEC                                                      \
  60 // 60초 단위 안정적 데이터 집계 (중복 방지를 위해 60초 필수)

// Wi-Fi 및 서버 API 설정 (Kconfig에서 설정된 값 사용)
// menuconfig의 "AsangP Client Configuration" 메뉴에서 값을 설정하세요.
#define WIFI_SSID CONFIG_WIFI_SSID
#define WIFI_USER CONFIG_WIFI_USER
#define WIFI_PASS CONFIG_WIFI_PASS
#define API_URL CONFIG_API_URL
#define API_KEY CONFIG_API_KEY
#define DEVICE_ID CONFIG_DEVICE_ID
#define WIFI_SNIFF_DURATION_MS 2000
#define BLE_SCAN_DURATION_MS 2000

static const char *TAG = "CrowdCheck";

// 서버로부터 수신될 동적 임계값 (초기 기본값)
int wifi_rssi_threshold = -70;
int bt_rssi_threshold = -70;

// 비트맵 최적화를 통한 고유 MAC 식별 (ESP32-Paxcounter 방식)
// 65536 비트 = 2048 * 32비트 (각 프로토콜별 8KB 메모리 사용)
uint32_t seen_ids_map_wifi[2048] = {0};
uint32_t seen_ids_map_ble[2048] = {0};

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

bool is_mac_seen(uint32_t* map, uint16_t id) {
  return (map[WORD_OFFSET(id)] & (1UL << BIT_OFFSET(id))) != 0;
}

void mark_mac_seen(uint32_t* map, uint16_t id) {
  map[WORD_OFFSET(id)] |= (1UL << BIT_OFFSET(id));
}
SemaphoreHandle_t ble_sync_sem;

// ==========================================
// Wi-Fi 스니퍼 로직
// ==========================================
void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  // Management Frame만 취급합니다.
  if (type != WIFI_PKT_MGMT)
    return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  int rssi = pkt->rx_ctrl.rssi;

#if ENABLE_LIVE_RSSI_MONITOR
  static uint32_t last_wifi_log = 0;
  uint32_t now = xTaskGetTickCount() * portTICK_PERIOD_MS;
  if (now - last_wifi_log > 1000) { // 1초에 1번만 출력 (Watchdog 방지)
    last_wifi_log = now;
    ESP_LOGI(TAG, "📡 [실시간 Wi-Fi] 주변 기기 RSSI: %d (임계값 %d %s)", rssi,
             wifi_rssi_threshold,
             rssi >= wifi_rssi_threshold ? "✔ 통과(카운트됨)"
                                         : "❌ 차단(문 밖)");
  }
#endif

  // RSSI 임계값 미만인 경우 무시
  if (rssi < wifi_rssi_threshold)
    return;

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
    if (!is_random)
      return;

    // MAC 주소의 마지막 2바이트를 추출하여 16비트 ID로 변환
    uint16_t id = (mac[4] << 8) | mac[5];

    std::lock_guard<std::mutex> lock(mac_mutex);
    if (!is_mac_seen(seen_ids_map_wifi, id)) {
      mark_mac_seen(seen_ids_map_wifi, id);
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
  if (data == nullptr || len == 0) return true;

  int offset = 0;
  while (offset < len) {
    uint8_t ad_len = data[offset];
    if (ad_len == 0 || offset + 1 + ad_len > len)
      break;

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
      ESP_LOGI(TAG, "🔵 [실시간 BLE] 주변 기기 RSSI: %d (임계값 %d %s)", rssi,
               bt_rssi_threshold,
               rssi >= bt_rssi_threshold ? "✔ 통과(카운트됨)"
                                         : "❌ 차단(문 밖)");
    }
#endif

    if (rssi < bt_rssi_threshold)
      return 0;

    const uint8_t *mac = event->disc.addr.val;
    int addr_type = event->disc.addr.type;

    // 랜덤 주소(Random Address)인지 확인하여 고정 기기를 필터링합니다.
    if (addr_type != BLE_ADDR_RANDOM && addr_type != BLE_ADDR_RANDOM_ID)
      return 0;

    // 애플 기기의 동시다발적 MAC 주소 뻥튀기 방지 필터 통과 여부 확인
    if (!is_valid_ble_payload(event->disc.data, event->disc.length_data)) {
      std::lock_guard<std::mutex> lock(mac_mutex);
      dropped_apple_packet_count++;
      return 0; // 조건에 맞지 않는 애플의 다른 찌꺼기 패킷들은 즉시 버림(Drop)
    }

    // NimBLE의 주소는 Little-endian이므로 mac[0], mac[1]이 가장 오른쪽(마지막)
    // 2바이트입니다. 이를 16비트 ID로 변환합니다.
    uint16_t id = (mac[1] << 8) | mac[0];

    std::lock_guard<std::mutex> lock(mac_mutex);
    if (!is_mac_seen(seen_ids_map_ble, id)) {
      mark_mac_seen(seen_ids_map_ble, id);
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
static void ble_on_sync(void) { xSemaphoreGive(ble_sync_sem); }

void start_ble_scan() {
  struct ble_gap_disc_params disc_params;
  memset(&disc_params, 0, sizeof(disc_params));
  disc_params.passive = 1; // 패시브 스캔
  disc_params.filter_duplicates = 1;

  // 무한히 스캔 시작 (이후 cancel로 제어)
  ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params,
               ble_gap_event_cb, NULL);
}

void stop_ble_scan() { ble_gap_disc_cancel(); }

// ==========================================
// HTTP & Wi-Fi 통신 로직
// ==========================================
static EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (event_base == WIFI_EVENT &&
             event_id == WIFI_EVENT_STA_DISCONNECTED) {
    wifi_event_sta_disconnected_t *disconn =
        (wifi_event_sta_disconnected_t *)event_data;
    ESP_LOGE(TAG, "Wi-Fi Disconnected. Reason: %d", disconn->reason);
  } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
  }
}

bool connect_wifi() {
  extern const uint8_t wpa2_ca_pem_start[] asm("_binary_wpa2_ca_pem_start");
  extern const uint8_t wpa2_ca_pem_end[]   asm("_binary_wpa2_ca_pem_end");

  wifi_event_group = xEventGroupCreate();
  esp_event_handler_instance_t instance_any_id;
  esp_event_handler_instance_t instance_got_ip;
  esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                      &wifi_event_handler, NULL,
                                      &instance_any_id);
  esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                      &wifi_event_handler, NULL,
                                      &instance_got_ip);

  wifi_config_t wifi_config = {};
  strlcpy((char *)wifi_config.sta.ssid, WIFI_SSID,
          sizeof(wifi_config.sta.ssid));

  // WPA2-Enterprise (아이디/비밀번호) 방식인지, 일반 WPA2-PSK 방식인지 확인
  if (strlen(WIFI_USER) > 0) {
    ESP_LOGI(TAG, "WPA2-Enterprise (802.1x) 모드로 연결을 시도합니다.");
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);

    // 1. 서버 인증서 검증 활성화 (Evil Twin 방지)
    unsigned int ca_pem_bytes = wpa2_ca_pem_end - wpa2_ca_pem_start;
    esp_err_t cert_err = esp_eap_client_set_ca_cert(wpa2_ca_pem_start, ca_pem_bytes);
    if (cert_err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set WPA2 Enterprise CA certificate: %s", esp_err_to_name(cert_err));
        return false; // 인증서 설정 실패 시 연결 취소
    }

    // 2. 고객님 요청대로 TTLS/PEAP 강제 지정을 완전히 삭제했습니다!
    // 이렇게 하면 아이폰처럼 공유기가 던져주는 방식을 그대로 받아들입니다(자동
    // 협상).

    // 3. 외부/내부 식별자 및 라우팅 설정
    // 맥/아이폰에서 접속할 때 입력하시는 아이디(bsm0546@ajou.ac.kr)가 정확히 맞으므로,
    // 도메인을 자르지 않고 입력하신 WIFI_USER를 그대로 Outer/Inner Identity에 모두 적용합니다.
    ESP_LOGI(TAG, "=> Identity: [%s] (길이: %d)", WIFI_USER, strlen(WIFI_USER));
    ESP_LOGI(TAG, "=> 입력된 비번 길이: %d", strlen(WIFI_PASS));

    // Outer Identity (껍데기 아이디)
    ESP_ERROR_CHECK(
        esp_eap_client_set_identity((uint8_t *)WIFI_USER, strlen(WIFI_USER)));

    // Inner Identity (진짜 아이디)
    ESP_ERROR_CHECK(
        esp_eap_client_set_username((uint8_t *)WIFI_USER, strlen(WIFI_USER)));
    ESP_ERROR_CHECK(
        esp_eap_client_set_password((uint8_t *)WIFI_PASS, strlen(WIFI_PASS)));

    // [중요] 최신 인증 서버들은 ClientHello에 SNI(Server Name Indication) 확장이 없으면
    // 곧바로 연결을 끊어버리는 경우가 있습니다. (애플 기기들은 기본적으로 SNI를 포함합니다)
    // 따라서 아주대학교 도메인을 SNI로 명시적으로 전송하도록 설정합니다.
    // [수정] Mac 패킷에 SNI가 없으므로 서버가 예기치 않은 확장을 받고 끊었을 수 있습니다. 주석 처리합니다.
    // ESP_ERROR_CHECK(esp_eap_client_set_domain_name("ajou.ac.kr"));

    // [출시용] 불필요한 디버그 로그 제거 완료

    // v4.4에서는 EAP-TTLS는 지원하지만 내부 EAP(GTC) 모듈이 아예 존재하지 않습니다.
    // 따라서 Phase 2를 EAP로 설정하면 서버가 GTC를 요구할 때 응답을 만들지 못하고 뻗습니다.
    // AirCUVE 서버가 완벽하게 지원하는 안전한 대안인 PAP(비밀번호 전송) 방식으로 우회합니다.
    ESP_ERROR_CHECK(esp_eap_client_set_ttls_phase2_method(ESP_EAP_TTLS_PHASE2_PAP));

    ESP_ERROR_CHECK(esp_wifi_sta_enterprise_enable());
  } else {
    ESP_LOGI(TAG, "일반 WPA2-PSK 모드로 연결을 시도합니다.");
    strlcpy((char *)wifi_config.sta.password, WIFI_PASS,
            sizeof(wifi_config.sta.password));
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
  }

  esp_wifi_connect();

  EventBits_t bits =
      xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE,
                          pdFALSE, pdMS_TO_TICKS(15000));

  esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                        instance_got_ip);
  esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                        instance_any_id);
  vEventGroupDelete(wifi_event_group);

  if (bits & WIFI_CONNECTED_BIT) {
    ESP_LOGI(TAG, "Wi-Fi Connected successfully.");
    return true;
  } else {
    ESP_LOGE(TAG, "Wi-Fi Connection failed.");
    esp_wifi_disconnect();
    return false;
  }
}

esp_err_t _http_event_handle(esp_http_client_event_t *evt) {
  static char output_buffer[512];
  static int output_len = 0;

  switch (evt->event_id) {
  case HTTP_EVENT_ON_DATA: {
    int copy_len = evt->data_len;
    if (output_len + copy_len < sizeof(output_buffer)) {
      memcpy(output_buffer + output_len, evt->data, copy_len);
      output_len += copy_len;
    }
  } break;
  case HTTP_EVENT_ON_FINISH:
    output_buffer[output_len] = '\0';
    ESP_LOGI(TAG, "HTTP Response: %s", output_buffer);

    if (output_len > 0) {
      cJSON *json = cJSON_Parse(output_buffer);
      if (json != NULL) {
        cJSON *wifi_th =
            cJSON_GetObjectItemCaseSensitive(json, "wifi_rssi_threshold");
        cJSON *bt_th =
            cJSON_GetObjectItemCaseSensitive(json, "bt_rssi_threshold");

        if (cJSON_IsNumber(wifi_th)) {
          wifi_rssi_threshold = wifi_th->valueint;
        }
        if (cJSON_IsNumber(bt_th)) {
          bt_rssi_threshold = bt_th->valueint;
        }
        ESP_LOGI(TAG, "Updated Thresholds -> Wi-Fi: %d, BT: %d",
                 wifi_rssi_threshold, bt_rssi_threshold);
        cJSON_Delete(json);
      }
    }
    output_len = 0;
    break;
  case HTTP_EVENT_DISCONNECTED:
    output_len = 0;
    break;
  default:
    break;
  }
  return ESP_OK;
}

void send_congestion_data(int w_count, int b_count) {
  char post_data[200];
  snprintf(post_data, sizeof(post_data),
           "{\"device_id\":\"%s\",\"wifi_count\":%d,\"ble_count\":%d}",
           DEVICE_ID, w_count, b_count);

  esp_http_client_config_t config = {};
  config.url = API_URL;
  config.event_handler = _http_event_handle;
  config.crt_bundle_attach = esp_crt_bundle_attach; // HTTPS 인증서 자동 검증

  esp_http_client_handle_t client = esp_http_client_init(&config);
  esp_http_client_set_method(client, HTTP_METHOD_POST);
  esp_http_client_set_header(client, "Content-Type", "application/json");
  esp_http_client_set_header(client, "X-API-KEY", API_KEY);
  esp_http_client_set_post_field(client, post_data, strlen(post_data));

  esp_err_t err = esp_http_client_perform(client);
  if (err == ESP_OK) {
    ESP_LOGI(TAG, "HTTP POST Status = %d",
             (int)esp_http_client_get_status_code(client));
  } else {
    ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
  }

  esp_http_client_cleanup(client);
}

// ==========================================
// 메인 어플리케이션 엔트리 포인트
// ==========================================
extern "C" void app_main() {
  ESP_LOGI(TAG, "CrowdCheck System Starting...");

  // 1. NVS 초기화 (Wi-Fi 및 BLE 스택의 내부 상태 저장을 위해 필수)
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  esp_netif_init();
  esp_event_loop_create_default();
  esp_netif_create_default_wifi_sta();

  // 2. BLE (NimBLE) 초기화
  ble_sync_sem = xSemaphoreCreateBinary();
  if (ble_sync_sem == NULL) {
    ESP_LOGE(TAG, "Failed to create ble_sync_sem due to insufficient heap memory.");
    return;
  }
  ESP_ERROR_CHECK(esp_nimble_hci_and_controller_init());
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

  // 기기의 고유 팩토리 MAC 주소 복원
  uint8_t factory_mac[6];
  ESP_ERROR_CHECK(esp_read_mac(factory_mac, ESP_MAC_WIFI_STA));
  ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_STA, factory_mac));
  ESP_LOGI(TAG, "Device MAC set to factory value: %02x:%02x:%02x:%02x:%02x:%02x",
           factory_mac[0], factory_mac[1], factory_mac[2],
           factory_mac[3], factory_mac[4], factory_mac[5]);

  ESP_ERROR_CHECK(esp_wifi_start());
  ESP_LOGI(TAG, "Wi-Fi Stack Initialized.");

  // [부팅 시 1회 통신] 초기 임계값 설정을 받아오기 위해 서버에 더미 데이터 전송
  ESP_LOGI(TAG, "부팅 후 초기 임계값 동기화 시작...");
  if (connect_wifi()) {
    send_congestion_data(0, 0);
    esp_wifi_disconnect();
  }

  // 4. 메인 루프 (120초 스캔 -> 5초 전송 반복)
  while (true) {
    ESP_LOGI(TAG, "=== 스캔 윈도우 시작 (%d초) ===", SCAN_DURATION_SEC);
    uint32_t start_time = xTaskGetTickCount() * portTICK_PERIOD_MS;

    while ((xTaskGetTickCount() * portTICK_PERIOD_MS) - start_time <
           (SCAN_DURATION_SEC * 1000)) {

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
    memset(seen_ids_map_wifi, 0, sizeof(seen_ids_map_wifi));
    memset(seen_ids_map_ble, 0, sizeof(seen_ids_map_ble));
    wifi_count = 0;
    ble_count = 0;
    filtered_wifi_count = 0;
    filtered_ble_count = 0;
    dropped_apple_packet_count = 0;
    mac_mutex.unlock();

    ESP_LOGI(TAG, ">> 수집된 고유 Wi-Fi 기기 수: %d (중복 필터링됨: %d건)",
             current_wifi, current_filtered_wifi);
    ESP_LOGI(TAG,
             ">> 수집된 고유 BLE 기기 수: %d (중복 필터링됨: %d건, 뻥튀기 "
             "방지로 버려진 애플 패킷: %d건)",
             current_ble, current_filtered_ble, current_dropped_apple);
    ESP_LOGI(TAG, ">> 혼잡도 데이터 서버로 HTTP POST 전송 중...");

    if (connect_wifi()) {
      send_congestion_data(current_wifi, current_ble);
      esp_wifi_disconnect();
    } else {
      ESP_LOGW(TAG, "Wi-Fi 연결 실패로 전송 생략");
      // 전송 실패 시 연결 대기에 소모된 시간이 있으므로 추가 대기 없음
    }
  }
}
