# AsangP_Client 프로젝트 메모 (MEMORY.md)

## 프로젝트 개요
- **목표**: ESP32-S 보드를 이용한 Wi-Fi 및 BLE 스니핑 기반 혼잡도 측정 시스템 클라이언트 개발.
- **환경**: ESP-IDF, C++ (Arduino 프레임워크 미사용)
- **주요 기능**:
  - 120초 스캔 윈도우 동안 Wi-Fi(Probe Request)와 BLE(Advertisement)를 시분할로 번갈아가며 스니핑.
  - **ESP32-Paxcounter 비트맵 최적화** 기법을 적용하여 8KB 메모리만으로 기기 카운팅 및 중복 처리.
  - Random MAC 필터링을 통해 고정 기기(공유기, 스마트TV 등) 제외 및 Wi-Fi/BLE 각각 독립 카운트.
  - 스캔 완료 후 5초 동안 (추후 구현할) 서버로 전송 대기 및 데이터 초기화.
  - 공식 `esp_wifi` 및 네이티브 `NimBLE` C API 사용.

## 진행 내역
- [x] 요구사항 및 기술 스택 논의 완료 (ESP-IDF 네이티브 API 적용)
- [x] 구현 계획서 검토 완료
- [x] `CrowdCheck.cpp` 소스 파일 생성 완료
  - Wi-Fi Promiscuous 패킷 필터링(Probe Request) 완료
  - NimBLE C API 기반 스캐닝 구성 완료
  - FreeRTOS 시분할 스케줄링 로직 작성 완료
  - **ESP32-Paxcounter 기반 최적화 이식 완료 (비트맵 방식 및 Random MAC 필터링)**

## 추후 진행 사항
- [ ] 서버 API 규격 확정 후 HTTP POST 전송 로직 추가 (Raw 데이터 대신 `wifi_count`, `ble_count` 2개 값 전송)
- [ ] 하드웨어(ESP32-S) 빌드 및 디버깅 테스트 진행
