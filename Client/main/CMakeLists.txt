idf_component_register(SRCS "CrowdCheck.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES esp_wifi nvs_flash bt esp_http_client esp-tls json wpa_supplicant)
