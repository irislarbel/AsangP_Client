idf_component_register(SRCS "CrowdCheck.cpp"
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES "wpa2_ca.pem"
                    REQUIRES esp_wifi nvs_flash bt esp_http_client esp-tls json wpa_supplicant)
