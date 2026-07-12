idf_component_register(
    SRCS "hsm.cpp"
    INCLUDE_DIRS "." "${IDF_PATH}/components/openthread/openthread/third_party/mbedtls/repo/include"    
    REQUIRES openthread esp_http_server esp_wifi nvs_flash fatfs sdmmc vfs driver esp_driver_uart cjson
)

