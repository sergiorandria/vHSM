#include <dirent.h>
#include <errno.h>
#include <memory>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "driver/uart.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_vfs_fat.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sdmmc_cmd.h"

#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"

#include "cJSON.h"

static const char *TAG = "sign_hsm";

#define PIN_NUM_MISO GPIO_NUM_19
#define PIN_NUM_MOSI GPIO_NUM_23
#define PIN_NUM_CLK GPIO_NUM_18
#define PIN_NUM_CS GPIO_NUM_12
#define MOUNT_POINT "/sdcard"
#define SD_MAX_FREQ_KHZ 4000 // keep low, do not touch

#define KEYS_DIR MOUNT_POINT "/keys"
#define TMP_DIR MOUNT_POINT "/tmp"
#define USERID_MAX_LEN 64
#define FILENAME_MAX_LEN 128
#define MAX_JSON_LINE_LEN 8192
#define MAX_FILE_READ_LEN (32 * 1024)
#define SIGNATURE_MAX_BYTES 512
#define SIGNATURE_B64_BUF_LEN 700

#define DEBUG_UART_NUM UART_NUM_1
#define DEBUG_UART_TX_PIN GPIO_NUM_17
#define DEBUG_UART_BAUD 115200

// ---- WiFi STA config (lazy: hardcoded, joins your existing network) ----
#define STA_SSID "Ttano"
#define STA_PASS "#123Wifi_trano_456"
#define HTTP_BODY_MAX_LEN MAX_JSON_LINE_LEN

// ---- Global RNG (seeded once at boot, reused everywhere) ----
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;

// ---- C++ RAII Wrappers ----
struct cJSONDeleter {
  void operator()(cJSON *p) const {
    if (p)
      cJSON_Delete(p);
  }
};
using cJSON_ptr = std::unique_ptr<cJSON, cJSONDeleter>;

struct cJSONStringDeleter {
  void operator()(char *p) const {
    if (p)
      cJSON_free(p);
  }
};
using cJSON_str_ptr = std::unique_ptr<char, cJSONStringDeleter>;

class PKContext {
  mbedtls_pk_context ctx;

public:
  PKContext() { mbedtls_pk_init(&ctx); }
  ~PKContext() { mbedtls_pk_free(&ctx); }
  mbedtls_pk_context *get() { return &ctx; }
};

// ---- Debug Logging ----
static int debug_uart_vprintf(const char *fmt, va_list args) {
  char buf[256];
  int len = vsnprintf(buf, sizeof(buf), fmt, args);
  if (len > 0) {
    int to_write = (len < (int)sizeof(buf)) ? len : (int)sizeof(buf) - 1;
    uart_write_bytes(DEBUG_UART_NUM, buf, to_write);
  }
  return len;
}

static void init_debug_log_uart(void) {
  uart_config_t cfg = {};
  cfg.baud_rate = DEBUG_UART_BAUD;
  cfg.data_bits = UART_DATA_8_BITS;
  cfg.parity = UART_PARITY_DISABLE;
  cfg.stop_bits = UART_STOP_BITS_1;
  cfg.flow_ctrl = UART_HW_FLOWCTRL_DISABLE;
  uart_driver_install(DEBUG_UART_NUM, 256, 256, 0, NULL, 0);
  uart_param_config(DEBUG_UART_NUM, &cfg);
  uart_set_pin(DEBUG_UART_NUM, DEBUG_UART_TX_PIN, UART_PIN_NO_CHANGE,
               UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
  esp_log_set_vprintf(debug_uart_vprintf);
}

// ---- Validation ----
static bool is_safe_name_component(const char *s, size_t max_len) {
  size_t len = strlen(s);
  if (len == 0 || len > max_len || strcmp(s, ".") == 0 || strcmp(s, "..") == 0)
    return false;
  const char *allowed =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
  return strspn(s, allowed) == len;
}

static bool validate_string_component(cJSON *item, size_t max_len) {
  return cJSON_IsString(item) && item->valuestring != NULL &&
         is_safe_name_component(item->valuestring, max_len);
}

// ---- Filesystem ----
static esp_err_t mount_sd_card(sdmmc_card_t **out_card) {
  esp_vfs_fat_sdmmc_mount_config_t mount_config = {};
  mount_config.format_if_mount_failed = false;
  mount_config.max_files = 5;
  mount_config.allocation_unit_size = 16 * 1024;

  spi_bus_config_t bus_cfg = {};
  bus_cfg.mosi_io_num = PIN_NUM_MOSI;
  bus_cfg.miso_io_num = PIN_NUM_MISO;
  bus_cfg.sclk_io_num = PIN_NUM_CLK;
  bus_cfg.quadwp_io_num = -1;
  bus_cfg.quadhd_io_num = -1;
  bus_cfg.max_transfer_sz = 10000;

  esp_err_t ret = spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize SPI bus (%s)", esp_err_to_name(ret));
    return ret;
  }

  sdmmc_host_t host = SDSPI_HOST_DEFAULT();
  host.slot = SPI2_HOST;
  host.max_freq_khz = SD_MAX_FREQ_KHZ;

  sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
  slot_config.gpio_cs = PIN_NUM_CS;
  slot_config.host_id = (spi_host_device_t)host.slot;

  ret = esp_vfs_fat_sdspi_mount(MOUNT_POINT, &host, &slot_config, &mount_config,
                                out_card);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to mount filesystem or init card (%s)",
             esp_err_to_name(ret));
    spi_bus_free(SPI2_HOST);
    return ret;
  }
  return ESP_OK;
}

static void ensure_dir_exists(const char *path) {
  if (mkdir(path, 0777) != 0 && errno != EEXIST) {
    ESP_LOGW(TAG, "Could not create directory %s (errno=%d)", path, errno);
  }
}

static void clear_tmp_dir(void) {
  DIR *d = opendir(TMP_DIR);
  if (!d)
    return;
  struct dirent *entry;
  while ((entry = readdir(d)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    std::string path = std::string(TMP_DIR) + "/" + entry->d_name;
    if (unlink(path.c_str()) != 0) {
      ESP_LOGW(TAG, "Could not remove tmp entry %s", path.c_str());
    }
  }
  closedir(d);
}

// ---- Helpers ----
static std::string make_error(const char *reason) {
  cJSON_ptr err(cJSON_CreateObject());
  cJSON_AddStringToObject(err.get(), "status", "error");
  cJSON_AddStringToObject(err.get(), "error", reason);
  cJSON_str_ptr s(cJSON_PrintUnformatted(err.get()));
  return std::string(s.get());
}

static std::string make_success(cJSON_ptr &resp) {
  cJSON_AddStringToObject(resp.get(), "status", "ok");
  cJSON_str_ptr out(cJSON_PrintUnformatted(resp.get()));
  return std::string(out.get());
}

static const char *pk_alg_name_for(mbedtls_pk_context *key) {
  switch (mbedtls_pk_get_type(key)) {
  case MBEDTLS_PK_RSA:
    return "RSA-PKCS1-SHA256";
  case MBEDTLS_PK_ECKEY:
  case MBEDTLS_PK_ECDSA:
    return "ECDSA-SHA256";
  default:
    return "unknown";
  }
}

static esp_err_t read_sd_file(const std::string &path,
                              std::vector<uint8_t> &out_buf) {
  FILE *f = fopen(path.c_str(), "rb");
  if (!f)
    return ESP_FAIL;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  if (sz < 0 || (size_t)sz > MAX_FILE_READ_LEN) {
    fclose(f);
    return ESP_FAIL;
  }
  fseek(f, 0, SEEK_SET);
  out_buf.resize(sz > 0 ? sz : 1);
  size_t read = fread(out_buf.data(), 1, sz, f);
  fclose(f);
  return (read == (size_t)sz) ? ESP_OK : ESP_FAIL;
}

static esp_err_t load_key_for_user(const std::string &userId,
                                   PKContext &key_out) {
  std::string key_path = std::string(KEYS_DIR) + "/" + userId + ".pem";
  std::vector<uint8_t> buf;

  if (read_sd_file(key_path, buf) != ESP_OK)
    return ESP_ERR_NOT_FOUND;
  buf.push_back('\0'); // Null terminator for PEM parser

  int ret = mbedtls_pk_parse_key(key_out.get(), buf.data(), buf.size(), NULL, 0,
                                 mbedtls_ctr_drbg_random, &g_ctr_drbg);
  mbedtls_platform_zeroize(buf.data(), buf.size());

  if (ret != 0) {
    ESP_LOGE(TAG, "Failed to parse key for user: -0x%04x", -ret);
    return ESP_FAIL;
  }
  return ESP_OK;
}

static esp_err_t sign_hash(mbedtls_pk_context *key, const uint8_t hash[32],
                           std::string &out_b64) {
  uint8_t sig[SIGNATURE_MAX_BYTES];
  size_t sig_len = 0;

  if (mbedtls_pk_sign(key, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig),
                      &sig_len, mbedtls_ctr_drbg_random, &g_ctr_drbg) != 0) {
    return ESP_FAIL;
  }

  std::vector<uint8_t> b64_buf(SIGNATURE_B64_BUF_LEN);
  size_t olen = 0;
  if (mbedtls_base64_encode(b64_buf.data(), b64_buf.size(), &olen, sig,
                            sig_len) != 0) {
    return ESP_FAIL;
  }

  out_b64 = std::string((char *)b64_buf.data(), olen);
  return ESP_OK;
}

// ---- Command Handlers ----
static std::string handle_create_key(cJSON *root) {
  cJSON *userIdItem = cJSON_GetObjectItemCaseSensitive(root, "userId");
  cJSON *overwriteItem = cJSON_GetObjectItemCaseSensitive(root, "overwrite");

  if (!validate_string_component(userIdItem, USERID_MAX_LEN))
    return make_error("missing_or_invalid_userId");

  bool overwrite = cJSON_IsBool(overwriteItem) && cJSON_IsTrue(overwriteItem);
  std::string key_path =
      std::string(KEYS_DIR) + "/" + userIdItem->valuestring + ".pem";

  if (!overwrite && access(key_path.c_str(), F_OK) == 0) {
    return make_error("key_already_exists");
  }

  PKContext key;
  if (mbedtls_pk_setup(key.get(),
                       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) {
    return make_error("key_setup_failed");
  }

  if (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*key.get()),
                          mbedtls_ctr_drbg_random, &g_ctr_drbg) != 0) {
    return make_error("key_generation_failed");
  }

  uint8_t pem_buf[2048];
  uint8_t pub_pem_buf[512];

  if (mbedtls_pk_write_key_pem(key.get(), pem_buf, sizeof(pem_buf)) != 0 ||
      mbedtls_pk_write_pubkey_pem(key.get(), pub_pem_buf,
                                  sizeof(pub_pem_buf)) != 0) {
    mbedtls_platform_zeroize(pem_buf, sizeof(pem_buf));
    return make_error("key_export_failed");
  }

  FILE *f = fopen(key_path.c_str(), "wb");
  if (!f) {
    mbedtls_platform_zeroize(pem_buf, sizeof(pem_buf));
    return make_error("key_write_failed");
  }

  size_t pem_len = strlen((char *)pem_buf);
  size_t written = fwrite(pem_buf, 1, pem_len, f);
  fclose(f);

  mbedtls_platform_zeroize(pem_buf, sizeof(pem_buf));

  if (written != pem_len)
    return make_error("key_write_incomplete");

  cJSON_ptr resp(cJSON_CreateObject());
  cJSON_AddStringToObject(resp.get(), "userId", userIdItem->valuestring);
  cJSON_AddStringToObject(resp.get(), "publicKeyAlgorithm", "ECDSA-P256");
  cJSON_AddStringToObject(resp.get(), "publicKeyPem", (char *)pub_pem_buf);
  return make_success(resp);
}

static std::string handle_upload_start(cJSON *root) {
  cJSON *filenameItem = cJSON_GetObjectItemCaseSensitive(root, "filename");
  if (!validate_string_component(filenameItem, FILENAME_MAX_LEN))
    return make_error("missing_or_invalid_filename");

  std::string tmp_path = std::string(TMP_DIR) + "/" + filenameItem->valuestring;
  FILE *f = fopen(tmp_path.c_str(), "wb");
  if (!f)
    return make_error("tmp_create_failed");
  fclose(f);

  cJSON_ptr resp(cJSON_CreateObject());
  cJSON_AddStringToObject(resp.get(), "filename", filenameItem->valuestring);
  return make_success(resp);
}

static std::string handle_upload_chunk(cJSON *root) {
  cJSON *filenameItem = cJSON_GetObjectItemCaseSensitive(root, "filename");
  cJSON *dataItem = cJSON_GetObjectItemCaseSensitive(root, "dataBase64");

  if (!validate_string_component(filenameItem, FILENAME_MAX_LEN))
    return make_error("missing_or_invalid_filename");
  if (!cJSON_IsString(dataItem) || dataItem->valuestring == NULL)
    return make_error("missing_dataBase64");

  size_t b64_len = strlen(dataItem->valuestring);
  size_t max_decoded_len = (b64_len * 3) / 4 + 1;
  std::vector<uint8_t> decoded(max_decoded_len);

  size_t actual_len = 0;
  if (mbedtls_base64_decode(decoded.data(), decoded.size(), &actual_len,
                            (const unsigned char *)dataItem->valuestring,
                            b64_len) != 0) {
    return make_error("invalid_base64");
  }

  std::string tmp_path = std::string(TMP_DIR) + "/" + filenameItem->valuestring;
  FILE *f = fopen(tmp_path.c_str(), "ab");
  if (!f)
    return make_error("tmp_open_failed");

  size_t written = fwrite(decoded.data(), 1, actual_len, f);
  long total_size = ftell(f);
  fclose(f);

  if (written != actual_len)
    return make_error("tmp_write_incomplete");

  cJSON_ptr resp(cJSON_CreateObject());
  cJSON_AddStringToObject(resp.get(), "filename", filenameItem->valuestring);
  cJSON_AddNumberToObject(resp.get(), "bytesWritten", actual_len);
  cJSON_AddNumberToObject(resp.get(), "totalBytes", total_size);
  return make_success(resp);
}

static std::string handle_upload_end(cJSON *root) {
  cJSON *filenameItem = cJSON_GetObjectItemCaseSensitive(root, "filename");
  if (!validate_string_component(filenameItem, FILENAME_MAX_LEN))
    return make_error("missing_or_invalid_filename");

  std::string tmp_path = std::string(TMP_DIR) + "/" + filenameItem->valuestring;
  struct stat st;
  if (stat(tmp_path.c_str(), &st) != 0)
    return make_error("file_not_found");

  cJSON_ptr resp(cJSON_CreateObject());
  cJSON_AddStringToObject(resp.get(), "filename", filenameItem->valuestring);
  cJSON_AddNumberToObject(resp.get(), "totalBytes", st.st_size);
  return make_success(resp);
}

static std::string handle_sign(cJSON *root) {
  cJSON *userIdItem = cJSON_GetObjectItemCaseSensitive(root, "userId");
  cJSON *filenameItem = cJSON_GetObjectItemCaseSensitive(root, "filename");
  cJSON *metadataItem = cJSON_GetObjectItemCaseSensitive(root, "metadata");

  if (!validate_string_component(userIdItem, USERID_MAX_LEN))
    return make_error("missing_or_invalid_userId");
  if (!validate_string_component(filenameItem, FILENAME_MAX_LEN))
    return make_error("missing_or_invalid_filename");

  PKContext key;
  esp_err_t krc = load_key_for_user(userIdItem->valuestring, key);
  if (krc == ESP_ERR_NOT_FOUND)
    return make_error("unknown_userId");
  if (krc != ESP_OK)
    return make_error("key_load_failed");

  std::string tmp_path = std::string(TMP_DIR) + "/" + filenameItem->valuestring;
  std::vector<uint8_t> file_buf;
  if (read_sd_file(tmp_path, file_buf) != ESP_OK)
    return make_error("file_not_found_or_too_large");

  std::string metadata_for_hash = "null";
  if (metadataItem) {
    cJSON_str_ptr meta_str(cJSON_PrintUnformatted(metadataItem));
    if (meta_str)
      metadata_for_hash = meta_str.get();
  }

  std::vector<uint8_t> combined;
  std::string uid = userIdItem->valuestring;

  combined.insert(combined.end(), uid.begin(), uid.end());
  combined.push_back('|');
  combined.insert(combined.end(), metadata_for_hash.begin(),
                  metadata_for_hash.end());
  combined.push_back('|');
  combined.insert(combined.end(), file_buf.begin(), file_buf.end());

  uint8_t hash[32];
  if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), combined.data(),
                 combined.size(), hash) != 0) {
    clear_tmp_dir();
    return make_error("hash_failed");
  }

  char hash_hex[65];
  for (int i = 0; i < 32; i++)
    snprintf(&hash_hex[i * 2], 3, "%02x", hash[i]);

  std::string sig_b64;
  if (sign_hash(key.get(), hash, sig_b64) != ESP_OK) {
    clear_tmp_dir();
    return make_error("signing_failed");
  }

  clear_tmp_dir(); // Clean up automatically after sign regardless of branch
                   // success

  cJSON_ptr resp(cJSON_CreateObject());
  cJSON_AddStringToObject(resp.get(), "userId", userIdItem->valuestring);
  cJSON_AddStringToObject(resp.get(), "filename", filenameItem->valuestring);
  cJSON_AddStringToObject(resp.get(), "hashAlgorithm", "SHA-256");
  cJSON_AddStringToObject(resp.get(), "hashHex", hash_hex);
  cJSON_AddStringToObject(resp.get(), "signatureAlgorithm",
                          pk_alg_name_for(key.get()));
  cJSON_AddStringToObject(resp.get(), "signatureBase64", sig_b64.c_str());

  return make_success(resp);
}

static std::string handle_request(const char *json_line) {
  cJSON_ptr root(cJSON_Parse(json_line));
  if (!root)
    return make_error("invalid_json");

  cJSON *cmdItem = cJSON_GetObjectItemCaseSensitive(root.get(), "cmd");
  if (!cJSON_IsString(cmdItem) || cmdItem->valuestring == NULL)
    return make_error("missing_cmd");

  std::string cmd = cmdItem->valuestring;
  if (cmd == "createKey")
    return handle_create_key(root.get());
  if (cmd == "uploadStart")
    return handle_upload_start(root.get());
  if (cmd == "uploadChunk")
    return handle_upload_chunk(root.get());
  if (cmd == "uploadEnd")
    return handle_upload_end(root.get());
  if (cmd == "sign")
    return handle_sign(root.get());

  return make_error("unknown_cmd");
}

// ---- WiFi + HTTP transport ----
static esp_err_t cmd_post_handler(httpd_req_t *req) {
  if (req->content_len <= 0 || req->content_len >= HTTP_BODY_MAX_LEN) {
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(
        req, "{\"status\":\"error\",\"error\":\"body_too_large_or_empty\"}",
        HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
  }

  std::vector<char> buf(req->content_len + 1);
  int received = 0;
  while (received < req->content_len) {
    int ret =
        httpd_req_recv(req, buf.data() + received, req->content_len - received);
    if (ret == HTTPD_SOCK_ERR_TIMEOUT)
      continue;
    if (ret <= 0) {
      httpd_resp_send_500(req);
      return ESP_FAIL;
    }
    received += ret;
  }
  buf[req->content_len] = '\0';

  ESP_LOGI(TAG, "RX (%d bytes): %s", (int)req->content_len, buf.data());

  std::string response = handle_request(buf.data());
  ESP_LOGI(TAG, "TX: %s", response.c_str());

  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, response.c_str(), response.size());
  return ESP_OK;
}

static httpd_handle_t start_http_server(void) {
  httpd_handle_t server = NULL;
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.stack_size = 8192; // JSON parsing + mbedtls signing need headroom

  if (httpd_start(&server, &config) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start HTTP server");
    return NULL;
  }

  httpd_uri_t cmd_uri = {};
  cmd_uri.uri = "/cmd";
  cmd_uri.method = HTTP_POST;
  cmd_uri.handler = cmd_post_handler;
  cmd_uri.user_ctx = NULL;
  httpd_register_uri_handler(server, &cmd_uri);

  return server;
}

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (event_base == WIFI_EVENT &&
             event_id == WIFI_EVENT_STA_DISCONNECTED) {
    ESP_LOGW(TAG, "WiFi disconnected, retrying...");
    esp_wifi_connect();
  } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
  }
}

static void wifi_init_sta(void) {
  s_wifi_event_group = xEventGroupCreate();

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_create_default_wifi_sta();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                             &wifi_event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                             &wifi_event_handler, NULL));

  wifi_config_t wifi_config = {};
  strncpy((char *)wifi_config.sta.ssid, STA_SSID, sizeof(wifi_config.sta.ssid));
  strncpy((char *)wifi_config.sta.password, STA_PASS,
          sizeof(wifi_config.sta.password));
  wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_LOGI(TAG, "Connecting to SSID:%s ...", STA_SSID);
  xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE,
                      portMAX_DELAY);
}

extern "C" void app_main(void) {
  init_debug_log_uart();
  ESP_LOGI(TAG, "Booting ESP32 signing HSM (WiFi mode)");

  esp_err_t nvs_ret = nvs_flash_init();
  if (nvs_ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      nvs_ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    nvs_ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(nvs_ret);

  sdmmc_card_t *card = NULL;
  if (mount_sd_card(&card) != ESP_OK) {
    ESP_LOGE(TAG, "SD card mount failed, halting.");
    return;
  }
  ESP_LOGI(TAG, "Filesystem mounted at %s", MOUNT_POINT);

  ensure_dir_exists(KEYS_DIR);
  ensure_dir_exists(TMP_DIR);
  clear_tmp_dir();

  mbedtls_entropy_init(&g_entropy);
  mbedtls_ctr_drbg_init(&g_ctr_drbg);
  const char *pers = "esp32_hsm";
  if (mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                            (const unsigned char *)pers, strlen(pers)) != 0) {
    ESP_LOGE(TAG, "Failed to seed RNG, halting.");
    return;
  }

  wifi_init_sta();
  if (start_http_server() == NULL) {
    ESP_LOGE(TAG, "HTTP server failed to start, halting.");
    return;
  }

  ESP_LOGI(TAG, "Ready - POST JSON commands to http://<esp32-ip>/cmd "
                "(see log line above for the IP)");

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
