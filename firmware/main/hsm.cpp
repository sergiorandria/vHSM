#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
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
#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_vfs_fat.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
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
#define AUDIT_DIR MOUNT_POINT "/logs"
#define AUDIT_FILE AUDIT_DIR "/audit.log"
#define AUDIT_STATE_FILE AUDIT_DIR "/.audit_state"
#define USERID_MAX_LEN 64
#define FILENAME_MAX_LEN 128
#define MAX_JSON_LINE_LEN 8192
#define MAX_FILE_READ_LEN (32 * 1024)
#define MAX_UPLOAD_BYTES (32 * 1024)
#define SIGNATURE_MAX_BYTES 512
#define SIGNATURE_B64_BUF_LEN 700

#define RATE_WINDOW_S 60
#define MAX_SIGN_LIMIT_ENTRIES 32
#define SD_BLOCK_SIZE 512

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
    // Mirror the same line to the USB/console serial (UART0) so that
    // `idf.py -p /dev/ttyUSB0 monitor` shows everything too.
    fputs(buf, stdout);
    fflush(stdout);
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

// ---- Security: rate limiting + audit log ----
static uint32_t now_s(void) {
  return (uint32_t)(esp_timer_get_time() / 1000000);
}

static bool rate_limited_window(uint32_t &start, uint32_t &count, uint32_t max,
                                uint32_t window_s) {
  uint32_t now = now_s();
  if (now - start >= window_s) {
    start = now;
    count = 0;
  }
  if (count >= max)
    return true;
  count++;
  return false;
}

// Global device-wide request throttle.
static struct {
  uint32_t start;
  uint32_t count;
} s_global_window;
static bool global_rate_limited() {
  return rate_limited_window(s_global_window.start, s_global_window.count,
                             CONFIG_HSM_MAX_REQ_PER_MIN, RATE_WINDOW_S);
}

// Per-user sign throttle (limits ECDSA signing throughput per identity).
struct UserSignLimit {
  std::string userId;
  uint32_t start;
  uint32_t count;
};
static std::vector<UserSignLimit> s_user_sign_limits;

static bool user_sign_rate_limited(const std::string &userId) {
  uint32_t now = now_s();
  for (auto &u : s_user_sign_limits) {
    if (u.userId == userId) {
      if (now - u.start >= RATE_WINDOW_S) {
        u.start = now;
        u.count = 0;
      }
      if (u.count >= CONFIG_HSM_SIGN_LIMIT_PER_MIN)
        return true;
      u.count++;
      return false;
    }
  }
  if (s_user_sign_limits.size() >= MAX_SIGN_LIMIT_ENTRIES)
    s_user_sign_limits.erase(s_user_sign_limits.begin());
  UserSignLimit u;
  u.userId = userId;
  u.start = now;
  u.count = 1;
  s_user_sign_limits.push_back(std::move(u));
  return false;
}

// Per-TCP-connection throttle. esp_http_server caps open sockets (default 7),
// so this bounds each client that doesn't reuse a connection too.
struct ConnRate {
  uint32_t start;
  uint32_t count;
};
static void conn_rate_free(void *p) { free(p); }

static bool conn_rate_limited(httpd_req_t *req) {
  auto *cc = (ConnRate *)req->sess_ctx;
  if (!cc) {
    cc = (ConnRate *)calloc(1, sizeof(ConnRate));
    if (!cc)
      return false;
    cc->start = now_s();
    req->sess_ctx = cc;
    req->free_ctx = conn_rate_free;
  }
  return rate_limited_window(cc->start, cc->count, CONFIG_HSM_MAX_REQ_PER_CONN,
                             RATE_WINDOW_S);
}

// Failed-auth lockout with exponential backoff.
static struct {
  uint32_t window_start_s;
  uint32_t failures;
  uint32_t cooldown_s;
  uint32_t lock_until_s;
} s_auth_fail;

static uint32_t auth_lock_remaining_s(void) {
  uint32_t now = now_s();
  if (s_auth_fail.lock_until_s != 0 && now < s_auth_fail.lock_until_s)
    return s_auth_fail.lock_until_s - now;
  return 0;
}

static void record_auth_failure(void) {
  uint32_t now = now_s();
  if (now - s_auth_fail.window_start_s >= CONFIG_HSM_AUTH_FAIL_WINDOW_S) {
    s_auth_fail.window_start_s = now;
    s_auth_fail.failures = 0;
  }
  s_auth_fail.failures++;
  if (s_auth_fail.failures >= (uint32_t)CONFIG_HSM_AUTH_FAIL_MAX) {
    uint32_t base = (s_auth_fail.cooldown_s == 0)
                        ? (uint32_t)CONFIG_HSM_AUTH_LOCK_BASE_S
                        : s_auth_fail.cooldown_s;
    s_auth_fail.cooldown_s = base * 2;
    if (s_auth_fail.cooldown_s > (uint32_t)CONFIG_HSM_AUTH_LOCK_MAX_S)
      s_auth_fail.cooldown_s = CONFIG_HSM_AUTH_LOCK_MAX_S;
    s_auth_fail.lock_until_s = now + s_auth_fail.cooldown_s;
    s_auth_fail.window_start_s = now;
    s_auth_fail.failures = 0;
  }
}

static void record_auth_success(void) {
  s_auth_fail.lock_until_s = 0;
  s_auth_fail.window_start_s = now_s();
  s_auth_fail.failures = 0;
}

// Append-only audit trail. Each line carries the SHA-256 of the previous line,
// forming a chain that makes tampering detectable.
static uint32_t s_audit_seq = 0;
static char s_audit_prev_hash[65] = {0};

static std::string sha256_hex(const void *data, size_t len) {
  uint8_t hash[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
             (const unsigned char *)data, len, hash);
  char hex[65];
  for (int i = 0; i < 32; i++)
    snprintf(&hex[i * 2], 3, "%02x", hash[i]);
  return std::string(hex, 64);
}

static void audit_sanitize(std::string &s) {
  for (char &c : s) {
    if (c == ',' || c == '\n' || c == '\r' || c == '"')
      c = '_';
  }
  if (s.empty())
    s = "-";
}

static void audit_log(const char *event, const char *user, const char *detail) {
#if CONFIG_HSM_AUDIT_ENABLED
  std::string u = user ? user : "-";
  std::string d = detail ? detail : "-";
  audit_sanitize(u);
  audit_sanitize(d);

  uint32_t ts = now_s();
  char raw[512];
  snprintf(raw, sizeof(raw), "%" PRIu32 ",%" PRIu32 ",%s,%s,%s", s_audit_seq,
           ts, event, u.c_str(), d.c_str());

  std::string rec = std::string(raw) + "," + s_audit_prev_hash + "\n";

  FILE *f = fopen(AUDIT_FILE, "a");
  if (!f) {
    ESP_LOGW(TAG, "audit: cannot append to %s", AUDIT_FILE);
    return;
  }
  bool ok = fwrite(rec.data(), 1, rec.size(), f) == rec.size();
  fclose(f);

  if (ok) {
    std::string h = sha256_hex(raw, strlen(raw));
    memcpy(s_audit_prev_hash, h.data(), 64);
    s_audit_seq++;
    FILE *sf = fopen(AUDIT_STATE_FILE, "w");
    if (sf) {
      fprintf(sf, "%" PRIu32 "\n%s\n", s_audit_seq, s_audit_prev_hash);
      fclose(sf);
    }
  } else {
    ESP_LOGW(TAG, "audit: write failed");
  }
#else
  (void)event;
  (void)user;
  (void)detail;
#endif
}

static void audit_init(void) {
#if CONFIG_HSM_AUDIT_ENABLED
  ensure_dir_exists(AUDIT_DIR);
  FILE *sf = fopen(AUDIT_STATE_FILE, "r");
  if (sf) {
    if (fscanf(sf, "%" PRIu32 "\n%64s\n", &s_audit_seq, s_audit_prev_hash) !=
        2) {
      s_audit_seq = 0;
      snprintf(s_audit_prev_hash, sizeof(s_audit_prev_hash), "%064u", 0u);
    }
    fclose(sf);
  } else {
    s_audit_seq = 0;
    snprintf(s_audit_prev_hash, sizeof(s_audit_prev_hash), "%064u", 0u);
  }
  audit_log("boot", NULL, "ESP32 signing HSM started");
#endif
}

// ---- Helpers ----
struct CmdResult {
  int status;
  std::string body;
};

static int error_http_status(const char *code) {
  static const struct {
    const char *code;
    int status;
  } table[] = {
      {"invalid_json", 400},
      {"missing_cmd", 400},
      {"missing_or_invalid_userId", 400},
      {"missing_or_invalid_filename", 400},
      {"missing_dataBase64", 400},
      {"invalid_base64", 400},
      {"body_too_large_or_empty", 400},
      {"unauthorized", 401},
      {"unknown_cmd", 404},
      {"unknown_userId", 404},
      {"file_not_found", 404},
      {"file_not_found_or_too_large", 404},
      {"key_already_exists", 409},
      {"file_too_large", 413},
      {"rate_limited", 429},
      {"temporarily_locked", 503},
  };
  for (auto &e : table)
    if (strcmp(e.code, code) == 0)
      return e.status;
  return 500;
}

static const char *error_message(const char *code) {
  static const struct {
    const char *code;
    const char *message;
  } table[] = {
      {"invalid_json", "Request body is not valid JSON"},
      {"missing_cmd", "Missing or invalid 'cmd' field"},
      {"unknown_cmd", "Unknown command"},
      {"missing_or_invalid_userId", "Missing or invalid 'userId'"},
      {"missing_or_invalid_filename", "Missing or invalid 'filename'"},
      {"missing_dataBase64", "Missing 'dataBase64' field"},
      {"invalid_base64", "'dataBase64' is not valid base64"},
      {"body_too_large_or_empty",
       "Request body must be non-empty and under 8 KiB"},
      {"unauthorized", "Invalid or missing bearer token"},
      {"temporarily_locked",
       "Too many failed auth attempts; device is locked out"},
      {"rate_limited", "Operation rate limit exceeded"},
      {"file_too_large", "Upload exceeds the maximum allowed size"},
      {"key_already_exists", "A key for this user already exists"},
      {"unknown_userId", "No key exists for this user"},
      {"file_not_found", "Uploaded file not found"},
      {"file_not_found_or_too_large", "Uploaded file not found or too large"},
  };
  for (auto &e : table)
    if (strcmp(e.code, code) == 0)
      return e.message;
  return "Internal error";
}

static const char *error_hint(const char *code) {
  static const struct {
    const char *code;
    const char *hint;
  } table[] = {
      {"invalid_json",
       "Send one well-formed JSON object, e.g. {\"cmd\":\"sign\"}"},
      {"missing_cmd", "cmd must be one of: createKey, uploadStart, "
                      "uploadChunk, uploadEnd, sign"},
      {"unknown_cmd", "Supported commands: createKey, uploadStart, "
                      "uploadChunk, uploadEnd, sign"},
      {"missing_or_invalid_userId",
       "userId must be 1-64 chars using A-Z a-z 0-9 - _ ."},
      {"missing_or_invalid_filename",
       "filename must be 1-128 chars using A-Z a-z 0-9 - _ ."},
      {"missing_dataBase64",
       "Include the file chunk, base64-encoded, in 'dataBase64'"},
      {"invalid_base64", "Re-encode the chunk with standard base64"},
      {"body_too_large_or_empty", "Send a compact JSON body without wrappers"},
      {"unauthorized",
       "Add header 'Authorization: Bearer <token>' (menuconfig HSM_API_TOKEN)"},
      {"temporarily_locked",
       "Wait for the cooldown (see the Retry-After header) before retrying"},
      {"rate_limited", "Slow down: fewer commands per minute"},
      {"file_too_large",
       "Files are capped at 32 KiB; upload in smaller chunks"},
      {"key_already_exists", "Set overwrite:true to replace the existing key"},
      {"unknown_userId", "Generate a key first with cmd=createKey"},
      {"file_not_found",
       "Run uploadStart, uploadChunk, uploadEnd before signing"},
      {"file_not_found_or_too_large", "Re-upload the file (max 32 KiB)"},
  };
  for (auto &e : table)
    if (strcmp(e.code, code) == 0)
      return e.hint;
  return "";
}

static CmdResult make_error(const char *code) {
  cJSON_ptr err(cJSON_CreateObject());
  cJSON_AddStringToObject(err.get(), "status", "error");
  cJSON_AddStringToObject(err.get(), "error", code);
  cJSON_AddStringToObject(err.get(), "message", error_message(code));
  const char *hint = error_hint(code);
  if (hint[0] != '\0')
    cJSON_AddStringToObject(err.get(), "hint", hint);
  cJSON_str_ptr s(cJSON_PrintUnformatted(err.get()));
  CmdResult r;
  r.status = error_http_status(code);
  r.body = s.get() ? s.get() : "{}";
  return r;
}

static CmdResult make_success(cJSON_ptr &resp) {
  cJSON_AddStringToObject(resp.get(), "status", "ok");
  cJSON_str_ptr out(cJSON_PrintUnformatted(resp.get()));
  CmdResult r;
  r.status = 200;
  r.body = out.get() ? out.get() : "{}";
  return r;
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

static uint32_t s_sign_count = 0;
static sdmmc_card_t *g_card = NULL;

// ---- Command Handlers ----
static CmdResult handle_create_key(cJSON *root) {
  cJSON *userIdItem = cJSON_GetObjectItemCaseSensitive(root, "userId");
  cJSON *overwriteItem = cJSON_GetObjectItemCaseSensitive(root, "overwrite");

  if (!validate_string_component(userIdItem, USERID_MAX_LEN))
    return make_error("missing_or_invalid_userId");

  bool overwrite = cJSON_IsBool(overwriteItem) && cJSON_IsTrue(overwriteItem);
  bool existed = false;
  std::string key_path =
      std::string(KEYS_DIR) + "/" + userIdItem->valuestring + ".pem";
  if (access(key_path.c_str(), F_OK) == 0)
    existed = true;

  if (!overwrite && existed) {
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
  audit_log(existed && overwrite ? "key_overwritten" : "key_created",
            userIdItem->valuestring, "ECDSA-P256");
  return make_success(resp);
}

static CmdResult handle_upload_start(cJSON *root) {
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

static CmdResult handle_upload_chunk(cJSON *root) {
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
  struct stat prev;
  long cur = 0;
  if (stat(tmp_path.c_str(), &prev) == 0)
    cur = prev.st_size;
  if (cur >= MAX_UPLOAD_BYTES || (long)actual_len > MAX_UPLOAD_BYTES - cur)
    return make_error("file_too_large");

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

static CmdResult handle_upload_end(cJSON *root) {
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

static CmdResult handle_sign(cJSON *root) {
  cJSON *userIdItem = cJSON_GetObjectItemCaseSensitive(root, "userId");
  cJSON *filenameItem = cJSON_GetObjectItemCaseSensitive(root, "filename");

  if (!validate_string_component(userIdItem, USERID_MAX_LEN))
    return make_error("missing_or_invalid_userId");
  if (!validate_string_component(filenameItem, FILENAME_MAX_LEN))
    return make_error("missing_or_invalid_filename");

  if (user_sign_rate_limited(userIdItem->valuestring))
    return make_error("rate_limited");

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

  uint8_t hash[32];
  if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), file_buf.data(),
                 file_buf.size(), hash) != 0) {
    unlink(tmp_path.c_str());
    return make_error("hash_failed");
  }

  char hash_hex[65];
  for (int i = 0; i < 32; i++)
    snprintf(&hash_hex[i * 2], 3, "%02x", hash[i]);

  std::string sig_b64;
  if (sign_hash(key.get(), hash, sig_b64) != ESP_OK) {
    unlink(tmp_path.c_str());
    return make_error("signing_failed");
  }

  unlink(tmp_path.c_str()); // Clean up the signed upload
  s_sign_count++;
  audit_log(
      "sign", userIdItem->valuestring,
      (std::string(filenameItem->valuestring) + " hash=" + hash_hex).c_str());

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

static CmdResult handle_request(const char *json_line) {
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
static bool auth_enabled(void) { return CONFIG_HSM_API_TOKEN[0] != '\0'; }

static bool check_auth(httpd_req_t *req) {
  if (!auth_enabled())
    return true;
  char hdr[160];
  if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) !=
      ESP_OK)
    return false;
  static const char prefix[] = "Bearer ";
  if (strncmp(hdr, prefix, sizeof(prefix) - 1) != 0)
    return false;
  return strcmp(hdr + sizeof(prefix) - 1, CONFIG_HSM_API_TOKEN) == 0;
}

static void send_json(httpd_req_t *req, int status, const char *body) {
  switch (status) {
  case 200:
    httpd_resp_set_status(req, HTTPD_200);
    break;
  case 400:
    httpd_resp_set_status(req, "400 Bad Request");
    break;
  case 401:
    httpd_resp_set_status(req, "401 Unauthorized");
    break;
  case 404:
    httpd_resp_set_status(req, "404 Not Found");
    break;
  case 409:
    httpd_resp_set_status(req, "409 Conflict");
    break;
  case 413:
    httpd_resp_set_status(req, "413 Payload Too Large");
    break;
  case 429:
    httpd_resp_set_status(req, "429 Too Many Requests");
    break;
  case 503:
    httpd_resp_set_status(req, "503 Service Unavailable");
    break;
  default:
    httpd_resp_set_status(req, "500 Internal Server Error");
    break;
  }
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, body, strlen(body));
}

static esp_err_t cmd_post_handler(httpd_req_t *req) {
  // ---- DoS throttling: global + per-connection, before reading the body ----
  if (global_rate_limited() || conn_rate_limited(req)) {
    ESP_LOGW(TAG, "Rate limit exceeded on /cmd");
    audit_log("rate_limited", NULL, "/cmd global-or-connection");
    CmdResult e = make_error("rate_limited");
    send_json(req, e.status, e.body.c_str());
    return ESP_OK;
  }

  // ---- Authentication with brute-force lockout (exponential backoff) ----
  if (auth_enabled()) {
    uint32_t remaining = auth_lock_remaining_s();
    if (remaining > 0) {
      char retry[16];
      snprintf(retry, sizeof(retry), "%" PRIu32, remaining);
      httpd_resp_set_hdr(req, "Retry-After", retry);
      audit_log("auth_locked", NULL, NULL);
      CmdResult e = make_error("temporarily_locked");
      send_json(req, e.status, e.body.c_str());
      return ESP_OK;
    }
    if (!check_auth(req)) {
      record_auth_failure();
      audit_log("auth_failed", NULL, NULL);
      uint32_t now_lock = auth_lock_remaining_s();
      if (now_lock > 0) {
        char retry[16];
        snprintf(retry, sizeof(retry), "%" PRIu32, now_lock);
        httpd_resp_set_hdr(req, "Retry-After", retry);
        CmdResult e = make_error("temporarily_locked");
        send_json(req, e.status, e.body.c_str());
        return ESP_OK;
      }
      CmdResult e = make_error("unauthorized");
      send_json(req, e.status, e.body.c_str());
      return ESP_OK;
    }
    record_auth_success();
  }

  if (req->content_len <= 0 || req->content_len >= HTTP_BODY_MAX_LEN) {
    CmdResult e = make_error("body_too_large_or_empty");
    send_json(req, e.status, e.body.c_str());
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

  CmdResult result = handle_request(buf.data());
  ESP_LOGI(TAG, "TX (%d): %s", result.status, result.body.c_str());

  send_json(req, result.status, result.body.c_str());
  return ESP_OK;
}

static esp_err_t health_get_handler(httpd_req_t *req) {
  cJSON_ptr h(cJSON_CreateObject());
  cJSON_AddStringToObject(h.get(), "status", "ok");
  cJSON_AddStringToObject(h.get(), "service", "vHSM-ESP32");
  cJSON_AddStringToObject(h.get(), "version",
                          esp_app_get_description()->version);
  cJSON_AddNumberToObject(h.get(), "uptimeSeconds",
                          (double)(esp_timer_get_time() / 1000000));
  cJSON_AddNumberToObject(h.get(), "freeHeapBytes",
                          (double)heap_caps_get_free_size(MALLOC_CAP_8BIT));
  cJSON_AddNumberToObject(h.get(), "authEnabled", auth_enabled() ? 1 : 0);

  wifi_ap_record_t ap;
  if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
    cJSON_AddStringToObject(h.get(), "wifiSsid", (const char *)ap.ssid);
    cJSON_AddNumberToObject(h.get(), "wifiRssi", ap.rssi);
    cJSON_AddNumberToObject(h.get(), "wifiChannel", ap.primary);
  } else {
    cJSON_AddStringToObject(h.get(), "wifiSsid", "not-connected");
    cJSON_AddNumberToObject(h.get(), "wifiRssi", 0);
  }

  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  esp_netif_ip_info_t ip;
  if (netif && esp_netif_get_ip_info(netif, &ip) == ESP_OK) {
    char ipbuf[16];
    snprintf(ipbuf, sizeof(ipbuf), IPSTR, IP2STR(&ip.ip));
    cJSON_AddStringToObject(h.get(), "ip", ipbuf);
  }

  if (g_card) {
    cJSON_AddNumberToObject(h.get(), "sdTotalBytes",
                            (double)g_card->csd.capacity * SD_BLOCK_SIZE);
  }
  uint32_t keys = 0;
  DIR *d = opendir(KEYS_DIR);
  if (d) {
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
      if (strstr(ent->d_name, ".pem") != NULL)
        keys++;
    closedir(d);
  }
  cJSON_AddNumberToObject(h.get(), "keyCount", keys);
  cJSON_AddNumberToObject(h.get(), "signCount", (double)s_sign_count);
  cJSON_AddNumberToObject(h.get(), "auditEnabled",
                          CONFIG_HSM_AUDIT_ENABLED ? 1 : 0);

  CmdResult ok = make_success(h);
  send_json(req, ok.status, ok.body.c_str());
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

  httpd_uri_t health_uri = {};
  health_uri.uri = "/health";
  health_uri.method = HTTP_GET;
  health_uri.handler = health_get_handler;
  health_uri.user_ctx = NULL;
  httpd_register_uri_handler(server, &health_uri);

  return server;
}

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static const char *wifi_authmode_str(wifi_auth_mode_t m) {
  switch (m) {
  case WIFI_AUTH_OPEN:
    return "OPEN";
  case WIFI_AUTH_WEP:
    return "WEP";
  case WIFI_AUTH_WPA_PSK:
    return "WPA_PSK";
  case WIFI_AUTH_WPA2_PSK:
    return "WPA2_PSK";
  case WIFI_AUTH_WPA_WPA2_PSK:
    return "WPA_WPA2_PSK";
  case WIFI_AUTH_WPA2_ENTERPRISE:
    return "WPA2_ENTERPRISE";
  case WIFI_AUTH_WPA3_PSK:
    return "WPA3_PSK";
  case WIFI_AUTH_WPA2_WPA3_PSK:
    return "WPA2_WPA3_PSK";
  case WIFI_AUTH_WAPI_PSK:
    return "WAPI_PSK";
  default:
    return "?";
  }
}

static const char *wifi_disconnect_reason_str(int r) {
  switch (r) {
  case WIFI_REASON_UNSPECIFIED:
    return "UNSPECIFIED";
  case WIFI_REASON_AUTH_EXPIRE:
    return "AUTH_EXPIRE (802.11 auth handshake timed out)";
  case WIFI_REASON_AUTH_LEAVE:
    return "AUTH_LEAVE";
  case WIFI_REASON_ASSOC_EXPIRE:
    return "ASSOC_EXPIRE";
  case WIFI_REASON_ASSOC_TOOMANY:
    return "ASSOC_TOOMANY (AP overloaded)";
  case WIFI_REASON_NOT_AUTHED:
    return "NOT_AUTHED (not authenticated yet)";
  case WIFI_REASON_NOT_ASSOCED:
    return "NOT_ASSOCED";
  case WIFI_REASON_ASSOC_LEAVE:
    return "ASSOC_LEAVE";
  case WIFI_REASON_ASSOC_NOT_AUTHED:
    return "ASSOC_NOT_AUTHED";
  case WIFI_REASON_DISASSOC_PWRCAP_BAD:
    return "DISASSOC_PWRCAP_BAD";
  case WIFI_REASON_DISASSOC_SUPCHAN_BAD:
    return "DISASSOC_SUPCHAN_BAD";
  case WIFI_REASON_IE_INVALID:
    return "IE_INVALID";
  case WIFI_REASON_MIC_FAILURE:
    return "MIC_FAILURE (EAPOL MIC mismatch, likely wrong password)";
  case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
    return "4WAY_HANDSHAKE_TIMEOUT (EAPOL 4-way handshake stalled, likely "
           "wrong password)";
  case WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT:
    return "GROUP_KEY_UPDATE_TIMEOUT";
  case WIFI_REASON_IE_IN_4WAY_DIFFERS:
    return "IE_IN_4WAY_DIFFERS";
  case WIFI_REASON_GROUP_CIPHER_INVALID:
    return "GROUP_CIPHER_INVALID";
  case WIFI_REASON_PAIRWISE_CIPHER_INVALID:
    return "PAIRWISE_CIPHER_INVALID";
  case WIFI_REASON_AKMP_INVALID:
    return "AKMP_INVALID (AP/STA auth mode mismatch)";
  case WIFI_REASON_UNSUPP_RSN_IE_VERSION:
    return "UNSUPP_RSN_IE_VERSION";
  case WIFI_REASON_INVALID_RSN_IE_CAP:
    return "INVALID_RSN_IE_CAP";
  case WIFI_REASON_802_1X_AUTH_FAILED:
    return "802_1X_AUTH_FAILED";
  case WIFI_REASON_CIPHER_SUITE_REJECTED:
    return "CIPHER_SUITE_REJECTED";
  case WIFI_REASON_BEACON_TIMEOUT:
    return "BEACON_TIMEOUT (AP went quiet / out of range)";
  case WIFI_REASON_NO_AP_FOUND:
    return "NO_AP_FOUND (SSID not visible; check SSID / band / AP power)";
  case WIFI_REASON_AUTH_FAIL:
    return "AUTH_FAIL (WPA/WPA2 authentication rejected, wrong password?)";
  case WIFI_REASON_ASSOC_FAIL:
    return "ASSOC_FAIL (AP rejected association)";
  case WIFI_REASON_HANDSHAKE_TIMEOUT:
    return "HANDSHAKE_TIMEOUT (WiFi handshake timeout)";
  default:
    return "UNKNOWN_REASON";
  }
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT) {
    switch (event_id) {
    case WIFI_EVENT_STA_START:
      ESP_LOGI(TAG, "[WIFI] STA started (radio up)");
      break;
    case WIFI_EVENT_STA_STOP:
      ESP_LOGI(TAG, "[WIFI] STA stopped");
      break;
    case WIFI_EVENT_STA_CONNECTED: {
      wifi_event_sta_connected_t *e = (wifi_event_sta_connected_t *)event_data;
      ESP_LOGI(TAG,
               "[WIFI] CONNECTED to SSID '%s' BSSID " MACSTR " ch=%d auth=%s",
               e->ssid, MAC2STR(e->bssid), e->channel,
               wifi_authmode_str((wifi_auth_mode_t)e->authmode));
      ESP_LOGI(TAG,
               "[WIFI] 802.11 association + WPA 4-way handshake (EAPOL) OK");
      break;
    }
    case WIFI_EVENT_STA_DISCONNECTED: {
      wifi_event_sta_disconnected_t *e =
          (wifi_event_sta_disconnected_t *)event_data;
      ESP_LOGW(TAG, "[WIFI] DISCONNECTED from '%s' reason=%d (%s)", e->ssid,
               (int)e->reason, wifi_disconnect_reason_str(e->reason));
      ESP_LOGW(TAG, "[WIFI] Retrying connection...");
      esp_wifi_connect();
      break;
    }
    case WIFI_EVENT_STA_AUTHMODE_CHANGE: {
      wifi_event_sta_authmode_change_t *e =
          (wifi_event_sta_authmode_change_t *)event_data;
      ESP_LOGI(TAG, "[WIFI] AP authmode changed: %s -> %s",
               wifi_authmode_str((wifi_auth_mode_t)e->old_mode),
               wifi_authmode_str((wifi_auth_mode_t)e->new_mode));
      break;
    }
    case WIFI_EVENT_STA_BEACON_TIMEOUT:
      ESP_LOGW(TAG, "[WIFI] Beacon timeout (AP not responding)");
      break;
    default:
      ESP_LOGD(TAG, "[WIFI] event id=%ld", (long)event_id);
      break;
    }
  } else if (event_base == IP_EVENT) {
    if (event_id == IP_EVENT_STA_GOT_IP) {
      ip_event_got_ip_t *e = (ip_event_got_ip_t *)event_data;
      ESP_LOGI(TAG, "=====================================================");
      ESP_LOGI(TAG, "[NET] Got IP:   " IPSTR, IP2STR(&e->ip_info.ip));
      ESP_LOGI(TAG, "[NET] Netmask:  " IPSTR, IP2STR(&e->ip_info.netmask));
      ESP_LOGI(TAG, "[NET] Gateway:  " IPSTR, IP2STR(&e->ip_info.gw));
      ESP_LOGI(TAG, "[NET] API ready: http://" IPSTR "/cmd",
               IP2STR(&e->ip_info.ip));
      ESP_LOGI(TAG, "=====================================================");
      xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    } else if (event_id == IP_EVENT_STA_LOST_IP) {
      ESP_LOGW(TAG, "[NET] IP address lost");
    }
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
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID,
                                             &wifi_event_handler, NULL));

  wifi_config_t wifi_config = {};
  strncpy((char *)wifi_config.sta.ssid, STA_SSID, sizeof(wifi_config.sta.ssid));
  strncpy((char *)wifi_config.sta.password, STA_PASS,
          sizeof(wifi_config.sta.password));
  wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());

  uint8_t mac[6];
  if (esp_wifi_get_mac(WIFI_IF_STA, mac) == ESP_OK) {
    ESP_LOGI(TAG,
             "[WIFI] STA MAC: " MACSTR
             " (look up this MAC on your router's client list)",
             MAC2STR(mac));
  }

  // Active scan first so we can prove the target SSID is visible to this radio.
  wifi_scan_config_t scan_cfg = {};
  scan_cfg.show_hidden = false;
  scan_cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;
  esp_err_t sret = esp_wifi_scan_start(&scan_cfg, true);
  if (sret == ESP_OK) {
    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    std::vector<wifi_ap_record_t> aps(ap_num);
    esp_wifi_scan_get_ap_records(&ap_num, aps.data());
    ESP_LOGI(TAG, "[WIFI] Scan done: %u AP%s visible", (unsigned)ap_num,
             ap_num == 1 ? "" : "s");
    for (uint16_t i = 0; i < ap_num; i++) {
      const wifi_ap_record_t &ap = aps[i];
      const char *ours = (strcmp((const char *)ap.ssid, STA_SSID) == 0)
                             ? "   <<< target network"
                             : "";
      ESP_LOGI(TAG, "[WIFI]   '%s' ch=%d rssi=%d dBm auth=%s%s",
               (const char *)ap.ssid, ap.primary, ap.rssi,
               wifi_authmode_str(ap.authmode), ours);
    }
  } else {
    ESP_LOGW(TAG, "[WIFI] scan failed: %s", esp_err_to_name(sret));
  }

  ESP_LOGI(TAG, "[WIFI] Connecting to SSID '%s' (min auth %s)...", STA_SSID,
           wifi_authmode_str(WIFI_AUTH_WPA2_PSK));
  ESP_ERROR_CHECK(esp_wifi_connect());

  xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE,
                      portMAX_DELAY);

  // Dump live AP info / signal strength now that we are associated.
  wifi_ap_record_t ap;
  if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
    ESP_LOGI(TAG, "[WIFI] Associated: '%s' ch=%d rssi=%d dBm auth=%s",
             (const char *)ap.ssid, ap.primary, ap.rssi,
             wifi_authmode_str(ap.authmode));
  }
}

static void wifi_status_task(void *arg) {
  while (1) {
    vTaskDelay(pdMS_TO_TICKS(30000));
    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
      ESP_LOGI(TAG, "[WIFI] status: '%s' ch=%d rssi=%d dBm",
               (const char *)ap.ssid, ap.primary, ap.rssi);
    } else {
      ESP_LOGW(TAG, "[WIFI] status: not connected");
    }
  }
}

extern "C" void app_main(void) {
  init_debug_log_uart();
  ESP_LOGI(TAG, "Booting ESP32 signing HSM (WiFi mode)");

  // Show the WPA supplicant's 4-way-handshake debug lines (requires
  // CONFIG_ESP_WIFI_DEBUG_PRINT=y and CONFIG_LOG_MAXIMUM_LEVEL >= DEBUG).
  esp_log_level_set("wpa", ESP_LOG_DEBUG);

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
  g_card = card;
  ESP_LOGI(TAG, "Filesystem mounted at %s", MOUNT_POINT);

  ensure_dir_exists(KEYS_DIR);
  ensure_dir_exists(TMP_DIR);
  clear_tmp_dir();
  audit_init();

  ESP_LOGI(TAG,
           "Rate limits: %d req/min global, %d req/conn/min, "
           "%d sign/min/user",
           CONFIG_HSM_MAX_REQ_PER_MIN, CONFIG_HSM_MAX_REQ_PER_CONN,
           CONFIG_HSM_SIGN_LIMIT_PER_MIN);

  mbedtls_entropy_init(&g_entropy);
  mbedtls_ctr_drbg_init(&g_ctr_drbg);
  const char *pers = "esp32_hsm";
  if (mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                            (const unsigned char *)pers, strlen(pers)) != 0) {
    ESP_LOGE(TAG, "Failed to seed RNG, halting.");
    return;
  }

  if (CONFIG_HSM_API_TOKEN[0] == '\0') {
    ESP_LOGW(TAG, "API authentication DISABLED: HSM_API_TOKEN is empty.");
  }

  wifi_init_sta();
  xTaskCreate(wifi_status_task, "wifi_status", 4096, NULL, tskIDLE_PRIORITY + 1,
              NULL);
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
