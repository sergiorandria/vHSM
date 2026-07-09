// main.cpp
// ESP-IDF SD card (SPI mode) init + write test
// Wiring (from MicroSD module -> ESP32):
//   3V3  -> 3.3V   (see note below if your card needs 5V)
//   CS   -> GPIO 4
//   MOSI -> GPIO 23
//   CLK  -> GPIO 18
//   MISO -> GPIO 19
//   GND  -> GND
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdmmc_cmd.h"
#include <stdio.h>
#include <string.h>
static const char *TAG = "sd_spi";
#define PIN_NUM_MISO GPIO_NUM_19
#define PIN_NUM_MOSI GPIO_NUM_23
#define PIN_NUM_CLK GPIO_NUM_18
#define PIN_NUM_CS GPIO_NUM_4
#define MOUNT_POINT "/sdcard"

// SD SPI clock, in kHz. Some cards/modules (especially bare breakout boards
// without level shifting) are unreliable at the driver's default probe/data
// frequencies and need to be forced slower. Adjust to whatever frequency
// you've confirmed works reliably with this card/module.
#define SD_MAX_FREQ_KHZ 4000

extern "C" void app_main(void) {
  esp_err_t ret;
  ESP_LOGI(TAG, "Initializing SD card over SPI");

  // Give the card time to power up and stabilize before we start clocking it.
  // This does NOT fix CRC/signal-integrity errors (that's a wiring/frequency
  // issue - see SD_MAX_FREQ_KHZ above), but some cards/modules do need a
  // short settle time after VCC is applied before they respond correctly.
  vTaskDelay(pdMS_TO_TICKS(500));

  // Mount config: create filesystem if it doesn't exist, keep files open limit
  // low Zero-init then assign fields individually — same reasoning as bus_cfg
  // above; newer IDF versions add fields (read_only, use_one_fat,
  // disk_status_check_enable) that a designated-initializer list would
  // otherwise need to enumerate explicitly under -Werror.
  esp_vfs_fat_sdmmc_mount_config_t mount_config = {};
  mount_config.format_if_mount_failed = true;
  mount_config.max_files = 5;
  mount_config.allocation_unit_size = 16 * 1024;
  sdmmc_card_t *card;
  // SPI bus configuration
  // NOTE: zero-init first, then assign fields individually. A designated-
  // initializer list here trips -Werror=missing-field-initializers on newer
  // IDF versions, since spi_bus_config_t gained extra octal-SPI fields
  // (data4_io_num..data7_io_num, flags, isr_cpu_id, etc.) that would
  // otherwise need to be listed explicitly.
  spi_bus_config_t bus_cfg = {};
  bus_cfg.mosi_io_num = PIN_NUM_MOSI;
  bus_cfg.miso_io_num = PIN_NUM_MISO;
  bus_cfg.sclk_io_num = PIN_NUM_CLK;
  bus_cfg.quadwp_io_num = -1;
  bus_cfg.quadhd_io_num = -1;
  bus_cfg.max_transfer_sz = 10000;
  ret = spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize SPI bus (%s)", esp_err_to_name(ret));
    return;
  }
  // SD SPI device config (host + CS pin)
  sdmmc_host_t host = SDSPI_HOST_DEFAULT();
  host.slot = SPI2_HOST;
  host.max_freq_khz = SD_MAX_FREQ_KHZ;
  sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
  slot_config.gpio_cs = PIN_NUM_CS;
  slot_config.host_id = (spi_host_device_t)host.slot;
  ret = esp_vfs_fat_sdspi_mount(MOUNT_POINT, &host, &slot_config, &mount_config,
                                &card);
  if (ret != ESP_OK) {
    if (ret == ESP_FAIL) {
      ESP_LOGE(TAG, "Failed to mount filesystem. "
                    "Set format_if_mount_failed = true to format the card.");
    } else {
      ESP_LOGE(TAG,
               "Failed to initialize the card (%s). "
               "Check wiring / pull-ups / card power / SD_MAX_FREQ_KHZ.",
               esp_err_to_name(ret));
    }
    spi_bus_free(SPI2_HOST);
    return;
  }
  ESP_LOGI(TAG, "Filesystem mounted at %s", MOUNT_POINT);
  sdmmc_card_print_info(stdout, card);
  // Write a test file
  const char *file_path = MOUNT_POINT "/hello.txt";
  ESP_LOGI(TAG, "Writing to %s", file_path);
  FILE *f = fopen(file_path, "w");
  if (f == NULL) {
    ESP_LOGE(TAG, "Failed to open file for writing");
  } else {
    fprintf(f, "Hello from ESP32 over SPI!\n");
    fclose(f);
    ESP_LOGI(TAG, "Write successful");
  }
  // Read it back to verify
  f = fopen(file_path, "r");
  if (f == NULL) {
    ESP_LOGE(TAG, "Failed to open file for reading");
  } else {
    char line[128];
    fgets(line, sizeof(line), f);
    fclose(f);
    char *pos = strchr(line, '\n');
    if (pos)
      *pos = '\0';
    ESP_LOGI(TAG, "Read from file: '%s'", line);
  }
  // Unmount and free bus
  esp_vfs_fat_sdcard_unmount(MOUNT_POINT, card);
  spi_bus_free(SPI2_HOST);
  ESP_LOGI(TAG, "Card unmounted, done.");
}
