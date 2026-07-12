# ESP32 Signing HSM Firmware

This firmware implements a signing Hardware Security Module (HSM) on ESP32, providing HTTP-based cryptographic operations:

- **Key Generation**: Create ECDSA P-256 keys for users (stored on SD card)
- **File Upload**: Handle file uploads in chunks to temporary storage
- **Signing**: Sign uploaded files with user keys, returning signature and hash

## Hardware Requirements

- ESP32 development board
- SD card module connected via SPI:
  - MOSI: GPIO 23
  - MISO: GPIO 19
  - CLK:  GPIO 18
  - CS:   GPIO 12
- UART1 (TX: GPIO 17) for debug logging (115200 baud)

## Software Dependencies

This firmware uses the ESP-IDF framework and requires the following components:
- esp_http_server
- esp_wifi
- nvs_flash
- fatfs
- sdmmc
- vfs
- driver
- esp_driver_uart
- cjson
- mbedtls (included via ESP-IDF)

## WiFi Configuration

The firmware is configured to connect to a specific WiFi network (hardcoded):
- SSID: `YOUR_SSID`
- Password: `YOUR_PASSWORD`

To change these, modify `STA_SSID` and `STA_PASS` in `main/hsm.cpp`.

## Building and Flashing

1. Install [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
2. Set up the ESP-IDF environment:
   ```bash
   . $HOME/esp/esp-idf/export.sh   # Adjust path to your ESP-IDF installation
   ```
3. Build the firmware:
   ```bash
   idf.py build
   ```
4. Flash to your ESP32:
   ```bash
   idf.py -p PORT flash
   ```
5. Monitor debug output:
   ```bash
   idf.py -p PORT monitor
   ```

## Usage

Once connected to WiFi, the firmware will print its IP address to the debug UART. Send HTTP POST requests to `http://<ESP_IP>/cmd` with JSON payloads.

### Commands

#### `createKey`
Generate a new ECDSA P-256 key for a user.

**Request:**
```json
{
  "cmd": "createKey",
  "userId": "user123",
  "overwrite": false
}
```

**Response:**
```json
{
  "status": "ok",
  "userId": "user123",
  "publicKeyAlgorithm": "ECDSA-P256",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

#### `uploadStart`
Initialize an upload session.

**Request:**
```json
{
  "cmd": "uploadStart",
  "filename": "document.pdf"
}
```

**Response:**
```json
{
  "status": "ok",
  "filename": "document.pdf"
}
```

#### `uploadChunk`
Upload a chunk of file data (Base64 encoded).

**Request:**
```json
{
  "cmd": "uploadChunk",
  "filename": "document.pdf",
  "dataBase64": "base64-encoded-chunk-data"
}
```

**Response:**
```json
{
  "status": "ok",
  "filename": "document.pdf",
  "bytesWritten": 1024,
  "totalBytes": 2048
}
```

#### `uploadEnd`
Finalize an upload session.

**Request:**
```json
{
  "cmd": "uploadEnd",
  "filename": "document.pdf"
}
```

**Response:**
```json
{
  "status": "ok",
  "filename": "document.pdf",
  "totalBytes": 4096
}
```

#### `sign`
Sign an uploaded file with a user's key.

**Request:**
```json
{
  "cmd": "sign",
  "userId": "user123",
  "filename": "document.pdf",
  "metadata": {"optional": "metadata"}
}
```

**Response:**
```json
{
  "status": "ok",
  "userId": "user123",
  "filename": "document.pdf",
  "hashAlgorithm": "SHA-256",
  "hashHex": "a1b2c3...",
  "signatureAlgorithm": "ECDSA-SHA256",
  "signatureBase64": "MEUCIQD..."
}
```

## Notes

- Files are stored temporarily on the SD card in `/sdcard/tmp` and are automatically deleted after signing.
- User keys are stored as PEM files in `/sdcard/keys`.
- The firmware includes basic input validation to prevent path traversal attacks.
- Debug logs are output via UART1 at 115200 baud.

## License

This project is part of the Virtual HSM (vHSM) system. See the [root README](../README.md) for licensing information.
