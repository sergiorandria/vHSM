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

Once connected to WiFi, the firmware will print its IP address (and the full `http://<IP>/cmd` URL) to the monitor. Send HTTP POST requests to `http://<ESP_IP>/cmd` with JSON payloads.

### Authentication

Every `/cmd` request must include a bearer token to prove the caller may sign:

```
Authorization: Bearer <token>
```

The token is set at build time in the Kconfig option `HSM_API_TOKEN` (`idf.py menuconfig` → *vHSM HSM Firmware*), e.g. a random 32+ character hex value. If the token is left empty, authentication is disabled and the firmware logs a warning at boot — **not recommended**, since any device on the network could sign documents.

Unauthenticated requests get `401 Unauthorized`. Example:

```bash
curl -X POST http://<ESP_IP>/cmd -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"cmd":"createKey","userId":"user123","overwrite":false}'
```

### Health endpoint

`GET http://<ESP_IP>/health` returns device status without authentication:

```json
{
  "status": "ok",
  "service": "vHSM-ESP32",
  "version": "1.0",
  "uptimeSeconds": 42,
  "freeHeapBytes": 123456,
  "authEnabled": 1,
  "wifiSsid": "Ttano",
  "wifiRssi": -51,
  "wifiChannel": 6,
  "ip": "192.168.1.42",
  "sdTotalBytes": 3889233920,
  "keyCount": 3,
  "signCount": 17,
  "auditEnabled": 1
}
```

### Errors

Errors are structured as JSON with a machine-readable `error` code plus a
human `message` and optional `hint`. The HTTP status matches the error:
`400` bad request, `401` unauthorized, `404` not found, `409` key exists,
`413` file too large, `429` rate limited, `503` locked out.

### Rate limiting & brute-force protection

- Global throttle: `HSM_MAX_REQ_PER_MIN` requests/minute to `/cmd`.
- Per-connection throttle: `HSM_MAX_REQ_PER_CONN` requests/minute per TCP connection.
- Per-user sign throttle: `HSM_SIGN_LIMIT_PER_MIN` sign operations/minute per user.
- Auth lockout: after `HSM_AUTH_FAIL_MAX` failed authentications within
  `HSM_AUTH_FAIL_WINDOW_S` seconds, `/cmd` returns `503` with a `Retry-After`
  header and a cooldown that doubles on each consecutive burst
  (`HSM_AUTH_LOCK_BASE_S` → `HSM_AUTH_LOCK_MAX_S`).

### Audit log

With `HSM_AUDIT_ENABLED`, every security-relevant operation is appended to
`/sdcard/logs/audit.log`. Each line is
`seq,uptimeSeconds,event,user,detail,prevHash` where `prevHash` is the SHA-256
of the previous line, forming a tamper-evident chain. Events include `boot`,
`key_created`, `key_overwritten`, `sign`, `auth_failed`, `auth_locked`, and
`rate_limited`.

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
Sign an uploaded file with a user's key. The hash is the SHA-256 digest of the uploaded file bytes alone (no extra binding), so a verifier only needs the file itself to recompute it.

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

The `metadata` field is echoed back to the caller for provenance only; it is *not* part of the signed hash.

**Verification (off-device):** the signer's public key is returned by `createKey`. Verify with OpenSSL:

```bash
# 1. Recompute the file hash
sha256sum document.pdf        # must equal hashHex

# 2. Verify signature (RSA-SHA256 / ECDSA-SHA256)
openssl dgst -sha256 -verify public.pem -signature sig.der document.pdf
```

For ECDSA keys the signature is a DER-encoded ASN.1 sequence; convert `signatureBase64` to DER bytes before verifying. (The REST API `rest_api` uses a SoftHSM/PKCS#11-backed signer and is not affected by this firmware contract.)

## Notes

- Debug logs are mirrored to both the USB/console serial (so `idf.py -p /dev/ttyUSB0 monitor` shows everything) and UART1 (GPIO17) at 115200 baud.
- For WiFi troubleshooting the firmware logs the STA MAC address, a list of visible APs, connect/disconnect events with 802.11 reason codes, the WPA 4-way handshake progress, and the acquired IP address.
- Files are stored temporarily on the SD card in `/sdcard/tmp`; each uploaded file is automatically deleted after the `sign` request that consumes it (cleanup is scoped to that file, so concurrent uploads are not affected).
- Uploads are capped at 32 KiB (`MAX_UPLOAD_BYTES`); larger files are rejected with `file_too_large`.
- User keys are stored as PEM files in `/sdcard/keys`.
- The firmware includes basic input validation to prevent path traversal attacks.
- Debug logs are output via UART1 at 115200 baud.

## License

This project is part of the Virtual HSM (vHSM) system. See the [root README](../README.md) for licensing information.
