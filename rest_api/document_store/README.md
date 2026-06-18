# vHSM Document Store API

A secure Go-based REST API that performs **on-the-fly AES-GCM 256-bit encryption** using a Virtual Hardware Security Module (**SoftHSM2**) via the PKCS#11 interface, before storing the encrypted payloads into a **MinIO (S3-compatible)** object storage system.

## Architecture & Project Structure

```text
.
├── data/                 # Local directory (optional context)
├── docker-compose.yml    # Orchestrates MinIO, MinIO Initialization, and the Go API
├── Dockerfile            # Multi-stage build (Builder with Golang SDK -> Runtime with Debian-slim)
├── entrypoint.sh         # Shell script automating SoftHSM token/key initialization
├── go.mod                # Go module file
├── go.sum                # Go checksum file
├── main.go               # REST API entry point (Gin Gonic framework & PKCS#11 engine)
├── minio_utils/
│   └── minio_client.go   # S3 storage interaction helper functions
├── README.md             # This documentation file
└── softhsm_tokens/       # Persistent host folder mounting your cryptographic keys
```

- **Symmetric Encryption**: Handled completely inside the SoftHSM engine (`CKM_AES_GCM`). Plaintext keys never leak into the application memory layer.
- **Initialization Pipeline**: The `entrypoint.sh` script checks if a token exists inside the Docker container at startup. If missing, it creates the token, provisions a 256-bit AES key, and updates the local state seamlessly.

---

## Getting Started

### 1. Prerequisites
Make sure you have the following installed on your machine:
- [Docker](https://docker.com)
- [Docker Compose](https://docker.com)
- `curl` (for local endpoint testing)

### 2. Configure Environment Variables
Create a `.env` file in the root directory next to your `docker-compose.yml`:

```env
# MinIO Configuration
MINIO_ROOT_USER=admin
MINIO_ROOT_PASSWORD=supersecretpassword
MINIO_BUCKET=thesis

# SoftHSM / PKCS#11 Configuration
HSM_PIN=1234
HSM_TOKEN_LABEL=MaCleThesis
HSM_LABEL=my-aes-key
HSM_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
```

### 3. Spin up the Stack
Run Docker Compose to build the application image and boot all required services (MinIO, MinIO-init engine, and the API server):

```bash
docker compose up -d --build
```

---

## 📡 API Endpoints & Usage

### Encrypt and Upload a Document

- **URL**: `/api/v1/encrypt`
- **Method**: `POST`
- **Content-Type**: `multipart/form-data`

#### Request Parameters:

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `thesisId` | `string` | Alphanumeric identifier, max 128 chars (allows `-` and `_`). |
| `document` | `file` | The raw document binary to encrypt. |

#### Example Request:
```bash
curl -X POST http://localhost:8080/api/v1/encrypt \
  -F "thesisId=THESE-2026-001" \
  -F "document=@go.mod"
```

#### Expected Responses:
- **`200 OK` / `201 Created`**: The file was successfully encrypted by the HSM and written to MinIO.
- **`400 Bad Request`**: Malformed parameters or invalid naming formats.
- **`500 Internal Server Error`**: HSM binding crash or storage connection breakdown.

---

## 🛠️ Diagnostics & Useful Commands

### Check logs for HSM state or MinIO connectivity:
```bash
docker logs -f api-vhsm
```

### Manually interact with the persistent HSM inside the container:
```bash
docker exec -it api-vhsm pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-objects --login --pin 1234
```

### Tear down containers and reset storage volumes:
```bash
docker compose down --volumes
```
