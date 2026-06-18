# Project: HSM-Secured Document Store

This project provides a secure API service that encrypts documents using a hardware-backed security module (SoftHSM2) and stores them in MinIO (S3-compatible storage).

## Prerequisites

* **Docker & Docker Compose** installed.
* **Go 1.26+** (if building locally).
* A `.env` file at the root of the project (see below).

## Setup & Initialization

### 1. Configure Environment Variables

Create a `.env` file in the project root to store your secrets. **Do not commit this file to Git.**

```text
MINIO_ROOT_USER=your_username
MINIO_ROOT_PASSWORD=your_secure_password
HSM_PIN=your_pin (ex: 1234)
HSM_LABEL=your_key_label (ex: thesisLabel)

```

### 2. Prepare HSM Storage

SoftHSM requires a persistent directory on the host machine to store its tokens. Create it and set appropriate permissions:

```bash
mkdir -p ./softhsm_tokens
chmod 777 ./softhsm_tokens

```

### 3. Build and Launch

Build the Docker images and start the services in detached mode:

```bash
docker compose up --build -d

```

### 4. Initialize the HSM Token

The HSM token must be initialized once before it can store keys. Run this command inside the running API container:

```bash
docker exec -it api-vhsm softhsm2-util --init-token --slot 0 --label "ThesisLabel" --pin 1234 --so-pin 1234

```

*Note: Replace `--slot 0` with the appropriate slot index if your environment configuration differs.*

## API Usage

### Encrypt and Store a Document

Send a `POST` request to the `/api/v1/encrypt` endpoint. The API expects a multipart form request.

**Example using `curl`:**

```bash
curl -X POST http://localhost:8080/api/v1/encrypt \
  -F "thesisId=THESIS-001" \
  -F "document=@path/to/your/file.pdf"

```

The API will return a JSON response containing:

* **status**: Operation result.
* **ledger**: An object containing the `thesisId`, a SHA-256 `fileHash` (for audit purposes), and a timestamp.

## Maintenance & Troubleshooting

* **Check logs:** `docker compose logs -f api-vhsm`
* **List HSM objects:** ```bash
docker exec -it api-vhsm pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 --list-objects
```

```


* **Cleanup:** To stop and remove the containers, run `docker compose down`. To delete data (including HSM tokens), remove the `softhsm_tokens` folder and the `minio_data` volume.