C'est une excellente idée. Avoir une documentation en anglais rendra votre projet plus accessible à une communauté internationale.

Voici le `README.md` mis à jour en anglais, incluant les informations pour accéder à la console MinIO.

---

# vHSM Document Store

This project provides a secure document storage solution, combining **MinIO** for object storage and **SoftHSM2 (PKCS#11)** for hardware-backed encryption.

## 1. HSM Configuration (SoftHSM2)

Prepare your virtual HSM environment:

### A. Installation and Permissions

```bash
# Install SoftHSM2
sudo apt-get update && sudo apt-get install softhsm2

# Setup token directory and permissions
sudo mkdir -p /var/lib/softhsm/tokens/
sudo chown -R $USER:$USER /var/lib/softhsm/
sudo chmod 755 /etc/softhsm/
sudo chmod 644 /etc/softhsm/softhsm2.conf

```

### B. Initialize Token

```bash
# Initialize slot 0
softhsm2-util --init-token --slot 0 --label "MaCleThesis" --pin 1234 --so-pin 1234

```

### C. Generate AES Key

```bash
# Generate 256-bit (32 bytes) AES key
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keygen --key-type AES:32 \
  --label "MaCleThesis" \
  --usage-encrypt --usage-decrypt

```

---

## 2. Running the Services

Launch the services in the following order:

### Step 1: Start MinIO Server

```bash
go run minio_server.go

```

**Accessing MinIO:**

* **Console UI:** [http://127.0.0.1:9001](https://www.google.com/search?q=http://127.0.0.1:9001)
* **API Endpoint:** [http://127.0.0.1:9000](https://www.google.com/search?q=http://127.0.0.1:9000)
* **Credentials:** `admin` / `password123` (as defined in `minio_server.go`)

### Step 2: Start the API

```bash
export SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
go run main.go

```

---

## 3. Testing the API

Use `curl` to upload and encrypt a document:

```bash
curl -X POST http://localhost:8080/api/v1/encrypt \
  -F "thesisId=THESIS-001" \
  -F "document=@your_document.pdf"

```

---

## 4. Troubleshooting

* **`EACCES` error**: Check file permissions on `/etc/softhsm/softhsm2.conf`.
* **`key not found`**: Verify your key presence:
```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 --list-objects

```


* **MinIO access**: Ensure the MinIO binary is in your system `PATH`.

---

*Note: This architecture ensures that sensitive files are never stored in plain text, leveraging cryptographic hardware abstraction for high-security environments.*