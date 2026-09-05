# Virtual HSM (vHSM)

A virtual Hardware Security Module (HSM) implementation that provides PKCS#11 interface and REST API for cryptographic operations, backed by Hyperledger Fabric for secure audit logging and key management.

## Architecture

The vHSM consists of several components:

```
┌─────────────────────┐
│ Jury Application    │
│ (Web/Desktop UI)    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Go Backend API      │
│ (Gin/Fiber)         │
└──────────┬──────────┘
           │
           ├─────────────────┐
           │                 │
           ▼                 ▼
┌─────────────────┐   ┌─────────────────┐
│ SoftHSM         │   │ Document Store  │
│ PKCS#11         │   │ Thesis PDFs     │
└────────┬────────┘   └────────┬────────┘
         │                     │
         ▼                     ▼
    Digital Signature      SHA256 Hash
         │                     │
         └──────────┬──────────┘
                    ▼
          ┌───────────────────┐
          │ Fabric Gateway    │
          │ Go SDK            │
          └─────────┬─────────┘
                    ▼
          ┌───────────────────┐
          │ Hyperledger Fabric│
          │ Chaincode         │
          └─────────┬─────────┘
                    ▼
          ┌───────────────────┐
          │ Distributed Ledger│
          └───────────────────┘
```

## Security & Compliance Features

vHSM ships a set of defense-in-depth features aimed at regulated / post-quantum
threat models. All of them are implemented behind compile-time and runtime
switches so the default build stays clean and portable.

### F5 — FIPS 140-3 operating mode
When `VHSM_FIPS=1` is set at runtime (or the binary is built with
`VHSM_USE_SECURE_CRYPTO=ON`), vHSM enters a FIPS gate:
- Only FIPS-approved mechanisms are accepted for signing/encryption; everything
  else is rejected closed (see `src/crypto/fips.h` `mechanism_approved()`).
- A self-test (`fips_self_test()`) runs SHA-256, AES-256-GCM and ECDSA P-256
  known-answer tests at `C_Initialize`.
- DRBG entropy is bound to `RDRAND` (x86 `rdrand64`) when `VHSM_ENTROPY=rdrand`
  or FIPS mode is active, and fails closed if the hardware source is missing.
- TPM2 is left as a documented hook behind `-DVHSM_TPM` (not wired by default).

### F1 — Post-quantum / hybrid signatures
`src/crypto/pqc_provider.{h,cpp}` adds a Dilithium/SPHINCS+ companion signature
over the same digest as the classical signature. It is built with `liboqs`
behind `-DVHSM_PQC`; without that flag it fails closed so the default build is
unaffected. Hybrid records carry `pqc_algo` / `signature_pqc_b64` /
`key_fingerprint_pqc` end-to-end (DB columns, `SignatureRecord`, ledger
`RecordSignature` upsert, and the admin `SignatureDetail`).

### F2 — Key policy / attestation engine
Keys may carry a `CKA_VHSM_POLICY` (vendor attribute `0x81000005`) JSON document
describing who may sign, with which mechanism, within what time window, and with
how many attestations (quorum). `C_Sign` evaluates the policy and fails closed.
Attestations are collected on-ledger via the `PolicyContract`
(`PublishKey` / `SubmitAttestation` / `AttestationsFor` / `VerifyPolicy`); when
quorum is required the sign path enforces it through `LedgerClient::verify_policy`.

### F3 — Externally-verifiable audit ↔ ledger proof
The append-only audit log is a hash chain whose tail is anchored on the ledger
(`RecordAuditTail`, invoked after every append via a tail-publisher callback),
so a truncated or forged local audit file is detectable. The admin RPC
`VerifyIntegrity` re-walks every row's HMAC, verifies the audit hash-chain, and
cross-checks each `COMMITTED` row's `tx_id` against the Fabric ledger,
reporting any mismatch.

### F6 — Exactly-once idempotent anchoring
`LedgerWorker` keeps an in-flight `record_id` set and drops duplicate
submissions; accepted records mark the DB row `PROCESSING` so a crash/restart
cannot re-anchor them. The ledger `RecordSignature` is an idempotent upsert keyed
by `record_id`, giving exactly-once semantics across retries and crashes.

### F4 — Prometheus metrics
A `vhsm_metrics` library (counters/gauges) instruments the ledger worker
(committed/failed/pending), notification delivery (delivered/failed), outbox
depth, and audit chain length. Scrape the gRPC `Metrics` RPC
(`Metrics(Empty) -> MetricsResponse` carrying Prometheus exposition text) with
Prometheus or `curl`.

### F7 — Read-only web audit UI
`web/` is a React + Vite single-page app that browses signatures and shows the
ledger-anchored proof and audit tail. The `rest_api` serves it as static SPA and
exposes `GET /api/v1/proof/:recordId` and `GET /api/v1/audit/tail`.

### F8 — Fabric Control Console (2026-09-04)
`web/` now includes a **control console** + `rest_api/internal/fabric_manager.go` (979 LOC): guided `generate-network.sh`/`enroll-network.sh`/`docker compose`/`peer channel join`/`chaincode approve/commit` lifecycle, live SSE transactions (`/transactions/stream`), audit tamper VerifyIntegrity, and HSM Sign. See `rest_api/README.md` for `/api/v1/fabric/*`.

### F9 — Mobile app (Expo SDK 54)
`mobile/` (React Native / Expo, 6 screens: Home/Thesis/History/Notifications/Login/Settings) via `rest_api/internal/mobile_service.go` + C++ `MobilePushAdapter` (`src/notification/mobile_push_adapter.*`) — FCM/Expo push registration and inbox polling (`/api/v1/mobile/*`). See `mobile/README.md`.

## Getting Started

### Prerequisites

- CMake 3.21 or higher
- C++23 compiler (GCC, Clang, or MSVC)
- OpenSSL
- gRPC (if VHSM_ADMIN_GRPC is enabled)
- Protobuf
- Database backend (SQLite3, PostgreSQL, or MySQL)
- libcurl (for email/webhook notifications)
- nlohmann_json (3.11.0 or higher)
- Go 1.19+ (for the REST API)
- Docker and Docker Compose (for Hyperledger Fabric tests)

### Building

The repository ships CMake presets (see `CMakePresets.json`) — prefer them over
hand-rolled `cmake` invocations:

```bash
cmake --preset linux-ninja     # RelWithDebInfo, Ninja, sqlite, no gRPC/ledger
cmake --build build -j         # parallel build
ctest --test-dir build -j      # run all 271 unit tests
```

Available presets:

| Preset        | Build dir      | Purpose                                        |
| ------------- | -------------- | ---------------------------------------------- |
| `linux-ninja` | `build/`       | Default Linux development build (RelWithDebInfo) |
| `release`     | `build-release/` | Optimized `-O3` + LTO production build       |
| `windows-msvc`| `build/`       | Windows MSVC via vcpkg manifest                |
| `asan`        | `build-asan/`  | ASan + UBSan instrumented build                |

Manual configuration (without presets) works as well:

```bash
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

If no `CMAKE_BUILD_TYPE` is given, the project defaults to `RelWithDebInfo`.
When `ccache` is installed it is picked up automatically as compiler launcher.

#### Build Performance Options

- `VHSM_ENABLE_IPO`: Interprocedural optimization / LTO for Release,
  RelWithDebInfo and MinSizeRel (default: auto-detected; ON when the
  toolchain supports it). Debug builds stay LTO-free so debuggers and
  sanitizers behave predictably.
- `VHSM_UNITY_BUILD`: Unity build — concatenates sources per target for much
  faster clean builds at the cost of slower incremental rebuilds
  (default: `OFF`; can collide with file-local symbols).
- `VHSM_LINKER`: Linker override (`default`, `bfd`, `lld`, `mold`;
  default: `default`). Only change this after verifying your compiler +
  linker combination supports LTO (e.g. lld is known-broken with GCC 16 LTO).

#### CMake Options

- `VHSM_DB_BACKEND`: Database backend (`sqlite`, `postgres`, `mysql`) (default: `sqlite`)
- `VHSM_ASYNC_DB`: Use async write queue for DB (default: `OFF`)
- `VHSM_REQUIRE_DB`: Fail C_Sign if DB write fails (default: `ON`)
- `VHSM_ADMIN_GRPC`: Build gRPC admin server (default: `ON`)
- `VHSM_NOTIFY_EMAIL`: Build email notification adapter (default: `ON`)
- `VHSM_NOTIFY_WEBHOOK`: Build webhook notification adapter (default: `ON`)
- `VHSM_NOTIFY_BUS_SIZE`: Notification ring buffer capacity (default: `1024`)
- `VHSM_STORE_BACKEND`: Signature store backend (`db`, `ledger`) (default: `db`; `ledger` forces `VHSM_LEDGER=ON`)
- `VHSM_LEDGER`: Build the Fabric ledger signature anchor integration (default: `ON`)
- `VHSM_USE_SECURE_CRYPTO`: Use hardened `vhsm-secure-crypto` clone instead of system OpenSSL for symmetric primitives (default: `ON`)
- `VHSM_PQC`: Build PQC/hybrid Dilithium/SPHINCS+ signatures via `liboqs` (default: `OFF`; when off the provider fails closed)
- `VHSM_TPM`: Compile the TPM2 entropy/key hook (documented only; not wired by default) (default: `OFF`)
- `VHSM_FIPS`: Compile FIPS gate + self-test paths (default: `OFF`)

The documented full ledger build (also used by CI):
```bash
cmake -S . -B build-ledger -DVHSM_LEDGER=ON -DVHSM_ADMIN_GRPC=ON \
      -DVHSM_STORE_BACKEND=db -DVHSM_BUILD_EXAMPLES=OFF
cmake --build build-ledger --target vhsm_ledger vhsm_signature_store vhsm_admin vhsm_pkcs11 -j4
cd rest_api && go build ./... && go vet ./...
```

Example:
```bash
cmake .. -DVHSM_DB_BACKEND=postgres -DVHSM_NOTIFY_EMAIL=ON
```

### Running the REST API

The REST API is located in the `rest_api` directory.

1. Install dependencies:
   ```bash
   cd rest_api
   go mod download
   ```

2. Run the installation script to set up environment variables and configuration:
   ```bash
   ./install.sh
   ```

3. Copy the service file and adjust paths as needed:
   ```bash
   sudo cp vhsm.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl start vhsm
   ```

4. The API will be available at `http://localhost:8080` (default port).

### Running Tests

#### Unit Tests

```bash
ctest --test-dir build -j   # parallel run of all unit tests
```

#### REST API Tests

See [tests/rest_api/README.md](tests/rest_api/README.md) for detailed instructions on running the REST API tests, which require a running Hyperledger Fabric network.

## Configuration

Configuration files are located in `/etc/vhsm/` after installation.

Key configuration files:
- `vhsm.conf`: Main configuration file
- Email/webhook adapter configurations (if enabled)

## Documentation

- [REST API Documentation](rest_api/README.md)
- [Project Plan](plan/)
- [Source Code Structure](src/)

## License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

## Acknowledgments

- Hyperledger Fabric for blockchain infrastructure
- SoftHSM for PKCS#11 reference implementation