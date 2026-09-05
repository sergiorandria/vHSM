# Changelog

All notable changes to Virtual HSM follow Keep a Changelog and SemVer 2.0.

## [1.0.0] - 2026-08-23
### Added
- Windows compatibility: `SecureBuffer` (VirtualLock/VirtualProtect), `LedgerWorker` hardware_concurrency via `GetLogicalProcessorInformationEx`, `Vault` atomic write via `MoveFileExW`/`_commit`, `KeyWrap`/`SecureRNG` VirtualLock, `wallet` flock→`LockFileEx`, `p11_init` `%LOCALAPPDATA%` fallback, `CMakePresets` (`windows-msvc`/`linux-ninja`/`asan`), `vcpkg.json` manifest.
- Versioning: `project(VERSION 1.0.0)`, `cmake/version.h.in` → `vhsm/version.h`, `C_GetInfo` uses `VHSM_VERSION_MAJOR/MINOR`, `VirtualHSMConfigVersion.cmake`, `CHANGELOG.md`.
- DDD: `HsmInstanceId` value object + `IHsmInstanceProvider` port + `DatabaseHsmInstanceProvider` (thread-safe, `IDbConnection` query/exec), `RetryPolicy` instance fields, conditional `vhsm_ledger` linking, `src/core/pal.h` PAL.

### Fixed
- `ledger_worker` malloc/BufferType, `max` macro clash, `sleep_interruptible` drain semantics, `hsm_instance` visibility/namespace/DB API, `secure_buffer` mman guard.

## [1.2.0] - 2026-08-26
### Added
- **Fabric DeliverClient production hardening** (`third_party/fabric-gateway-cpp` 1.1.0→1.2.0): `CheckpointStore`/`FileCheckpointStore` (atomic temp+fsync+rename), `FullBlock` decoder (header hashes, TxValidationCode, ChaincodeEvent from `ChaincodeAction` bytes), `DeliverClient` reconnect with `RetryPolicy` (1s→30s capped backoff) + `Logger` integration (`set_retry_policy`/`set_logger`), `common/result.h` (`Result<T>`), `common/logger.h` (Stderr/Syslog sinks), `common/retry_policy.h`.
- **Audit hash chain** (`src/audit`): `HashChainedAuditLog` — HMAC-SHA256 chain (`SEQ|TS|ID|TYPE|PREV` → `HMAC(chain_key)`), `derive_audit_chain_key` HKDF domain `vHSM-audit-chain`, fsync per record, `verify_chain()` + tail recovery, fallback to `P11AuditLog` pre-KEK; 4 unit tests.
- **Login throttling** (`src/session`): `LoginThrottle` — progressive 250ms·2ⁿ (cap 8s, soft threshold 3) per slot:user, `AppContainer::login_throttle`, applied outside token mutex in `C_Login`; 5 unit tests.
- **C ABI Result** (`src/abi`): `CkStatus = expected<void, CK_RV>` (`ok_ck`/`err_ck`, `[[nodiscard]]`) — `AuditLog::append` now `CkStatus noexcept`, second adopter after `try_uuid_v4`.
- **TSan stress suite** (`tests/stress`): `VHSM_ENABLE_TSAN` (`-fsanitize=thread -O2 -Wno-cpp`), `stress_tsan` — 8×200 concurrent audit appends (chain must verify) + throttle hammer; 0 races.
- **Throughput bench** (`tests/bench`): `VHSM_ENABLE_BENCH`, `vhsm_bench` drives real C API (`C_GenerateKeyPair` → `C_Sign`/`C_Verify`/`C_Digest`/session churn) and reports median ops/sec (~4.6k ECDSA signs/s on P-256).
- **PKCS#11 examples** (`examples/pkcs11`): `01_init_and_login` … `06_wrap_unwrap` + `examples/README.md`, `VHSM_BUILD_EXAMPLES` option (links `vhsm_pkcs11` + `vhsm_signature_store`).
- **Logging** (`src/log`): `Logger`/`Sink`/`StderrSink`/`SyslogSink` (journald), `AppContainer::logger` + `global_logger()` fallback for `ThreadPool`/`LedgerWorker`/`OutboxPoller`.
- **CI** (`.github/workflows/ci.yml`): `linux-ledger` (ledger+bench+TSan smoke, `libgrpc++`/`protobuf` deps) and `integration-fabric` scaffolding (`if: false`, fabric-samples + Docker).
- Build performance: `VHSM_ENABLE_IPO` (CMake-managed LTO), `VHSM_UNITY_BUILD`, `VHSM_LINKER`, `ccache` detection, `release` preset.

### Changed
- Optimization level owned by `CMAKE_BUILD_TYPE` only — removed hardcoded global `-O2`; counteracted `vhsm-secure-crypto` directory-scope `-O2` so Release gets `-O3`.
- `cmake/CompilerFlags.cmake`: rewrote `add_hardening_flags` as `vhsm_target_hardening` (visibility only); warnings/hardening/LTO live in top-level.
- Modernized `SQLite::SQLite3` → `SQLite3::SQLite3`.
- `examples/pkcs11` AES-GCM decrypt noted as best-effort (tag handling varies), RSA-PKCS primary.

### Fixed
- `.gitignore` swallowed `src/log` — added negation; ignore `build-asan`/`build-release`/`build-bench`/`build-tsan`.
- `src/log/logger.cpp` non-copyable fallback via `new` + `<atomic>`; `src/threadpool` PUBLIC `vhsm_log` link.
- `src/pkcs11/composition_root` orphan-slot bug (`ensure_default_token` inserted into local `Slot` then discarded — `C_GetSlotList` always empty) and `C_Finalize` UAF (`global_slot_manager().reset()` after `g_appContainer` destroyed).
- `src/pkcs11/p11_internal` shim persistence: `p11_store_key`/`p11_build_key_from_attrs`/`fingerprint` now via `vhsm::scrypto` DER import/export (shim `d2i`/`i2d` are no-op stubs) + `p11_ecdsa_sign` fixed-size 256B buffer with retry for variable DER (70-72B P-256).
- `third_party/fabric-gateway-cpp` namespace collision (`::common` vs `fabric::common`), `ChaincodeAction.events` bytes field, header `bytes` fields, `_VHSMXX_NODISCARD` → `[[nodiscard]]`.
- `third_party/vhsm-secure-crypto` `constant_time.h` volatile + barrier, `selftest` HKDF RFC 5869 A.1 + PBKDF2 KATs.

### Security
- `vhsm-secure-crypto` EC/RSA DER import/export via `ec_import_private_der` etc. (real OpenSSL inside `NO_SHIM` region) instead of stub `d2i` — persisted-key sign/verify was broken in default shim build.

## [1.3.0] - 2026-09-04
### Added
- **Fabric Control Console** (`web` 259→660 LOC + `rest_api/internal/fabric_manager.go` 979 LOC): guided `generate-network.sh`/`enroll-network.sh`/`docker compose`/`peer channel join`/`chaincode approve/commit`, live SSE `GET /transactions/stream`, `VerifyAudit`/`SimulateTamper`, `SignWithHSM` — blue/techno theme, `DeployOverlay` + `Infrastructure` edit (no delete) + `Live Transactions` drawer. Served as SPA from `rest_api` (`web/dist` 173kB gzip 53.8kB).

- **Mobile app** (`mobile/` Expo SDK 54, React Native, 6 screens: Home/Login/Thesis/History/Notifications/Settings): `push.ts`/`useNotifications.ts` JWT auth + FCM/Expo push, `mobile_service.go` + C++ `MobilePushAdapter` (`notification/mobile_push_adapter.*`, `src/notification/CMakeLists.txt`) — `POST/GET/DELETE /api/v1/mobile/devices` + polling fallback `/mobile/notifications` aggregated from `GetThesisHistory`.

- **Professional docs**: `rest_api/README.md` rewritten from joke to full API reference (`/api/v1/theses`, `/proof`, `/fabric/*`, `/mobile/*`, env `.env`, RBAC, CORS allowlist, PV hash immutability), `README.md` F8/F9 sections, `docs/VHSM_PROJECT_COMPLETION_STATUS.md` 70%→95%.

### Fixed
- `third_party/fabric-gateway-cpp` rewind `60af953` → `e5adfad` restored (`0313072`): `e281b37` namespace/encode (`serialized_block`, `ChaincodeEvent` bytes, `protos::DeliverResponse`), `9391090` Result/Logger/RetryPolicy, `e5adfad` Proposal/Commit/offline signing. Standalone `cmake --build` now clean; `https://github.com/sergiorandria/fabric-gateway-cpp` `origin/main` pushed to `e5adfad`.
- `src/pkcs11/p11_crypto.cpp:398` `#ifdef VHSM_LEDGER` guard + `signature_store/mysql_connection.cpp:4` / `postgres_connection.cpp:4` `__has_include` stubs — sqlite-only builds now succeed without `libmysqlclient`/`libpq`.
- `src/pkcs11/composition_root.h` formatting churn reverted (clang-format noise).

### Verified
- `cmake --preset linux-ninja && cmake --build build -j4` + `ctest 310/310` `6.73s` + `go vet 0` + `npm run build` `909ms` + `fabric-gateway-cpp` standalone `1.40s` clean. `master` `18c6253` + `dev` `01d4bcd` merged and pushed; `rest_api` + `web` + `mobile` stacks demonstrable for defense.
