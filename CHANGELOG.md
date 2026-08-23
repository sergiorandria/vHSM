# Changelog

All notable changes to Virtual HSM follow Keep a Changelog and SemVer 2.0.

## [1.0.0] - 2026-08-23
### Added
- Windows compatibility: `SecureBuffer` (VirtualLock/VirtualProtect), `LedgerWorker` hardware_concurrency via `GetLogicalProcessorInformationEx`, `Vault` atomic write via `MoveFileExW`/`_commit`, `KeyWrap`/`SecureRNG` VirtualLock, `wallet` flock→`LockFileEx`, `p11_init` `%LOCALAPPDATA%` fallback, `CMakePresets` (`windows-msvc`/`linux-ninja`/`asan`), `vcpkg.json` manifest.
- Versioning: `project(VERSION 1.0.0)`, `cmake/version.h.in` → `vhsm/version.h`, `C_GetInfo` uses `VHSM_VERSION_MAJOR/MINOR`, `VirtualHSMConfigVersion.cmake`, `CHANGELOG.md`.
- DDD: `HsmInstanceId` value object + `IHsmInstanceProvider` port + `DatabaseHsmInstanceProvider` (thread-safe, `IDbConnection` query/exec), `RetryPolicy` instance fields, conditional `vhsm_ledger` linking, `src/core/pal.h` PAL.

### Fixed
- `ledger_worker` malloc/BufferType, `max` macro clash, `sleep_interruptible` drain semantics, `hsm_instance` visibility/namespace/DB API, `secure_buffer` mman guard.

## [Unreleased]
### Planned
- PAL for remaining POSIX (`SecureRNG` entropy already via `BCryptGenRandom` on Windows), full `types.h` split (`PKCS11Types`/`SignatureRecord` aggregate), `composition_root` extraction, `services/` bounded contexts.
