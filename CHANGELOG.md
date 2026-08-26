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
### Added
- Build performance: `VHSM_ENABLE_IPO` (CMake-managed LTO for Release/RelWithDebInfo/MinSizeRel via `CheckIPOSupported`, replacing hand-rolled `-flto` that was never applied), `VHSM_UNITY_BUILD` option (default `OFF`), `VHSM_LINKER` override (`bfd|lld|mold`, default keeps toolchain choice), automatic `ccache` compiler-launcher detection, `release` CMake preset (`build-release/`, `-O3` + LTO).
- Default build type: empty `CMAKE_BUILD_TYPE` now falls back to `RelWithDebInfo` instead of silently disabling all optimization.

### Changed
- Optimization level is owned by `CMAKE_BUILD_TYPE` only — removed the hardcoded global `-O2`; counteracted the vendored vhsm-secure-crypto's directory-scope `-O2` so Release builds actually get `-O3`.
- `cmake/CompilerFlags.cmake`: rewrote unused `add_hardening_flags` helper as `vhsm_target_hardening` (visibility hardening only); warnings/hardening/LTO now live exclusively in the top-level file.
- Modernized deprecated `SQLite::SQLite3` target name to `SQLite3::SQLite3`.

### Fixed
- `.gitignore`: `[Ll]og/` rule swallowed the new `src/log/` module — added negation patterns; ignore preset build dirs `build-asan/` and `build-release/`.
- `src/log/logger.cpp`: global fallback logger constructed in place via `std::call_once` (Logger is non-copyable); missing `<atomic>`.
- `src/threadpool`: link `vhsm_log` PUBLICly — `thread_pool.h` logs through `vhsm::log::global_logger()`.

### Planned
- PAL for remaining POSIX (`SecureRNG` entropy already via `BCryptGenRandom` on Windows), full `types.h` split (`PKCS11Types`/`SignatureRecord` aggregate), `composition_root` extraction, `services/` bounded contexts.
