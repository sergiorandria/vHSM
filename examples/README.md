# vHSM Examples

## PKCS#11 (`examples/pkcs11/`)

Self-contained C++ examples that drive the vHSM PKCS#11 module directly
(`C_Initialize` → `C_Login` → crypto). No Fabric network required — they
use `:memory:` SQLite so every run is isolated.

| # | File | Concepts |
|---|---|---|
| 01 | `ex01_init_and_login.cpp` | Library lifecycle, slots, sessions, PIN |
| 02 | `ex02_generate_keys.cpp` | `C_GenerateKeyPair` for RSA-2048, P-256, P-384 |
| 03 | `ex03_sign_verify.cpp` | `C_Sign`/`C_Verify` (ECDSA-SHA256 + RSA-SHA256), tamper check |
| 04 | `ex04_encrypt_decrypt.cpp` | `C_Encrypt`/`C_Decrypt` — AES-GCM + RSA-PKCS |
| 05 | `ex05_digest_and_find.cpp` | `C_Digest` (SHA-256/384) + `C_FindObjects`/`C_GetAttributeValue` |
| 06 | `ex06_wrap_unwrap.cpp` | `C_WrapKey`/`C_UnwrapKey` (AES wrapped by RSA-PKCS) |

### Build

```bash
# Via CMake (recommended)
cmake --preset linux-ninja -DVHSM_BUILD_EXAMPLES=ON
cmake --build build -j
./build/examples/pkcs11/ex01_init_and_login
./build/examples/pkcs11/ex03_sign_verify
# ...

# Or standalone with g++ (after building the library once)
g++ -std=c++23 examples/pkcs11/ex03_sign_verify.cpp -I src -L build -lvhsm_pkcs11 -o /tmp/ex03 && /tmp/ex03
```

All examples set `VHSM_DB_PATH=:memory:` so they leave no state on disk.
Point `VHSM_DB_PATH` at a file path to persist keys across runs, and set
`VHSM_VAULT_PATH`/`VHSM_VAULT_PASSWORD` to enable the encrypted vault
(Phase 7 persistence).

### Benchmark

The throughput harness from Phase 7 lives in `tests/bench/vhsm_bench.cpp`:

```bash
cmake -S . -B build-bench -G Ninja -DVHSM_ENABLE_BENCH=ON
cmake --build build-bench --target vhsm_bench && ./build-bench/tests/bench/vhsm_bench
```
