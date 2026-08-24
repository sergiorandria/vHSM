# vhsm-secure-crypto — Hardened OpenSSL Clone for vHSM

Minimal, auditable replacement for the OpenSSL subset used by vHSM.

## Why a clone

Upstream OpenSSL is ~500k LOC, includes TLS, X.509, legacy ciphers (MD5, SHA1, DES, RC4), engine/provider indirection, and global error stacks — all attack surface vHSM does not need.

`vhsm-secure-crypto` implements **only what vHSM uses**, with secure defaults:

| Needed by vHSM | OpenSSL API replaced | Implementation here |
|---|---|---|
| SHA-256/384/512 | `EVP_Digest*` | FIPS 180-4 from scratch, constant-time |
| HMAC-SHA256 | `HMAC()` | RFC 2104, constant-time compare |
| HKDF-SHA256 | custom `hkdf_sha256` | RFC 5869, no provider |
| PBKDF2-HMAC-SHA256 | `PKCS5_PBKDF2_HMAC` | RFC 2898, fixed iterations 310k |
| AES-256-GCM | `EVP_aes_256_gcm` | FIPS 197 + GHASH, constant-time tag check |
| AES-256-ECB | `EVP_aes_256_ecb` | single-block, no padding, locked memory |
| RAND_bytes | `RAND_bytes` | `getrandom(2)` + CTR_DRBG-AES256 |
| RSA 2048+ sign/verify/encrypt | `EVP_PKEY_*` RSA | policy wrapper (no <2048, no PKCS#1 v1.5 encrypt without OAEP) |
| ECDSA P-256/P-384/P-521 | `EVP_PKEY_EC` | NIST curves only, ECDH via `EVP_PKEY_derive` |
| Secure cleanse | `OPENSSL_cleanse` | `explicit_bzero` / `SecureZeroMemory`, compiler barrier |

## Security hardening vs stock OpenSSL for this project

1. **No legacy algorithms** — SHA1, MD5, DES, RC4, 1024-bit RSA, P-192 etc. removed at compile time (`#error` if requested).
2. **Fail-closed defaults** — `PBKDF2 iterations = 310,000` (OWASP 2023), vault `kVaultPbkdf2Iterations` validated, `AES-GCM` tag failure throws, `KeyWrap::unwrap` constant-time `A==AIV` check.
3. **Constant-time** — `constant_time_eq()` for HMAC, GCM tag, RowIntegrity, `CRYPTO_memcmp` semantics; no early-exit `memcmp`.
4. **Memory protection** — `mlock`/`VirtualLock` for KEK, DRBG state, `SecureBuffer`; `cleanse()` with volatile + memory barrier; `mlock` failure is hard error, not silent.
5. **RNG** — `getrandom(2)` → `BCryptGenRandom` on Windows, never `/dev/urandom` fallback without `GRND_RANDOM`; CTR_DRBG-AES256 reseeds at 100k, constructor seeds from `getrandom` with blocking.
6. **Nonce misuse resistance** — AES-GCM `encrypt()` generates 12-byte nonce via `SecureRNG`, checks `iv_len==12`; decrypt enforces `tag == 16`.
7. **Reduced API surface** — no `SSL_*`, no `X509_*`, no `PEM_*`, no `ENGINE_*`, no global `ERR_get_error()`. Errors are exceptions via `VHSM_CHECK`.
8. **No global mutable state** — each `EVP_*_CTX` is owned by RAII guard; no `ERR_clear_error()` dance.
9. **Compiler hardening inherited** — built with `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -pie`.

## Layout

```
include/vhsm/scrypto/  — public headers (drop-in for <openssl/evp.h> in vHSM)
src/hash/              — SHA-256/512 (FIPS 180-4)
src/cipher/            — AES-256 core, GCM, ECB
src/kdf/               — PBKDF2, HKDF
src/rng/               — SecureRNG + CTR_DRBG
src/pkey/              — RSA/EC policy wrappers
src/mem/               — cleanse, mlock
```

## Usage

```cmake
option(VHSM_USE_SECURE_CRYPTO "Use vhsm-secure-crypto instead of system OpenSSL" ON)

if(VHSM_USE_SECURE_CRYPTO)
  add_subdirectory(third_party/vhsm-secure-crypto)
  target_link_libraries(vhsm_crypto PUBLIC vhsm_secure_crypto)
else()
  find_package(OpenSSL REQUIRED)
  target_link_libraries(vhsm_crypto PUBLIC OpenSSL::Crypto)
endif()
```

Headers migrate gradually:

```cpp
// old
#include <openssl/evp.h>
// new (shim, still works with system OpenSSL fallback)
#include <vhsm/scrypto/evp_compat.h>
```

Or use native API:

```cpp
#include <vhsm/scrypto/hash.h>
#include <vhsm/scrypto/aes_gcm.h>
auto d = vhsm::scrypto::sha256(data);
auto ct = vhsm::scrypto::aes_gcm_encrypt(key, plaintext);
```

## Self-test

On library load, FIPS known-answer tests run (SHA256("abc"), AES-GCM NIST vector, HMAC-SHA256 RFC 4231). Failure aborts.

## License

MIT — same as vHSM.
