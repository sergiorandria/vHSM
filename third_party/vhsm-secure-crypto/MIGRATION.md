# Migration Guide — from OpenSSL to vhsm-secure-crypto

## Quick switch

```bash
# old (system OpenSSL)
cmake -S . -B build
# new (hardened clone, same API via alias)
cmake -S . -B build -DVHSM_USE_SECURE_CRYPTO=ON
```

No code changes required for existing `target_link_libraries(… OpenSSL::Crypto)` — top-level `CMakeLists.txt` aliases it to `vhsm_secure_crypto` when `VHSM_USE_SECURE_CRYPTO=ON`.

## Gradual code migration (recommended for new code)

Replace OpenSSL includes with scrypto headers:

| Before | After |
|---|---|
| `#include <openssl/evp.h>` + `EVP_sha256()` | `#include <vhsm/scrypto/hash.h>` + `scrypto::sha256()` |
| `HMAC(EVP_sha256(), …)` | `scrypto::hmac_sha256(key,data)` |
| `PKCS5_PBKDF2_HMAC` | `scrypto::pbkdf2_hmac_sha256(pw,salt,310000,32)` |
| `EVP_aes_256_gcm()` via `EVP_CIPHER_CTX` | `scrypto::aes256_gcm_encrypt(key,pt)` |
| `RAND_bytes(buf,n)` | `scrypto::SecureRng().bytes(buf,n)` |
| `OPENSSL_cleanse(p,l)` | `scrypto::cleanse(p,l)` |
| `EVP_PKEY*` RSA/EC | `scrypto::RsaKeyPair` / `scrypto::EcKeyPair` (policy enforced) |
| `memcmp(a,b,n)==0` for tags/HMAC | `scrypto::constant_time_eq(a,b,n)` |

### Example — RowIntegrity HMAC before/after

Before (OpenSSL, timing-leaky `==`):
```cpp
unsigned char out[32]; unsigned int l;
HMAC(EVP_sha256(), key.data(),key.size(), conc.data(),conc.size(), out,&l);
std::string computed = to_hex(out,l);
return computed == stored_hmac; // early exit
```

After (scrypto, constant-time):
```cpp
auto out = vhsm::scrypto::hmac_sha256(key, conc_bytes);
std::string computed = to_hex(out);
return vhsm::scrypto::constant_time_eq_str(computed, stored_hmac);
```

### Example — AES-GCM Vault

Before:
```cpp
EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), …);
// 20 lines + error stack
```

After:
```cpp
auto res = vhsm::scrypto::aes256_gcm_encrypt(key, plaintext);
// res.ciphertext, res.nonce (12 B), res.tag (16 B) — constant-time tag, auto nonce
auto pt = vhsm::scrypto::aes256_gcm_decrypt(key, res); // throws on auth fail
```

## Policy changes you will notice

* RSA `<2048` → exception (was silently accepted by OpenSSL)
* AES-GCM nonce must be 12 bytes, tag 16 bytes (was 1–16, now strict)
* `PBKDF2 iterations < 100k` logs warning; Vault format now requires `310k` (was 2048)
* `RSA encrypt` only allows `OAEP_SHA256` (PKCS1 v1.5 for encrypt is rejected)

## Enabling pure mode (no OpenSSL at all)

```cmake
cmake -DVHSM_SCRYPTO_PURE=ON -DVHSM_USE_SECURE_CRYPTO=ON
```

Requires the bignum backend for RSA/EC (currently stub). Keep `PURE=OFF` (default) to use OpenSSL only for big-integer math, isolated in `src/pkey/*_policy.cpp`.

## Self-test

```bash
/tmp/vhsm_scrypto_build/vhsm_scrypto_selftest
# also runs automatically at library load when VHSM_USE_SECURE_CRYPTO=ON
```
