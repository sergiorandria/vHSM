# Security Policy — vhsm-secure-crypto

## Threat model (vHSM specific)

* **HSM key exfiltration** via swap, core dump, or uninitialized memory — mitigated by `mlock` + `cleanse`.
* **Signature forgery** via GCM tag bypass or HMAC timing — mitigated by constant-time checks, fail-closed.
* **Weak key generation** — RSA <2048 rejected, only NIST P-256/P-384/P-521 allowed.
* **Entropy failure** — `getrandom` blocking, no PRNG fallback to `rand()`.
* **Supply chain** — single-file auditable primitives, no external fetches at runtime.

## Hardening checklist

- [x] No `memcmp` for secrets — use `constant_time_eq`
- [x] No `RAND_bytes` without `getrandom` seed
- [x] PBKDF2 iterations >= 310k in production (`vault_format.h` validated)
- [x] AES-GCM IV 12 bytes, never reused (generated per encrypt)
- [x] `OPENSSL_cleanse` replaced by `scrypto::cleanse` with compiler barrier
- [x] `EVP_CIPHER_CTX` / `EVP_MD_CTX` freed on all paths (RAII)
- [x] No `EVP_PKEY` reuse across threads without lock

## Auditing

All crypto primitives are in `src/hash`, `src/cipher`, `src/kdf` — under 2k LOC total.
Review `constant_time.h` and `mem/secure_cleanse.cpp` first.

## Reporting

File an issue with label `security` or contact maintainer. Do not include secrets.
