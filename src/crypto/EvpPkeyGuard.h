#ifndef VHSM_CRYPTO_EVP_PKEY_GUARD
#define VHSM_CRYPTO_EVP_PKEY_GUARD

#include <openssl/evp.h>

namespace vhsm::crypto {

// RAII guard for EVP_PKEY* — the key OBJECT (not the CTX). Existing guards
// (PkeyCtxGuard etc.) cover context types; this covers the key itself.
struct EvpPkeyGuard {
  EVP_PKEY *pkey;
  explicit EvpPkeyGuard(EVP_PKEY *p) noexcept : pkey(p) {}
  ~EvpPkeyGuard() {
    if (pkey)
      EVP_PKEY_free(pkey);
  }
  EvpPkeyGuard(const EvpPkeyGuard &) = delete;
  EvpPkeyGuard &operator=(const EvpPkeyGuard &) = delete;

  _VHSMXX_NODISCARD EVP_PKEY *get() const noexcept { return pkey; }
};

} // namespace vhsm::crypto

#endif // VHSM_CRYPTO_EVP_PKEY_GUARD
