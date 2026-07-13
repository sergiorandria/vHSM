#ifndef VHSM_CRYPTO_PKEY_CTX_GUARD
#define VHSM_CRYPTO_PKEY_CTX_GUARD

#include "ctx_guard.h"
#include <openssl/evp.h>

namespace vhsm::crypto
{
struct PkeyCtxGuard : public CtxGuard<EVP_PKEY_CTX>
{
    EVP_PKEY_CTX* ctx;
    explicit PkeyCtxGuard(EVP_PKEY_CTX* c) noexcept : CtxGuard(c) {}

    ~PkeyCtxGuard() noexcept
    {
        if (ctx)
        {
            EVP_PKEY_CTX_free(ctx);
        }
    }
};
} // namespace vhsm::crypto
#endif // VHSM_CRYPTO_PKEY_CTX_GUARD