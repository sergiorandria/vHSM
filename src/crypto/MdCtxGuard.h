#ifndef VHSM_CRYPTO_MDCTX_GUARD
#define VHSM_CRYPTO_MDCTX_GUARD

#include "ctx_guard.h"
#include <openssl/evp.h>

namespace vhsm::crypto
{
struct MdCtxGuard : public CtxGuard<EVP_MD_CTX>
{
    EVP_MD_CTX* ctx;
    explicit MdCtxGuard(EVP_MD_CTX* c) noexcept : CtxGuard(c) {}
    ~MdCtxGuard() noexcept
    {
        if (ctx)
        {
            EVP_MD_CTX_free(ctx);
        }
    }
};
} // namespace vhsm::crypto
#endif