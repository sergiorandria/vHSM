#ifndef VHSM_CRYPTO_MDCTX_GUARD
#define VHSM_CRYPTO_MDCTX_GUARD

#include "ctx_guard.h"
#include <openssl/evp.h>

namespace vhsm::crypto
{
class MdCtxGuard : public CtxGuard<EVP_MD_CTX>
{
public: 
    explicit MdCtxGuard(EVP_MD_CTX* c) noexcept : CtxGuard(c) {}
    ~MdCtxGuard() override
    {
        if (this->ctx_)
        {
            EVP_MD_CTX_free(this->ctx_);
        }
    }
};
} // namespace vhsm::crypto
#endif