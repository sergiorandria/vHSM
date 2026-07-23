#ifndef VHSM_CRYPTO_PKEY_CTX_GUARD
#define VHSM_CRYPTO_PKEY_CTX_GUARD

#include "ctx_guard.h"
#include <openssl/evp.h>

namespace vhsm::crypto
{
class PkeyCtxGuard : public CtxGuard<EVP_PKEY_CTX>
{
public: 
    explicit PkeyCtxGuard(EVP_PKEY_CTX* c) noexcept : CtxGuard(c) {}

    ~PkeyCtxGuard() override
    {
        if (this->ctx_)
        {
            EVP_PKEY_CTX_free(this->ctx_);
        }
    }
};
} // namespace vhsm::crypto
#endif // VHSM_CRYPTO_PKEY_CTX_GUARD