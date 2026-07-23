#ifndef VHSM_CRYPTO_CIPHER_CTX_GUARD
#define VHSM_CRYPTO_CIPHER_CTX_GUARD

#include "ctx_guard.h"
#include <openssl/evp.h>

namespace vhsm::crypto
{
class CipherCtxGuard : public vhsm::crypto::CtxGuard<EVP_CIPHER_CTX>
{
public:
    explicit CipherCtxGuard(EVP_CIPHER_CTX* c) noexcept : CtxGuard(c) {}

    ~CipherCtxGuard() override
    {
        if (this->ctx_)
        {
            EVP_CIPHER_CTX_free(this->ctx_);
        }
    }
};
} // namespace vhsm::crypto

#endif // VHSM_CRYPTO_CIPHER_CTX_GUARD