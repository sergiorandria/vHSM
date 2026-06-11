#ifndef VHSM_CRYPTO_PKEY_CTX_GUARD 
#define VHSM_CRYPTO_PKEY_CTX_GUARD

#include <openssl/evp.h>

namespace vhsm::crypto {
struct PkeyCtxGuard {
    EVP_PKEY_CTX* ctx;
    explicit PkeyCtxGuard(EVP_PKEY_CTX* c) noexcept : ctx(c) {}
    
    ~PkeyCtxGuard() noexcept { 
        if (ctx) {
            EVP_PKEY_CTX_free(ctx);         
        }
    }

    PkeyCtxGuard(const PkeyCtxGuard&) = delete;
    PkeyCtxGuard& operator=(const PkeyCtxGuard&) = delete;
};
}
#endif // VHSM_CRYPTO_PKEY_CTX_GUARD