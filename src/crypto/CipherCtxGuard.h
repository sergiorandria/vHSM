#ifndef VHSM_CRYPTO_CIPHER_CTX_GUARD 
#define VHSM_CRYPTO_CIPHER_CTX_GUARD

#include <openssl/evp.h> 

namespace vhsm::crypto { 
struct CipherCtxGuard { 
    EVP_CIPHER_CTX* ctx;
    explicit CipherCtxGuard(EVP_CIPHER_CTX* c) noexcept : ctx(c) {}
    
    ~CipherCtxGuard() noexcept { 
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);         
        }
    }

    CipherCtxGuard(const CipherCtxGuard&) = delete;
    CipherCtxGuard& operator=(const CipherCtxGuard&) = delete;
};
} // vhsm::crypto

#endif // VHSM_CRYPTO_CIPHER_CTX_GUARD 