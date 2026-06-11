#ifndef VHSM_CRYPTO_MDCTX_GUARD 
#define VHSM_CRYPTO_MDCTX_GUARD

#include <openssl/evp.h>

namespace {
    struct MdCtxGuard {
    EVP_MD_CTX* ctx;
    explicit MdCtxGuard(EVP_MD_CTX* c) noexcept : ctx(c) {}
    ~MdCtxGuard() noexcept { 
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }

    MdCtxGuard(const MdCtxGuard&) = delete;
    MdCtxGuard& operator=(const MdCtxGuard&) = delete;
};
} // namespace 
#endif 