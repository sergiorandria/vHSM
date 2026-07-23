#ifndef VHSM_CTX_GUARD_H
#define VHSM_CTX_GUARD_H

#include <concepts>
#include <openssl/evp.h>
#include <type_traits>

namespace vhsm::crypto
{

// CtxContext should be a valid context from openssl
template <typename T>
concept EVP_CTX_CONCEPT = requires(T&& __v) {
    std::is_same_v<T, EVP_CIPHER_CTX> || std::is_same_v<EVP_MAC_CTX, T> || std::is_same_v<EVP_PKEY_CTX, T>;
};

template <typename CtxContext>
    requires EVP_CTX_CONCEPT<CtxContext>
class CtxGuard
{
protected:
    CtxContext* ctx_;

public:
    CtxGuard(CtxContext* ctx) : ctx_(ctx) {}

    // Should be implemented by
    // child classes
    virtual ~CtxGuard() = 0; 

    inline CtxContext* getCtx() { return ctx_; } 

    CtxGuard(const CtxGuard&) = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
};

template <class CtxContext>
    requires EVP_CTX_CONCEPT<CtxContext>
inline CtxGuard<CtxContext>::~CtxGuard() {
    // Placeholder for destructor implementation
} 
} // namespace vhsm::crypto

#endif // VHSM_CTX_GUARD_H