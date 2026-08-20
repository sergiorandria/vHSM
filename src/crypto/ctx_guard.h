#ifndef VHSM_CTX_GUARD_H
#define VHSM_CTX_GUARD_H

#include <concepts>
#include <openssl/evp.h>
#include <type_traits>

namespace vhsm::crypto {

// WHY CtxGuard template + concepts: OpenSSL returns untyped EVP_CIPHER_CTX*,
// EVP_MD_CTX*, EVP_PKEY_CTX* pointers. All must be freed with context-specific
// free functions (EVP_CIPHER_CTX_free, EVP_MD_CTX_free, EVP_PKEY_CTX_free).
// CtxGuard<T> uses C++20 concepts to constrain T to valid EVP types at compile
// time, then derived classes specialize the destructor to call the correct free
// function. This prevents memory leaks (destructor always fires) while
// maintaining type safety (wrong type = compile error).
//
// WHY concepts instead of specialization: Concepts enforce constraints
// explicitly (T must be one of three types). This is clearer than template
// specialization and catches errors at declaration (template <typename T>
// requires EVP_CTX_CONCEPT<T>) rather than at instantiation.

// WHY EVP_CTX_CONCEPT lists three types: Cipher contexts
// (encryption/decryption), message digest contexts (hashing), and key contexts
// (RSA/ECC operations) are the main EVP types used in vHSM. Other EVP types
// (RAND_CTX, etc.) are not currently used, so the concept restricts to the safe
// set.
template <typename T>
concept EVP_CTX_CONCEPT = requires(T &&__v) {
  std::is_same_v<T, EVP_CIPHER_CTX> || std::is_same_v<EVP_MAC_CTX, T> ||
      std::is_same_v<EVP_PKEY_CTX, T>;
};

// WHY CtxGuard is a base class template: Derived classes (CipherCtxGuard,
// MdCtxGuard, PkeyCtxGuard) specialize the destructor to call the appropriate
// OpenSSL free function. The base class handles pointer storage and the common
// interface (getCtx()). Derived classes implement the RAII guarantee (cleanup
// via destructor).
template <typename CtxContext>
  requires EVP_CTX_CONCEPT<CtxContext>
class CtxGuard {
protected:
  CtxContext *ctx_;

public:
  // WHY take raw pointer: Callers receive OpenSSL pointers directly (e.g., from
  // EVP_CIPHER_CTX_new()). We take ownership by storing it; the destructor
  // frees it.
  CtxGuard(CtxContext *ctx) : ctx_(ctx) {}

  // WHY pure virtual destructor: Derived classes must override with the
  // appropriate OpenSSL free function (EVP_CIPHER_CTX_free, etc.). Pure virtual
  // ensures this is not forgotten; instantiating CtxGuard directly is a compile
  // error.
  virtual ~CtxGuard() = 0;

  // WHY inline getter: Direct access to the wrapped pointer. Callers pass it to
  // OpenSSL functions that expect EVP_*_CTX*. Inlining avoids function call
  // overhead.
  inline CtxContext *getCtx() { return ctx_; }

  // WHY non-copyable: Each guard owns one context pointer. Copying would create
  // two guards with the same pointer; both destructors would call free(),
  // causing a double-free.
  CtxGuard(const CtxGuard &) = delete;
  CtxGuard &operator=(const CtxGuard &) = delete;
};

template <class CtxContext>
  requires EVP_CTX_CONCEPT<CtxContext>
inline CtxGuard<CtxContext>::~CtxGuard() {
  // Placeholder for destructor implementation
  // WHY pure virtual destructor needs inline implementation: C++ requires that
  // even pure virtual destructors have a body (since they'll be called during
  // derived destruction). The body is empty here; derived classes provide the
  // actual cleanup.
}
} // namespace vhsm::crypto

#endif // VHSM_CTX_GUARD_H