/*
 * rsa.cpp
 *
 * Implementation of RSA helper functions using OpenSSL EVP APIs.
 * Implements key generation, signing and verification using EVP_PKEY and
 * EVP_MD_CTX. The implementation relies on the EVP high-level interface
 * so it supports algorithm agility and modern OpenSSL usage.
 *
 * All OpenSSL calls are checked via VHSM_CHECK / VHSM_CHECK_MSG.
 * RAII guards ensure no context is leaked on any exception path.
 */

#include "rsa.h"
#include "../core/error.h"
#include "PkeyCtxGuard.h"
#include "MdCtxGuard.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace vhsm::crypto {

// Generate an RSA keypair of the given bit size. Returns an RSAKeyPair
// that contains a new EVP_PKEY*; caller must free with EVP_PKEY_free.
RSAKeyPair RSAUtil::generate_key(int bits)
{
    VHSM_CHECK_MSG(bits >= 2048, "RSAUtil::generate_key: key size must be >= 2048 bits");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    VHSM_CHECK_MSG(ctx != nullptr, "RSAUtil::generate_key: EVP_PKEY_CTX_new_id failed");
    PkeyCtxGuard guard(ctx);

    VHSM_CHECK(EVP_PKEY_keygen_init(ctx) == 1);
    VHSM_CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) == 1);

    EVP_PKEY* pkey = nullptr;
    VHSM_CHECK(EVP_PKEY_keygen(ctx, &pkey) == 1);

    return { pkey };
}

// Sign `data` using the provided EVP_PKEY RSA key and SHA-256.
// Returns the signature bytes.
std::vector<uint8_t> RSAUtil::sign(EVP_PKEY* key, const std::vector<uint8_t>& data)
{
    VHSM_CHECK_MSG(key != nullptr, "RSAUtil::sign: key is null");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    VHSM_CHECK_MSG(ctx != nullptr, "RSAUtil::sign: EVP_MD_CTX_new failed");
    MdCtxGuard guard(ctx);

    VHSM_CHECK(EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1);

    // First call: obtain required signature length.
    size_t siglen = 0;
    VHSM_CHECK(EVP_DigestSign(ctx, nullptr, &siglen, data.data(), data.size()) == 1);

    std::vector<uint8_t> sig(siglen);

    // Second call: produce the actual signature.
    VHSM_CHECK(EVP_DigestSign(ctx, sig.data(), &siglen, data.data(), data.size()) == 1);

    // siglen may be smaller than the initial estimate; trim to actual size.
    sig.resize(siglen);

    return sig;
}

// Verify a signature over `data` using the provided EVP_PKEY RSA key and SHA-256.
// Returns true if verification succeeds, false on signature mismatch.
// Throws on OpenSSL internal error (rc < 0).
bool RSAUtil::verify(EVP_PKEY* key, const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature)
{
    VHSM_CHECK_MSG(key != nullptr, "RSAUtil::verify: key is null");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    VHSM_CHECK_MSG(ctx != nullptr, "RSAUtil::verify: EVP_MD_CTX_new failed");
    MdCtxGuard guard(ctx);

    VHSM_CHECK(EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1);

    const int rc = EVP_DigestVerify
    (
        ctx,
        signature.data(),
        signature.size(),
        data.data(),
        data.size()
    );

    // rc == 1  → valid signature
    // rc == 0  → invalid signature (not an OpenSSL error, just a mismatch)
    // rc <  0  → OpenSSL internal error — propagate via VHSM_CHECK
    VHSM_CHECK_MSG(rc >= 0, "RSAUtil::verify: EVP_DigestVerify returned an error");

    return rc == 1;
}
} // namespace vhsm::crypto