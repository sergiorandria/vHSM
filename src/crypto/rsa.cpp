/*
 * rsa.cpp
 *
 * Implementation of RSA helper functions using OpenSSL EVP APIs.
 * Implements key generation, signing and verification using EVP_PKEY and
 * EVP_MD_CTX. The implementation relies on the EVP high-level interface
 * so it supports algorithm agility and modern OpenSSL usage.
 *
 * The functions allocate OpenSSL objects (EVP_PKEY, EVP_MD_CTX) and return
 * raw pointers or vectors. Callers must free allocated EVP_PKEY objects with
 * EVP_PKEY_free when appropriate. Error handling is intentionally minimal in
 * these helpers; callers and tests should check OpenSSL error state on failures.
 */

#include "rsa.h"

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdexcept>

// Generate an RSA keypair of the given bit size. Returns an RSAKeyPair
// that contains a new EVP_PKEY*; caller must free with EVP_PKEY_free.
RSAKeyPair RSAUtil::generate_key(int bits)
{
    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!ctx)
        throw std::runtime_error("ctx");

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        throw std::runtime_error("keygen init");

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
        throw std::runtime_error("set bits");

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        throw std::runtime_error("keygen");

    EVP_PKEY_CTX_free(ctx);

    return { pkey };
}

// Sign `data` using the provided EVP_PKEY RSA key and SHA-256.
// Returns the signature bytes. On error an exception may be thrown by callers
// after adding error checks in the implementation.
std::vector<uint8_t> RSAUtil::sign(EVP_PKEY* key, const std::vector<uint8_t>& data)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_DigestSignInit
    (
        ctx,
        nullptr,
        EVP_sha256(),
        nullptr,
        key
    );

    size_t siglen = 0;

    EVP_DigestSign
    (
        ctx,
        nullptr,
        &siglen,
        data.data(),
        data.size()
    );

    std::vector<uint8_t> sig(siglen);

    EVP_DigestSign
    (
        ctx,
        sig.data(),
        &siglen,
        data.data(),
        data.size()
    );

    sig.resize(siglen);

    EVP_MD_CTX_free(ctx);

    return sig;
}

// Verify a signature over `data` using the provided EVP_PKEY RSA key and SHA-256.
// Returns true if verification succeeds.
bool RSAUtil::verify(EVP_PKEY* key, const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_DigestVerifyInit
    (
        ctx,
        nullptr,
        EVP_sha256(),
        nullptr,
        key
    );

    int rc = EVP_DigestVerify
    (
        ctx,
        signature.data(),
        signature.size(),
        data.data(),
        data.size()
    );

    EVP_MD_CTX_free(ctx);

    return rc == 1;
}