/*
 * ecc.cpp
 *
 * Implementation of ECC helper functions using OpenSSL EVP APIs.
 * Implements EC key generation, signing/verification and shared secret
 * derivation (ECDH) via EVP_PKEY and EVP_PKEY_CTX interfaces.
 *
 * The implementation currently assumes successful OpenSSL calls; callers
 * should check for errors and free allocated OpenSSL objects as needed.
 */

#include "ecc.h"

#include <openssl/ec.h>
#include <stdexcept>

// Convert an enum Curve into the corresponding OpenSSL NID.
static int curve_to_nid(Curve curve)
{
    switch(curve)
    {
        case Curve::P256:
            return NID_X9_62_prime256v1;

        case Curve::P384:
            return NID_secp384r1;

        case Curve::P521:
            return NID_secp521r1;
    }

    return NID_X9_62_prime256v1;
}

// Generate an EC keypair for `curve`. Returns an ECKeyPair holding an
// EVP_PKEY*; caller must free with EVP_PKEY_free.
ECKeyPair ECC::generate_key(Curve curve)
{
    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);

    EVP_PKEY_keygen_init(ctx);

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
        ctx,
        curve_to_nid(curve));

    EVP_PKEY* key = nullptr;

    EVP_PKEY_keygen(ctx, &key);

    EVP_PKEY_CTX_free(ctx);

    return { key };
}

// Sign and verify using SHA-256 and EVP_DigestSign/Verify.
std::vector<uint8_t> ECC::sign(EVP_PKEY* key, const std::vector<uint8_t>& data)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_DigestSignInit(
        ctx,
        nullptr,
        EVP_sha256(),
        nullptr,
        key);

    size_t siglen = 0;

    EVP_DigestSign(
        ctx,
        nullptr,
        &siglen,
        data.data(),
        data.size());

    std::vector<uint8_t> sig(siglen);

    EVP_DigestSign(
        ctx,
        sig.data(),
        &siglen,
        data.data(),
        data.size());

    sig.resize(siglen);

    EVP_MD_CTX_free(ctx);

    return sig;
}

bool ECC::verify(
    EVP_PKEY* key,
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& signature)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_DigestVerifyInit(
        ctx,
        nullptr,
        EVP_sha256(),
        nullptr,
        key);

    int rc = EVP_DigestVerify(
        ctx,
        signature.data(),
        signature.size(),
        data.data(),
        data.size());

    EVP_MD_CTX_free(ctx);

    return rc == 1;
}

// Derive ECDH shared secret using EVP_PKEY_derive. Returns raw secret
// bytes. Caller should zero and free secrets as appropriate.
std::vector<uint8_t> ECC::derive_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key)
{
    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new(private_key, nullptr);

    EVP_PKEY_derive_init(ctx);

    EVP_PKEY_derive_set_peer(
        ctx,
        peer_public_key);

    size_t len = 0;

    EVP_PKEY_derive(ctx, nullptr, &len);

    std::vector<uint8_t> secret(len);

    EVP_PKEY_derive(
        ctx,
        secret.data(),
        &len);

    secret.resize(len);

    EVP_PKEY_CTX_free(ctx);

    return secret;
}