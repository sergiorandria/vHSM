/*
 * ecc.cpp
 *
 * Implementation of ECC helper functions using OpenSSL EVP APIs.
 * Implements EC key generation, signing/verification and shared secret
 * derivation (ECDH) via EVP_PKEY and EVP_PKEY_CTX interfaces.
 *
 * All OpenSSL calls are checked via VHSM_CHECK / VHSM_CHECK_MSG.
 * RAII guards ensure no context is leaked on any exception path.
 */

#include "ecc.h"
#include "../core/error.h"
#include "../core/types.h"
#include "MdCtxGuard.h"
#include "PkeyCtxGuard.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace vhsm::crypto
{
// Convert an enum Curve into the corresponding OpenSSL NID.
static int curve_to_nid(Curve curve)
{
    switch (curve)
    {
        case Curve::EccCurveType_P256:
            return NID_X9_62_prime256v1;
        case Curve::EccCurveType_P384:
            return NID_secp384r1;
        case Curve::EccCurveType_P521:
            return NID_secp521r1;
    }

    // Unreachable if all enum values are handled above; guard against
    // undefined behaviour from a bad cast.
    throw std::invalid_argument("curve_to_nid: unknown Curve value");
}

// Generate an EC keypair for `curve`. Returns an ECKeyPair holding an
// EVP_PKEY*; caller must free with EVP_PKEY_free.
ECCKeyPair ECC::generate_key(Curve curve)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    VHSM_CHECK_MSG(ctx != nullptr, "ECC::generate_key: EVP_PKEY_CTX_new_id failed");
    PkeyCtxGuard guard(ctx);

    VHSM_CHECK(EVP_PKEY_keygen_init(ctx) == 1);
    VHSM_CHECK(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_to_nid(curve)) == 1);

    EVP_PKEY* key = nullptr;
    VHSM_CHECK(EVP_PKEY_keygen(ctx, &key) == 1);

    return {key};
}

// Sign `data` with `key` using SHA-256. Returns the DER-encoded signature.
std::vector<u8> ECC::sign(EVP_PKEY* key, const std::vector<u8>& data)
{
    VHSM_CHECK_MSG(key != nullptr, "ECC::sign: key is null");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    VHSM_CHECK_MSG(ctx != nullptr, "ECC::sign: EVP_MD_CTX_new failed");
    MdCtxGuard guard(ctx);

    VHSM_CHECK(EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1);

    // First call: obtain required signature length.
    size_t siglen = 0;
    VHSM_CHECK(EVP_DigestSign(ctx, nullptr, &siglen, data.data(), data.size()) == 1);

    std::vector<u8> sig(siglen);

    // Second call: produce the actual signature.
    VHSM_CHECK(EVP_DigestSign(ctx, sig.data(), &siglen, data.data(), data.size()) == 1);

    // siglen may be smaller than the initial estimate; trim to actual size.
    sig.resize(siglen);

    return sig;
}

// Verify `signature` over `data` with `key`. Returns true iff the signature
// is valid; returns false on verification failure (rc == 0).
// Any other negative return value from OpenSSL is treated as an error.
bool ECC::verify(EVP_PKEY* key, const std::vector<u8>& data, const std::vector<u8>& signature)
{
    VHSM_CHECK_MSG(key != nullptr, "ECC::verify: key is null");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    VHSM_CHECK_MSG(ctx != nullptr, "ECC::verify: EVP_MD_CTX_new failed");
    MdCtxGuard guard(ctx);

    VHSM_CHECK(EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1);

    const int rc = EVP_DigestVerify(ctx, signature.data(), signature.size(), data.data(), data.size());

    // rc == 1  → valid signature
    // rc == 0  → invalid signature (not an OpenSSL error, just a mismatch)
    // rc <  0  → OpenSSL error — propagate via VHSM_CHECK
    VHSM_CHECK_MSG(rc >= 0, "ECC::verify: EVP_DigestVerify returned an error");

    return rc == 1;
}

// Derive ECDH shared secret using EVP_PKEY_derive. Returns raw secret bytes.
// Caller is responsible for zeroing the returned buffer after use.
std::vector<u8> ECC::derive_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key)
{
    VHSM_CHECK_MSG(private_key != nullptr, "ECC::derive_shared_secret: private_key is null");
    VHSM_CHECK_MSG(peer_public_key != nullptr, "ECC::derive_shared_secret: peer_public_key is null");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    VHSM_CHECK_MSG(ctx != nullptr, "ECC::derive_shared_secret: EVP_PKEY_CTX_new failed");
    PkeyCtxGuard guard(ctx);

    VHSM_CHECK(EVP_PKEY_derive_init(ctx) == 1);
    VHSM_CHECK(EVP_PKEY_derive_set_peer(ctx, peer_public_key) == 1);

    // First call: obtain required buffer length.
    size_t len = 0;
    VHSM_CHECK(EVP_PKEY_derive(ctx, nullptr, &len) == 1);

    std::vector<u8> secret(len);

    // Second call: derive the actual shared secret.
    VHSM_CHECK(EVP_PKEY_derive(ctx, secret.data(), &len) == 1);

    // len may be smaller than the initial estimate; trim to actual size.
    secret.resize(len);

    return secret;
}
} // namespace vhsm::crypto