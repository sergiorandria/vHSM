/*
 * ecc.h
 *
 * Lightweight wrapper declarations for Elliptic Curve key operations using
 * OpenSSL EVP_PKEY APIs. Provides key generation, signing, verification and
 * ECDH shared secret derivation helpers that accept/return byte vectors and
 * raw EVP_PKEY pointers.
 *
 * WHY elliptic curves in addition to RSA: EC keys are smaller (256-bit curve ≈ 3072-bit RSA)
 * but equally secure. They're faster for signing/verification and generate shorter signatures.
 * vHSM supports both to let callers choose based on performance/compatibility requirements.
 *
 * WHY three curves (P256, P384, P521): NIST-approved curves with different security levels.
 * P256 is standard (fast); P384 is intermediate; P521 is high-security (slower). Applications
 * can select the curve that matches their threat model. P521 is conservative for long-term
 * archival (documents that must be valid in 20+ years).
 *
 * WHY derive_shared_secret for ECDH: Elliptic Curve Diffie-Hellman allows two parties to
 * compute a shared secret without ever transmitting it. Useful for key agreement (e.g.,
 * session key establishment). RSA doesn't support this; only EC does.
 *
 * The API is minimal: callers manage EVP_PKEY lifetimes and should free
 * EVP_PKEY objects with EVP_PKEY_free. Implementations propagate OpenSSL errors via exceptions.
 */

#pragma once

#include <openssl/evp.h>
#include <vector>

namespace vhsm::crypto
{
// WHY Curve enum: Explicit curve selection. Prevents accidental use of weak curves
// and makes the choice visible in code (better than magic strings or integers).
enum class Curve
{
    EccCurveType_P256,  // NIST P-256 (secp256r1): 128-bit security
    EccCurveType_P384,  // NIST P-384 (secp384r1): 192-bit security
    EccCurveType_P521   // NIST P-521 (secp521r1): 260-bit security
};

// WHY ECCKeyPair struct (same as RSAKeyPair): For semantic clarity and consistency
// with the RSA API. Using the same pattern (struct wrapping EVP_PKEY*) makes the
// interface uniform across algorithm families.
struct ECCKeyPair
{
    EVP_PKEY* key;
};

class ECC
{
public:
    // WHY generate_key takes Curve parameter: Caller specifies the desired curve.
    // NIST curves are hardened; the enum restricts to recommended choices.
    static ECCKeyPair generate_key(Curve curve);

    // WHY sign and verify have same signature as RSAUtil: Interchangeable interface.
    // CryptoEngine can call ECC::sign or RSAUtil::sign depending on key type
    // without special-casing the calling convention.
    static std::vector<uint8_t> sign(EVP_PKEY* key, const std::vector<uint8_t>& data);

    static bool verify(EVP_PKEY* key, const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature);

    // WHY derive_shared_secret is EC-only: RSA doesn't support key agreement.
    // ECDH (EC Diffie-Hellman) allows two parties to securely establish a shared secret.
    // The private key stays private; only public keys are exchanged. Useful for
    // confidential channel setup (e.g., signing sessions that need a session key).
    static std::vector<uint8_t> derive_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key);
};
} // namespace vhsm::crypto