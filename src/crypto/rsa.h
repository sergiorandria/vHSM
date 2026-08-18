#ifndef VHSM_CRYPTO_RSA
#define VHSM_CRYPTO_RSA

#include <memory>
#include <openssl/evp.h>
#include <vector>

/*
 * rsa.h
 *
 * Lightweight wrapper declarations for RSA operations using OpenSSL EVP_PKEY APIs.
 * Provides key generation, signing and verification helpers that work with
 * OpenSSL EVP_PKEY pointers. Callers are responsible for managing the
 * EVP_PKEY lifetime (free with EVP_PKEY_free when no longer needed).
 *
 * WHY low-level EVP_PKEY interface (not a key wrapper class): vHSM doesn't own keys;
 * the keystore does. RSAUtil provides utilities (sign, verify, key generation) that
 * operate on raw pointers. This keeps the crypto layer thin and focused on OpenSSL
 * wrapping, not key lifetime management. The keystore handles key storage, deletion,
 * attribute tracking. RSAUtil handles only the cryptographic operation.
 *
 * WHY caller manages EVP_PKEY lifetime: Ownership is explicit. The caller (keystore)
 * keeps the key and passes a pointer for operations. When done, they call EVP_PKEY_free.
 * This pattern is common in C APIs and avoids confusion about who owns what.
 *
 * Notes:
 * - Functions operate on raw byte vectors for input/output (no encoding/decoding).
 * - Errors from OpenSSL are propagated via exceptions (VHSM_CHECK_MSG).
 * - Supported key sizes: 2048, 3072, 4096 bits (configurable per use case).
 */
namespace vhsm::crypto
{

// WHY RSAKeyPair struct: Wraps EVP_PKEY for semantic clarity. A caller can say
// "RSAKeyPair key = RSAUtil::generate_key(2048)" instead of "EVP_PKEY* key = ...".
// The struct is simple (just a pointer) but makes intent clear.
struct RSAKeyPair
{
    EVP_PKEY* key;
};

class RSAUtil
{
public:
    // WHY generate_key takes bits parameter: Allows 2048-bit (basic), 3072-bit (standard),
    // 4096-bit (high-security) keys. The caller specifies the desired key strength.
    // Larger keys are slower but more resistant to future advances in factoring.
    static RSAKeyPair generate_key(int bits);

    // WHY sign returns std::vector: The raw DER signature bytes. No encoding,
    // no mechanism labels—just the signature that the caller can use/audit/store.
    static std::vector<uint8_t> sign(EVP_PKEY* key, const std::vector<uint8_t>& data);

    // WHY verify returns bool (not void): Verification is a predicate. true = valid,
    // false = invalid. The caller decides whether to throw, log, or ignore.
    // This gives flexibility; some callers want to retry or fallback.
    static bool verify(EVP_PKEY* key, const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature);
};
} // namespace vhsm::crypto
#endif // VHSM_CRYPTO_RSA