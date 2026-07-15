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
 * Notes:
 * - Functions operate on raw byte vectors for input/output.
 * - Errors from OpenSSL are not propagated by these declarations; implementations
 *   should check and surface OpenSSL error information.
 */
namespace vhsm::crypto
{

struct RSAKeyPair
{
    EVP_PKEY* key;
};

class RSAUtil
{
public:
    static RSAKeyPair generate_key(int bits);

    static std::vector<uint8_t> sign(EVP_PKEY* key, const std::vector<uint8_t>& data);

    static bool verify(EVP_PKEY* key, const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature);
};
} // namespace vhsm::crypto
#endif // VHSM_CRYPTO_RSA