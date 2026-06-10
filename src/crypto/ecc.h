/*
 * ecc.h
 *
 * Lightweight wrapper declarations for Elliptic Curve key operations using
 * OpenSSL EVP_PKEY APIs. Provides key generation, signing, verification and
 * ECDH shared secret derivation helpers that accept/return byte vectors and
 * raw EVP_PKEY pointers.
 *
 * The API is minimal: callers manage EVP_PKEY lifetimes and should free
 * EVP_PKEY objects with EVP_PKEY_free. Implementations should propagate
 * OpenSSL error information on failures.
 */

#pragma once

#include <vector>
#include <openssl/evp.h>

enum class Curve 
{
    P256,
    P384,
    P521
};

struct ECKeyPair 
{
    EVP_PKEY* key;
};

class ECC 
{
    public:
        static ECKeyPair generate_key(Curve curve);

        static std::vector<uint8_t> sign
        (
            EVP_PKEY* key,
            const std::vector<uint8_t>& data
        );

        static bool verify
        (
            EVP_PKEY* key,
            const std::vector<uint8_t>& data,
            const std::vector<uint8_t>& signature
        );

        static std::vector<uint8_t> derive_shared_secret
        (
            EVP_PKEY* private_key,
            EVP_PKEY* peer_public_key
        );
};