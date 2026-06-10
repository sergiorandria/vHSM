#pragma once

#include <vector>
#include <cstdint>

/*
 * aes_gcm.h
 *
 * Simple AES-256-GCM encryption/decryption helpers that encapsulate the
 * nonce, tag and ciphertext in `AESGCMResult` for easy transport.
 *
 * Usage notes:
 * - `encrypt` generates a 12-byte nonce and a 16-byte tag and returns the
 *   ciphertext along with the nonce and tag in `AESGCMResult`.
 * - `decrypt` verifies the GCM tag and returns the plaintext. On
 *   authentication failure it throws a runtime_error.
 *
 * Keys are expected to be 32 bytes for AES-256-GCM.
 */

struct AESGCMResult 
{
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> tag;
};

class AESGCM 
{
    public:
        static AESGCMResult encrypt
        (
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& plaintext
        );

        static std::vector<uint8_t> decrypt
        (
            const std::vector<uint8_t>& key,
            const AESGCMResult& data
        );
};