#ifndef VHSM_CRYPTO_AES_GCM
#define VHSM_CRYPTO_AES_GCM

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

#include <cstdint>
#include <vector>

#include "../core/types.h"

namespace vhsm::crypto
{
struct AESGCMResult
{
    std::vector<u8> ciphertext;
    std::vector<u8> nonce;
    std::vector<u8> tag;
};

class AESGCM
{
public:
    static AESGCMResult encrypt(const std::vector<u8>& key, const std::vector<u8>& plaintext);
    static std::vector<u8> decrypt(const std::vector<u8>& key, const AESGCMResult& data);
};
} // namespace vhsm::crypto

#endif // VHSM_CRYPTO_AES_GCM