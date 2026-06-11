#ifndef vHSM_AES_ECB_H
#define vHSM_AES_ECB_H

#include <cstdint>
#include <stdexcept>
#include "../core/types.h"

namespace vhsm::crypto {

    /**
     * @brief Low-level AES-256 ECB static block cipher utility.
     * Handles raw 16-byte cryptographic transformations via OpenSSL.
     */
    class AESECB {
    public:
        /**
         * @brief Encrypts a single 16-byte block using AES-256 ECB.
         * @param key Pointer to the 32-byte key buffer.
         * @param input Pointer to the 16-byte plaintext input block.
         * @param output Pointer to the 16-byte ciphertext output destination.
         */
        static void encrypt_block(const uint8_t* key, const uint8_t* input, uint8_t* output);

        /**
         * @brief Decrypts a single 16-byte block using AES-256 ECB.
         * @param key Pointer to the 32-byte key buffer.
         * @param input Pointer to the 16-byte ciphertext input block.
         * @param output Pointer to the 16-byte plaintext output destination.
         */
        static void decrypt_block(const uint8_t* key, const uint8_t* input, uint8_t* output);
    };

} // namespace vhsm::crypto

#endif // vHSM_AES_ECB_H