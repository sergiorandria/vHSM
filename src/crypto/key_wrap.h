#ifndef vHSM_KEY_WRAP_H
#define vHSM_KEY_WRAP_H

#include <vector>
#include <cstdint>
#include <stdexcept>
#include "../core/types.h"

namespace vhsm::crypto {

    /**
     * @brief RFC 3394 AES Key Wrap library container.
     * Manages structural orchestration and integrity verification using AESECB.
     */
    class KeyWrap {
    public:
        /**
         * @brief Constructor that initializes the library with a specific KEK.
         * @param master_kek The 32-byte (256-bit) Key Encryption Key.
         */
        explicit KeyWrap(const std::vector<u8>& master_kek);

        /**
         * @brief Destructor designed to securely erase the internal KEK from RAM.
         */
        ~KeyWrap();

        // Prevent structural memory duplication
        KeyWrap(const KeyWrap&) = delete;
        KeyWrap& operator=(const KeyWrap&) = delete;
        KeyWrap(KeyWrap&&) noexcept = default;
        KeyWrap& operator=(KeyWrap&&) noexcept = default;

        /**
         * @brief Encapsulates a target plaintext key using the internal KEK via RFC 3394.
         * @param plaintext_key Key to protect (size must be a multiple of 8 bytes, min 16 bytes).
         * @return Wrapped ciphertext vector (+8 bytes overhead).
         */
        std::vector<u8> wrap(const std::vector<u8>& plaintext_key) const;

        /**
         * @brief Decapsulates a wrapped key and validates the 6-round integrity matrix.
         * @param ciphertext_key Wrapped data starting with the 64-bit integrity register.
         * @return Decrypted raw key vector.
         * @throws std::runtime_error If verification fails.
         */
        std::vector<u8> unwrap(const std::vector<u8>& ciphertext_key) const;

    private:
        std::vector<u8> internal_kek;
        static const uint64_t AIV = 0xA6A6A6A6A6A6A6A6;
    };

} // namespace vhsm::crypto

#endif // vHSM_KEY_WRAP_H