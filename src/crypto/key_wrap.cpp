#include "key_wrap.h"
#include "aes_ecb.h"
#include <openssl/crypto.h>
#include <cstring>
#include <sys/mman.h>

namespace vhsm::crypto {

    KeyWrap::KeyWrap(const std::vector<u8>& master_kek) {
        if (master_kek.size() != 32) {
            throw std::invalid_argument("KeyWrap Initialization Error: KEK must be exactly 32 bytes for AES-256");
        }
        
        internal_kek = master_kek;
        mlock(internal_kek.data(), internal_kek.size());
    }

    KeyWrap::~KeyWrap() {
        if (!internal_kek.empty()) {
            OPENSSL_cleanse(internal_kek.data(), internal_kek.size());
            munlock(internal_kek.data(), internal_kek.size());
        }
    }

    std::vector<u8> KeyWrap::wrap(const std::vector<u8>& plaintext_key) const {
        if (plaintext_key.size() < 16 || plaintext_key.size() % 8 != 0) {
            throw std::invalid_argument("Plaintext key size must be a multiple of 8 bytes and >= 16 bytes");
        }

        size_t n = plaintext_key.size() / 8; 
        std::vector<u8> result((n + 1) * 8);

        mlock(result.data(), result.size());

        uint64_t A = AIV;
        std::memcpy(result.data() + 8, plaintext_key.data(), plaintext_key.size());

        uint8_t block[16];
        for (size_t j = 0; j <= 5; ++j) {
            for (size_t i = 1; i <= n; ++i) {
                std::memcpy(block, &A, 8);
                std::memcpy(block + 8, result.data() + (i * 8), 8);

                // Call isolated AES-ECB block cipher processing module
                AESECB::encrypt_block(internal_kek.data(), block, block);

                uint64_t t = (n * j) + i;
                std::memcpy(&A, block, 8);
                
                uint64_t t_be = __builtin_bswap64(t);
                A ^= t_be;

                std::memcpy(result.data() + (i * 8), block + 8, 8);
            }
        }

        std::memcpy(result.data(), &A, 8);
        
        OPENSSL_cleanse(block, sizeof(block));
        munlock(result.data(), result.size());

        return result;
    }

    std::vector<u8> KeyWrap::unwrap(const std::vector<u8>& ciphertext_key) const {
        if (ciphertext_key.size() < 24 || ciphertext_key.size() % 8 != 0) {
            throw std::invalid_argument("Ciphertext key size must be a multiple of 8 bytes and >= 24 bytes");
        }

        size_t n = (ciphertext_key.size() / 8) - 1;
        std::vector<u8> result(n * 8);
        
        mlock(result.data(), result.size());

        uint64_t A;
        std::memcpy(&A, ciphertext_key.data(), 8);
        std::memcpy(result.data(), ciphertext_key.data() + 8, result.size());

        uint8_t block[16];
        for (ssize_t j = 5; j >= 0; --j) {
            for (ssize_t i = n; i >= 1; --i) {
                uint64_t t = (n * j) + i;
                uint64_t t_be = __builtin_bswap64(t);
                
                A ^= t_be;

                std::memcpy(block, &A, 8);
                std::memcpy(block + 8, result.data() + ((i - 1) * 8), 8);

                // Call isolated AES-ECB block cipher processing module
                AESECB::decrypt_block(internal_kek.data(), block, block);

                std::memcpy(&A, block, 8);
                std::memcpy(result.data() + ((i - 1) * 8), block + 8, 8);
            }
        }

        if (A != AIV) {
            OPENSSL_cleanse(result.data(), result.size());
            OPENSSL_cleanse(block, sizeof(block));
            munlock(result.data(), result.size());
            throw std::runtime_error("CRITICAL SECURITY ERROR: Integrity verification failed.");
        }

        OPENSSL_cleanse(block, sizeof(block));
        munlock(result.data(), result.size());
        
        return result;
    }

} // namespace vhsm::crypto