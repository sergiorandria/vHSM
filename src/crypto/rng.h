#ifndef vHSM_RNG_H
#define vHSM_RNG_H

#include <vector>
#include <string>
#include <mutex>
#include <memory>
#include <cstdint>

namespace vHSM {

    /**
     * @brief NIST SP 800-90A CTR_DRBG Engine using AES-256.
     * Core cryptographic logic container.
     */
    class CTR_DRBG_AES256 {
    private:
        std::vector<uint8_t> key; 
        std::vector<uint8_t> V;   
        uint64_t reseed_counter;
        const uint64_t RESEED_INTERVAL = 100000; 

        void increment_V();
        void aes256_encrypt_block(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
        void update(const std::vector<uint8_t>& provided_data);

    public:
        explicit CTR_DRBG_AES256(const std::vector<uint8_t>& entropy_input);
        ~CTR_DRBG_AES256();

        void reseed(const std::vector<uint8_t>& entropy_input);
        std::vector<uint8_t> generate(size_t requested_bytes);
    };

    /**
     * @brief Thread-safe, memory-locked wrapper serving as the main public API.
     */
    class SecureRNG {
    private:
        std::unique_ptr<CTR_DRBG_AES256> engine;
        std::mutex engine_mutex;

        std::vector<uint8_t> get_system_entropy(const std::string& source_path);

    public:
        SecureRNG();
        ~SecureRNG();

        /**
         * @brief Fills a raw target buffer with cryptographically secure bytes.
         */
        void bytes(uint8_t* out_buffer, size_t size);

        /**
         * @brief Forces an immediate runtime entropy refresh from /dev/urandom.
         */
        void force_reseed();
    };
}

#endif // vHSM_RNG_H