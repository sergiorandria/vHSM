#include "rng.h"
#include <cstring>
#include <stdexcept>
#include <fstream>
#include <sys/mman.h>
#include <openssl/evp.h>

namespace vHSM {

    // =========================================================================
    // CTR_DRBG_AES256 Implementation
    // =========================================================================

    void CTR_DRBG_AES256::increment_V() {
        for (int i = 15; i >= 0; --i) {
            if (++V[i] != 0) break;
        }
    }

    void CTR_DRBG_AES256::aes256_encrypt_block(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("RNG Internal Error: Context creation failed");

        int len;
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data(), nullptr) ||
            1 != EVP_CIPHER_CTX_set_padding(ctx, 0) || 
            1 != EVP_EncryptUpdate(ctx, output.data(), &len, input.data(), 16)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("RNG Internal Error: AES hardware failure");
        }
        EVP_CIPHER_CTX_free(ctx);
    }

    void CTR_DRBG_AES256::update(const std::vector<uint8_t>& provided_data) {
        std::vector<uint8_t> temp(48, 0); 
        std::vector<uint8_t> output_block(16, 0);

        for (size_t i = 0; i < 3; ++i) {
            increment_V();
            aes256_encrypt_block(V, output_block);
            std::memcpy(temp.data() + (i * 16), output_block.data(), 16);
        }

        if (!provided_data.empty() && provided_data.size() == 48) {
            for (size_t i = 0; i < 48; ++i) {
                temp[i] ^= provided_data[i];
            }
        }

        std::memcpy(key.data(), temp.data(), 32);
        std::memcpy(V.data(), temp.data() + 32, 16);
        OPENSSL_cleanse(temp.data(), temp.size());
    }

    CTR_DRBG_AES256::CTR_DRBG_AES256(const std::vector<uint8_t>& entropy_input) {
        if (entropy_input.size() != 48) throw std::invalid_argument("Seed must be 48 bytes");
        key.assign(32, 0);
        V.assign(16, 0);
        reseed_counter = 1;
        update(entropy_input);
    }

    void CTR_DRBG_AES256::reseed(const std::vector<uint8_t>& entropy_input) {
        if (entropy_input.size() != 48) throw std::invalid_argument("Seed must be 48 bytes");
        update(entropy_input);
        reseed_counter = 1;
    }

    std::vector<uint8_t> CTR_DRBG_AES256::generate(size_t requested_bytes) {
        if (reseed_counter > RESEED_INTERVAL) throw std::runtime_error("Reseed threshold reached");

        std::vector<uint8_t> pseudo_random_bits;
        std::vector<uint8_t> output_block(16, 0);

        while (pseudo_random_bits.size() < requested_bytes) {
            increment_V();
            aes256_encrypt_block(V, output_block);
            pseudo_random_bits.insert(pseudo_random_bits.end(), output_block.begin(), output_block.end());
        }

        pseudo_random_bits.resize(requested_bytes);
        update(std::vector<uint8_t>()); // Enforce Forward Security
        reseed_counter++;

        return pseudo_random_bits;
    }

    CTR_DRBG_AES256::~CTR_DRBG_AES256() {
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(V.data(), V.size());
    }

    // =========================================================================
    // SecureRNG Public Wrapper Implementation
    // =========================================================================

    std::vector<uint8_t> SecureRNG::get_system_entropy(const std::string& source_path) {
        std::vector<uint8_t> entropy(48);
        std::ifstream source(source_path, std::ios::in | std::ios::binary);
        
        if (!source || !source.read(reinterpret_cast<char*>(entropy.data()), 48)) {
            throw std::runtime_error("RNG Failure: Enclave cannot reach system entropy source: " + source_path);
        }
        return entropy;
    }

    SecureRNG::SecureRNG() {
        std::lock_guard<std::mutex> lock(engine_mutex);
        
        // Lock this class space in physical memory to block side-channel host swaps
        mlock(this, sizeof(SecureRNG)); 

        // Blocking initialization at boot safely
        std::vector<uint8_t> boot_seed = get_system_entropy("/dev/random");
        engine = std::make_unique<CTR_DRBG_AES256>(boot_seed);
        OPENSSL_cleanse(boot_seed.data(), boot_seed.size());
    }

    void SecureRNG::bytes(uint8_t* out_buffer, size_t size) {
        if (!out_buffer || size == 0) return;
        std::lock_guard<std::mutex> lock(engine_mutex);

        try {
            std::vector<uint8_t> data = engine->generate(size);
            std::memcpy(out_buffer, data.data(), size);
            OPENSSL_cleanse(data.data(), data.size());
        } 
        catch (const std::runtime_error&) {
            // Self-healing forced reseed via high-speed live urandom
            std::vector<uint8_t> live_seed = get_system_entropy("/dev/urandom");
            engine->reseed(live_seed);
            OPENSSL_cleanse(live_seed.data(), live_seed.size());

            std::vector<uint8_t> data = engine->generate(size);
            std::memcpy(out_buffer, data.data(), size);
            OPENSSL_cleanse(data.data(), data.size());
        }
    }

    void SecureRNG::force_reseed() {
        std::lock_guard<std::mutex> lock(engine_mutex);
        std::vector<uint8_t> live_seed = get_system_entropy("/dev/urandom");
        engine->reseed(live_seed);
        OPENSSL_cleanse(live_seed.data(), live_seed.size());
    }

    SecureRNG::~SecureRNG() {
        munlock(this, sizeof(SecureRNG));
    }
}