#ifndef vHSM_RNG_H
#define vHSM_RNG_H

#include "../core/types.h"

#include <vector>
#include <string>
#include <mutex>
#include <memory>
#include <cstdint>

namespace vhsm::crypto {
// NIST SP 800-90A CTR_DRBG Engine using AES-256.
// Core cryptographic logic container.
// Maybe this class should be a singleton, 
// but I don't want to solve race condition later, 
// when integrating with another multi-threaded application.
class CTR_DRBG_AES256 {
public:
    explicit CTR_DRBG_AES256(const std::vector<u8>& entropy_input);
    ~CTR_DRBG_AES256();
    
    void reseed(const std::vector<u8>& entropy_input);
    std::vector<u8> generate(size_t requested_bytes);

private:
    std::vector<u8> key, V;
    uint64_t reseed_counter;
    const uint64_t RESEED_INTERVAL = 100000; 

    // These methods should be callable without 
    // instanciation.
    void increment_V();
    void aes256_encrypt_block(const std::vector<u8>& input, std::vector<u8>& output);
    void update(const std::vector<u8>& provided_data);
};
} // namespace vhsm::crypto

#endif // vHSM_RNG_H