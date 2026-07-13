#ifndef VHSM_CRYPTO_SECURE_RNG
#define VHSM_CRYPTO_SECURE_RNG

#include <memory.h>

#include "ctr_drbg_aes256.h"

namespace vhsm::crypto
{
/**
 * @brief Thread-safe, memory-locked wrapper serving as the main public API.
 *
 * A better RNG will simulate the heat transfer equation in a
 * large environment, then use a virtual captor to get the value every millisecond,
 * apply a batch function, and then restructure the generated value.
 * I really hope get_system_entropy() will succeed with that simulation perfectly,
 * scoring above 90% precision.
 */
//
class SecureRNG
{
private:
    std::unique_ptr<CTR_DRBG_AES256> engine;
    std::mutex engine_mutex;

    std::vector<u8> get_system_entropy(const std::string& source_path);

public:
    SecureRNG();
    ~SecureRNG();

    // Handling the exeption on the RESEED_INTERVAL exeeded
    void bytes(u8* out_buffer, size_t size);

    // Forces an immediate runtime entropy refresh from /dev/urandom.
    void force_reseed();
};
} // namespace vhsm::crypto
#endif // VHSM_CRYPTO_SECURE_RNG