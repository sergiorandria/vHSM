#include "SecureRNG.h"

#include <cstring>
#include <openssl/ssl.h>
#include <sys/mman.h>

namespace vhsm::crypto
{
SecureRNG::SecureRNG()
{
    std::lock_guard<std::mutex> lock(engine_mutex);

    // Lock this class space in physical memory to block side-channel host swaps
    mlock(this, sizeof(SecureRNG));

    // Blocking initialization at boot safely
    std::vector<uint8_t> boot_seed = get_system_entropy("/dev/random");
    engine = std::make_unique<CTR_DRBG_AES256>(boot_seed);
    OPENSSL_cleanse(boot_seed.data(), boot_seed.size());
}

void SecureRNG::bytes(uint8_t* out_buffer, size_t size)
{
    if (!out_buffer || size == 0)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(engine_mutex);

    try
    {
        std::vector<uint8_t> data = engine->generate(size);
        std::memcpy(out_buffer, data.data(), size);
        OPENSSL_cleanse(data.data(), data.size());
    }
    catch (const std::runtime_error&)
    {
        // Self-healing forced reseed via high-speed live urandom
        std::vector<uint8_t> live_seed = get_system_entropy("/dev/urandom");
        engine->reseed(live_seed);
        OPENSSL_cleanse(live_seed.data(), live_seed.size());

        std::vector<uint8_t> data = engine->generate(size);
        std::memcpy(out_buffer, data.data(), size);
        OPENSSL_cleanse(data.data(), data.size());
    }
}

void SecureRNG::force_reseed()
{
    std::lock_guard<std::mutex> lock(engine_mutex);
    std::vector<uint8_t> live_seed = get_system_entropy("/dev/urandom");
    engine->reseed(live_seed);
    OPENSSL_cleanse(live_seed.data(), live_seed.size());
}

SecureRNG::~SecureRNG() { munlock(this, sizeof(SecureRNG)); }
} // namespace vhsm::crypto