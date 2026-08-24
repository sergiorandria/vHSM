#include "SecureRNG.h"

#include <cstring>
#include <mutex>
#include <openssl/crypto.h>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace vhsm::crypto {
SecureRNG::SecureRNG() {
  std::lock_guard<std::mutex> lock(engine_mutex);

  // Lock this object in RAM so the DRBG state (key, V) never swaps to disk.
#ifdef _WIN32
  ::VirtualLock(this, sizeof(SecureRNG));
#else
  ::mlock(this, sizeof(SecureRNG));
#endif

  // Blocking initialization at boot safely
  std::vector<uint8_t> boot_seed = get_system_entropy("/dev/random");
  engine = std::make_unique<CTR_DRBG_AES256>(boot_seed);
  OPENSSL_cleanse(boot_seed.data(), boot_seed.size());
}

void SecureRNG::bytes(uint8_t *out_buffer, size_t size) {
  if (!out_buffer || size == 0) {
    return;
  }

  std::lock_guard<std::mutex> lock(engine_mutex);

  try {
    std::vector<uint8_t> data = engine->generate(size);
    std::memcpy(out_buffer, data.data(), size);
    OPENSSL_cleanse(data.data(), data.size());
  } catch (const std::runtime_error &) {
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
#ifdef _WIN32
  ::VirtualUnlock(this, sizeof(SecureRNG));
#else
  ::munlock(this, sizeof(SecureRNG));
#endif
}
} // namespace vhsm::crypto