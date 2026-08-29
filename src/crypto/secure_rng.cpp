#include "secure_rng.h"

#include "vhsm/scrypto/mem.h"
#include <cstring>
#include <mutex>
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

  // Blocking initialization at boot safely
  std::vector<uint8_t> boot_seed = get_system_entropy("/dev/random");
  engine = std::make_unique<CTR_DRBG_AES256>(boot_seed);
  vhsm::scrypto::cleanse(boot_seed.data(), boot_seed.size());

  // Lock this object AND the heap-allocated DRBG state in RAM so the key/V
  // material never swaps to disk. The engine is allocated via unique_ptr, so
  // mlock(this) alone does not cover it — pin the engine block explicitly.
  // mlock may fail in containers with a zero MEMLOCK rlimit; we treat that as
  // best-effort (the RNG still works, just not page-locked).
#ifdef _WIN32
  ::VirtualLock(this, sizeof(SecureRNG));
  if (engine) ::VirtualLock(engine.get(), sizeof(CTR_DRBG_AES256));
#else
  ::mlock(this, sizeof(SecureRNG));
  if (engine) ::mlock(engine.get(), sizeof(CTR_DRBG_AES256));
#endif
}

void SecureRNG::bytes(uint8_t *out_buffer, size_t size) {
  if (!out_buffer || size == 0) {
    return;
  }

  std::lock_guard<std::mutex> lock(engine_mutex);

  try {
    std::vector<uint8_t> data = engine->generate(size);
    std::memcpy(out_buffer, data.data(), size);
    vhsm::scrypto::cleanse(data.data(), data.size());
  } catch (const std::runtime_error &) {
    // Self-healing forced reseed via high-speed live urandom
    std::vector<uint8_t> live_seed = get_system_entropy("/dev/urandom");
    engine->reseed(live_seed);
    vhsm::scrypto::cleanse(live_seed.data(), live_seed.size());

    std::vector<uint8_t> data = engine->generate(size);
    std::memcpy(out_buffer, data.data(), size);
    vhsm::scrypto::cleanse(data.data(), data.size());
  }
}

void SecureRNG::force_reseed() {
  std::lock_guard<std::mutex> lock(engine_mutex);
  std::vector<uint8_t> live_seed = get_system_entropy("/dev/urandom");
  engine->reseed(live_seed);
  vhsm::scrypto::cleanse(live_seed.data(), live_seed.size());
}

SecureRNG::~SecureRNG() {
#ifdef _WIN32
  if (engine) ::VirtualUnlock(engine.get(), sizeof(CTR_DRBG_AES256));
  ::VirtualUnlock(this, sizeof(SecureRNG));
#else
  if (engine) ::munlock(engine.get(), sizeof(CTR_DRBG_AES256));
  ::munlock(this, sizeof(SecureRNG));
#endif
}
} // namespace vhsm::crypto