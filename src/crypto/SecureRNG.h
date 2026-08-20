#ifndef VHSM_CRYPTO_SECURE_RNG
#define VHSM_CRYPTO_SECURE_RNG

#include <memory.h>

#include "ctr_drbg_aes256.h"

namespace vhsm::crypto {
// WHY SecureRNG wraps CTR_DRBG_AES256: The DRBG is a low-level NIST-compliant
// engine that requires explicit entropy initialization and reseed management.
// SecureRNG adds:
//   1. Thread safety (mutex around engine state)
//   2. Automatic entropy seeding (from /dev/urandom or equivalent)
//   3. Public API simplicity (just call bytes(buffer, size))
//   4. Forced reseed capability (for testing and manual reseeding)
//
// WHY separate the engine and wrapper: The engine (CTR_DRBG_AES256) implements
// the NIST specification precisely. The wrapper adds production concerns
// (threading, entropy management). Keeping them separate allows the engine to
// be tested in isolation and reused in contexts where threading isn't needed.
//
// WHY unique_ptr<CTR_DRBG_AES256>: Engines encapsulate state (key, V counter).
// Taking ownership via unique_ptr ensures the engine is constructed once,
// during SecureRNG initialization, and destroyed when SecureRNG is destroyed.
// No manual memory management.

/**
 * @brief Thread-safe, memory-locked wrapper serving as the main public API.
 *
 * SecureRNG manages entropy seeding and provides a thread-safe interface to the
 * underlying CTR_DRBG_AES256 deterministic random number generator. The mutex
 * ensures that concurrent calls to bytes() don't corrupt the internal state.
 * The engine is reseeded after 100,000 requests (NIST SP 800-90A standard).
 *
 * WHY comment about better RNG future design: This is aspirational; the current
 * implementation uses /dev/urandom. The comment suggests a future
 * Gaussian-based DRBG (heat equation simulation) for improved entropy quality.
 * For now, the implementation is conservative: OS urandom is sufficient for
 * cryptographic operations.
 */
class SecureRNG {
private:
  // WHY unique_ptr: Exclusive ownership of the engine. Prevents accidental
  // sharing or use-after-free. The mutex protects concurrent access to
  // engine->generate().
  std::unique_ptr<CTR_DRBG_AES256> engine;

  // WHY mutex protects engine: CTR_DRBG_AES256 is not internally thread-safe.
  // Multiple threads calling generate() concurrently would corrupt the internal
  // state (key, V). The mutex ensures only one thread calls engine->generate()
  // at a time.
  std::mutex engine_mutex;

  // WHY private get_system_entropy: Entropy seed is obtained from the OS
  // (during construction and reseed). This method is private because the public
  // interface (bytes(), force_reseed()) manages entropy automatically. Callers
  // don't need to call it directly.
  std::vector<u8> get_system_entropy(const std::string &source_path);

public:
  SecureRNG();
  ~SecureRNG();

  // WHY bytes() is the main public API: Generate random bytes. Thread-safe
  // wrapper around engine->generate(). Lock the mutex, call the engine, release
  // the mutex. Simple and safe. Exceptions: If the engine hasn't been
  // initialized (e.g., construction failed), bytes() will throw. On reseed
  // failure (entropy source unavailable), bytes() throws.
  void bytes(u8 *out_buffer, size_t size);

  // WHY force_reseed() method: Testing may need to force reseed before/after
  // operations. Production code uses automatic reseed (every 100,000 requests).
  // force_reseed() lets tests verify reseed logic without generating 100,000
  // requests.
  void force_reseed();
};
} // namespace vhsm::crypto
#endif // VHSM_CRYPTO_SECURE_RNG