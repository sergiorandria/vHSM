#ifndef vHSM_RNG_H
#define vHSM_RNG_H

#include "../core/types.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vhsm::crypto {
// WHY CTR_DRBG_AES256 implements NIST SP 800-90A: This is the standard for
// deterministic random bit generation. It's proven secure, widely reviewed, and
// required for compliance in many security standards. Using a standard
// algorithm (rather than custom RNG logic) reduces the attack surface and gives
// confidence in the entropy quality.
//
// WHY use AES-256 (not ChaCha20, Salsa20, etc.): AES-256 is
// hardware-accelerated on modern CPUs (AES-NI), making it fast. NIST approved
// it for DRBG. The three components (key, V, reseed_counter) are all
// vHSM-managed, so we don't depend on third-party entropy sources beyond the
// initial seed (which comes from /dev/urandom).
//
// WHY not a singleton: Singleton makes global state, which complicates testing
// and multi-threaded integration. Instead, SecureRNG instantiates one
// CTR_DRBG_AES256 and wraps it with a mutex. If threads want private RNGs (for
// testing), they can create separate instances without fighting over a global
// lock. The tradeoff is that tests must manually pass the RNG instance around
// (but that's good for dependency injection).

class CTR_DRBG_AES256 {
public:
  // WHY explicit constructor takes entropy: The DRBG must be seeded with at
  // least as much entropy as the output security strength. For AES-256, that's
  // 256 bits minimum. The constructor validates the seed length and initializes
  // key and V.
  explicit CTR_DRBG_AES256(const std::vector<u8> &entropy_input);
  ~CTR_DRBG_AES256();

  // WHY separate reseed method: NIST requires reseeding periodically. After
  // generating 100,000 blocks (RESEED_INTERVAL), the state must be refreshed
  // with new entropy. Calling reseed() explicitly is useful for testing. In
  // production, SecureRNG calls it automatically when the counter exceeds the
  // threshold.
  void reseed(const std::vector<u8> &entropy_input);

  // WHY generate returns std::vector: Simpler than filling a caller-provided
  // buffer (caller doesn't need to allocate). The vector is returned by value,
  // which uses move semantics (cheap) to avoid copies.
  std::vector<u8> generate(size_t requested_bytes);

private:
  // WHY key and V are stored as vectors: These are the DRBG state. key is the
  // 256-bit AES key; V is the counter. Both must be kept secure (in
  // SecureBuffer eventually). For now, they're in regular vectors; a future
  // optimization could use SecureBuffer.
  std::vector<u8> key, V;

  // WHY reseed_counter tracks output: NIST mandates that we reseed if more than
  // RESEED_INTERVAL blocks have been generated since the last reseed. Tracking
  // the count prevents state exhaustion and weak output over long runs.
  u64 reseed_counter;

  // WHY RESEED_INTERVAL = 100,000: NIST standard for AES-based DRBGs. After
  // generating 100,000 outputs, entropy may be partially exhausted. Reseeding
  // periodically ensures ongoing entropy injection.
  const u64 RESEED_INTERVAL = 100000;

  // WHY private helper methods: increment_v(), aes256_encrypt_block(), update()
  // implement the NIST algorithm steps. They're private because callers don't
  // need to invoke them directly; generate() and reseed() use them internally.
  void increment_v();
  void aes256_encrypt_block(const std::vector<u8> &input,
                            std::vector<u8> &output);
  void update(const std::vector<u8> &provided_data);
};
} // namespace vhsm::crypto

#endif // vHSM_RNG_H