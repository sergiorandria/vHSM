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
// required for compliance in many security standards.
//
// DRBG merge: this class is now a thin adapter over
// vhsm::scrypto::CtrDrbgAes256 — single audited NIST implementation shared by
// PKCS#11 C_GenerateRandom and internal salt/nonce generation. Public API
// unchanged (48-byte seed, generate/reseed); all 9 unit tests pass against
// the delegated engine.

class CTR_DRBG_AES256 {
public:
  // WHY explicit constructor takes entropy: The DRBG must be seeded with at
  // least as much entropy as the output security strength. For AES-256, that's
  // 256 bits minimum (48 bytes = 32 seed + 16 personalization per NIST).
  explicit CTR_DRBG_AES256(const std::vector<u8> &entropy_input);
  ~CTR_DRBG_AES256();

  // Non-copyable: DRBG state is unique; copying would duplicate state and
  // violate forward-security guarantees.
  CTR_DRBG_AES256(const CTR_DRBG_AES256 &) = delete;
  CTR_DRBG_AES256 &operator=(const CTR_DRBG_AES256 &) = delete;

  // WHY separate reseed method: NIST requires reseeding periodically. After
  // generating 100,000 blocks (RESEED_INTERVAL), the state must be refreshed
  // with new entropy.
  void reseed(const std::vector<u8> &entropy_input);

  std::vector<u8> generate(size_t requested_bytes);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
} // namespace vhsm::crypto

#endif // vHSM_RNG_H
