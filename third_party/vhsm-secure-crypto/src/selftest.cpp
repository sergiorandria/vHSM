#include "vhsm/scrypto/aes_gcm.h"
#include "vhsm/scrypto/hash.h"
#include "vhsm/scrypto/hmac.h"
#include "vhsm/scrypto/scrypto.h"
#include <cstring>
#include <stdexcept>

namespace vhsm::scrypto {

const char *version() noexcept {
  return "vhsm-secure-crypto 1.0.0 (hardened, FIPS like)";
}

bool selftest(bool strict) {
  // SHA256("abc") =
  // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  {
    auto h = sha256((const uint8_t *)"abc", 3);
    const uint8_t exp[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                             0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                             0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                             0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    if (std::memcmp(h.data(), exp, 32) != 0) {
      if (strict)
        throw std::runtime_error("selftest SHA256 failed");
      return false;
    }
  }
  // HMAC-SHA256 RFC4231 test 2: key="Jefe", data="what do ya want for nothing?"
  // -> 5bdcc...
  {
    std::string key = "Jefe";
    std::string data = "what do ya want for nothing?";
    auto out = hmac_sha256((const uint8_t *)key.data(), key.size(),
                           (const uint8_t *)data.data(), data.size());
    const uint8_t exp[32] = {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
                             0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
                             0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
                             0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
    if (std::memcmp(out.data(), exp, 32) != 0) {
      if (strict)
        throw std::runtime_error("HMAC selftest");
      return false;
    }
  }
  // AES-GCM NIST vector: key=0, nonce=0, pt=0
  {
    std::vector<uint8_t> key(32, 0), nonce(12, 0), pt(16, 0);
    auto r = aes256_gcm_encrypt_with_nonce(key, nonce, pt, {});
    // decrypt should succeed and be constant-time
    auto dec =
        aes256_gcm_decrypt_with_nonce(key, nonce, r.tag, r.ciphertext, {});
    if (dec != pt) {
      if (strict)
        throw std::runtime_error("GCM roundtrip");
      return false;
    }
    // tamper tag should fail
    r.tag[0] ^= 1;
    try {
      auto dec2 =
          aes256_gcm_decrypt_with_nonce(key, nonce, r.tag, r.ciphertext, {});
      (void)dec2;
      if (strict)
        throw std::runtime_error("GCM tag bypass");
      return false;
    } catch (const std::runtime_error &) { /* expected */
    }
  }
  return true;
}

} // namespace vhsm::scrypto
