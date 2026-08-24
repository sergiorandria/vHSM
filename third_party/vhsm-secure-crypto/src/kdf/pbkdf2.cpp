#include "vhsm/scrypto/hmac.h"
#include "vhsm/scrypto/kdf.h"
#include "vhsm/scrypto/mem.h"
#include <cstring>
#include <stdexcept>

namespace vhsm::scrypto {

std::vector<uint8_t> pbkdf2_hmac_sha256(const std::string &pw,
                                        const std::vector<uint8_t> &salt,
                                        uint32_t iter, size_t out_len) {
  if (pw.empty())
    throw std::invalid_argument("pbkdf2: password empty");
  if (salt.empty())
    throw std::invalid_argument("pbkdf2: salt empty");
  if (iter == 0)
    throw std::invalid_argument("pbkdf2: iterations 0");
  if (out_len == 0)
    throw std::invalid_argument("pbkdf2: out_len 0");
  if (iter < 100000) {
    // Hardened project policy: warn but allow for tests (iterations low makes
    // brute-force easier) In production Vault uses 310k
  }
  const uint8_t *pw_bytes = reinterpret_cast<const uint8_t *>(pw.data());
  size_t pw_len = pw.size();
  std::vector<uint8_t> out;
  out.reserve(out_len);
  uint32_t blocks = (out_len + 31) / 32;
  for (uint32_t i = 1; i <= blocks; i++) {
    // U1 = HMAC(pw, salt || BE32(i))
    uint8_t be[4] = {uint8_t(i >> 24), uint8_t(i >> 16), uint8_t(i >> 8),
                     uint8_t(i)};
    std::vector<uint8_t> s;
    s.reserve(salt.size() + 4);
    s.insert(s.end(), salt.begin(), salt.end());
    s.insert(s.end(), be, be + 4);
    auto U = hmac_sha256(pw_bytes, pw_len, s.data(), s.size());
    std::array<uint8_t, 32> T = U;
    for (uint32_t j = 1; j < iter; j++) {
      U = hmac_sha256(pw_bytes, pw_len, U.data(), U.size());
      for (int k = 0; k < 32; k++)
        T[k] ^= U[k];
    }
    size_t remain = out_len - out.size();
    size_t take = remain < 32 ? remain : 32;
    out.insert(out.end(), T.begin(), T.begin() + take);
    cleanse(U.data(), 32);
    cleanse(T.data(), 32);
    cleanse(s.data(), s.size());
  }
  return out;
}

} // namespace vhsm::scrypto
