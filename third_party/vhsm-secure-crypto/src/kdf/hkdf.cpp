#include "vhsm/scrypto/hmac.h"
#include "vhsm/scrypto/kdf.h"
#include <stdexcept>

namespace vhsm::scrypto {

std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t> &ikm,
                                 const std::vector<uint8_t> &salt,
                                 const std::vector<uint8_t> &info,
                                 size_t out_len) {
  if (ikm.empty())
    throw std::invalid_argument("hkdf: IKM empty");
  if (out_len == 0)
    throw std::invalid_argument("hkdf: out_len 0");
  constexpr size_t H = 32;
  // Extract
  std::vector<uint8_t> s = salt;
  if (s.empty())
    s.assign(H, 0);
  auto prk_arr = hmac_sha256(s.data(), s.size(), ikm.data(), ikm.size());
  std::vector<uint8_t> prk(prk_arr.begin(), prk_arr.end());
  // Expand
  size_t n = (out_len + H - 1) / H;
  std::vector<uint8_t> out;
  out.reserve(n * H);
  std::vector<uint8_t> t_prev;
  for (uint8_t i = 1; n > 0; ++i, --n) {
    std::vector<uint8_t> in;
    in.reserve(t_prev.size() + info.size() + 1);
    in.insert(in.end(), t_prev.begin(), t_prev.end());
    in.insert(in.end(), info.begin(), info.end());
    in.push_back(i);
    auto blk = hmac_sha256(prk.data(), prk.size(), in.data(), in.size());
    out.insert(out.end(), blk.begin(), blk.end());
    t_prev.assign(blk.begin(), blk.end());
  }
  out.resize(out_len);
  return out;
}

std::vector<uint8_t> derive_db_hmac_key(const std::vector<uint8_t> &kek) {
  static const std::vector<uint8_t> info = {'v', 'H', 'S', 'M', '-', 'd',
                                            'b', '-', 'h', 'm', 'a', 'c'};
  return hkdf_sha256(kek, {}, info, 32);
}

} // namespace vhsm::scrypto
