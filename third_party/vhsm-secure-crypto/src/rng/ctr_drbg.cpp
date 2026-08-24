#include "vhsm/scrypto/aes.h"
#include "vhsm/scrypto/mem.h"
#include "vhsm/scrypto/rng.h"
#include <cstring>
#include <stdexcept>

namespace vhsm::scrypto {

CtrDrbgAes256::CtrDrbgAes256(const std::vector<uint8_t> &entropy48) {
  if (entropy48.size() != 48)
    throw std::invalid_argument("Seed must be 48 bytes");
  key_.assign(32, 0);
  V_.assign(16, 0);
  reseed_counter_ = 1;
  update(entropy48);
}
CtrDrbgAes256::~CtrDrbgAes256() {
  cleanse(key_.data(), key_.size());
  cleanse(V_.data(), V_.size());
}

void CtrDrbgAes256::increment_V() {
  for (int i = 15; i >= 0; --i)
    if (++V_[i] != 0)
      break;
}
void CtrDrbgAes256::aes256_encrypt_block_local(const std::vector<uint8_t> &in,
                                               std::vector<uint8_t> &out) {
  aes256_ecb_encrypt_block(key_.data(), in.data(), out.data());
}
void CtrDrbgAes256::update(const std::vector<uint8_t> &pd) {
  std::vector<uint8_t> temp(48, 0), blk(16, 0);
  for (size_t i = 0; i < 3; i++) {
    increment_V();
    aes256_encrypt_block_local(V_, blk);
    memcpy(temp.data() + i * 16, blk.data(), 16);
  }
  if (!pd.empty() && pd.size() == 48) {
    for (size_t i = 0; i < 48; i++)
      temp[i] ^= pd[i];
  }
  memcpy(key_.data(), temp.data(), 32);
  memcpy(V_.data(), temp.data() + 32, 16);
  cleanse(temp.data(), temp.size());
}
void CtrDrbgAes256::reseed(const std::vector<uint8_t> &e) {
  if (e.size() != 48)
    throw std::invalid_argument("Seed must be 48 bytes");
  update(e);
  reseed_counter_ = 1;
}
std::vector<uint8_t> CtrDrbgAes256::generate(size_t n) {
  if (reseed_counter_ > kReseedInterval)
    throw std::runtime_error("Reseed threshold reached");
  std::vector<uint8_t> out;
  out.reserve(n);
  std::vector<uint8_t> blk(16, 0);
  while (out.size() < n) {
    increment_V();
    aes256_encrypt_block_local(V_, blk);
    out.insert(out.end(), blk.begin(), blk.end());
  }
  out.resize(n);
  update({}); // forward security
  reseed_counter_++;
  cleanse(blk.data(), blk.size());
  return out;
}

} // namespace vhsm::scrypto
