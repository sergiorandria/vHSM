#pragma once
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vhsm::scrypto {

// CTR_DRBG-AES256 — NIST SP 800-90A, 256-bit strength
class CtrDrbgAes256 {
public:
  explicit CtrDrbgAes256(const std::vector<uint8_t> &entropy48);
  ~CtrDrbgAes256();
  void reseed(const std::vector<uint8_t> &entropy48);
  std::vector<uint8_t> generate(size_t n);

private:
  std::vector<uint8_t> key_, V_;
  uint64_t reseed_counter_ = 1;
  static constexpr uint64_t kReseedInterval = 100000;
  void increment_V();
  void aes256_encrypt_block_local(const std::vector<uint8_t> &in,
                                  std::vector<uint8_t> &out);
  void update(const std::vector<uint8_t> &provided);
};

// Thread-safe, mlocked wrapper — public API for vHSM
class SecureRng {
public:
  SecureRng();
  ~SecureRng();
  void bytes(uint8_t *out, size_t len);
  void force_reseed();
  static std::vector<uint8_t>
  get_system_entropy(const std::string &source_hint);

private:
  std::unique_ptr<CtrDrbgAes256> engine_;
  std::mutex mu_;
};

} // namespace vhsm::scrypto
