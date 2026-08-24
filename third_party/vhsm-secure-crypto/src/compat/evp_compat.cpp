#include "vhsm/scrypto/evp_compat.h"
#include "vhsm/scrypto/hash.h"
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace vhsm::scrypto::compat {
namespace {
std::unordered_map<const Sha256Ctx *, std::vector<uint8_t>> g_pending;
std::mutex g_mu;
} // namespace
void Sha256Ctx::init() {
  std::lock_guard<std::mutex> lk(g_mu);
  g_pending[this].clear();
  std::memset(h, 0, sizeof(h));
  total_len = 0;
  buflen = 0;
  std::memset(buf, 0, 64);
}
void Sha256Ctx::update(const uint8_t *d, size_t n) {
  std::lock_guard<std::mutex> lk(g_mu);
  auto &v = g_pending[this];
  v.insert(v.end(), d, d + n);
}
void Sha256Ctx::final(uint8_t out[32]) {
  std::vector<uint8_t> v;
  {
    std::lock_guard<std::mutex> lk(g_mu);
    auto it = g_pending.find(this);
    if (it != g_pending.end()) {
      v = it->second;
      g_pending.erase(it);
    }
  }
  auto r = vhsm::scrypto::sha256(v.data(), v.size());
  std::memcpy(out, r.data(), 32);
}
} // namespace vhsm::scrypto::compat
