#include "vhsm/scrypto/mem.h"
#include "vhsm/scrypto/rng.h"
#include <fstream>
#include <mutex>
#include <stdexcept>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <bcrypt.h>
#include <windows.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <cstring>
#include <errno.h>
#include <sys/random.h>
#include <unistd.h>
#endif

namespace vhsm::scrypto {

std::vector<uint8_t> SecureRng::get_system_entropy(const std::string &hint) {
#ifdef _WIN32
  (void)hint;
  std::vector<uint8_t> e(48);
  NTSTATUS s = BCryptGenRandom(nullptr, e.data(), (ULONG)e.size(),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (!BCRYPT_SUCCESS(s))
    throw std::runtime_error("BCryptGenRandom failed");
  return e;
#else
  std::vector<uint8_t> e(48);
  size_t off = 0;
  while (off < e.size()) {
    ssize_t n = getrandom(e.data() + off, e.size() - off, 0);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    off += n;
    if (off == e.size())
      return e;
  }
  // fallback to file hint
  std::string path = hint.empty() ? "/dev/urandom" : hint;
  std::ifstream f(path, std::ios::binary);
  if (!f || !f.read(reinterpret_cast<char *>(e.data()), 48))
    throw std::runtime_error("get_system_entropy failed: " + path);
  return e;
#endif
}

SecureRng::SecureRng() {
  std::lock_guard<std::mutex> lk(mu_);
  // mlock self
#ifdef _WIN32
  VirtualLock(this, sizeof(SecureRng));
#else
  // ignore mlock failure here? we throw via mlock_mem but this is object itself
  // not sensitive yet try mlock mlock(this,sizeof(SecureRng)); // may fail
  // without priv, ignore
#endif
  auto seed = get_system_entropy("/dev/random");
  engine_ = std::make_unique<CtrDrbgAes256>(seed);
  cleanse(seed.data(), seed.size());
}
SecureRng::~SecureRng() {
#ifdef _WIN32
  VirtualUnlock(this, sizeof(SecureRng));
#else
  // munlock(this,sizeof(SecureRng));
#endif
}
void SecureRng::bytes(uint8_t *out, size_t n) {
  if (!out || n == 0)
    return;
  std::lock_guard<std::mutex> lk(mu_);
  try {
    auto d = engine_->generate(n);
    memcpy(out, d.data(), n);
    cleanse(d.data(), d.size());
  } catch (const std::runtime_error &) {
    auto s = get_system_entropy("/dev/urandom");
    engine_->reseed(s);
    cleanse(s.data(), s.size());
    auto d = engine_->generate(n);
    memcpy(out, d.data(), n);
    cleanse(d.data(), d.size());
  }
}
void SecureRng::force_reseed() {
  std::lock_guard<std::mutex> lk(mu_);
  auto s = get_system_entropy("/dev/urandom");
  engine_->reseed(s);
  cleanse(s.data(), s.size());
}

} // namespace vhsm::scrypto
