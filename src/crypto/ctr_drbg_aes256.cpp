#include "ctr_drbg_aes256.h"
#include "../core/error.h"
#include "secure_rng.h"
#include "vhsm/scrypto/rng.h"
#include "vhsm/scrypto/mem.h"

#include <cstring>
#include <fstream>
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
#include <cerrno>
#include <sys/random.h>
#include <unistd.h>
#endif

namespace vhsm::crypto {

// DRBG merge: CTR_DRBG_AES256 is now a thin adapter over
// vhsm::scrypto::CtrDrbgAes256 (the audited clone implementation). The
// previous version duplicated ~60 lines of NIST SP 800-90A update/generate/
// reseed logic; both used the same scrypto AES ECB block primitive, so the
// only difference was bookkeeping. Delegating removes the duplicate and
// guarantees PKCS#11 C_GenerateRandom and internal salt/nonce generation
// share a single audited DRBG code path.
//
// Public API unchanged: constructor validates 48-byte seed exactly (same as
// before), reseed same, generate returns requested bytes and enforces
// forward security via per-call state update inside the clone.

struct CTR_DRBG_AES256::Impl {
  explicit Impl(const std::vector<u8> &entropy) : drbg(entropy) {}
  vhsm::scrypto::CtrDrbgAes256 drbg;
};

CTR_DRBG_AES256::CTR_DRBG_AES256(const std::vector<u8> &entropy_input)
    : impl_(std::make_unique<Impl>(entropy_input)) {}

CTR_DRBG_AES256::~CTR_DRBG_AES256() = default;

void CTR_DRBG_AES256::reseed(const std::vector<u8> &entropy_input) {
  impl_->drbg.reseed(entropy_input);
}

std::vector<u8> CTR_DRBG_AES256::generate(size_t requested_bytes) {
  return impl_->drbg.generate(requested_bytes);
}

std::vector<u8> SecureRNG::get_system_entropy(const std::string &source_path) {
#ifdef _WIN32
  // Windows: BCryptGenRandom is the CSPRNG; source_path is ignored (kept for
  // API compat with POSIX /dev/* call-sites). BCRYPT_USE_SYSTEM_PREFERRED_RNG
  // is the recommended flag per MS docs.
  (void)source_path;
  std::vector<u8> entropy(48);
  NTSTATUS s = ::BCryptGenRandom(nullptr, entropy.data(),
                                 static_cast<ULONG>(entropy.size()),
                                 BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (!BCRYPT_SUCCESS(s)) {
    throw std::runtime_error("RNG Failure: BCryptGenRandom failed");
  }
  return entropy;
#else
  // POSIX: try getrandom(2) first (no FD, no fallback file needed), then
  // fall back to reading source_path for older kernels/containers.
  std::vector<u8> entropy(48);
  std::size_t off = 0;
  while (off < entropy.size()) {
    ssize_t n = ::getrandom(entropy.data() + off, entropy.size() - off, 0);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break; // fall back to file
    }
    off += static_cast<std::size_t>(n);
    if (off == entropy.size())
      return entropy;
  }
  // Fallback: read from the requested source_path (usually /dev/urandom)
  if (off != entropy.size()) {
    std::ifstream source(source_path, std::ios::in | std::ios::binary);
    if (!source || !source.read(reinterpret_cast<char *>(entropy.data()), 48)) {
      throw std::runtime_error(
          "RNG Failure: Enclave cannot reach system entropy source: " +
          source_path);
    }
  }
  return entropy;
#endif
}
} // namespace vhsm::crypto
