#include "ctr_drbg_aes256.h"
#include "../core/error.h"
#include "secure_rng.h"
#include "fips.h"
#include "vhsm/scrypto/rng.h"
#include "vhsm/scrypto/mem.h"

#include <cstring>
#include <cstdlib>
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

// Hardware RNG (RDRAND) entropy binding. FIPS mode requires an approved entropy
// source; on x86 we bind the DRBG seed to the CPU RDRAND instruction. Fails
// closed when RDRAND is requested but unavailable. TPM2-bound entropy is a
// documented opt-in (VHSM_TPM) left as a hook: wire tpm2-tss RNG output here
// the same way when that flag is enabled.
#if defined(__x86_64__) || defined(__i386__)
static bool rdrand64(uint64_t *out) {
  uint8_t ok = 0;
  asm volatile("rdrand %0\n\tsetc %1" : "=r"(*out), "=qm"(ok) : : "cc");
  return ok != 0;
}
static bool hardware_rand_bytes(std::vector<u8> &buf) {
  for (size_t i = 0; i < buf.size(); i += 8) {
    uint64_t v = 0;
    bool got = false;
    for (int attempt = 0; attempt < 10; ++attempt) {
      if (rdrand64(&v)) {
        got = true;
        break;
      }
    }
    if (!got)
      return false;
    std::memcpy(buf.data() + i, &v, std::min<size_t>(8, buf.size() - i));
  }
  return true;
}
#else
static bool hardware_rand_bytes(std::vector<u8> &) { return false; }
#endif

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
  std::vector<u8> entropy(48);
  // Opt-in hardware RNG (RDRAND) binding. Selected by VHSM_ENTROPY=rdrand, or
  // forced under FIPS mode (RDRAND is the only entropy source we bind on x86).
  // Fails closed when RDRAND is requested but unavailable; under FIPS without
  // RDRAND we still fall through to getrandom (a CSPRNG) rather than refusing.
  const char *ent = std::getenv("VHSM_ENTROPY");
  const bool want_rdrand = (ent && std::strstr(ent, "rdrand") != nullptr);
  if (want_rdrand || fips_mode()) {
    if (hardware_rand_bytes(entropy)) {
      return entropy;
    }
    if (want_rdrand) {
      throw std::runtime_error(
          "RNG Failure: VHSM_ENTROPY=rdrand requested but RDRAND unavailable");
    }
  }
#ifdef _WIN32
  // Windows: BCryptGenRandom is the CSPRNG; source_path is ignored (kept for
  // API compat with POSIX /dev/* call-sites). BCRYPT_USE_SYSTEM_PREFERRED_RNG
  // is the recommended flag per MS docs.
  (void)source_path;
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
