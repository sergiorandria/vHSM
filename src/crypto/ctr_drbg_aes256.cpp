#include "ctr_drbg_aes256.h"
#include "../core/error.h"
#include "SecureRNG.h"
#include "vhsm/scrypto/aes.h"
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
void CTR_DRBG_AES256::increment_v() {
  for (int i = 15; i >= 0; --i) {
    if (++V[i] != 0) {
      break;
    }
  }
}

void CTR_DRBG_AES256::aes256_encrypt_block(const std::vector<u8> &input,
                                           std::vector<u8> &output) {
  vhsm::scrypto::aes256_ecb_encrypt_block(key.data(), input.data(),
                                          output.data());
}

void CTR_DRBG_AES256::update(const std::vector<u8> &provided_data) {
  std::vector<u8> temp(48, 0);
  std::vector<u8> output_block(16, 0);

  for (size_t i = 0; i < 3; ++i) {
    increment_v();
    aes256_encrypt_block(V, output_block);
    std::memcpy(temp.data() + (i * 16), output_block.data(), 16);
  }

  if (!provided_data.empty() && provided_data.size() == 48) {
    for (size_t i = 0; i < 48; ++i) {
      temp[i] ^= provided_data[i];
    }
  }

  std::memcpy(key.data(), temp.data(), 32);
  std::memcpy(V.data(), temp.data() + 32, 16);
  vhsm::scrypto::cleanse(temp.data(), temp.size());
}

CTR_DRBG_AES256::CTR_DRBG_AES256(const std::vector<u8> &entropy_input) {
  if (entropy_input.size() != 48) {
    throw std::invalid_argument("Seed must be 48 bytes");
  }

  key.assign(32, 0);
  V.assign(16, 0);
  reseed_counter = 1;
  update(entropy_input);
}

void CTR_DRBG_AES256::reseed(const std::vector<u8> &entropy_input) {
  if (entropy_input.size() != 48) {
    throw std::invalid_argument("Seed must be 48 bytes");
  }

  update(entropy_input);
  reseed_counter = 1;
}

std::vector<u8> CTR_DRBG_AES256::generate(size_t requested_bytes) {
  if (reseed_counter > RESEED_INTERVAL) {
    throw std::runtime_error("Reseed threshold reached");
  }

  std::vector<u8> pseudo_random_bits;
  std::vector<u8> output_block(16, 0);

  while (pseudo_random_bits.size() < requested_bytes) {
    increment_v();
    aes256_encrypt_block(V, output_block);
    pseudo_random_bits.insert(pseudo_random_bits.end(), output_block.begin(),
                              output_block.end());
  }

  pseudo_random_bits.resize(requested_bytes);
  update(std::vector<u8>()); // Enforce Forward Security
  reseed_counter++;

  return pseudo_random_bits;
}

CTR_DRBG_AES256::~CTR_DRBG_AES256() {
  vhsm::scrypto::cleanse(key.data(), key.size());
  vhsm::scrypto::cleanse(V.data(), V.size());
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