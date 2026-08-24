#include "vhsm/scrypto/hash.h"
#include "vhsm/scrypto/hmac.h"
#include "vhsm/scrypto/mem.h"
#include <cstring>

namespace vhsm::scrypto {

std::array<uint8_t, 32> hmac_sha256(const uint8_t *key, size_t kl,
                                    const uint8_t *data, size_t dl) {
  // RFC 2104
  uint8_t k0[64] = {0};
  if (kl > 64) {
    auto h = sha256(key, kl);
    std::memcpy(k0, h.data(), 32);
  } else if (kl > 0) {
    std::memcpy(k0, key, kl);
  }
  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; i++) {
    ipad[i] = k0[i] ^ 0x36;
    opad[i] = k0[i] ^ 0x5c;
  }
  // inner = sha256(ipad || data)
  // we can just incremental via our sha256 helper by concatenating via vector
  // small performance cost fine for KDF (not high-throughput TLS)
  std::vector<uint8_t> inner_input;
  inner_input.reserve(64 + dl);
  inner_input.insert(inner_input.end(), ipad, ipad + 64);
  inner_input.insert(inner_input.end(), data, data + dl);
  auto inner = sha256(inner_input.data(), inner_input.size());
  std::vector<uint8_t> outer_input;
  outer_input.reserve(64 + 32);
  outer_input.insert(outer_input.end(), opad, opad + 64);
  outer_input.insert(outer_input.end(), inner.begin(), inner.end());
  auto out = sha256(outer_input.data(), outer_input.size());
  cleanse(k0, 64);
  cleanse(ipad, 64);
  cleanse(opad, 64);
  cleanse(inner_input.data(), inner_input.size());
  cleanse(outer_input.data(), outer_input.size());
  return out;
}

std::vector<uint8_t> hmac(HashAlg alg, const uint8_t *key, size_t kl,
                          const uint8_t *data, size_t dl) {
  if (alg == HashAlg::SHA256) {
    auto a = hmac_sha256(key, kl, data, dl);
    return {a.begin(), a.end()};
  }
  // For SHA384/512 we implement similarly but using sha512/sha384 core
  // Simplified: use generic HMAC with blocksize 128 for SHA512 family
  if (alg == HashAlg::SHA384 || alg == HashAlg::SHA512) {
    size_t block = 128;
    size_t outlen = (alg == HashAlg::SHA384) ? 48 : 64;
    std::vector<uint8_t> k0(block, 0);
    if (kl > block) {
      // hash key with same alg
      std::vector<uint8_t> hk;
      if (alg == HashAlg::SHA384) {
        auto h = sha384(key, kl);
        hk.assign(h.begin(), h.end());
      } else {
        auto h = sha512(key, kl);
        hk.assign(h.begin(), h.end());
      }
      std::memcpy(k0.data(), hk.data(), hk.size());
      cleanse(hk.data(), hk.size());
    } else {
      std::memcpy(k0.data(), key, kl);
    }
    std::vector<uint8_t> ipad(block), opad(block);
    for (size_t i = 0; i < block; i++) {
      ipad[i] = k0[i] ^ 0x36;
      opad[i] = k0[i] ^ 0x5c;
    }
    std::vector<uint8_t> inner_in;
    inner_in.reserve(block + dl);
    inner_in.insert(inner_in.end(), ipad.begin(), ipad.end());
    inner_in.insert(inner_in.end(), data, data + dl);
    std::vector<uint8_t> inner;
    if (alg == HashAlg::SHA384) {
      auto h = sha384(inner_in.data(), inner_in.size());
      inner.assign(h.begin(), h.end());
    } else {
      auto h = sha512(inner_in.data(), inner_in.size());
      inner.assign(h.begin(), h.end());
    }
    std::vector<uint8_t> outer_in;
    outer_in.reserve(block + inner.size());
    outer_in.insert(outer_in.end(), opad.begin(), opad.end());
    outer_in.insert(outer_in.end(), inner.begin(), inner.end());
    std::vector<uint8_t> out;
    if (alg == HashAlg::SHA384) {
      auto h = sha384(outer_in.data(), outer_in.size());
      out.assign(h.begin(), h.end());
    } else {
      auto h = sha512(outer_in.data(), outer_in.size());
      out.assign(h.begin(), h.end());
    }
    cleanse(k0.data(), k0.size());
    cleanse(ipad.data(), ipad.size());
    cleanse(opad.data(), opad.size());
    cleanse(inner.data(), inner.size());
    cleanse(outer_in.data(), outer_in.size());
    cleanse(inner_in.data(), inner_in.size());
    out.resize(outlen);
    return out;
  }
  // fallback to sha256
  auto a = hmac_sha256(key, kl, data, dl);
  return {a.begin(), a.end()};
}

} // namespace vhsm::scrypto
