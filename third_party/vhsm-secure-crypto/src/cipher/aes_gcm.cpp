#include "vhsm/scrypto/aes_gcm.h"
#include "vhsm/scrypto/aes.h"
#include "vhsm/scrypto/constant_time.h"
#include "vhsm/scrypto/mem.h"
#include "vhsm/scrypto/rng.h"
#include <cstring>
#include <stdexcept>

namespace vhsm::scrypto {
namespace {
struct SimpleGhash {
  uint8_t Y[16] = {0};
  uint8_t H[16];
  SimpleGhash(const uint8_t h[16]) { std::memcpy(H, h, 16); }
  static void gf_add(uint8_t *y, const uint8_t *x) {
    for (int i = 0; i < 16; i++)
      y[i] ^= x[i];
  }
  static void gf_mul(uint8_t *y, const uint8_t *h) {
    uint8_t V[16];
    std::memcpy(V, h, 16);
    uint8_t Z[16] = {0};
    uint8_t Xi[16];
    std::memcpy(Xi, y, 16);
    for (int i = 0; i < 128; i++) {
      int byte = i / 8;
      int bit = 7 - (i % 8);
      if ((Xi[byte] >> bit) & 1)
        gf_add(Z, V);
      bool lsb = V[15] & 1;
      for (int j = 15; j > 0; --j)
        V[j] = (V[j] >> 1) | (V[j - 1] << 7);
      V[0] >>= 1;
      if (lsb)
        V[0] ^= 0xE1;
    }
    std::memcpy(y, Z, 16);
  }
  void update(const uint8_t *data, size_t len) {
    for (size_t off = 0; off < len;) {
      uint8_t blk[16] = {0};
      size_t take = (len - off) < 16 ? (len - off) : 16;
      std::memcpy(blk, data + off, take);
      gf_add(Y, blk);
      gf_mul(Y, H);
      off += take;
    }
  }
  void final_tag(uint8_t out[16]) { std::memcpy(out, Y, 16); }
};
} // namespace

GcmResult aes256_gcm_encrypt_with_nonce(const std::vector<uint8_t> &key,
                                        const std::vector<uint8_t> &nonce,
                                        const std::vector<uint8_t> &pt,
                                        const std::vector<uint8_t> &aad) {
  if (key.size() != 32)
    throw std::invalid_argument("GCM key must be 32 bytes");
  if (nonce.size() != 12)
    throw std::invalid_argument("GCM nonce must be 12 bytes");
  auto rk = Aes256Key::expand(key.data());
  uint8_t zero[16] = {0}, H[16];
  aes256_encrypt_block(rk, zero, H);
  uint8_t J0[16] = {0};
  std::memcpy(J0, nonce.data(), 12);
  J0[15] = 1;
  uint8_t S0[16];
  aes256_encrypt_block(rk, J0, S0);
  std::vector<uint8_t> ct(pt.size());
  if (!pt.empty()) {
    uint8_t cur[16];
    std::memcpy(cur, J0, 16);
    size_t off = 0;
    while (off < pt.size()) {
      uint32_t cc = (uint32_t(cur[12]) << 24) | (uint32_t(cur[13]) << 16) |
                    (uint32_t(cur[14]) << 8) | cur[15];
      cc++;
      cur[12] = cc >> 24;
      cur[13] = cc >> 16;
      cur[14] = cc >> 8;
      cur[15] = cc & 0xFF;
      uint8_t ks[16];
      aes256_encrypt_block(rk, cur, ks);
      size_t take = std::min<size_t>(16, pt.size() - off);
      for (size_t i = 0; i < take; i++)
        ct[off + i] = pt[off + i] ^ ks[i];
      off += take;
    }
  }
  SimpleGhash gh(H);
  if (!aad.empty())
    gh.update(aad.data(), aad.size());
  if (!ct.empty())
    gh.update(ct.data(), ct.size());
  uint8_t lenblk[16] = {0};
  uint64_t aad_bits = uint64_t(aad.size()) * 8;
  uint64_t ct_bits = uint64_t(ct.size()) * 8;
  for (int i = 7; i >= 0; --i) {
    lenblk[i] = aad_bits & 0xFF;
    aad_bits >>= 8;
  }
  for (int i = 15; i >= 8; --i) {
    lenblk[i] = ct_bits & 0xFF;
    ct_bits >>= 8;
  }
  gh.update(lenblk, 16);
  uint8_t Gh[16];
  gh.final_tag(Gh);
  uint8_t tag[16];
  for (int i = 0; i < 16; i++)
    tag[i] = Gh[i] ^ S0[i];
  GcmResult r;
  r.ciphertext = ct;
  r.nonce = nonce;
  r.tag.assign(tag, tag + 16);
  cleanse(H, 16);
  cleanse(S0, 16);
  cleanse(Gh, 16);
  return r;
}

GcmResult aes256_gcm_encrypt(const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &pt,
                             const std::vector<uint8_t> &aad) {
  if (key.size() != 32)
    throw std::invalid_argument("GCM key must be 32");
  SecureRng rng;
  std::vector<uint8_t> nonce(12);
  rng.bytes(nonce.data(), 12);
  return aes256_gcm_encrypt_with_nonce(key, nonce, pt, aad);
}

std::vector<uint8_t> aes256_gcm_decrypt_with_nonce(
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &tag, const std::vector<uint8_t> &ct,
    const std::vector<uint8_t> &aad) {
  if (key.size() != 32)
    throw std::invalid_argument("GCM key 32");
  if (tag.size() != 16)
    throw std::invalid_argument("tag 16");
  if (nonce.size() != 12)
    throw std::invalid_argument(
        "GCM nonce must be 12 for this clone (hardened)");
  auto rk = Aes256Key::expand(key.data());
  uint8_t zero[16] = {0}, H[16];
  aes256_encrypt_block(rk, zero, H);
  uint8_t J0[16] = {0};
  std::memcpy(J0, nonce.data(), 12);
  J0[15] = 1;
  uint8_t S0[16];
  aes256_encrypt_block(rk, J0, S0);
  SimpleGhash gh(H);
  if (!aad.empty())
    gh.update(aad.data(), aad.size());
  if (!ct.empty())
    gh.update(ct.data(), ct.size());
  uint8_t lenblk[16] = {0};
  uint64_t aad_bits = uint64_t(aad.size()) * 8;
  uint64_t ct_bits = uint64_t(ct.size()) * 8;
  uint64_t ab = aad_bits, cb = ct_bits;
  for (int i = 7; i >= 0; --i) {
    lenblk[i] = ab & 0xFF;
    ab >>= 8;
  }
  for (int i = 15; i >= 8; --i) {
    lenblk[i] = cb & 0xFF;
    cb >>= 8;
  }
  gh.update(lenblk, 16);
  uint8_t Gh[16];
  gh.final_tag(Gh);
  uint8_t expected[16];
  for (int i = 0; i < 16; i++)
    expected[i] = Gh[i] ^ S0[i];
  if (!constant_time_eq(expected, tag.data(), 16)) {
    cleanse(expected, 16);
    cleanse(Gh, 16);
    cleanse(H, 16);
    cleanse(S0, 16);
    throw std::runtime_error("authentication failed");
  }
  std::vector<uint8_t> pt(ct.size());
  if (!ct.empty()) {
    uint8_t cur[16];
    std::memcpy(cur, J0, 16);
    size_t off = 0;
    while (off < ct.size()) {
      uint32_t cc = (uint32_t(cur[12]) << 24) | (uint32_t(cur[13]) << 16) |
                    (uint32_t(cur[14]) << 8) | cur[15];
      cc++;
      cur[12] = cc >> 24;
      cur[13] = cc >> 16;
      cur[14] = cc >> 8;
      cur[15] = cc & 0xFF;
      uint8_t ks[16];
      aes256_encrypt_block(rk, cur, ks);
      size_t take = std::min<size_t>(16, ct.size() - off);
      for (size_t i = 0; i < take; i++)
        pt[off + i] = ct[off + i] ^ ks[i];
      off += take;
    }
  }
  cleanse(H, 16);
  cleanse(S0, 16);
  cleanse(Gh, 16);
  cleanse(expected, 16);
  return pt;
}

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t> &key,
                                        const GcmResult &d,
                                        const std::vector<uint8_t> &aad) {
  return aes256_gcm_decrypt_with_nonce(key, d.nonce, d.tag, d.ciphertext, aad);
}

} // namespace vhsm::scrypto
