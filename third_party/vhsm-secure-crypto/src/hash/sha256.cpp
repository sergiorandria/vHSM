#include "vhsm/scrypto/hash.h"
#include <cstring>
#include <iomanip>
#include <sstream>

namespace vhsm::scrypto {

// FIPS 180-4 SHA-256 — public domain, constant-time, no data-dependent branches
namespace {
inline uint32_t rotr(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}
inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}
inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}
inline uint32_t Sigma0(uint32_t x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
inline uint32_t Sigma1(uint32_t x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
inline uint32_t sigma0(uint32_t x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}
inline uint32_t sigma1(uint32_t x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

struct Ctx {
  uint32_t h[8];
  uint64_t total_len = 0;
  uint8_t buf[64];
  size_t buflen = 0;
  void init() {
    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;
    total_len = 0;
    buflen = 0;
    std::memset(buf, 0, 64);
  }
  void compress(const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = (uint32_t(block[i * 4]) << 24) |
             (uint32_t(block[i * 4 + 1]) << 16) |
             (uint32_t(block[i * 4 + 2]) << 8) | block[i * 4 + 3];
    for (int i = 16; i < 64; i++)
      w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5],
             g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t T1 = hh + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
      uint32_t T2 = Sigma0(a) + Maj(a, b, c);
      hh = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }
  void update(const uint8_t *data, size_t len) {
    total_len += len;
    size_t off = 0;
    if (buflen > 0) {
      size_t need = 64 - buflen;
      size_t take = len < need ? len : need;
      std::memcpy(buf + buflen, data, take);
      buflen += take;
      off += take;
      if (buflen == 64) {
        compress(buf);
        buflen = 0;
      }
    }
    for (; off + 64 <= len; off += 64)
      compress(data + off);
    if (off < len) {
      buflen = len - off;
      std::memcpy(buf, data + off, buflen);
    }
  }
  void final(uint8_t out[32]) {
    uint64_t bitlen = total_len * 8;
    uint8_t pad[64] = {0x80};
    size_t padlen = (buflen < 56) ? (56 - buflen) : (120 - buflen);
    // we need to feed pad + 8-byte length
    // use update for pad
    update(pad, padlen);
    uint8_t lenbe[8];
    for (int i = 7; i >= 0; --i) {
      lenbe[i] = uint8_t(bitlen & 0xFF);
      bitlen >>= 8;
    }
    update(lenbe, 8);
    // now buflen should be 0
    for (int i = 0; i < 8; i++) {
      out[i * 4] = (h[i] >> 24) & 0xFF;
      out[i * 4 + 1] = (h[i] >> 16) & 0xFF;
      out[i * 4 + 2] = (h[i] >> 8) & 0xFF;
      out[i * 4 + 3] = h[i] & 0xFF;
    }
  }
};
} // namespace

std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len) {
  Ctx c;
  c.init();
  c.update(data, len);
  std::array<uint8_t, 32> out{};
  c.final(out.data());
  return out;
}
std::string sha256_hex(const uint8_t *data, size_t len) {
  auto d = sha256(data, len);
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto b : d)
    oss << std::setw(2) << int(b);
  return oss.str();
}
std::vector<uint8_t> hash(HashAlg alg, const uint8_t *data, size_t len) {
  if (alg == HashAlg::SHA256) {
    auto a = sha256(data, len);
    return {a.begin(), a.end()};
  }
  if (alg == HashAlg::SHA512) {
    auto a = sha512(data, len);
    return {a.begin(), a.end()};
  }
  // SHA384
  auto a = sha384(data, len);
  return {a.begin(), a.end()};
}
const char *hash_name(HashAlg a) noexcept {
  switch (a) {
  case HashAlg::SHA256:
    return "SHA256";
  case HashAlg::SHA384:
    return "SHA384";
  case HashAlg::SHA512:
    return "SHA512";
  }
  return "SHA256";
}

} // namespace vhsm::scrypto
