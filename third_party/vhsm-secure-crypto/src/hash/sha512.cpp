#include "vhsm/scrypto/hash.h"
#include <cstring>

namespace vhsm::scrypto {
namespace {
inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
inline uint64_t Ch64(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (~x & z);
}
inline uint64_t Maj64(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}
inline uint64_t Sigma0_64(uint64_t x) {
  return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}
inline uint64_t Sigma1_64(uint64_t x) {
  return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}
inline uint64_t sigma0_64(uint64_t x) {
  return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}
inline uint64_t sigma1_64(uint64_t x) {
  return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

struct Ctx512 {
  uint64_t h[8];
  uint64_t total = 0;
  uint8_t buf[128];
  size_t blen = 0;
  void init384() {
    h[0] = 0xcbbb9d5dc1059ed8ULL;
    h[1] = 0x629a292a367cd507ULL;
    h[2] = 0x9159015a3070dd17ULL;
    h[3] = 0x152fecd8f70e5939ULL;
    h[4] = 0x67332667ffc00b31ULL;
    h[5] = 0x8eb44a8768581511ULL;
    h[6] = 0xdb0c2e0d64f98fa7ULL;
    h[7] = 0x47b5481dbefa4fa4ULL;
    total = 0;
    blen = 0;
    std::memset(buf, 0, 128);
  }
  void init512() {
    h[0] = 0x6a09e667f3bcc908ULL;
    h[1] = 0xbb67ae8584caa73bULL;
    h[2] = 0x3c6ef372fe94f82bULL;
    h[3] = 0xa54ff53a5f1d36f1ULL;
    h[4] = 0x510e527fade682d1ULL;
    h[5] = 0x9b05688c2b3e6c1fULL;
    h[6] = 0x1f83d9abfb41bd6bULL;
    h[7] = 0x5be0cd19137e2179ULL;
    total = 0;
    blen = 0;
    std::memset(buf, 0, 128);
  }
  void compress(const uint8_t b[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
      w[i] = (uint64_t(b[i * 8]) << 56) | (uint64_t(b[i * 8 + 1]) << 48) |
             (uint64_t(b[i * 8 + 2]) << 40) | (uint64_t(b[i * 8 + 3]) << 32) |
             (uint64_t(b[i * 8 + 4]) << 24) | (uint64_t(b[i * 8 + 5]) << 16) |
             (uint64_t(b[i * 8 + 6]) << 8) | b[i * 8 + 7];
    }
    for (int i = 16; i < 80; i++)
      w[i] = sigma1_64(w[i - 2]) + w[i - 7] + sigma0_64(w[i - 15]) + w[i - 16];
    uint64_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5],
             g = h[6], hh = h[7];
    for (int i = 0; i < 80; i++) {
      uint64_t T1 = hh + Sigma1_64(e) + Ch64(e, f, g) + K512[i] + w[i];
      uint64_t T2 = Sigma0_64(a) + Maj64(a, bb, c);
      hh = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = bb;
      bb = a;
      a = T1 + T2;
    }
    h[0] += a;
    h[1] += bb;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }
  void update(const uint8_t *data, size_t len) {
    total += len;
    size_t off = 0;
    if (blen > 0) {
      size_t need = 128 - blen;
      size_t take = len < need ? len : need;
      std::memcpy(buf + blen, data, take);
      blen += take;
      off += take;
      if (blen == 128) {
        compress(buf);
        blen = 0;
      }
    }
    for (; off + 128 <= len; off += 128)
      compress(data + off);
    if (off < len) {
      blen = len - off;
      std::memcpy(buf, data + off, blen);
    }
  }
  void final(uint8_t *out, size_t outlen) {
    uint64_t bitlen = total * 8;
    // pad: 0x80 then zeros, last 16 bytes = 128-bit length (high 64 zero, low
    // 64 bitlen)
    size_t padlen = (blen < 112) ? (112 - blen) : (240 - blen);
    uint8_t pad[240] = {0};
    pad[0] = 0x80;
    update(pad, padlen);
    uint8_t lenbe[16] = {0};
    for (int i = 15; i >= 8; --i) {
      lenbe[i] = uint8_t(bitlen & 0xFF);
      bitlen >>= 8;
    }
    update(lenbe, 16);
    // output
    uint8_t full[64];
    for (int i = 0; i < 8; i++) {
      full[i * 8] = (h[i] >> 56) & 0xFF;
      full[i * 8 + 1] = (h[i] >> 48) & 0xFF;
      full[i * 8 + 2] = (h[i] >> 40) & 0xFF;
      full[i * 8 + 3] = (h[i] >> 32) & 0xFF;
      full[i * 8 + 4] = (h[i] >> 24) & 0xFF;
      full[i * 8 + 5] = (h[i] >> 16) & 0xFF;
      full[i * 8 + 6] = (h[i] >> 8) & 0xFF;
      full[i * 8 + 7] = h[i] & 0xFF;
    }
    std::memcpy(out, full, outlen);
  }
};
} // namespace

std::array<uint8_t, 64> sha512(const uint8_t *d, size_t l) {
  Ctx512 c;
  c.init512();
  c.update(d, l);
  std::array<uint8_t, 64> o{};
  c.final(o.data(), 64);
  return o;
}
std::array<uint8_t, 48> sha384(const uint8_t *d, size_t l) {
  Ctx512 c;
  c.init384();
  c.update(d, l);
  std::array<uint8_t, 64> full{};
  c.final(full.data(), 64);
  std::array<uint8_t, 48> o{};
  std::memcpy(o.data(), full.data(), 48);
  return o;
}
} // namespace vhsm::scrypto
