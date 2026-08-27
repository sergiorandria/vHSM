#include <algorithm>
#include <gtest/gtest.h>

#include <vhsm/scrypto/hash.h>

#include <string>
#include <vector>

using namespace vhsm::scrypto;

namespace {
std::vector<uint8_t> to_vec(const std::array<uint8_t, 32> &a) {
  return {a.begin(), a.end()};
}
std::vector<uint8_t> to_vec(const std::array<uint8_t, 48> &a) {
  return {a.begin(), a.end()};
}
std::vector<uint8_t> to_vec(const std::array<uint8_t, 64> &a) {
  return {a.begin(), a.end()};
}
} // namespace

TEST(IncrementalHash, Sha256MatchesOneShot) {
  const std::string msg = "abc";
  IncrementalHash h(HashAlg::SHA256);
  h.update(reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
  EXPECT_EQ(h.finalize(), to_vec(sha256(msg)));
}

TEST(IncrementalHash, Sha256KnownAnswer) {
  // FIPS 180-4 SHA-256("abc")
  const std::vector<uint8_t> expected = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
      0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
      0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  IncrementalHash h(HashAlg::SHA256);
  h.update(reinterpret_cast<const uint8_t *>("abc"), 3);
  EXPECT_EQ(h.finalize(), expected);
}

TEST(IncrementalHash, Sha256ChunkedMatchesOneShot) {
  std::vector<uint8_t> data(1000);
  for (size_t i = 0; i < data.size(); ++i)
    data[i] = static_cast<uint8_t>(i * 31 + 7);

  IncrementalHash h(HashAlg::SHA256);
  for (size_t off = 0; off < data.size(); off += 7) {
    size_t n = std::min<size_t>(7, data.size() - off);
    h.update(data.data() + off, n);
  }
  EXPECT_EQ(h.finalize(), to_vec(sha256(data)));
}

TEST(IncrementalHash, Sha512MatchesOneShot) {
  const std::string msg = "abc";
  IncrementalHash h(HashAlg::SHA512);
  h.update(reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
  EXPECT_EQ(h.finalize(),
            to_vec(sha512(reinterpret_cast<const uint8_t *>(msg.data()),
                          msg.size())));
}

TEST(IncrementalHash, Sha384MatchesOneShot) {
  const std::string msg = "abc";
  IncrementalHash h(HashAlg::SHA384);
  h.update(reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
  EXPECT_EQ(h.finalize(),
            to_vec(sha384(reinterpret_cast<const uint8_t *>(msg.data()),
                          msg.size())));
}

TEST(IncrementalHash, VectorUpdateOverload) {
  std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
  IncrementalHash h(HashAlg::SHA256);
  h.update(data);
  EXPECT_EQ(h.finalize(), to_vec(sha256(data)));
}
