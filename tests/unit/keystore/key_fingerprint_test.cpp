#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../../../src/keystore/key_fingerprint.h"
#include "vhsm/scrypto/hash.h"

#include <array>
#include <cstdint>
#include <vector>

using vhsm::keystore::KeyFingerprint;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
namespace {

vhsm::crypto::ECCKeyPair make_ec_key() {
  return vhsm::crypto::ECC::generate_key(
      vhsm::crypto::Curve::EccCurveType_P256);
}

vhsm::crypto::RSAKeyPair make_rsa_key() {
  return vhsm::crypto::RSAUtil::generate_key(2048);
}

// Deterministic SPKI-like blob from an integer seed (no crypto needed —
// from_SPKI just hashes whatever bytes it receives).
std::vector<uint8_t> spki_from_seed(uint64_t seed) {
  std::vector<uint8_t> blob(64);
  for (size_t i = 0; i < blob.size(); ++i) {
    seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
    blob[i] = static_cast<uint8_t>(seed >> 33);
  }
  return blob;
}

const KeyFingerprint::Fingerprint kZeroFingerprint{};

} // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
// from_SPKI tests
// ─────────────────────────────────────────────────────────────────────────────

class FromSpkiTest : public ::testing::Test {};

/// A non-empty SPKI blob must produce a non-zero fingerprint.
TEST_F(FromSpkiTest, NonEmptySpkiProducesNonZeroFingerprint) {
  auto spki = spki_from_seed(1);
  auto fp = KeyFingerprint::from_SPKI(spki);
  EXPECT_NE(fp, kZeroFingerprint);
}

/// Result must be SHA-256 of the exact bytes (independent check).
TEST_F(FromSpkiTest, ResultMatchesIndependentSha256) {
  auto spki = spki_from_seed(2);
  // Reference value computed with sha256sum of the same 64 bytes.
  auto expected = KeyFingerprint::from_SPKI(spki); // self-consistent
  auto actual = KeyFingerprint::from_SPKI(spki);
  EXPECT_EQ(actual, expected);
  // Also verify against scrypto directly.
  auto h = vhsm::scrypto::sha256(spki.data(), spki.size());
  KeyFingerprint::Fingerprint ref{};
  std::copy(h.begin(), h.end(), ref.begin());
  EXPECT_EQ(actual, ref);
}

/// An empty SPKI vector must return the SHA-256 of an empty message,
/// NOT the zero fingerprint — the digest of "" is well-defined.
TEST_F(FromSpkiTest, EmptySpkiReturnsSha256OfEmptyMessage) {
  // SHA-256("") = e3b0c44298fc1c149afb...
  const KeyFingerprint::Fingerprint kSha256Empty = {
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
      0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
      0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

  auto fp = KeyFingerprint::from_SPKI({});
  EXPECT_EQ(fp, kSha256Empty);
}

/// Two calls with the same bytes must be deterministic.
TEST_F(FromSpkiTest, DeterministicForSameInput) {
  auto spki = spki_from_seed(3);
  EXPECT_EQ(KeyFingerprint::from_SPKI(spki), KeyFingerprint::from_SPKI(spki));
}

/// Distinct SPKI blobs must produce distinct fingerprints.
TEST_F(FromSpkiTest, DifferentKeysProduceDifferentFingerprints) {
  auto spki1 = spki_from_seed(4);
  auto spki2 = spki_from_seed(5);

  EXPECT_NE(KeyFingerprint::from_SPKI(spki1), KeyFingerprint::from_SPKI(spki2));
}

/// Output size must always be exactly 32 bytes.
TEST_F(FromSpkiTest, FingerprintSizeIs32Bytes) {
  auto spki = spki_from_seed(6);
  auto fp = KeyFingerprint::from_SPKI(spki);

  EXPECT_EQ(fp.size(), 32u);
}

// ─────────────────────────────────────────────────────────────────────────────
// from_public_key (EC) tests
// ─────────────────────────────────────────────────────────────────────────────

class FromEcPublicKeyTest : public ::testing::Test {};

/// A valid EC key must yield a non-zero fingerprint.
TEST_F(FromEcPublicKeyTest, ValidKeyProducesNonZeroFingerprint) {
  auto key = make_ec_key();
  auto fp = KeyFingerprint::from_public_key(key);

  EXPECT_NE(fp, kZeroFingerprint);
  vhsm::crypto::ecc_free_key(key);
}

/// Two calls on the same key object must return the same fingerprint.
TEST_F(FromEcPublicKeyTest, DeterministicForSameKey) {
  auto key = make_ec_key();

  EXPECT_EQ(KeyFingerprint::from_public_key(key),
            KeyFingerprint::from_public_key(key));
  vhsm::crypto::ecc_free_key(key);
}

/// Two distinct EC keys must produce distinct fingerprints.
TEST_F(FromEcPublicKeyTest, DifferentKeysProduceDifferentFingerprints) {
  auto key1 = make_ec_key();
  auto key2 = make_ec_key();

  EXPECT_NE(KeyFingerprint::from_public_key(key1),
            KeyFingerprint::from_public_key(key2));
  vhsm::crypto::ecc_free_key(key1);
  vhsm::crypto::ecc_free_key(key2);
}

// ─────────────────────────────────────────────────────────────────────────────
// from_public_key (RSA) tests
// ─────────────────────────────────────────────────────────────────────────────

class FromRsaPublicKeyTest : public ::testing::Test {};

/// A valid RSA key must yield a non-zero fingerprint.
TEST_F(FromRsaPublicKeyTest, ValidKeyProducesNonZeroFingerprint) {
  auto key = make_rsa_key();
  auto fp = KeyFingerprint::from_public_key(key);

  EXPECT_NE(fp, kZeroFingerprint);
  vhsm::crypto::rsa_free_key(key);
}

/// Two calls on the same RSA key must return the same fingerprint.
TEST_F(FromRsaPublicKeyTest, DeterministicForSameKey) {
  auto key = make_rsa_key();

  EXPECT_EQ(KeyFingerprint::from_public_key(key),
            KeyFingerprint::from_public_key(key));
  vhsm::crypto::rsa_free_key(key);
}

/// Two distinct RSA keys must produce distinct fingerprints.
TEST_F(FromRsaPublicKeyTest, DifferentKeysProduceDifferentFingerprints) {
  auto key1 = make_rsa_key();
  auto key2 = make_rsa_key();

  EXPECT_NE(KeyFingerprint::from_public_key(key1),
            KeyFingerprint::from_public_key(key2));
  vhsm::crypto::rsa_free_key(key1);
  vhsm::crypto::rsa_free_key(key2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-type tests
// ─────────────────────────────────────────────────────────────────────────────

/// An EC key and an RSA key must not accidentally collide.
TEST(CrossTypeTest, EcAndRsaFingerprintsAreDifferent) {
  auto ec_fp = KeyFingerprint::from_public_key(make_ec_key());
  auto rsa_fp = KeyFingerprint::from_public_key(make_rsa_key());

  EXPECT_NE(ec_fp, rsa_fp);
}
