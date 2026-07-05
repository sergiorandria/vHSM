#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../../../src/keystore/key_fingerprint.h"

// OpenSSL helpers needed to generate real key pairs for integration tests
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <vector>
#include <array>
#include <cstdint>

using vhsm::keystore::KeyFingerprint;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
namespace {

/// Build a DER/SPKI blob from any EVP_PKEY (used to produce expected values
/// and to exercise from_SPKI directly).
std::vector<uint8_t> evp_pkey_to_spki(EVP_PKEY* pkey)
{
    BIO* bio = BIO_new(BIO_s_mem());
    EXPECT_NE(bio, nullptr);
    EXPECT_EQ(i2d_PUBKEY_bio(bio, pkey), 1);

    BUF_MEM* mem_ptr = nullptr;
    BIO_get_mem_ptr(bio, &mem_ptr);

    std::vector<uint8_t> spki(
        reinterpret_cast<uint8_t*>(mem_ptr->data),
        reinterpret_cast<uint8_t*>(mem_ptr->data) + mem_ptr->length
    );
    BIO_free(bio);
    return spki;
}

/// Compute SHA-256 via raw OpenSSL (independent reference implementation).
KeyFingerprint::Fingerprint sha256_of(const std::vector<uint8_t>& data)
{
    KeyFingerprint::Fingerprint out{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, out.data(), nullptr);
    EVP_MD_CTX_free(ctx);
    return out;
}

/// Generate a fresh P-256 key pair wrapped in vhsm::crypto::ECKeyPair.
/// Adjust the struct initialisation to match your actual ECKeyPair layout.
vhsm::crypto::ECKeyPair make_ec_key()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // Assumes ECKeyPair holds a public `EVP_PKEY* key` member.
    // Adapt if your struct uses a different field name or ownership model.
    return vhsm::crypto::ECKeyPair{ pkey };
}

/// Generate a fresh RSA-2048 key pair wrapped in vhsm::crypto::RSAKeyPair.
vhsm::crypto::RSAKeyPair make_rsa_key()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    return vhsm::crypto::RSAKeyPair{ pkey };
}

const KeyFingerprint::Fingerprint kZeroFingerprint{};

} // anonymous namespace


// ─────────────────────────────────────────────────────────────────────────────
// from_SPKI tests
// ─────────────────────────────────────────────────────────────────────────────

class FromSpkiTest : public ::testing::Test {};

/// A non-empty SPKI blob must produce a non-zero fingerprint.
TEST_F(FromSpkiTest, NonEmptySpkiProducesNonZeroFingerprint)
{
    auto ec  = make_ec_key();
    auto spki = evp_pkey_to_spki(ec.key);

    auto fp = KeyFingerprint::from_SPKI(spki);
    EXPECT_NE(fp, kZeroFingerprint);
}

/// Result must match an independent SHA-256 computed over the same bytes.
TEST_F(FromSpkiTest, ResultMatchesIndependentSha256)
{
    auto ec   = make_ec_key();
    auto spki = evp_pkey_to_spki(ec.key);

    auto expected = sha256_of(spki);
    auto actual   = KeyFingerprint::from_SPKI(spki);

    EXPECT_EQ(actual, expected);
}

/// An empty SPKI vector must return the SHA-256 of an empty message,
/// NOT the zero fingerprint — the digest of "" is well-defined.
TEST_F(FromSpkiTest, EmptySpkiReturnsSha256OfEmptyMessage)
{
    // SHA-256("") = e3b0c44298fc1c149afb...
    const KeyFingerprint::Fingerprint kSha256Empty = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    auto fp = KeyFingerprint::from_SPKI({});
    EXPECT_EQ(fp, kSha256Empty);
}

/// Two calls with the same bytes must be deterministic.
TEST_F(FromSpkiTest, DeterministicForSameInput)
{
    auto ec   = make_ec_key();
    auto spki = evp_pkey_to_spki(ec.key);

    EXPECT_EQ(KeyFingerprint::from_SPKI(spki), KeyFingerprint::from_SPKI(spki));
}

/// Distinct SPKI blobs (different keys) must produce distinct fingerprints.
TEST_F(FromSpkiTest, DifferentKeysProduceDifferentFingerprints)
{
    auto spki1 = evp_pkey_to_spki(make_ec_key().key);
    auto spki2 = evp_pkey_to_spki(make_ec_key().key);

    EXPECT_NE(KeyFingerprint::from_SPKI(spki1), KeyFingerprint::from_SPKI(spki2));
}

/// Output size must always be exactly 32 bytes.
TEST_F(FromSpkiTest, FingerprintSizeIs32Bytes)
{
    auto spki = evp_pkey_to_spki(make_ec_key().key);
    auto fp   = KeyFingerprint::from_SPKI(spki);

    EXPECT_EQ(fp.size(), 32u);
}


// ─────────────────────────────────────────────────────────────────────────────
// from_public_key (EC) tests
// ─────────────────────────────────────────────────────────────────────────────

class FromEcPublicKeyTest : public ::testing::Test {};

/// A valid EC key must yield a non-zero fingerprint.
TEST_F(FromEcPublicKeyTest, ValidKeyProducesNonZeroFingerprint)
{
    auto key = make_ec_key();
    auto fp  = KeyFingerprint::from_public_key(key);

    EXPECT_NE(fp, kZeroFingerprint);
}

/// Result must equal from_SPKI called on the same key's SPKI encoding.
TEST_F(FromEcPublicKeyTest, MatchesFromSpkiOfSameKey)
{
    auto key      = make_ec_key();
    auto spki     = evp_pkey_to_spki(key.key);
    auto expected = KeyFingerprint::from_SPKI(spki);

    EXPECT_EQ(KeyFingerprint::from_public_key(key), expected);
}

/// Two calls on the same key object must return the same fingerprint.
TEST_F(FromEcPublicKeyTest, DeterministicForSameKey)
{
    auto key = make_ec_key();

    EXPECT_EQ(KeyFingerprint::from_public_key(key),
              KeyFingerprint::from_public_key(key));
}

/// Two distinct EC keys must produce distinct fingerprints.
TEST_F(FromEcPublicKeyTest, DifferentKeysProduceDifferentFingerprints)
{
    auto key1 = make_ec_key();
    auto key2 = make_ec_key();

    EXPECT_NE(KeyFingerprint::from_public_key(key1),
              KeyFingerprint::from_public_key(key2));
}


// ─────────────────────────────────────────────────────────────────────────────
// from_public_key (RSA) tests
// ─────────────────────────────────────────────────────────────────────────────

class FromRsaPublicKeyTest : public ::testing::Test {};

/// A valid RSA key must yield a non-zero fingerprint.
TEST_F(FromRsaPublicKeyTest, ValidKeyProducesNonZeroFingerprint)
{
    auto key = make_rsa_key();
    auto fp  = KeyFingerprint::from_public_key(key);

    EXPECT_NE(fp, kZeroFingerprint);
}

/// Result must equal from_SPKI called on the same RSA key's SPKI encoding.
TEST_F(FromRsaPublicKeyTest, MatchesFromSpkiOfSameKey)
{
    auto key      = make_rsa_key();
    auto spki     = evp_pkey_to_spki(key.key);
    auto expected = KeyFingerprint::from_SPKI(spki);

    EXPECT_EQ(KeyFingerprint::from_public_key(key), expected);
}

/// Two calls on the same RSA key must return the same fingerprint.
TEST_F(FromRsaPublicKeyTest, DeterministicForSameKey)
{
    auto key = make_rsa_key();

    EXPECT_EQ(KeyFingerprint::from_public_key(key),
              KeyFingerprint::from_public_key(key));
}

/// Two distinct RSA keys must produce distinct fingerprints.
TEST_F(FromRsaPublicKeyTest, DifferentKeysProduceDifferentFingerprints)
{
    auto key1 = make_rsa_key();
    auto key2 = make_rsa_key();

    EXPECT_NE(KeyFingerprint::from_public_key(key1),
              KeyFingerprint::from_public_key(key2));
}


// ─────────────────────────────────────────────────────────────────────────────
// Cross-type tests
// ─────────────────────────────────────────────────────────────────────────────

/// An EC key and an RSA key must not accidentally collide.
TEST(CrossTypeTest, EcAndRsaFingerprintsAreDifferent)
{
    auto ec_fp  = KeyFingerprint::from_public_key(make_ec_key());
    auto rsa_fp = KeyFingerprint::from_public_key(make_rsa_key());

    EXPECT_NE(ec_fp, rsa_fp);
}

/// from_public_key(EC) and from_SPKI must agree on the same underlying key.
TEST(CrossTypeTest, EcPublicKeyAgreeWithSpkiPath)
{
    auto key  = make_ec_key();
    auto spki = evp_pkey_to_spki(key.key);

    EXPECT_EQ(KeyFingerprint::from_public_key(key),
              KeyFingerprint::from_SPKI(spki));
}

/// from_public_key(RSA) and from_SPKI must agree on the same underlying key.
TEST(CrossTypeTest, RsaPublicKeyAgreeWithSpkiPath)
{
    auto key  = make_rsa_key();
    auto spki = evp_pkey_to_spki(key.key);

    EXPECT_EQ(KeyFingerprint::from_public_key(key),
              KeyFingerprint::from_SPKI(spki));
}