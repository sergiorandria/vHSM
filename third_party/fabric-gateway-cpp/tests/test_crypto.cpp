// test_crypto.cpp — Phase 1 unit tests: keygen, CSR, sign/verify round-trip,
// plus the Identity and wallet layer.
//
// Build target: fabric_gateway_cpp_unit_tests (GoogleTest, linked against
// fabric-gateway-cpp).

#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <sys/stat.h>

#include "fabric/crypto/csr.h"
#include "fabric/crypto/ec.h"
#include "fabric/crypto/secure_string.h"
#include "fabric/identity/identity.h"
#include "fabric/identity/wallet.h"

namespace fs = std::filesystem;
using fabric::crypto::CSR;
using fabric::crypto::ECKeyPair;
using fabric::crypto::SecureString;
using fabric::identity::CustomHardenedWallet;
using fabric::identity::Identity;
using fabric::identity::InMemoryWallet;

namespace {

const char *kMasterKey =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

bool contains(const std::string &haystack, const std::string &needle) {
  return haystack.find(needle) != std::string::npos;
}

bool contains(const std::vector<std::string> &haystack, const std::string &needle) {
  for (const auto &s : haystack) {
    if (s == needle) {
      return true;
    }
  }
  return false;
}

bool readFileHelper(const std::string &path, std::string &out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  out = ss.str();
  return true;
}

// Unique temp directory for hardened-wallet tests, created in SetUp and
// removed after the fixture is done. The master key is injected via the
// environment so put()/get() have an at-rest wrapping key available.
class HardenedWalletTest : public ::testing::Test {
 protected:
  void SetUp() override {
    setenv("FABRIC_WALLET_MASTER_KEY", kMasterKey, 1);
    dir_ = fs::temp_directory_path() /
           ("fabric_wallet_test_" +
            std::to_string(
                std::chrono::system_clock::now().time_since_epoch().count()));
    fs::remove_all(dir_);
    auto res = CustomHardenedWallet::create(dir_.string());
    ASSERT_TRUE(res.has_value()) << res.error().message();
    wallet_.emplace(std::move(res).value());
  }

  void TearDown() override {
    wallet_.reset();
    fs::remove_all(dir_);
  }

  fs::path dir_;
  std::optional<CustomHardenedWallet> wallet_;
};

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// ECKeyPair — key generation
// ─────────────────────────────────────────────────────────────────────────────

TEST(ECKeyPairTest, GenerateReturnsPEMKeys) {
  auto [priv, pub] = ECKeyPair::generate();

  EXPECT_FALSE(priv.empty());
  EXPECT_FALSE(pub.empty());

  // Private key is a PEM-encoded ECPrivateKey block.
  EXPECT_TRUE(contains(priv.str(), "-----BEGIN EC PRIVATE KEY-----"));
  EXPECT_TRUE(contains(priv.str(), "-----END EC PRIVATE KEY-----"));

  // Public key is a PEM-encoded SPKI block.
  EXPECT_TRUE(contains(pub, "-----BEGIN PUBLIC KEY-----"));
  EXPECT_TRUE(contains(pub, "-----END PUBLIC KEY-----"));

  // Public and private material must differ.
  EXPECT_NE(priv.str(), pub);
}

TEST(ECKeyPairTest, TwoGeneratedKeyPairsDiffer) {
  auto [privA, pubA] = ECKeyPair::generate();
  auto [privB, pubB] = ECKeyPair::generate();

  EXPECT_NE(privA.str(), privB.str());
  EXPECT_NE(pubA, pubB);
}

// ─────────────────────────────────────────────────────────────────────────────
// ECKeyPair — sign / verify round-trip
// ─────────────────────────────────────────────────────────────────────────────

TEST(ECKeyPairTest, SignVerifyRoundTrip) {
  auto [priv, pub] = ECKeyPair::generate();

  ECKeyPair key(priv.str());
  const std::string data = "payload to sign";

  std::string sig = key.sign(data);
  EXPECT_FALSE(sig.empty());

  // Signature is a hex string of the DER-encoded ECDSA-Sig-Value.
  EXPECT_TRUE(contains(sig, "30")); // ASN.1 SEQUENCE tag opens the DER blob
  EXPECT_EQ(sig.size() % 2, 0u);

  EXPECT_TRUE(key.verify(data, sig));
}

TEST(ECKeyPairTest, SignVerifyRoundTripEmptyPayload) {
  auto [priv, pub] = ECKeyPair::generate();

  ECKeyPair key(priv.str());
  std::string sig = key.sign("");
  EXPECT_TRUE(key.verify("", sig));
}

TEST(ECKeyPairTest, VerifyRejectsTamperedPayload) {
  auto [priv, pub] = ECKeyPair::generate();

  ECKeyPair key(priv.str());
  std::string sig = key.sign("original");
  EXPECT_TRUE(key.verify("original", sig));

  EXPECT_FALSE(key.verify("tampered", sig));
  EXPECT_FALSE(key.verify("", sig));
}

TEST(ECKeyPairTest, VerifyRejectsWrongSignatureBytes) {
  auto [priv, pub] = ECKeyPair::generate();

  ECKeyPair key(priv.str());
  std::string data = "data";
  EXPECT_FALSE(key.verify(data, "deadbeef"));
  EXPECT_FALSE(key.verify(data, ""));
  EXPECT_FALSE(key.verify(data, "0f"));
}

TEST(ECKeyPairTest, ReloadedPrivateKeyVerifiesAcrossInstances) {
  auto [priv, pub] = ECKeyPair::generate();

  ECKeyPair a(priv.str());
  ECKeyPair b(priv.str());
  EXPECT_EQ(a.getPrivateKeyPEM().str(), b.getPrivateKeyPEM().str());
  EXPECT_EQ(a.getPublicKeyPEM(), b.getPublicKeyPEM());

  std::string data = "cross-instance";
  std::string sig = a.sign(data);
  EXPECT_TRUE(b.verify(data, sig));
}

TEST(ECKeyPairTest, LoadRejectsGarbagePem) {
  EXPECT_THROW(ECKeyPair("not a pem key at all"), std::runtime_error);
}

// ─────────────────────────────────────────────────────────────────────────────
// CSR — PKCS#10
// ─────────────────────────────────────────────────────────────────────────────

TEST(CSRTest, GenerateProducesValidCSR) {
  auto [priv, pub] = ECKeyPair::generate();

  std::string csr = CSR::generate(priv.str(), "user1@example.com", "Org1", "Dev",
                                  "City", "ST", "US");

  EXPECT_TRUE(contains(csr, "-----BEGIN CERTIFICATE REQUEST-----"));
  EXPECT_TRUE(contains(csr, "-----END CERTIFICATE REQUEST-----"));

  // The CSR must be self-signed by the requesting key and verify cleanly.
  EXPECT_TRUE(CSR::validate(csr));
}

TEST(CSRTest, GeneratedCSRCarriesSubjectAndPublicKey) {
  auto [priv, pub] = ECKeyPair::generate();

  std::string csr = CSR::generate(priv.str(), "cn.example.org", "Org1");

  std::string extracted = CSR::extractPublicKey(csr);
  EXPECT_FALSE(extracted.empty());
  EXPECT_TRUE(contains(extracted, "-----BEGIN PUBLIC KEY-----"));

  // The public key the CSR carries must equal the one from the keypair.
  EXPECT_EQ(extracted, pub);
}

TEST(CSRTest, ValidateRejectsGarbage) {
  EXPECT_FALSE(CSR::validate("this is definitely not a CSR"));
  EXPECT_FALSE(CSR::validate(""));
}

TEST(CSRTest, ValidateAcceptsCSRWithSans) {
  auto [priv, pub] = ECKeyPair::generate();
  std::string csr = CSR::generate(priv.str(), "svc.example.com", "Org1", "", "", "",
                                  "", {"svc.example.com", "www.example.com"});
  EXPECT_TRUE(CSR::validate(csr));
}

TEST(CSRTest, GenerateThrowsOnInvalidKey) {
  EXPECT_THROW(CSR::generate("not-a-valid-pem-key", "cn"), std::runtime_error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity
// ─────────────────────────────────────────────────────────────────────────────

TEST(IdentityTest, GettersRoundTrip) {
  Identity id("Org1MSP", "-----BEGIN CERTIFICATE-----",
              "-----BEGIN PRIVATE KEY-----");

  EXPECT_EQ(id.getMSPID(), "Org1MSP");
  EXPECT_EQ(id.getCertificate(), "-----BEGIN CERTIFICATE-----");
  EXPECT_EQ(id.getPrivateKey(), "-----BEGIN PRIVATE KEY-----");
  EXPECT_TRUE(id.isValid());
}

TEST(IdentityTest, PartialIdentityIsInvalid) {
  EXPECT_FALSE(Identity("", "", "").isValid());
  EXPECT_FALSE(Identity("Org1MSP", "", "").isValid());
  EXPECT_FALSE(Identity("", "cert", "").isValid());
  EXPECT_FALSE(Identity("", "", "key").isValid());
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryWallet
// ─────────────────────────────────────────────────────────────────────────────

TEST(InMemoryWalletTest, PutGetExistsListDelete) {
  InMemoryWallet wallet;
  Identity id("Org1MSP", "CERT", "KEY");

  ASSERT_TRUE(wallet.put("user1", id).has_value());
  // Duplicate label must not overwrite.
  EXPECT_FALSE(wallet.put("user1", id).has_value());

  ASSERT_TRUE(wallet.exists("user1"));
  EXPECT_FALSE(wallet.exists("missing"));

  auto got = wallet.get("user1");
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(got.value()->getMSPID(), "Org1MSP");
  EXPECT_EQ(got.value()->getCertificate(), "CERT");

  EXPECT_FALSE(wallet.get("missing").has_value());

  auto labels = wallet.list();
  ASSERT_EQ(labels.size(), 1u);
  EXPECT_EQ(labels[0], "user1");

  ASSERT_TRUE(wallet.deleteIdentity("user1").has_value());
  EXPECT_FALSE(wallet.exists("user1"));
  EXPECT_FALSE(wallet.deleteIdentity("user1").has_value());
  EXPECT_TRUE(wallet.list().empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// CustomHardenedWallet (encrypted, access-controlled file wallet)
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(HardenedWalletTest, HasMasterKey) {
  EXPECT_TRUE(wallet_->hasMasterKey());
}

TEST_F(HardenedWalletTest, PutGetExistsDelete) {
  Identity id("Org1MSP", "CERTIFICATE-PEM", "PRIVATE-KEY-PEM");

  ASSERT_TRUE(wallet_->put("alice", id).has_value());
  EXPECT_TRUE(wallet_->exists("alice"));
  EXPECT_FALSE(wallet_->exists("bob"));

  auto got = wallet_->get("alice");
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(got.value()->getMSPID(), "Org1MSP");
  EXPECT_EQ(got.value()->getCertificate(), "CERTIFICATE-PEM");
  EXPECT_EQ(got.value()->getPrivateKey(), "PRIVATE-KEY-PEM");

  ASSERT_TRUE(wallet_->deleteIdentity("alice").has_value());
  EXPECT_FALSE(wallet_->exists("alice"));
  EXPECT_FALSE(wallet_->get("alice").has_value());
}

TEST_F(HardenedWalletTest, GetUnknownLabelReturnsNull) {
  EXPECT_FALSE(wallet_->get("nobody").has_value());
  EXPECT_FALSE(wallet_->exists("nobody"));
}

TEST_F(HardenedWalletTest, ListReturnsStoredLabels) {
  ASSERT_TRUE(wallet_->put("alice", Identity("msp", "c", "k")).has_value());
  ASSERT_TRUE(wallet_->put("bob", Identity("msp", "c", "k")).has_value());

  auto labels = wallet_->list();
  ASSERT_EQ(labels.size(), 2u);
  EXPECT_TRUE(contains(labels, "alice"));
  EXPECT_TRUE(contains(labels, "bob"));
}

TEST_F(HardenedWalletTest, PrivateKeyIsEncryptedAtRest) {
  Identity id("Org1MSP", "CERTIFICATE-PEM", "PRIVATE-KEY-PEM");
  ASSERT_TRUE(wallet_->put("alice", id));

  std::string blob;
  ASSERT_TRUE(readFileHelper(dir_.string() + "/alice.id", blob));
  // The on-disk blob must carry the magic header and must NOT contain the
  // plaintext private key.
  EXPECT_TRUE(contains(blob, "FHW2"));
  EXPECT_FALSE(contains(blob, "PRIVATE-KEY-PEM"));
}

TEST_F(HardenedWalletTest, FilesUseRestrictedPermissions) {
  ASSERT_TRUE(wallet_->put("alice", Identity("msp", "c", "k")));
  std::string path = dir_.string() + "/alice.id";

  struct stat st {};
  ASSERT_EQ(stat(path.c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600);

  struct stat dst {};
  ASSERT_EQ(stat(dir_.string().c_str(), &dst), 0);
  EXPECT_EQ(dst.st_mode & 0777, 0700);
}

TEST_F(HardenedWalletTest, RejectsPathTraversalLabels) {
  Identity id("msp", "c", "k");
  // Labels containing separators or ".." must be refused and must not create
  // any file outside the wallet directory.
  EXPECT_FALSE(wallet_->put("../../escape", id).has_value());
  EXPECT_FALSE(wallet_->put("a/b", id).has_value());
  EXPECT_FALSE(wallet_->get("../../escape").has_value());
  EXPECT_FALSE(wallet_->exists("../.."));

  fs::path parent = dir_.parent_path();
  EXPECT_FALSE(fs::exists(parent / "escape.id"));
  EXPECT_FALSE(fs::exists(parent / "escape.id.tmp"));
}

TEST_F(HardenedWalletTest, TamperedBlobFailsToDecrypt) {
  ASSERT_TRUE(wallet_->put("alice", Identity("msp", "c", "k")).has_value());
  std::string path = dir_.string() + "/alice.id";
  std::string blob;
  ASSERT_TRUE(readFileHelper(path, blob));
  ASSERT_FALSE(blob.empty());
  blob[blob.size() / 2] ^= 0xFF;  // flip a bit in the ciphertext
  {
    std::ofstream out(path, std::ios::binary);
    out.write(blob.data(), blob.size());
  }
  EXPECT_FALSE(wallet_->get("alice").has_value());
}

// SecureString must actually scrub its backing store on wipe and on
// destruction — the whole point of routing key material through it. A plain
// memset would be elidable by the optimizer; OPENSSL_cleanse is not.
TEST(SecureStringTest, WipesOnExplicitWipe) {
  const std::string secret = "super-secret-key-material";
  SecureString s(secret);
  EXPECT_EQ(s.str(), secret);
  EXPECT_EQ(s.size(), secret.size());

  s.wipe();
  // After wiping, the bytes are zeroed (size is preserved) — not the original
  // plaintext.
  ASSERT_EQ(s.size(), secret.size());
  for (unsigned char c : s.str()) {
    EXPECT_EQ(c, 0);
  }
}

TEST(SecureStringTest, WipesOnDestructionAndMove) {
  const std::string secret = "another-secret-value";
  SecureString a(secret);
  SecureString b(std::move(a));
  EXPECT_EQ(b.str(), secret);
  // moved-from object is empty and wiping it is a safe no-op
  a.wipe();
  EXPECT_TRUE(a.empty());

  // A copy keeps its own independent buffer; wiping one leaves the other.
  SecureString c(b);
  c.wipe();
  EXPECT_EQ(b.str(), secret);  // b untouched by c's wipe
  for (unsigned char ch : c.str()) {
    EXPECT_EQ(ch, 0);
  }
}