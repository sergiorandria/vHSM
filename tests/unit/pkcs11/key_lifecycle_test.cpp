#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>
#include <vector>

#include "../../../src/pkcs11/pkcs11.h"
#include "../../../src/pkcs11/pkcs11_internal.h"
#include "../../../src/keystore/key_state.h"

using namespace vhsm::pkcs11;
using vhsm::keystore::KeyState;

namespace {

// Mirror the bench's end-to-end bootstrap (C_Initialize -> slot -> session ->
// PIN -> login). GTEST_SKIP when no token is present so the suite stays green
// in token-less environments; where a token exists the full lifecycle is
// exercised.
class KeyLifecycleTest : public ::testing::Test {
protected:
  CK_SESSION_HANDLE h_ = CK_INVALID_HANDLE;

  void SetUp() override {
    ::setenv("VHSM_DB_PATH", ":memory:", 1);
    ::unsetenv("VHSM_VAULT_PATH");
    ::unsetenv("VHSM_VAULT_PASSWORD");
    ::unsetenv("VHSM_LEDGER_ENDPOINT");
    vhsm::session::detail::global_slot_manager().reset();

    if (C_Initialize(nullptr) != CKR_OK)
      GTEST_SKIP() << "C_Initialize failed";
    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    if (C_GetSlotList(CK_TRUE, slots, &n) != CKR_OK || n == 0)
      GTEST_SKIP() << "no slots with tokens present";
    if (C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                      0, &h_) != CKR_OK)
      GTEST_SKIP() << "C_OpenSession failed";
    const char *pin = "1234";
    C_InitPIN(h_, (CK_UTF8CHAR_PTR)pin, 4);
    if (C_Login(h_, CKU_USER, (CK_UTF8CHAR_PTR)pin, 4) != CKR_OK)
      GTEST_SKIP() << "C_Login failed";
  }

  void TearDown() override {
    if (h_ != CK_INVALID_HANDLE) {
      C_Logout(h_);
      C_CloseSession(h_);
    }
    C_Finalize(nullptr);
    vhsm::session::detail::global_slot_manager().reset();
  }

  // Set the vendor lifecycle-state attribute via the public C API.
  void set_state(CK_OBJECT_HANDLE key, KeyState st) {
    u8 b = static_cast<u8>(st);
    CK_ATTRIBUTE a{vhsm::keystore::CKA_VHSM_KEY_STATE, &b, 1};
    EXPECT_EQ(C_SetAttributeValue(h_, key, &a, 1), CKR_OK);
  }

  KeyState get_state(CK_OBJECT_HANDLE key) {
    auto o = p11_get_object(h_, key);
    return o ? o->getKeyState() : KeyState::Revoked;
  }
};

TEST_F(KeyLifecycleTest, SignBlockedWhenNotActive) {
  CK_MECHANISM mech{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_BBOOL t = CK_TRUE, f = CK_FALSE;
  static const char curve[] = "P-256";
  CK_ATTRIBUTE pub_tmpl[] = {{CKA_VERIFY, &t, sizeof(t)},
                             {CKA_TOKEN, &f, sizeof(f)},
                             {CKA_EC_PARAMS, (void *)curve, sizeof(curve) - 1}};
  CK_ATTRIBUTE priv_tmpl[] = {{CKA_SIGN, &t, sizeof(t)},
                              {CKA_TOKEN, &f, sizeof(f)}};
  CK_OBJECT_HANDLE pub = 0, priv = 0;
  ASSERT_EQ(C_GenerateKeyPair(h_, &mech, pub_tmpl, 3, priv_tmpl, 2, &pub, &priv),
            CKR_OK);

  unsigned char msg[32];
  std::memset(msg, 0xA5, sizeof(msg));
  CK_MECHANISM sig_mech{CKM_ECDSA_SHA256, nullptr, 0};
  unsigned char sig[256];
  CK_ULONG sig_len = sizeof(sig);

  // Active: signing works.
  ASSERT_EQ(C_SignInit(h_, &sig_mech, priv), CKR_OK);
  ASSERT_EQ(C_Sign(h_, msg, sizeof(msg), sig, &sig_len), CKR_OK);

  // Immediate re-sign (real 2nd sign) with a correctly-sized buffer.
  // PKCS#11 requires *pulSignatureLen to hold the buffer capacity on input;
  // reusing the previously-returned length is a client bug and yields
  // CKR_BUFFER_TOO_SMALL when the DER signature size grows (70–72 bytes).
  ASSERT_EQ(C_SignInit(h_, &sig_mech, priv), CKR_OK);
  CK_ULONG sig_len2 = sizeof(sig);
  ASSERT_EQ(C_Sign(h_, msg, sizeof(msg), sig, &sig_len2), CKR_OK);

  // Rotating: signing is refused (may still verify/decrypt).
  set_state(priv, KeyState::Rotating);
  EXPECT_EQ(C_SignInit(h_, &sig_mech, priv), CKR_OK);
  EXPECT_EQ(C_Sign(h_, msg, sizeof(msg), sig, &sig_len),
            CKR_KEY_FUNCTION_NOT_PERMITTED);

  // Revoked: signing refused.
  set_state(priv, KeyState::Revoked);
  EXPECT_EQ(C_SignInit(h_, &sig_mech, priv), CKR_OK);
  EXPECT_EQ(C_Sign(h_, msg, sizeof(msg), sig, &sig_len),
            CKR_KEY_FUNCTION_NOT_PERMITTED);
}

TEST_F(KeyLifecycleTest, DecryptBlockedWhenRevoked) {
  CK_MECHANISM mech{CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  CK_BBOOL t = CK_TRUE, f = CK_FALSE;
  CK_ULONG kBits = 2048;
  CK_ATTRIBUTE pub_tmpl[] = {{CKA_ENCRYPT, &t, sizeof(t)},
                             {CKA_TOKEN, &f, sizeof(f)}};
  CK_ATTRIBUTE priv_tmpl[] = {{CKA_DECRYPT, &t, sizeof(t)},
                              {CKA_TOKEN, &f, sizeof(f)},
                              {CKA_MODULUS_BITS, (void *)&kBits, sizeof(kBits)}};
  CK_OBJECT_HANDLE pub = 0, priv = 0;
  ASSERT_EQ(C_GenerateKeyPair(h_, &mech, pub_tmpl, 2, priv_tmpl, 3, &pub, &priv),
            CKR_OK);

  unsigned char pt[16];
  std::memset(pt, 0x42, sizeof(pt));
  CK_MECHANISM enc_mech{CKM_RSA_PKCS, nullptr, 0};
  unsigned char ct[256];
  CK_ULONG ct_len = sizeof(ct);
  ASSERT_EQ(C_EncryptInit(h_, &enc_mech, pub), CKR_OK);
  ASSERT_EQ(C_Encrypt(h_, pt, sizeof(pt), ct, &ct_len), CKR_OK);

  CK_MECHANISM dec_mech{CKM_RSA_PKCS, nullptr, 0};
  unsigned char out[256];
  CK_ULONG out_len = sizeof(out);

  // Active: decrypt works.
  ASSERT_EQ(C_DecryptInit(h_, &dec_mech, priv), CKR_OK);
  ASSERT_EQ(C_Decrypt(h_, ct, ct_len, out, &out_len), CKR_OK);
  ASSERT_EQ(out_len, CK_ULONG{sizeof(pt)});
  EXPECT_EQ(std::memcmp(out, pt, sizeof(pt)), 0);

  // Revoked: decrypt refused.
  set_state(priv, KeyState::Revoked);
  EXPECT_EQ(C_DecryptInit(h_, &dec_mech, priv), CKR_OK);
  EXPECT_EQ(C_Decrypt(h_, ct, ct_len, out, &out_len),
            CKR_KEY_FUNCTION_NOT_PERMITTED);
}

TEST_F(KeyLifecycleTest, RotateProducesActiveKeyAndSupersedesOld) {
  CK_MECHANISM mech{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_BBOOL t = CK_TRUE, f = CK_FALSE;
  static const char curve[] = "P-256";
  static const char label[] = "rotkey";
  CK_ATTRIBUTE pub_tmpl[] = {{CKA_VERIFY, &t, sizeof(t)},
                             {CKA_TOKEN, &f, sizeof(f)},
                             {CKA_LABEL, (void *)label, sizeof(label) - 1},
                             {CKA_EC_PARAMS, (void *)curve, sizeof(curve) - 1}};
  CK_ATTRIBUTE priv_tmpl[] = {{CKA_SIGN, &t, sizeof(t)},
                              {CKA_TOKEN, &f, sizeof(f)},
                              {CKA_LABEL, (void *)label, sizeof(label) - 1}};
  CK_OBJECT_HANDLE pub = 0, priv = 0;
  ASSERT_EQ(C_GenerateKeyPair(h_, &mech, pub_tmpl, 4, priv_tmpl, 3, &pub, &priv),
            CKR_OK);
  EXPECT_EQ(get_state(priv), KeyState::Active);

  CK_OBJECT_HANDLE newPub = 0, newPriv = 0;
  ASSERT_EQ(p11_rotate_keypair(h_, priv, pub_tmpl, 4, priv_tmpl, 3, &newPub,
                               &newPriv),
            CKR_OK);
  ASSERT_NE(newPriv, priv);

  // Old key superseded (Rotating); new key Active.
  EXPECT_EQ(get_state(priv), KeyState::Rotating);
  EXPECT_EQ(get_state(newPriv), KeyState::Active);

  unsigned char msg[32];
  std::memset(msg, 0x7E, sizeof(msg));
  CK_MECHANISM sig_mech{CKM_ECDSA_SHA256, nullptr, 0};
  unsigned char sig[256];
  CK_ULONG sig_len = sizeof(sig);

  // New key signs fine.
  ASSERT_EQ(C_SignInit(h_, &sig_mech, newPriv), CKR_OK);
  ASSERT_EQ(C_Sign(h_, msg, sizeof(msg), sig, &sig_len), CKR_OK);

  // Old (Rotating) key can no longer sign.
  EXPECT_EQ(C_SignInit(h_, &sig_mech, priv), CKR_OK);
  EXPECT_EQ(C_Sign(h_, msg, sizeof(msg), sig, &sig_len),
            CKR_KEY_FUNCTION_NOT_PERMITTED);
}

// The pure policy mapping is unit-tested apart from the full stack so the
// rule itself is covered even where no token is available.
TEST(KeyStatePolicy, PureMapping) {
  EXPECT_EQ(p11_key_state_error(KeyState::Active, /*forSigning=*/true), CKR_OK);
  EXPECT_EQ(p11_key_state_error(KeyState::Active, /*forSigning=*/false), CKR_OK);
  EXPECT_EQ(p11_key_state_error(KeyState::Rotating, /*forSigning=*/true),
            CKR_KEY_FUNCTION_NOT_PERMITTED);
  EXPECT_EQ(p11_key_state_error(KeyState::Rotating, /*forSigning=*/false),
            CKR_OK);
  EXPECT_EQ(p11_key_state_error(KeyState::Revoked, /*forSigning=*/true),
            CKR_KEY_FUNCTION_NOT_PERMITTED);
  EXPECT_EQ(p11_key_state_error(KeyState::Revoked, /*forSigning=*/false),
            CKR_KEY_FUNCTION_NOT_PERMITTED);
}

} // namespace
