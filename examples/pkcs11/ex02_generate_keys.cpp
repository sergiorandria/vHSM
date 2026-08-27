// 02 — Key generation: RSA-2048 and EC P-256/P-384
//
//   g++ -std=c++23 examples/pkcs11/02_generate_keys.cpp -I src -L build -lvhsm_pkcs11 -o /tmp/ex02 && /tmp/ex02

#include <cstdio>
#include <cstdlib>

#include "pkcs11/pkcs11.h"

static void ck(const char *w, CK_RV rv) {
  if (rv != CKR_OK) {
    std::fprintf(stderr, "%s: 0x%08lx\n", w, (unsigned long)rv);
    std::exit(1);
  }
}

int main() {
  ::setenv("VHSM_DB_PATH", ":memory:", 1);
  ck("C_Initialize", C_Initialize(nullptr));

  CK_SLOT_ID slot; CK_ULONG n = 1;
  ck("C_GetSlotList", C_GetSlotList(CK_TRUE, &slot, &n));
  CK_SESSION_HANDLE h;
  ck("C_OpenSession", C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, 0, &h));
  C_InitPIN(h, (CK_UTF8CHAR_PTR)"1234", 4);
  ck("C_Login", C_Login(h, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4));

  CK_BBOOL t = CK_TRUE, f = CK_FALSE;

  // --- RSA-2048 ---
  {
    CK_MECHANISM mech{CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_ULONG bits = 2048;
    CK_ATTRIBUTE pub[] = {{CKA_TOKEN, &f, sizeof(f)}, {CKA_VERIFY, &t, sizeof(t)}};
    CK_ATTRIBUTE priv[] = {{CKA_TOKEN, &f, sizeof(f)}, {CKA_SIGN, &t, sizeof(t)}, {CKA_PRIVATE, &t, sizeof(t)}, {CKA_SENSITIVE, &t, sizeof(t)}, {CKA_MODULUS_BITS, &bits, sizeof(bits)}};
    CK_OBJECT_HANDLE pub_h, priv_h;
    ck("C_GenerateKeyPair/RSA", C_GenerateKeyPair(h, &mech, pub, 2, priv, 5, &pub_h, &priv_h));
    std::printf("RSA-2048: pub=%lu priv=%lu\n", (unsigned long)pub_h, (unsigned long)priv_h);
  }

  // --- EC P-256 ---
  {
    CK_MECHANISM mech{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
    static const char curve[] = "P-256";
    CK_ATTRIBUTE pub[] = {{CKA_TOKEN, &f, sizeof(f)}, {CKA_VERIFY, &t, sizeof(t)}, {CKA_EC_PARAMS, (void*)curve, sizeof(curve)-1}};
    CK_ATTRIBUTE priv[] = {{CKA_TOKEN, &f, sizeof(f)}, {CKA_SIGN, &t, sizeof(t)}};
    CK_OBJECT_HANDLE pub_h, priv_h;
    ck("C_GenerateKeyPair/EC", C_GenerateKeyPair(h, &mech, pub, 3, priv, 2, &pub_h, &priv_h));
    std::printf("EC P-256: pub=%lu priv=%lu\n", (unsigned long)pub_h, (unsigned long)priv_h);
  }

  // --- EC P-384 ---
  {
    CK_MECHANISM mech{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
    static const char curve[] = "P-384";
    CK_ATTRIBUTE pub[] = {{CKA_TOKEN, &f, sizeof(f)}, {CKA_VERIFY, &t, sizeof(t)}, {CKA_EC_PARAMS, (void*)curve, sizeof(curve)-1}};
    CK_ATTRIBUTE priv[] = {{CKA_TOKEN, &f, sizeof(f)}, {CKA_SIGN, &t, sizeof(t)}};
    CK_OBJECT_HANDLE pub_h, priv_h;
    ck("C_GenerateKeyPair/P-384", C_GenerateKeyPair(h, &mech, pub, 3, priv, 2, &pub_h, &priv_h));
    std::printf("EC P-384: pub=%lu priv=%lu\n", (unsigned long)pub_h, (unsigned long)priv_h);
  }

  C_Logout(h); C_CloseSession(h); C_Finalize(nullptr);
  std::printf("done.\n");
}
