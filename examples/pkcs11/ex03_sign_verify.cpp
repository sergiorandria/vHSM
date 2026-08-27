// 03 — Sign / Verify with ECDSA (P-256) and RSA-PKCS#1 v1.5
//
//   g++ -std=c++23 examples/pkcs11/03_sign_verify.cpp -I src -L build -lvhsm_pkcs11 -o /tmp/ex03 && /tmp/ex03

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "pkcs11/pkcs11.h"

static void ck(const char *w, CK_RV rv) {
  if (rv != CKR_OK) { std::fprintf(stderr, "%s: 0x%08lx\n", w, (unsigned long)rv); std::exit(1); }
}

int main() {
  ::setenv("VHSM_DB_PATH", ":memory:", 1);
  ck("C_Initialize", C_Initialize(nullptr));
  CK_SLOT_ID slot; CK_ULONG n=1; ck("C_GetSlotList", C_GetSlotList(CK_TRUE,&slot,&n));
  CK_SESSION_HANDLE h; ck("C_OpenSession", C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,0,&h));
  C_InitPIN(h,(CK_UTF8CHAR_PTR)"1234",4); ck("C_Login", C_Login(h,CKU_USER,(CK_UTF8CHAR_PTR)"1234",4));

  const std::string msg = "vHSM sign/verify example";
  CK_BBOOL t=CK_TRUE,f=CK_FALSE;

  // --- ECDSA P-256 ---
  {
    CK_MECHANISM gen{CKM_EC_KEY_PAIR_GEN,nullptr,0};
    static const char curve[]="P-256";
    CK_ATTRIBUTE pubT[]={{CKA_TOKEN,&f,sizeof(f)},{CKA_VERIFY,&t,sizeof(t)},{CKA_EC_PARAMS,(void*)curve,sizeof(curve)-1}};
    CK_ATTRIBUTE privT[]={{CKA_TOKEN,&f,sizeof(f)},{CKA_SIGN,&t,sizeof(t)}};
    CK_OBJECT_HANDLE pub,priv; ck("Gen/EC", C_GenerateKeyPair(h,&gen,pubT,3,privT,2,&pub,&priv));

    CK_MECHANISM mech{CKM_ECDSA_SHA256,nullptr,0};
    std::vector<CK_BYTE> sig(256); CK_ULONG sig_len=sig.size();
    ck("C_SignInit", C_SignInit(h,&mech,priv));
    ck("C_Sign", C_Sign(h,(CK_BYTE_PTR)msg.data(),msg.size(),sig.data(),&sig_len));
    sig.resize(sig_len);
    std::printf("ECDSA sig: %lu bytes\n",(unsigned long)sig_len);

    ck("C_VerifyInit", C_VerifyInit(h,&mech,pub));
    ck("C_Verify", C_Verify(h,(CK_BYTE_PTR)msg.data(),msg.size(),sig.data(),sig_len));
    std::printf("ECDSA verify: OK\n");

    // Tampered message must fail
    std::string bad = msg; bad[0]^=1;
    CK_RV rv = C_VerifyInit(h,&mech,pub);
    if (rv==CKR_OK) rv = C_Verify(h,(CK_BYTE_PTR)bad.data(),bad.size(),sig.data(),sig_len);
    std::printf("ECDSA tampered verify: %s (expected fail)\n", rv==CKR_OK?"UNEXPECTED OK":"correctly rejected");
  }

  // --- RSA PKCS#1 + SHA-256 ---
  {
    CK_MECHANISM gen{CKM_RSA_PKCS_KEY_PAIR_GEN,nullptr,0};
    CK_ULONG bits=2048;
    CK_ATTRIBUTE pubT[]={{CKA_TOKEN,&f,sizeof(f)},{CKA_VERIFY,&t,sizeof(t)}};
    CK_ATTRIBUTE privT[]={{CKA_TOKEN,&f,sizeof(f)},{CKA_SIGN,&t,sizeof(t)},{CKA_MODULUS_BITS,&bits,sizeof(bits)}};
    CK_OBJECT_HANDLE pub,priv; ck("Gen/RSA", C_GenerateKeyPair(h,&gen,pubT,2,privT,3,&pub,&priv));

    CK_MECHANISM mech{CKM_SHA256_RSA_PKCS,nullptr,0};
    std::vector<CK_BYTE> sig(512); CK_ULONG sig_len=sig.size();
    ck("C_SignInit/RSA", C_SignInit(h,&mech,priv));
    ck("C_Sign/RSA", C_Sign(h,(CK_BYTE_PTR)msg.data(),msg.size(),sig.data(),&sig_len));
    sig.resize(sig_len);
    std::printf("RSA sig: %lu bytes\n",(unsigned long)sig_len);
    ck("C_VerifyInit/RSA", C_VerifyInit(h,&mech,pub));
    ck("C_Verify/RSA", C_Verify(h,(CK_BYTE_PTR)msg.data(),msg.size(),sig.data(),sig_len));
    std::printf("RSA verify: OK\n");
  }

  C_Logout(h); C_CloseSession(h); C_Finalize(nullptr);
}
