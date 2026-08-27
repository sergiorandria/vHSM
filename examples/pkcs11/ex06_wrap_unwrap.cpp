// 06 — Wrap / Unwrap (AES key wrapped by RSA)
//
//   g++ -std=c++23 examples/pkcs11/06_wrap_unwrap.cpp -I src -L build -lvhsm_pkcs11 -o /tmp/ex06 && /tmp/ex06

#include <cstdio>
#include <cstdlib>
#include <vector>

#include "pkcs11/pkcs11.h"

static void ck(const char *w, CK_RV rv){ if(rv!=CKR_OK){std::fprintf(stderr,"%s: 0x%08lx\n",w,(unsigned long)rv);std::exit(1);} }

int main(){
  ::setenv("VHSM_DB_PATH",":memory:",1);
  ck("C_Initialize",C_Initialize(nullptr));
  CK_SLOT_ID slot; CK_ULONG n=1; ck("C_GetSlotList",C_GetSlotList(CK_TRUE,&slot,&n));
  CK_SESSION_HANDLE h; ck("C_OpenSession",C_OpenSession(slot,CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,0,&h));
  C_InitPIN(h,(CK_UTF8CHAR_PTR)"1234",4); ck("C_Login",C_Login(h,CKU_USER,(CK_UTF8CHAR_PTR)"1234",4));

  CK_BBOOL t=CK_TRUE,f=CK_FALSE;

  // Wrapping RSA key
  CK_MECHANISM gen{CKM_RSA_PKCS_KEY_PAIR_GEN,nullptr,0};
  CK_ULONG bits=2048;
  CK_ATTRIBUTE wrapPubT[]={{CKA_TOKEN,&f,sizeof(f)},{CKA_WRAP,&t,sizeof(t)}};
  CK_ATTRIBUTE wrapPrivT[]={{CKA_TOKEN,&f,sizeof(f)},{CKA_UNWRAP,&t,sizeof(t)},{CKA_MODULUS_BITS,&bits,sizeof(bits)}};
  CK_OBJECT_HANDLE wrapPub,wrapPriv;
  ck("Gen/wrapping",C_GenerateKeyPair(h,&gen,wrapPubT,2,wrapPrivT,3,&wrapPub,&wrapPriv));
  std::printf("wrapping key: pub=%lu priv=%lu\n",(unsigned long)wrapPub,(unsigned long)wrapPriv);

  // AES key to be wrapped
  CK_MECHANISM aesGen{CKM_AES_KEY_GEN,nullptr,0};
  CK_ULONG key_len=32;
  CK_ATTRIBUTE aesTmpl[]={{CKA_TOKEN,&f,sizeof(f)},{CKA_ENCRYPT,&t,sizeof(t)},{CKA_DECRYPT,&t,sizeof(t)},{CKA_VALUE_LEN,&key_len,sizeof(key_len)},{CKA_EXTRACTABLE,&t,sizeof(t)}};
  CK_OBJECT_HANDLE aes;
  CK_RV rv = C_GenerateKey(h,&aesGen,aesTmpl,5,&aes);
  if(rv!=CKR_OK){ std::printf("AES keygen not available: 0x%lx\n",(unsigned long)rv); C_Finalize(nullptr); return 0; }
  std::printf("AES key: %lu\n",(unsigned long)aes);

  // Wrap with RSA PKCS#1 v1.5
  CK_MECHANISM wrapMech{CKM_RSA_PKCS,nullptr,0};
  std::vector<CK_BYTE> wrapped(512); CK_ULONG wrapped_len=wrapped.size();
  ck("C_WrapKey",C_WrapKey(h,&wrapMech,wrapPub,aes,wrapped.data(),&wrapped_len));
  wrapped.resize(wrapped_len);
  std::printf("wrapped: %lu bytes\n",(unsigned long)wrapped_len);

  // Destroy original, unwrap
  ck("C_DestroyObject/AES",C_DestroyObject(h,aes));
  CK_OBJECT_CLASS cls=CKO_SECRET_KEY; CK_KEY_TYPE ktype=CKK_AES;
  CK_ATTRIBUTE unwrapTmpl[]={{CKA_CLASS,&cls,sizeof(cls)},{CKA_KEY_TYPE,&ktype,sizeof(ktype)},{CKA_TOKEN,&f,sizeof(f)},{CKA_ENCRYPT,&t,sizeof(t)},{CKA_DECRYPT,&t,sizeof(t)}};
  CK_OBJECT_HANDLE unwrapped;
  ck("C_UnwrapKey",C_UnwrapKey(h,&wrapMech,wrapPriv,wrapped.data(),wrapped.size(),unwrapTmpl,5,&unwrapped));
  std::printf("unwrapped: %lu (round-trip OK)\n",(unsigned long)unwrapped);

  C_Logout(h); C_CloseSession(h); C_Finalize(nullptr);
}
