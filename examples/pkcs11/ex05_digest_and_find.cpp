// 05 — Digest (SHA-256/384) and FindObjects
//
//   g++ -std=c++23 examples/pkcs11/05_digest_and_find.cpp -I src -L build -lvhsm_pkcs11 -o /tmp/ex05 && /tmp/ex05

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "pkcs11/pkcs11.h"

static void ck(const char *w, CK_RV rv){ if(rv!=CKR_OK){std::fprintf(stderr,"%s: 0x%08lx\n",w,(unsigned long)rv);std::exit(1);} }
static std::string hex(const std::vector<CK_BYTE>& v){ std::string o; char buf[3]; for(auto b:v){ std::snprintf(buf,sizeof(buf),"%02x",b); o+=buf;} return o; }

int main(){
  ::setenv("VHSM_DB_PATH",":memory:",1);
  ck("C_Initialize",C_Initialize(nullptr));
  CK_SLOT_ID slot; CK_ULONG n=1; ck("C_GetSlotList",C_GetSlotList(CK_TRUE,&slot,&n));
  CK_SESSION_HANDLE h; ck("C_OpenSession",C_OpenSession(slot,CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,0,&h));
  C_InitPIN(h,(CK_UTF8CHAR_PTR)"1234",4); ck("C_Login",C_Login(h,CKU_USER,(CK_UTF8CHAR_PTR)"1234",4));

  // --- SHA digests ---
  const std::string msg="The quick brown fox jumps over the lazy dog";
  for(auto mech_type: {CKM_SHA256, CKM_SHA384}){
    CK_MECHANISM mech{mech_type,nullptr,0};
    std::vector<CK_BYTE> out(64); CK_ULONG out_len=out.size();
    ck("C_DigestInit",C_DigestInit(h,&mech));
    ck("C_Digest",C_Digest(h,(CK_BYTE_PTR)msg.data(),msg.size(),out.data(),&out_len));
    out.resize(out_len);
    std::printf("%s: %s\n", mech_type==CKM_SHA256?"SHA-256":"SHA-384", hex(out).c_str());
  }

  // --- Create a few objects then FindObjects by CKA_LABEL ---
  CK_BBOOL f=CK_FALSE;
  for(int i=0;i<3;++i){
    std::string label="demo-obj-"+std::to_string(i);
    CK_OBJECT_CLASS cls=CKO_DATA;
    CK_ATTRIBUTE tmpl[]={{CKA_CLASS,&cls,sizeof(cls)},{CKA_TOKEN,&f,sizeof(f)},{CKA_LABEL,(void*)label.data(),label.size()},{CKA_VALUE,(void*)label.data(),label.size()}};
    CK_OBJECT_HANDLE o; ck("C_CreateObject",C_CreateObject(h,tmpl,4,&o));
  }
  {
    CK_OBJECT_CLASS cls=CKO_DATA;
    CK_ATTRIBUTE find[]={{CKA_CLASS,&cls,sizeof(cls)}};
    ck("C_FindObjectsInit",C_FindObjectsInit(h,find,1));
    CK_OBJECT_HANDLE found[10]; CK_ULONG cnt=0;
    ck("C_FindObjects",C_FindObjects(h,found,10,&cnt));
    std::printf("FindObjects: %lu data objects\n",(unsigned long)cnt);
    for(CK_ULONG i=0;i<cnt;++i){
      char label[64]={}; CK_ATTRIBUTE a{CKA_LABEL,label,sizeof(label)};
      C_GetAttributeValue(h,found[i],&a,1);
      std::printf("  [%lu] label=%.*s\n",(unsigned long)found[i], (int)a.ulValueLen, label);
    }
    ck("C_FindObjectsFinal",C_FindObjectsFinal(h));
  }

  C_Logout(h); C_CloseSession(h); C_Finalize(nullptr);
}
