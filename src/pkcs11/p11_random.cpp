#include "pkcs11.h"
#include "pkcs11_internal.h"
#include "pkcs11_types.h"

#include "../crypto/SecureRNG.h"

extern "C" {
namespace vhsm::pkcs11 {

namespace {
vhsm::crypto::SecureRNG g_rng;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                   CK_ULONG ulSeedLen) {
  (void)hSession;
  if (!pSeed && ulSeedLen > 0)
    return CKR_ARGUMENTS_BAD;
  return CKR_OK;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData,
                       CK_ULONG ulRandomLen) {
  (void)hSession;
  if (!RandomData)
    return CKR_ARGUMENTS_BAD;
  if (ulRandomLen == 0)
    return CKR_OK;
  try {
    g_rng.bytes(RandomData, ulRandomLen);
  } catch (...) {
    return CKR_GENERAL_ERROR;
  }
  return CKR_OK;
}

} // namespace vhsm::pkcs11
} // extern "C"
