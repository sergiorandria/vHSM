#include "pkcs11.h"
#include "pkcs11_types.h"
#include "pkcs11_internal.h"

#include <cstring>

namespace vhsm::pkcs11 {

namespace {

CK_RV stub_session(CK_SESSION_HANDLE) { return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV stub_opstate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) { return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV stub_setstate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) { return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV stub_mech_init(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) { return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV stub_buf(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV stub_wait(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) { return CKR_FUNCTION_NOT_SUPPORTED; }

} // namespace

static CK_FUNCTION_LIST g_functionList = {
    {2, 40},
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    stub_opstate,                       // C_GetOperationState
    stub_setstate,                      // C_SetOperationState
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    stub_mech_init,                     // C_SignRecoverInit
    stub_buf,                           // C_SignRecover
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    stub_mech_init,                     // C_VerifyRecoverInit
    stub_buf,                           // C_VerifyRecover
    stub_buf,                           // C_DigestEncryptUpdate
    stub_buf,                           // C_DecryptDigestUpdate
    stub_buf,                           // C_SignEncryptUpdate
    stub_buf,                           // C_DecryptVerifyUpdate
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    stub_session,                       // C_GetFunctionStatus
    stub_session,                       // C_CancelFunction
    stub_wait,                          // C_WaitForSlotEvent
};

} // namespace vhsm::pkcs11

extern "C" CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    if (!ppFunctionList) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &vhsm::pkcs11::g_functionList;
    return CKR_OK;
}
