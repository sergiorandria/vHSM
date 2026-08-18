#include "pkcs11_internal.h"
#include "pkcs11.h"
#include "pkcs11_types.h"

#include <cstring>

namespace vhsm::pkcs11 {

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!phSession) return CKR_ARGUMENTS_BAD;
    if (!p11_get_slot(slotID)) return CKR_SLOT_ID_INVALID;
    return g_sessionManager.openSession(slotID, flags, pApplication, Notify, phSession);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    CK_RV rv = g_sessionManager.closeSession(hSession);
    if (rv == CKR_OK) p11_clear_session_objects(hSession);
    return rv;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    CK_RV rv = g_sessionManager.closeAllSessions(slotID);
    g_objectRegistry.clear();
    g_activeMech.clear();
    g_findResults.clear();
    g_loginState.clear();
    return rv;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    Session* s = p11_get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    std::memset(pInfo, 0, sizeof(CK_SESSION_INFO));
    pInfo->slotID = s->getSlotID();
    pInfo->flags  = s->getFlags();
    CK_USER_TYPE ut = CKU_INVALID;
    auto it = g_loginState.find(hSession);
    if (it != g_loginState.end()) ut = it->second;
    bool rw = (s->getFlags() & CKF_RW_SESSION) != 0;
    if (ut == CKU_USER)       pInfo->state = rw ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    else if (ut == CKU_SO)    pInfo->state = rw ? CKS_RW_SO_FUNCTIONS   : CKS_RO_SO_FUNCTIONS;
    else                      pInfo->state = rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    pInfo->ulDeviceError = 0;
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (userType != CKU_USER && userType != CKU_SO) return CKR_USER_TYPE_INVALID;
    keystore::Token* tok = p11_get_token_for_session(hSession);
    if (!tok) return CKR_SESSION_HANDLE_INVALID;
    CK_RV rv = tok->login(userType, reinterpret_cast<const CK_CHAR*>(pPin), ulPinLen);
    if (rv == CKR_OK) g_loginState[hSession] = userType;
    return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    keystore::Token* tok = p11_get_token_for_session(hSession);
    if (!tok) return CKR_SESSION_HANDLE_INVALID;
    CK_USER_TYPE ut = CKU_USER;
    auto it = g_loginState.find(hSession);
    if (it != g_loginState.end()) ut = it->second;
    CK_RV rv = tok->logout(ut);
    g_loginState.erase(hSession);
    return rv;
}

} // namespace vhsm::pkcs11
