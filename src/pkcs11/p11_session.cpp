#include "pkcs11.h"
#include "pkcs11_internal.h"
#include "pkcs11_types.h"

#include <cstring>
#include <sstream>

namespace vhsm::pkcs11 {

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!phSession)
    return CKR_ARGUMENTS_BAD;
  if (!p11_get_slot(slotID))
    return CKR_SLOT_ID_INVALID;
  return g_sessionManager.openSession(slotID, flags, pApplication, Notify,
                                      phSession);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  CK_RV rv = g_sessionManager.closeSession(hSession);
  if (rv == CKR_OK)
    p11_clear_session_objects(hSession);
  return rv;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  CK_RV rv = g_sessionManager.closeAllSessions(slotID);
  std::lock_guard<std::mutex> lock(g_stateMutex);
  g_objectRegistry.clear();
  g_activeMech.clear();
  g_findResults.clear();
  g_loginState.clear();
  return rv;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  if (!pInfo)
    return CKR_ARGUMENTS_BAD;
  auto s = p11_get_session(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  std::memset(pInfo, 0, sizeof(CK_SESSION_INFO));
  pInfo->slotID = s->getSlotID();
  pInfo->flags = s->getFlags();
  CK_USER_TYPE ut = CKU_INVALID;
  {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    auto it = g_loginState.find(hSession);
    if (it != g_loginState.end())
      ut = it->second;
  }
  bool rw = (s->getFlags() & CKF_RW_SESSION) != 0;
  if (ut == CKU_USER)
    pInfo->state = rw ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
  else if (ut == CKU_SO)
    pInfo->state = rw ? CKS_RW_SO_FUNCTIONS : CKS_RO_SO_FUNCTIONS;
  else
    pInfo->state = rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
  pInfo->ulDeviceError = 0;
  return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (userType != CKU_USER && userType != CKU_SO)
    return CKR_USER_TYPE_INVALID;
  keystore::Token *tok = p11_get_token_for_session(hSession);
  if (!tok)
    return CKR_SESSION_HANDLE_INVALID;

  bool was_locked = (userType == CKU_USER)
                        ? tok->is_user_pin_locked() == CK_TRUE
                        : tok->is_so_pin_locked() == CK_TRUE;
  CK_RV rv =
      tok->login(userType, reinterpret_cast<const CK_CHAR *>(pPin), ulPinLen);
  if (rv == CKR_OK) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_loginState[hSession] = userType;
    return CKR_OK;
  }

  // Brute-force protection: when a failed attempt trips the lockout
  // threshold, surface a PIN_LOCKOUT security event (WARN) so operators
  // are immediately aware of a possible PIN brute-force.
  bool now_locked = (userType == CKU_USER)
                        ? tok->is_user_pin_locked() == CK_TRUE
                        : tok->is_so_pin_locked() == CK_TRUE;
  if (!was_locked && now_locked) {
    auto s = p11_get_session(hSession);
    int slot_id = s ? static_cast<int>(s->getSlotID()) : 0;
    std::stringstream detail_ss;
    detail_ss << R"({"user_type":")"
              << (userType == CKU_USER ? "CKU_USER" : "CKU_SO")
              << R"(","max_attempts":)" << tok->max_pin_attempts() << R"(})";
    p11_publish_event(
        vhsm::notification::NotificationEvent::EventType::PIN_LOCKOUT,
        vhsm::notification::NotificationEvent::Severity::WARNING, slot_id,
        tok->get_label(), "token:" + tok->get_id(),
        "PIN lockout: " + std::string(userType == CKU_USER ? "user" : "SO") +
            " PIN locked after " + std::to_string(tok->max_pin_attempts()) +
            " failed attempts",
        detail_ss.str(), std::nullopt, "C_Login");
  }
  return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  keystore::Token *tok = p11_get_token_for_session(hSession);
  if (!tok)
    return CKR_SESSION_HANDLE_INVALID;
  CK_USER_TYPE ut = CKU_USER;
  {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    auto it = g_loginState.find(hSession);
    if (it != g_loginState.end())
      ut = it->second;
  }
  CK_RV rv = tok->logout(ut);
  {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_loginState.erase(hSession);
  }
  return rv;
}

} // namespace vhsm::pkcs11
