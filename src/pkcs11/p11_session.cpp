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
  // SessionManager::closeSession destroys the Session object, which owns all
  // per-session operation/find state — nothing global left to clear.
  return g_sessionManager.closeSession(hSession);
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  // SessionManager::closeAllSessions destroys every Session for the slot.
  // Per-session state (op buffers, find results, login state) dies with the
  // Session objects; no parallel global maps to clean up.
  return g_sessionManager.closeAllSessions(slotID);
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
  // Single source of truth: Session::getUserType() (was g_loginState map).
  CK_USER_TYPE ut = s->getUserType();
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
  auto s = p11_get_session(hSession);
  if (!tok || !s)
    return CKR_SESSION_HANDLE_INVALID;

  bool was_locked = (userType == CKU_USER)
                        ? tok->is_user_pin_locked() == CK_TRUE
                        : tok->is_so_pin_locked() == CK_TRUE;
  CK_RV rv =
      tok->login(userType, reinterpret_cast<const CK_CHAR *>(pPin), ulPinLen);
  if (rv == CKR_OK) {
    // Record login on the Session itself (replaces g_loginState map).
    // Token::login already verified the PIN; Session::login just records the
    // userType and derives state_ from it. Pass an empty SecureBuffer since
    // the PIN has been consumed by Token::login.
    SecureBuffer pin_sink(1);
    return s->login(userType, pin_sink);
  }

  // Brute-force protection: when a failed attempt trips the lockout
  // threshold, surface a PIN_LOCKOUT security event (WARN) so operators
  // are immediately aware of a possible PIN brute-force.
  bool now_locked = (userType == CKU_USER)
                        ? tok->is_user_pin_locked() == CK_TRUE
                        : tok->is_so_pin_locked() == CK_TRUE;
  if (!was_locked && now_locked) {
    int slot_id = static_cast<int>(s->getSlotID());
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
  auto s = p11_get_session(hSession);
  if (!tok || !s)
    return CKR_SESSION_HANDLE_INVALID;
  // Single source of truth: read the user type from the Session (was
  // g_loginState). Then token logout + session logout together.
  CK_USER_TYPE ut = s->getUserType();
  CK_RV rv = tok->logout(ut);
  if (rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN) {
    // Clear per-session op/find state too.
    s->logout();
    s->opEnd();
    s->clearFindResults();
    if (rv == CKR_USER_NOT_LOGGED_IN)
      rv = CKR_OK; // idempotent logout is friendlier and matches old behavior
  }
  return rv;
}

} // namespace vhsm::pkcs11
