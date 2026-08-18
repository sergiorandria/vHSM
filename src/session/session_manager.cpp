#include "session_manager.h"

namespace vhsm::session {

SessionManager::SessionManager()
    : v_clock_()
    , v_core_(v_clock_)
{
}

SessionManager::~SessionManager() = default;

CK_RV SessionManager::openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                                  CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession) {
    // --- Public API input validation (GLIBC-style: fail fast on bad args) ---
    if (phSession == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }

    // Check if flags are valid (only CKF_RW_SESSION | CKF_SERIAL_SESSION allowed).
    if ((flags & ~(CKF_RW_SESSION | CKF_SERIAL_SESSION)) != 0) {
        return CKR_ARGUMENTS_BAD;
    }

    return v_core_.v_open_session(slotID, flags, pApplication, notify, phSession);
}

CK_RV SessionManager::closeSession(CK_SESSION_HANDLE hSession) {
    return v_core_.v_close_session(hSession);
}

CK_RV SessionManager::closeAllSessions(CK_SLOT_ID slotID) {
    return v_core_.v_close_all_sessions(slotID);
}

CK_RV SessionManager::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    if (pInfo == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    return v_core_.v_get_session_info(hSession, pInfo);
}

Session* SessionManager::getSession(CK_SESSION_HANDLE hSession) {
    return v_core_.v_get_session(hSession);
}

bool SessionManager::haveSession(CK_SLOT_ID slotID) {
    return v_core_.v_have_session(slotID);
}

bool SessionManager::haveROSession(CK_SLOT_ID slotID) {
    return v_core_.v_have_ro_session(slotID);
}

} // namespace vhsm::session
