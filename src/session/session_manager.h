#ifndef VHSM_SESSION_SESSION_MANAGER_H
#define VHSM_SESSION_SESSION_MANAGER_H

#include "session.h"
#include "../core/types.h"
#include <list>
#include <mutex>
#include <atomic>

namespace vhsm::session {

class SessionManager {
public:
    SessionManager();
    ~SessionManager();

    // Open a new session
    CK_RV openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                     CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession);

    // Close an existing session
    CK_RV closeSession(CK_SESSION_HANDLE hSession);

    // Close all sessions for a slot
    CK_RV closeAllSessions(CK_SLOT_ID slotID);

    // Get information about a session
    CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);

    // Get a session pointer by handle
    Session* getSession(CK_SESSION_HANDLE hSession);

    // Check if slot has any sessions
    bool haveSession(CK_SLOT_ID slotID);

    // Check if slot has any read-only sessions
    bool haveROSession(CK_SLOT_ID slotID);

private:
    std::list<Session> sessions_;
    std::mutex mutex_;
    std::atomic<CK_SESSION_HANDLE> nextSessionId_;  // For generating unique session handles
};

} // namespace vhsm::session

#endif