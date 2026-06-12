#include "session_manager.h"
#include "../core/utils.h"

namespace vhsm::session {

SessionManager::SessionManager()
    : nextSessionId_(1)  // Start from 1, as 0 is typically invalid
{
    // Constructor implementation will go here
    // could initialize any necessary resources if needed in the future
}

SessionManager::~SessionManager() {
    // Destructor - close all open sessions
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.clear();
}

CK_RV SessionManager::openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                                CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession) {
    // Validate parameters
    if (phSession == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }

    // Check if flags are valid
    if ((flags & ~(CKF_RW_SESSION | CKF_SERIAL_SESSION)) != 0) {
        return CKR_ARGUMENTS_BAD;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Generate a unique session handle
    CK_SESSION_HANDLE hSession = nextSessionId_++;
    if (hSession == 0) {  // Handle wrap-around
        hSession = nextSessionId_++;
    }

    // Create the session object
    sessions_.emplace_back(hSession, slotID, flags, pApplication, notify);
    //Session& session = sessions_.back();

    // Return the session handle
    *phSession = hSession;

    return CKR_OK;
}

CK_RV SessionManager::closeSession(CK_SESSION_HANDLE hSession) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Find the session with the given handle
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it->getHandle() == hSession) {
            // Remove the session
            it = sessions_.erase(it);
            return CKR_OK;
        }
    }

    // Session not found
    return CKR_SESSION_HANDLE_INVALID;
}

CK_RV SessionManager::closeAllSessions(CK_SLOT_ID slotID) {
    std::lock_guard<std::mutex> lock(mutex_);

    bool found = false;
    auto it = sessions_.begin();
    while (it != sessions_.end()) {
        if (it->getSlotID() == slotID) {
            it = sessions_.erase(it);
            found = true;
        } else {
            ++it;
        }
    }

    return found ? CKR_OK : CKR_OK;  // Return OK even if no sessions were found
}

CK_RV SessionManager::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    if (pInfo == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Find the session with the given handle
    for (const auto& session : sessions_) {
        if (session.getHandle() == hSession) {
            session.getSessionInfo(pInfo);
            return CKR_OK;
        }
    }

    // Session not found
    return CKR_SESSION_HANDLE_INVALID;
}

Session* SessionManager::getSession(CK_SESSION_HANDLE hSession) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Find the session with the given handle
    for (auto& session : sessions_) {
        if (session.getHandle() == hSession) {
            return &session;
        }
    }

    // Session not found
    return nullptr;
}

bool SessionManager::haveSession(CK_SLOT_ID slotID) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if there are any sessions for the given slot
    for (const auto& session : sessions_) {
        if (session.getSlotID() == slotID) {
            return true;
        }
    }

    return false;
}

bool SessionManager::haveROSession(CK_SLOT_ID slotID) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& session : sessions_) {
        if (session.getSlotID() == slotID &&
            !(session.getFlags() & CKF_RW_SESSION)) {  // ← flag, not state
            return true;
        }
    }
    return false;
}

} // namespace vhsm::session