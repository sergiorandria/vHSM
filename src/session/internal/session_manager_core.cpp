#include "session_manager_core.h"

namespace vhsm::session::internal {

v_SessionManagerCore_M1::v_SessionManagerCore_M1(const IHsmClock &clock)
    : v_next_session_id_(1) // Start from 1, as 0 is typically invalid
      ,
      v_clock_(clock), v_last_op_at_(clock.now()) {}

void v_SessionManagerCore_M1::v_touch_op() noexcept {
  v_last_op_at_ = v_clock_.now();
}

CK_RV v_SessionManagerCore_M1::v_open_session(CK_SLOT_ID slotID, CK_FLAGS flags,
                                              CK_VOID_PTR pApplication,
                                              CK_NOTIFY notify,
                                              CK_SESSION_HANDLE_PTR phSession) {
  std::lock_guard<std::mutex> lock(v_mutex_);

  CK_SESSION_HANDLE hSession = v_next_session_id_++;
  if (hSession == 0) { // Handle wrap-around
    hSession = v_next_session_id_++;
  }

  v_sessions_.emplace_back(
      std::make_shared<Session>(hSession, slotID, flags, pApplication, notify));

  *phSession = hSession;
  v_touch_op();
  return CKR_OK;
}

CK_RV v_SessionManagerCore_M1::v_close_session(CK_SESSION_HANDLE hSession) {
  std::lock_guard<std::mutex> lock(v_mutex_);

  for (auto it = v_sessions_.begin(); it != v_sessions_.end(); ++it) {
    if ((*it)->getHandle() == hSession) {
      it = v_sessions_.erase(it);
      v_touch_op();
      return CKR_OK;
    }
  }

  return CKR_SESSION_HANDLE_INVALID;
}

CK_RV v_SessionManagerCore_M1::v_close_all_sessions(CK_SLOT_ID slotID) {
  std::lock_guard<std::mutex> lock(v_mutex_);

  bool found = false;
  auto it = v_sessions_.begin();
  while (it != v_sessions_.end()) {
    if ((*it)->getSlotID() == slotID) {
      it = v_sessions_.erase(it);
      found = true;
    } else {
      ++it;
    }
  }

  v_touch_op();
  return found ? CKR_OK : CKR_OK; // Return OK even if no sessions were found
}

CK_RV v_SessionManagerCore_M1::v_get_session_info(CK_SESSION_HANDLE hSession,
                                                  CK_SESSION_INFO_PTR pInfo) {
  std::lock_guard<std::mutex> lock(v_mutex_);

  for (const auto &session : v_sessions_) {
    if (session->getHandle() == hSession) {
      session->getSessionInfo(pInfo);
      return CKR_OK;
    }
  }

  return CKR_SESSION_HANDLE_INVALID;
}

std::shared_ptr<Session>
v_SessionManagerCore_M1::v_get_session(CK_SESSION_HANDLE hSession) {
  std::lock_guard<std::mutex> lock(v_mutex_);

  for (auto &session : v_sessions_) {
    if (session->getHandle() == hSession) {
      return session;
    }
  }

  return nullptr;
}

bool v_SessionManagerCore_M1::v_have_session(CK_SLOT_ID slotID) {
  std::lock_guard<std::mutex> lock(v_mutex_);

  for (const auto &session : v_sessions_) {
    if (session->getSlotID() == slotID) {
      return true;
    }
  }

  return false;
}

bool v_SessionManagerCore_M1::v_have_ro_session(CK_SLOT_ID slotID) {
  std::lock_guard<std::mutex> lock(v_mutex_);

  for (const auto &session : v_sessions_) {
    if (session->getSlotID() == slotID &&
        !(session->getFlags() & CKF_RW_SESSION)) { // ← flag, not state
      return true;
    }
  }
  return false;
}

HsmTimePoint v_SessionManagerCore_M1::v_last_op_at() const noexcept {
  return v_last_op_at_;
}

} // namespace vhsm::session::internal
