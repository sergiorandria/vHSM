#ifndef VHSM_SESSION_INTERNAL_SESSION_MANAGER_CORE_H
#define VHSM_SESSION_INTERNAL_SESSION_MANAGER_CORE_H

#include "../../core/hsm_clock.h"
#include "../session.h"

#include <atomic>
#include <cstdint>
#include <list>
#include <mutex>

namespace vhsm::session::internal {

// Internal business-logic core for SessionManager.
//
// Owns the live session registry and all session lifecycle / query logic.
// The public vhsm::session::SessionManager is a thin GLIBC-style facade that
// validates raw CK_* inputs and forwards here.
//
// Time is supplied via an injected IHsmClock so the behaviour is deterministic
// and unit-testable with a FrozenHsmClock (see v_last_op_at()).
class v_SessionManagerCore_M1 {
public:
    explicit v_SessionManagerCore_M1(const IHsmClock& clock);
    ~v_SessionManagerCore_M1() = default;

    v_SessionManagerCore_M1(const v_SessionManagerCore_M1&) = delete;
    v_SessionManagerCore_M1& operator=(const v_SessionManagerCore_M1&) = delete;

    CK_RV v_open_session(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                         CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession);

    CK_RV v_close_session(CK_SESSION_HANDLE hSession);

    CK_RV v_close_all_sessions(CK_SLOT_ID slotID);

    CK_RV v_get_session_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);

    Session* v_get_session(CK_SESSION_HANDLE hSession);

    bool v_have_session(CK_SLOT_ID slotID);

    bool v_have_ro_session(CK_SLOT_ID slotID);

    // Timestamp (wall-clock via injected IHsmClock) of the last session op.
    HsmTimePoint v_last_op_at() const noexcept;

private:
    void v_touch_op() noexcept;

    std::list<Session> v_sessions_;
    std::mutex v_mutex_;
    std::atomic<CK_SESSION_HANDLE> v_next_session_id_;

    const IHsmClock& v_clock_;
    HsmTimePoint v_last_op_at_;
};

} // namespace vhsm::session::internal

#endif // VHSM_SESSION_INTERNAL_SESSION_MANAGER_CORE_H
