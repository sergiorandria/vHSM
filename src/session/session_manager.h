#ifndef VHSM_SESSION_SESSION_MANAGER_H
#define VHSM_SESSION_SESSION_MANAGER_H

#include "../core/system_hsm_clock.h"
#include "../domain/core/kernel_types.h"
#include "../domain/pkcs11/pkcs11_types.h"
#include "internal/session_manager_core.h"
#include "session.h"

#include <atomic>
#include <list>
#include <memory>
#include <mutex>

namespace vhsm::session {

// WHY SessionManager is a public facade: PKCS#11 is a C API; SessionManager
// bridges from C (raw pointers, error codes) to C++ (exceptions, smart
// pointers, RAII). This layer validates raw CK_* inputs (null checks, slot ID
// bounds) and delegates all business logic to v_SessionManagerCore_M1. Same
// pattern as Token/keystore: separate input validation (facade) from state
// management (core).
//
// WHY sessions are stored in a registry (not returned as pointers): PKCS#11
// uses opaque handles (CK_SESSION_HANDLE). Callers get a handle, pass it back
// to C_GetSessionInfo, C_Login, etc. The SessionManager maps handles to Session
// objects internally. This pattern prevents accidental use-after-free (if a
// session is deleted, its handle becomes invalid and can't be accidentally
// reused).
//
// WHY SystemHsmClock is injected: Tests can inject FrozenHsmClock for
// deterministic timing. Session timeouts and operation deadlines depend on
// wall-clock time. Dependency injection allows testing time-dependent logic
// without real delays.

class SessionManager {
public:
  SessionManager();
  ~SessionManager();

  // WHY openSession validates and delegates: Input validation (CK_* types,
  // bounds checks) happens here. The core handles session creation, registry
  // management, and handle allocation. This separation keeps the facade thin
  // and the core focused. Open a new session. Validates raw CK_* inputs, then
  // delegates to the internal core that owns the session registry.
  [[nodiscard]] CK_RV openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession);

  // WHY closeSession takes a handle (not a Session*): Callers don't have
  // Session pointers; they have handles. The manager looks up the handle in its
  // registry and deletes the session. If the handle is invalid, closeSession
  // returns an error (CKR_SESSION_HANDLE_INVALID).
  [[nodiscard]] CK_RV closeSession(CK_SESSION_HANDLE hSession);

  // WHY closeAllSessions per-slot: A slot may have multiple open sessions
  // (read-only and read-write). Closing all at once is useful for cleanup when
  // a token is removed or the library is finalized. The manager iterates over
  // sessions for this slotID and closes each.
  [[nodiscard]] CK_RV closeAllSessions(CK_SLOT_ID slotID);

  // WHY getSessionInfo populates a CK_SESSION_INFO_PTR: PKCS#11 API pattern.
  // The caller allocates a struct; we fill it with all session attributes.
  // Avoids returning a complex struct (which doesn't port well to C).
  [[nodiscard]] CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);

  // WHY getSession returns shared_ptr<Session>: Internal callers (C_Sign,
  // C_GetAttributeValue) need to work with the session. Returning shared_ptr
  // avoids use-after-free: the caller's reference keeps the Session alive even
  // if another thread closes the session (closing only erases the manager's
  // ref).
  std::shared_ptr<Session> getSession(CK_SESSION_HANDLE hSession);

  // WHY haveSession checks for any session on a slot: Some operations require
  // at least one session to be open on a slot (e.g., token operations).
  // haveSession lets callers quickly check without iterating.
  bool haveSession(CK_SLOT_ID slotID);

  // WHY haveROSession specifically: Some operations are only valid in read-only
  // sessions. haveROSession lets callers check for at least one read-only
  // session without iteration.
  bool haveROSession(CK_SLOT_ID slotID);

private:
  // WHY SystemHsmClock: Injected for testability. Production uses system time;
  // tests can freeze time.
  vhsm::SystemHsmClock v_clock_;

  // WHY v_core_ owns the registry: All session state, locking, and handle
  // allocation logic lives in the core. The manager is a thin validation layer.
  vhsm::session::internal::v_SessionManagerCore_M1 v_core_;
};

} // namespace vhsm::session

#endif
