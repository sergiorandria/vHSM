#ifndef VHSM_SESSION_SESSION_H
#define VHSM_SESSION_SESSION_H

#include "../core/secure_buffer.h"
#include "../core/types.h"
#include "../keystore/object_store.h"
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace vhsm::session {

// WHY Session represents a PKCS#11 session: In PKCS#11, a "session" is a
// stateful connection between an application and a token. Sessions track login
// state, current operations, and per-session attributes. Multiple sessions can
// exist on the same token (different login states, different operations in
// parallel). Each session has its own object visibility scope (a private key
// created in one session may be visible to another, depending on token
// settings).
//
// WHY each Session has its own ObjectStore: Object stores are per-session in
// this design. Applications can create/find/destroy objects within a session.
// The store enforces isolation and visibility rules. If a different design were
// needed (shared object store across sessions), the ObjectStore could be moved
// to Token; for now, it's session-private.
//
// WHY non-copyable due to mutex: Each Session has a unique mutex protecting its
// state. Copying would duplicate the mutex, violating synchronization semantics
// (two copies with separate locks could race). Non-copyable enforces single
// ownership.
class Session {
public:
  // WHY constructor takes explicit parameters: Session identity is fixed at
  // creation (handle, slotID, flags, notify callback). All are PKCS#11
  // semantics provided by the caller (SessionManager). Explicit parameters make
  // the contract clear.
  Session(CK_SESSION_HANDLE handle, CK_SLOT_ID slotID, CK_FLAGS flags,
          CK_VOID_PTR pApplication, CK_NOTIFY notify);

  ~Session();

  // WHY non-copyable and non-movable: Sessions are stateful (login state,
  // operation state, object store). Copying/moving would create confusing
  // duplicates. Sessions should be managed via pointers or references (by
  // SessionManager).
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;

  // WHY separate getters for each field: PKCS#11 C_GetSessionInfo requires
  // returning all session attributes. Separate getters allow callers to query
  // individual fields efficiently. [[nodiscard]] catches accidental misuse.
  [[nodiscard]] CK_SESSION_HANDLE getHandle() const noexcept;
  [[nodiscard]] CK_SLOT_ID getSlotID() const noexcept;
  [[nodiscard]] CK_FLAGS getFlags() const noexcept;
  [[nodiscard]] CK_STATE getState() const noexcept;
  [[nodiscard]] CK_USER_TYPE getUserType() const noexcept;

  // WHY separate state transition methods: PKCS#11 session state machine has
  // explicit transitions (login → logout, initialize operation → finalize
  // operation). Separate methods make state changes explicit and allow
  // validation (can't finalize an uninitialized operation). This prevents logic
  // bugs.
  //
  // WHY login/logout take userType and PIN: Login state depends on who is
  // logged in (CKU_USER vs CKU_SO) and whether the PIN is correct. The PIN is
  // sensitive, so it's wrapped in SecureBuffer (zeroed after use).
  CK_RV login(CK_USER_TYPE userType, const SecureBuffer &pin);
  CK_RV logout();

  // WHY initializeOperation / finalizeOperation: PKCS#11 requires initializing
  // an operation (select mechanism, pass parameters) before performing
  // sign/encrypt/verify/decrypt. Finalizing closes the operation and clears
  // state. This prevents accidental reuse of operation state across multiple
  // operations.
  CK_RV initializeOperation(CK_MECHANISM_TYPE mechanism,
                            CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
  CK_RV finalizeOperation();

  // Per-operation state (migrated from global g_stateMutex maps)
  // These replace g_activeMech, g_opBuf, g_signKey, g_gcmIv, etc.
  // Each Session now owns its own operation state, so cross-session
  // contention is zero (per spec, same session not used concurrently).
  CK_RV opBegin(CK_MECHANISM_TYPE mech, CK_OBJECT_HANDLE key);
  CK_RV opCheck() const;
  void opEnd();

  // Operation buffer: zero-copy access for multi-part ops
  // Previously g_opBuf[h] was copied under global lock. Now Session owns
  // the buffer and callers can move or access by const ref without copy.
  void opUpdate(const uint8_t *data, size_t len);
  void opReserve(size_t len); // hint for reserve at Init time
  [[nodiscard]] const std::vector<uint8_t> &opBuffer() const noexcept;
  [[nodiscard]] std::vector<uint8_t> opTakeBuffer(); // move out exactly once at Final
  void opClear() noexcept;

  // Mechanism and key for current operation
  [[nodiscard]] CK_MECHANISM_TYPE opMech() const noexcept;
  [[nodiscard]] CK_OBJECT_HANDLE opKey() const noexcept;

  // GCM / OAEP params (previously g_gcmIv, g_gcmAad, g_oaepMgf1, g_oaepLabel)
  void setGcmParams(const std::vector<uint8_t> &iv, const std::vector<uint8_t> &aad);
  [[nodiscard]] const std::vector<uint8_t> &gcmIv() const noexcept;
  [[nodiscard]] const std::vector<uint8_t> &gcmAad() const noexcept;
  void setOaepParams(const std::string &mgf1, const std::vector<uint8_t> &label);
  [[nodiscard]] const std::string &oaepMgf1() const noexcept;
  [[nodiscard]] const std::vector<uint8_t> &oaepLabel() const noexcept;

  // Find results (previously g_findResults)
  void setFindResults(std::vector<CK_OBJECT_HANDLE> handles);
  [[nodiscard]] bool hasFindResults() const noexcept;
  // True between FindInit and FindFinal — used for CKR_OPERATION_ACTIVE.
  void setFindActive(bool active) noexcept { findActive_ = active; }
  [[nodiscard]] bool findActive() const noexcept { return findActive_; }
  // Returns next batch and advances pos; O(1) vs old vector::erase O(n)
  size_t findNextBatch(CK_OBJECT_HANDLE *out, size_t maxCount);
  void clearFindResults() noexcept;

  // WHY getObjectStore is mutable and const: Sessions need to access (and
  // modify) the object store to create/find/destroy objects. Both const and
  // non-const versions allow callers to work with mutable or immutable
  // sessions. The mutex protects concurrent access.
  [[nodiscard]] vhsm::keystore::internal::v_ObjectStore_M1 &
  getObjectStore() noexcept;
  [[nodiscard]] const vhsm::keystore::internal::v_ObjectStore_M1 &
  getObjectStore() const noexcept;

  // Enumerate all handles in this session's store (replaces g_objectRegistry)
  [[nodiscard]] std::vector<CK_OBJECT_HANDLE> allHandles() const;

  // WHY getSessionInfo populates a pointer: PKCS#11 C_GetSessionInfo uses the
  // caller's CK_SESSION_INFO struct. This method fills it with all session
  // attributes at once, avoiding multiple round-trips to query individual
  // fields.
  void getSessionInfo(CK_SESSION_INFO_PTR pInfo) const;

  // WHY separate accessors for notify callback: The application and notify
  // callback are PKCS#11 semantics that stay unchanged after session creation.
  // Accessors allow SessionManager to pass them to the original caller (for
  // event notification).
  CK_VOID_PTR getApplication() const noexcept;
  CK_NOTIFY getNotify() const noexcept;

private:
  // WHY handle_ is unique: CK_SESSION_HANDLE is the session's opaque
  // identifier. Callers use handles (not pointers) to refer to sessions. The
  // SessionManager maps handles to Session objects. Immutable after creation
  // ensures handle stability.
  CK_SESSION_HANDLE handle_;

  // WHY slotID_ is immutable: Sessions are bound to a specific slot (token). A
  // session can't migrate to a different slot. This is enforced by making
  // slotID_ private and set-once in the constructor.
  CK_SLOT_ID slotID_;

  // WHY flags_ are immutable: Session flags (CKF_RW_SESSION,
  // CKF_SERIAL_SESSION) are set at creation and don't change. They define
  // whether the session is read-only, whether multiple simultaneous operations
  // are allowed, etc.
  CK_FLAGS flags_;

  // WHY state_ is mutable: Session state (public, user functions, SO functions)
  // changes via login/logout. The state determines which operations are allowed
  // (e.g., SO functions only available to the SO user, in SO session state).
  CK_STATE state_;

  // WHY userType_ tracks login identity: When logged in, this field holds
  // CKU_USER or CKU_SO (the user type). When not logged in, it's set to
  // CKU_INVALID. Guides operation authorization (some operations require a
  // specific user type).
  CK_USER_TYPE userType_;

  vhsm::keystore::internal::v_ObjectStore_M1 objectStore_;

  // WHY operationInitialized_ and currentOperationMechanism_: Track the current
  // operation state. Once an operation is initialized (e.g., C_SignInit), these
  // fields track what's active. Prevents accidental mixing of operations (can't
  // call C_Encrypt while a sign operation is initialized).
  bool operationInitialized_;
  CK_MECHANISM_TYPE currentOperationMechanism_;

  // Per-operation state (migrated from global maps)
  CK_MECHANISM_TYPE activeMech_{0};
  CK_OBJECT_HANDLE signKey_{0};
  std::vector<uint8_t> opBuf_;
  std::vector<uint8_t> gcmIv_;
  std::vector<uint8_t> gcmAad_;
  std::string oaepMgf1_;
  std::vector<uint8_t> oaepLabel_;

  // Find results per session (replaces g_findResults)
  std::vector<CK_OBJECT_HANDLE> findHandles_;
  size_t findPos_{0};
  bool findActive_{false};

  // WHY pApplication_ and notify_: PKCS#11 callback mechanism. Applications
  // register a callback (notify_) to receive events (e.g., "token inserted").
  // pApplication_ is context data passed to the callback. These are stored but
  // rarely used in simple HSM implementations; included for API compliance.
  CK_VOID_PTR pApplication_;
  CK_NOTIFY notify_;

  // WHY mutable mutex_: Protects all session state from concurrent access.
  // mutable allows const methods (like getHandle()) to lock (for consistency
  // checks or future logging). In practice, const methods often don't need the
  // lock, but the pattern is safe.
  // Note: per spec, same session is not used concurrently for op state
  // (C_SignUpdate etc.), so opBuf_ etc. could be lock-free, but we keep the
  // mutex for queryable state (state_/userType_ via C_GetSessionInfo).
  mutable std::mutex mutex_;
};

} // namespace vhsm::session

#endif // VHSM_SESSION_SESSION_H
