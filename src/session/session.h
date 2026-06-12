#ifndef VHSM_SESSION_SESSION_H
#define VHSM_SESSION_SESSION_H

#include "../core/types.h"
#include "../keystore/object_store.h"
#include "../core/secure_buffer.h"
#include <mutex>

namespace vhsm::session {

class Session {
public:
    // Constructor
    Session(CK_SESSION_HANDLE handle, CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify);

    // Destructor
    ~Session();

    // Non-copyable and non-movable due to mutex
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // Getters
    [[nodiscard]] CK_SESSION_HANDLE getHandle() const noexcept;
    [[nodiscard]] CK_SLOT_ID getSlotID() const noexcept;
    [[nodiscard]] CK_FLAGS getFlags() const noexcept;
    [[nodiscard]] CK_STATE getState() const noexcept;
    [[nodiscard]] CK_USER_TYPE getUserType() const noexcept;

    // State transitions
    CK_RV login(CK_USER_TYPE userType, const SecureBuffer& pin);
    CK_RV logout();
    CK_RV initializeOperation(CK_MECHANISM_TYPE mechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV finalizeOperation();

    // Object store access
    [[nodiscard]] vhsm::keystore::ObjectStore& getObjectStore() noexcept;
    [[nodiscard]] const vhsm::keystore::ObjectStore& getObjectStore() const noexcept;

    // Session info (for C_GetSessionInfo)
    void getSessionInfo(CK_SESSION_INFO_PTR pInfo) const;

    // Notify callback accessors
    CK_VOID_PTR getApplication() const noexcept;
    CK_NOTIFY getNotify() const noexcept;

private:
    // Session handle (unique identifier)
    CK_SESSION_HANDLE handle_;

    // Associated slot
    CK_SLOT_ID slotID_;

    // Session flags (from CKF_* constants)
    CK_FLAGS flags_;

    // Current session state
    CK_STATE state_;

    // User type if logged in (CKU_USER or CKU_SO)
    CK_USER_TYPE userType_;

    // Object store for this session
    vhsm::keystore::ObjectStore objectStore_;

    // Operation state
    bool operationInitialized_;
    CK_MECHANISM_TYPE currentOperationMechanism_;

    // Application pointer and notify callback
    CK_VOID_PTR pApplication_;
    CK_NOTIFY notify_;

    // Mutex for thread safety
    mutable std::mutex mutex_;
};

} // namespace vhsm::session

#endif // VHSM_SESSION_SESSION_H