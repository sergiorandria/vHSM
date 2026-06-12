#include "session.h"

namespace vhsm::session {

Session::Session(CK_SESSION_HANDLE handle, CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify)
    : handle_(handle)
    , slotID_(slotID)
    , flags_(flags)
    , state_((flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION)  // Start as read-only public session
    , userType_(CKU_INVALID)
    , operationInitialized_(false)
    , currentOperationMechanism_(0)
    , pApplication_(pApplication)
    , notify_(notify)
{
    // Constructor implementation
}

Session::~Session() {
    // Destructor - cleanup any ongoing operations
    if (operationInitialized_) {
        // In a real implementation, we would finalize the operation
        operationInitialized_ = false;
    }
}

CK_SESSION_HANDLE Session::getHandle() const noexcept {
    return handle_;
}

CK_SLOT_ID Session::getSlotID() const noexcept {
    return slotID_;
}

CK_FLAGS Session::getFlags() const noexcept {
    return flags_;
}

CK_STATE Session::getState() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

CK_USER_TYPE Session::getUserType() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return userType_;
}

CK_RV Session::login(CK_USER_TYPE userType, const SecureBuffer& /*pin*/) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if we're already logged in
    if (state_ == CKS_RW_USER_FUNCTIONS || state_ == CKS_RW_SO_FUNCTIONS ||
        state_ == CKS_RO_USER_FUNCTIONS || state_ == CKS_RO_SO_FUNCTIONS) {
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    // Validate user type
    if (userType != CKU_USER && userType != CKU_SO) {
        return CKR_USER_TYPE_INVALID;
    }

    // In a real implementation, we would validate the PIN against the token
    // For now, we'll accept any PIN (this would be replaced with actual validation)

    // Set the user type and update state based on session flags
    userType_ = userType;
    bool isReadWriteSession = (flags_ & CKF_RW_SESSION) != 0;

    if (userType == CKU_SO) {
        state_ = isReadWriteSession ? CKS_RW_SO_FUNCTIONS : CKS_RO_SO_FUNCTIONS;
    } else { // CKU_USER
        state_ = isReadWriteSession ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    }

    return CKR_OK;
}

CK_RV Session::logout() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if we're logged in
    if (state_ == CKS_RO_PUBLIC_SESSION || state_ == CKS_RW_PUBLIC_SESSION) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    // Reset session state
    userType_ = CKU_INVALID;

    // Reset to public session state based on flags
    if (flags_ & CKF_RW_SESSION) {
        state_ = CKS_RW_PUBLIC_SESSION;
    } else {
        state_ = CKS_RO_PUBLIC_SESSION;
    }

    // Finalize any ongoing operation
    if (operationInitialized_) {
        operationInitialized_ = false;
        currentOperationMechanism_ = 0;
    }

    return CKR_OK;
}

CK_RV Session::initializeOperation(CK_MECHANISM_TYPE mechanism, CK_ATTRIBUTE_PTR /*pTemplate*/, CK_ULONG /*ulCount*/) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if we're logged in (user functions)
    if (state_ != CKS_RW_USER_FUNCTIONS && state_ != CKS_RW_SO_FUNCTIONS) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    // Check if an operation is already initialized
    if (operationInitialized_) {
        return CKR_OPERATION_ACTIVE;
    }

    // In a real implementation, we would validate the mechanism and template
    // For now, we'll just store the mechanism and mark as initialized

    operationInitialized_ = true;
    currentOperationMechanism_ = mechanism;

    return CKR_OK;
}

CK_RV Session::finalizeOperation() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if an operation is initialized
    if (!operationInitialized_) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    // Reset operation state
    operationInitialized_ = false;
    currentOperationMechanism_ = 0;

    return CKR_OK;
}

vhsm::keystore::ObjectStore& Session::getObjectStore() noexcept {
    return objectStore_;
}

const vhsm::keystore::ObjectStore& Session::getObjectStore() const noexcept {
    return objectStore_;
}

void Session::getSessionInfo(CK_SESSION_INFO_PTR pInfo) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (pInfo == nullptr) {
        return;
    }

    // Fill in the session info according to PKCS#11 spec
    pInfo->slotID = slotID_;
    pInfo->state = state_;
    pInfo->flags = flags_;

    // Note: In a real implementation, we would have a device error state
    pInfo->ulDeviceError = 0;
}

// Notify callback accessors
CK_VOID_PTR Session::getApplication() const noexcept {
    return pApplication_;
}

CK_NOTIFY Session::getNotify() const noexcept {
    return notify_;
}

} // namespace vhsm::session