#include "session.h"

namespace vhsm::session {

static constexpr CK_OBJECT_HANDLE kInvalidObjectHandle = 0;

Session::Session(CK_SESSION_HANDLE handle, CK_SLOT_ID slotID, CK_FLAGS flags,
                 CK_VOID_PTR pApplication, CK_NOTIFY notify)
    : handle_(handle), slotID_(slotID), flags_(flags),
      state_((flags & CKF_RW_SESSION)
                 ? CKS_RW_PUBLIC_SESSION
                 : CKS_RO_PUBLIC_SESSION) // Start as read-only public session
      ,
      userType_(CKU_INVALID), operationInitialized_(false),
      currentOperationMechanism_(0), activeMech_(0),
      signKey_(0), pApplication_(pApplication),
      notify_(notify) {
  // Constructor implementation
}

Session::~Session() {
  // Destructor - cleanup any ongoing operations
  if (operationInitialized_) {
    operationInitialized_ = false;
  }
}

CK_SESSION_HANDLE Session::getHandle() const noexcept { return handle_; }

CK_SLOT_ID Session::getSlotID() const noexcept { return slotID_; }

CK_FLAGS Session::getFlags() const noexcept { return flags_; }

CK_STATE Session::getState() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return state_;
}

CK_USER_TYPE Session::getUserType() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return userType_;
}

CK_RV Session::login(CK_USER_TYPE userType, const SecureBuffer & /*pin*/) {
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
  // For now, we'll accept any PIN (this would be replaced with actual
  // validation)

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
  // Clear per-operation state
  activeMech_ = 0;
  signKey_ = kInvalidObjectHandle;
  opBuf_.clear();
  opBuf_.shrink_to_fit();
  gcmIv_.clear();
  gcmAad_.clear();
  oaepMgf1_.clear();
  oaepLabel_.clear();
  findHandles_.clear();
  findPos_ = 0;

  return CKR_OK;
}

CK_RV Session::initializeOperation(CK_MECHANISM_TYPE mechanism,
                                   CK_ATTRIBUTE_PTR /*pTemplate*/,
                                   CK_ULONG /*ulCount*/) {
  std::lock_guard<std::mutex> lock(mutex_);

  // Check if we're logged in (user functions) — preserved PKCS#11 semantics.
  if (state_ != CKS_RW_USER_FUNCTIONS && state_ != CKS_RW_SO_FUNCTIONS &&
      state_ != CKS_RO_USER_FUNCTIONS && state_ != CKS_RO_SO_FUNCTIONS) {
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

  // Clear per-operation buffers
  activeMech_ = 0;
  signKey_ = kInvalidObjectHandle;
  opBuf_.clear();
  opBuf_.shrink_to_fit();
  gcmIv_.clear();
  gcmAad_.clear();
  oaepMgf1_.clear();
  oaepLabel_.clear();

  return CKR_OK;
}

// Per-operation state

CK_RV Session::opBegin(CK_MECHANISM_TYPE mech, CK_OBJECT_HANDLE key) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (operationInitialized_) {
    // Already have an active operation via initializeOperation
    // For new path, we use activeMech_/signKey_ directly
    if (activeMech_ != 0) return CKR_OPERATION_ACTIVE;
  }
  activeMech_ = mech;
  signKey_ = key;
  opBuf_.clear();
  return CKR_OK;
}

CK_RV Session::opCheck() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return (activeMech_ == 0) ? CKR_OPERATION_NOT_INITIALIZED : CKR_OK;
}

void Session::opEnd() {
  std::lock_guard<std::mutex> lock(mutex_);
  activeMech_ = 0;
  signKey_ = kInvalidObjectHandle;
  opBuf_.clear();
  opBuf_.shrink_to_fit();
  gcmIv_.clear();
  gcmAad_.clear();
  oaepMgf1_.clear();
  oaepLabel_.clear();
  // Do not clear find state here
}

void Session::opUpdate(const uint8_t *data, size_t len) {
  if (!data || len == 0) return;
  std::lock_guard<std::mutex> lock(mutex_);
  // Single-writer per spec, but we keep lock for queryable state separation
  opBuf_.insert(opBuf_.end(), data, data + len);
}

void Session::opReserve(size_t len) {
  std::lock_guard<std::mutex> lock(mutex_);
  opBuf_.reserve(len);
}

const std::vector<uint8_t> &Session::opBuffer() const noexcept {
  // Per spec, same session not used concurrently for op, so no lock needed
  // for single-reader. But we keep lock for safety if called concurrently.
  // To avoid contention, we return const ref without lock — caller must ensure
  // session affinity (which PKCS#11 guarantees).
  return opBuf_;
}

std::vector<uint8_t> Session::opTakeBuffer() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<uint8_t> out = std::move(opBuf_);
  opBuf_.clear();
  return out;
}

void Session::opClear() noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  opBuf_.clear();
  opBuf_.shrink_to_fit();
}

CK_MECHANISM_TYPE Session::opMech() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return activeMech_;
}

CK_OBJECT_HANDLE Session::opKey() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return signKey_;
}

void Session::setGcmParams(const std::vector<uint8_t> &iv,
                           const std::vector<uint8_t> &aad) {
  std::lock_guard<std::mutex> lock(mutex_);
  gcmIv_ = iv;
  gcmAad_ = aad;
}

const std::vector<uint8_t> &Session::gcmIv() const noexcept {
  return gcmIv_;
}

const std::vector<uint8_t> &Session::gcmAad() const noexcept {
  return gcmAad_;
}

void Session::setOaepParams(const std::string &mgf1,
                            const std::vector<uint8_t> &label) {
  std::lock_guard<std::mutex> lock(mutex_);
  oaepMgf1_ = mgf1;
  oaepLabel_ = label;
}

const std::string &Session::oaepMgf1() const noexcept {
  return oaepMgf1_;
}

const std::vector<uint8_t> &Session::oaepLabel() const noexcept {
  return oaepLabel_;
}

void Session::setFindResults(std::vector<CK_OBJECT_HANDLE> handles) {
  std::lock_guard<std::mutex> lock(mutex_);
  findHandles_ = std::move(handles);
  findPos_ = 0;
  findActive_ = true;
}

bool Session::hasFindResults() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return findPos_ < findHandles_.size();
}

size_t Session::findNextBatch(CK_OBJECT_HANDLE *out, size_t maxCount) {
  std::lock_guard<std::mutex> lock(mutex_);
  size_t n = 0;
  while (findPos_ < findHandles_.size() && n < maxCount) {
    if (out) out[n] = findHandles_[findPos_];
    ++findPos_;
    ++n;
  }
  return n;
}

void Session::clearFindResults() noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  findHandles_.clear();
  findHandles_.shrink_to_fit();
  findPos_ = 0;
  findActive_ = false;
}

vhsm::keystore::internal::v_ObjectStore_M1 &Session::getObjectStore() noexcept {
  return objectStore_;
}

const vhsm::keystore::internal::v_ObjectStore_M1 &
Session::getObjectStore() const noexcept {
  return objectStore_;
}

std::vector<CK_OBJECT_HANDLE> Session::allHandles() const {
  // Enumerate directly from store (replaces g_objectRegistry)
  // We use the store's shared lock to snapshot handles
  auto &store = const_cast<Session*>(this)->getObjectStore();
  // Need to get all handles via v_get_object_count + iteration is O(n)
  // For now, we can use the store's internal table via a new accessor
  // As a fallback, we return empty and let caller use store directly
  // This will be implemented via v_all_handles() in object_store
  return store.v_all_handles();
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
CK_VOID_PTR Session::getApplication() const noexcept { return pApplication_; }

CK_NOTIFY Session::getNotify() const noexcept { return notify_; }

} // namespace vhsm::session
