#include "token.h"
#include "../core/utils.h"

namespace vhsm::keystore {

Token::Token(const std::string& label, const std::string& id)
    : label_(label)
    , id_(id)
    , session_count_(0)
    , rw_session_count_(0)
    , token_initialized_(CK_FALSE)
    , user_pin_set_(CK_FALSE)
    , so_pin_set_(CK_FALSE)
    , user_login_required_(CK_TRUE)
    , so_login_required_(CK_TRUE)
{
    // Initialize object store
}

Token::~Token() {
    // Zero out PINs
    user_pin_.wipe();
    so_pin_.wipe();
}

const std::string& Token::getLabel() const noexcept {
    return label_;
}

const std::string& Token::getId() const noexcept {
    return id_;
}

CK_ULONG Token::getMaxSessionCount() const noexcept {
    // For simplicity, we'll return a large number
    return 1024;
}

CK_ULONG Token::getSessionCount() const noexcept {
    return session_count_.load();
}

CK_ULONG Token::getMaxRwSessionCount() const noexcept {
    return 1024;
}

CK_ULONG Token::getRwSessionCount() const noexcept {
    return rw_session_count_.load();
}

CK_BBOOL Token::isTokenInitialized() const noexcept {
    return token_initialized_.load();
}

CK_BBOOL Token::isUserPinSet() const noexcept {
    return user_pin_set_.load();
}

CK_BBOOL Token::isSoPinSet() const noexcept {
    return so_pin_set_.load();
}

CK_BBOOL Token::isUserLoginRequired() const noexcept {
    return user_login_required_.load();
}

CK_BBOOL Token::isSoLoginRequired() const noexcept {
    return so_login_required_.load();
}

CK_USER_TYPE Token::getLoginState() const noexcept {
    // This is not really per token, but per session. We'll return CKU_INVALID as placeholder.
    return CKU_INVALID;
}

// Object management
template<typename T, typename... Args>
std::pair<CK_OBJECT_HANDLE, T*> Token::createObject(Args&&... args) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return object_store_.createObject<T>(std::forward<Args>(args)...);
}

HsmObject* Token::getObject(CK_OBJECT_HANDLE handle) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return object_store_.getObject(handle);
}

const HsmObject* Token::getObject(CK_OBJECT_HANDLE handle) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return object_store_.getObject(handle);
}

bool Token::destroyObject(CK_OBJECT_HANDLE handle) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return object_store_.destroyObject(handle);
}

// PIN management
CK_RV Token::initializeUserPin(const CK_CHAR* pin, CK_ULONG pinLen) {
    std::lock_guard<std::mutex> lock(user_pin_mutex_);
    if (user_pin_set_.load() == CK_TRUE) {
        return CKR_USER_PIN_ALREADY_INITIALIZED;
    }
    user_pin_.write(sizeof(decltype(pin[0])), pin, pinLen);
    user_pin_set_.store(CK_TRUE);
    return CKR_OK;
}

CK_RV Token::initializeSoPin(const CK_CHAR* pin, CK_ULONG pinLen) {
    std::lock_guard<std::mutex> lock(so_pin_mutex_);
    if (so_pin_set_.load() == CK_TRUE) {
        return CKR_SO_PIN_ALREADY_INITIALIZED;
    }
    so_pin_.write(sizeof(decltype(pin[0])), pin, pinLen);
    so_pin_set_.store(CK_TRUE);
    return CKR_OK;
}

CK_RV Token::setUserPin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    std::lock_guard<std::mutex> lock(user_pin_mutex_);
    if (user_pin_set_.load() == CK_FALSE) {
        return CKR_USER_PIN_NOT_INITIALIZED;
    }
    // Verify old PIN
    if (oldLen != user_pin_.size() || std::memcmp(oldPin, user_pin_.data(), oldLen) != 0) {
        return CKR_PIN_INCORRECT;
    }
    // Set new PIN
    user_pin_.write(sizeof(decltype(newPin[0])), newPin, newLen);
    return CKR_OK;
}

CK_RV Token::setSoPin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    std::lock_guard<std::mutex> lock(so_pin_mutex_);
    if (so_pin_set_.load() == CK_FALSE) {
        return CKR_SO_PIN_NOT_INITIALIZED;
    }
    // Verify old PIN
    if (oldLen != so_pin_.size() || std::memcmp(oldPin, so_pin_.data(), oldLen) != 0) {
        return CKR_PIN_INCORRECT;
    }
    // Set new PIN
    so_pin_.write(sizeof(decltype(newPin[0])), newPin, newLen);
    return CKR_OK;
}

CK_RV Token::verifyUserPin(const CK_CHAR* pin, CK_ULONG pinLen) {
    std::lock_guard<std::mutex> lock(user_pin_mutex_);
    if (user_pin_set_.load() == CK_FALSE) {
        return CKR_USER_PIN_NOT_INITIALIZED;
    }
    if (pinLen != user_pin_.size() || std::memcmp(pin, user_pin_.data(), pinLen) != 0) {
        return CKR_PIN_INCORRECT;
    }
    return CKR_OK;
}

CK_RV Token::verifySoPin(const CK_CHAR* pin, CK_ULONG pinLen) {
    std::lock_guard<std::mutex> lock(so_pin_mutex_);
    if (so_pin_set_.load() == CK_FALSE) {
        return CKR_SO_PIN_NOT_INITIALIZED;
    }
    if (pinLen != so_pin_.size() || std::memcmp(pin, so_pin_.data(), pinLen) != 0) {
        return CKR_PIN_INCORRECT;
    }
    return CKR_OK;
}

CK_RV Token::changeUserPin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    return setUserPin(oldPin, oldLen, newPin, newLen);
}

CK_RV Token::changeSoPin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    return setSoPin(oldPin, oldLen, newPin, newLen);
}

CK_RV Token::login(CK_USER_TYPE userType, const CK_CHAR* pin, CK_ULONG pinLen) {
    // In a real implementation, we would update the session's login state.
    // For now, we just verify the PIN and return success.
    // The actual login state is tracked per session.
    if (userType == CKU_USER) {
        return verifyUserPin(pin, pinLen);
    } else if (userType == CKU_SO) {
        return verifySoPin(pin, pinLen);
    }
    return CKR_USER_TYPE_INVALID;
}

CK_RV Token::logout(CK_USER_TYPE userType) {
    // Invalidate the session's login state.
    // Again, actual state is per session.
    if (userType == CKU_USER || userType == CKU_SO) {
        // Nothing to do here, session will handle it.
        return CKR_OK;
    }
    return CKR_USER_TYPE_INVALID;
}

void Token::incrementSessionCount() {
    session_count_.fetch_add(1);
}

void Token::decrementSessionCount() {
    if (session_count_.load() > 0) {
        session_count_.fetch_sub(1);
    }
}

void Token::incrementRwSessionCount() {
    rw_session_count_.fetch_add(1);
}

void Token::decrementRwSessionCount() {
    if (rw_session_count_.load() > 0) {
        rw_session_count_.fetch_sub(1);
    }
}

// Explicit instantiation for common object types if needed
// We'll keep the template in the header for now.

} // namespace vhsm::keystore