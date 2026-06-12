#ifndef VHSM_KEYSTORE_TOKEN_H
#define VHSM_KEYSTORE_TOKEN_H

#include "../core/types.h"
#include "hsm_object.h"
#include "object_store.h"

#include <string>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>

namespace vhsm::keystore {

class Token {
public:
    Token(const std::string& label, const std::string& id);
    ~Token();

    // Non-copyable
    Token(const Token&) = delete;
    Token& operator=(const Token&) = delete;

    // Getters
    const std::string& getLabel() const noexcept;
    const std::string& getId() const noexcept;
    CK_ULONG getMaxSessionCount() const noexcept;
    CK_ULONG getSessionCount() const noexcept;
    CK_ULONG getMaxRwSessionCount() const noexcept;
    CK_ULONG getRwSessionCount() const noexcept;
    CK_BBOOL isTokenInitialized() const noexcept;
    CK_BBOOL isUserPinSet() const noexcept;
    CK_BBOOL isSoPinSet() const noexcept;
    CK_BBOOL isUserLoginRequired() const noexcept;
    CK_BBOOL isSoLoginRequired() const noexcept;
    CK_USER_TYPE getLoginState() const noexcept; // Returns CKU_SO or CKU_USER if logged in, else CKU_INVALID

    // Object management
    template<typename T, typename... Args>
    std::pair<CK_OBJECT_HANDLE, T*> createObject(Args&&... args);
    HsmObject* getObject(CK_OBJECT_HANDLE handle);
    const HsmObject* getObject(CK_OBJECT_HANDLE handle) const;
    bool destroyObject(CK_OBJECT_HANDLE handle);

    // PIN management
    CK_RV initializeUserPin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV initializeSoPin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV setUserPin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV setSoPin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV verifyUserPin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV verifySoPin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV changeUserPin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV changeSoPin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV login(CK_USER_TYPE userType, const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV logout(CK_USER_TYPE userType);

    // Session management (delegated to SlotManager, but token tracks counts)
    void incrementSessionCount();
    void decrementSessionCount();
    void incrementRwSessionCount();
    void decrementRwSessionCount();

private:
    std::string label_;
    std::string id_; // Token identifier (CKA_ID)

    // Object store for objects in this token
    ObjectStore object_store_;

    // Session counts
    std::atomic<CK_ULONG> session_count_;
    std::atomic<CK_ULONG> rw_session_count_;

    // Token flags
    std::atomic<CK_BBOOL> token_initialized_;
    std::atomic<CK_BBOOL> user_pin_set_;
    std::atomic<CK_BBOOL> so_pin_set_;
    std::atomic<CK_BBOOL> user_login_required_;
    std::atomic<CK_BBOOL> so_login_required_;

    // Login state (per token, not per session? Actually, login state is per session in PKCS#11.
    // But we can track per token for simplicity, assuming only one session can be logged in at a time?
    // However, PKCS#11 allows multiple sessions to be logged in as the same user.
    // We'll track login state per session in the Session class.
    // So we don't need login state here, just PIN status.

    // PINs (hashed? but for simplicity we store plaintext for now, but should be secure)
    SecureBuffer user_pin_{256};
    SecureBuffer so_pin_{256};
    std::size_t user_pin_len_{0};
    std::size_t so_pin_len_{0};
    std::mutex user_pin_mutex_;
    std::mutex so_pin_mutex_;

    // Mutex for protecting object store and session counts
    mutable std::shared_mutex mutex_;
};

} // namespace vhsm::keystore

#endif // VHSM_KEYSTORE_TOKEN_H