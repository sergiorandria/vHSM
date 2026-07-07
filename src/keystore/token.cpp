#include "token.h"
#include "../keystore/attribute_store.h"
#include "../keystore/hsm_object.h"

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
    // Zero out PINs.
    //
    // NOTE: these wipes are not protected by user_pin_mutex_ / so_pin_mutex_.
    // This is safe ONLY under the invariant that no other thread can be
    // inside verifyUserPin/setUserPin/etc. while ~Token() runs — i.e. the
    // Token must already be unreachable (last shared_ptr reference dropped,
    // no live Session holds a raw pointer to it). This invariant is enforced
    // by SlotManager/SessionManager lifetime rules and is NOT re-checked here.
    // If that ever changes, these wipes must be moved under the respective
    // mutexes.
    user_pin_.wipe();
    so_pin_.wipe();
}

const std::string& Token::get_label() const noexcept {
    return label_;
}

const std::string& Token::get_id() const noexcept {
    return id_;
}

CK_ULONG Token::get_max_session_count() const noexcept {
    // For simplicity, we'll return a large number
    return 1024;
}

CK_ULONG Token::get_session_count() const noexcept {
    return session_count_.load();
}

CK_ULONG Token::get_max_rw_session_count() const noexcept {
    return 1024;
}

CK_ULONG Token::get_rw_session_count() const noexcept {
    return rw_session_count_.load();
}

CK_BBOOL Token::is_token_initialized() const noexcept {
    return token_initialized_.load();
}

CK_BBOOL Token::is_user_pin_set() const noexcept {
    return user_pin_set_.load();
}

CK_BBOOL Token::is_so_pin_set() const noexcept {
    return so_pin_set_.load();
}

CK_BBOOL Token::is_user_login_required() const noexcept {
    return user_login_required_.load();
}

CK_BBOOL Token::is_so_login_required() const noexcept {
    return so_login_required_.load();
}

// NOTE: getLoginState() removed — see token.h for rationale. Login state is
// tracked per-Session, not per-Token.

HsmObject* Token::get_object(CK_OBJECT_HANDLE handle) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return object_store_.getObject(handle);
}

const HsmObject* Token::get_object(CK_OBJECT_HANDLE handle) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return object_store_.getObject(handle);
}

bool Token::destroy_object(CK_OBJECT_HANDLE handle) {
    // destroyObject MUTATES object_store_ (frees a slot). ObjectStore itself
    // is internally synchronized (its own std::mutex), but — same rationale
    // as createObject() in token.h — we take a unique_lock here for
    // forward-compatibility and to make the "this is a write" intent explicit.
    std::unique_lock<std::shared_mutex> lock(mutex_);
    return object_store_.destroyObject(handle);
}

std::vector<std::uint8_t> Token::get_kek() const {
    // Find an object with label "KEK" and type CKO_SECRET_KEY
    auto result = object_store_.find_object_if([&](HsmObject* obj) {
        AttributeStore attr_store(*obj);
        // Get label
        std::vector<u8> label_value;
        CK_ULONG label_len = 0;
        CK_RV rv = attr_store.getAttribute(CKA_LABEL, nullptr, &label_len);
        if (rv != CKR_OK) {
            return false;
        }

        label_value.resize(label_len);
        rv = attr_store.getAttribute(CKA_LABEL, label_value.data(), &label_len);
        if (rv != CKR_OK) {
            return false;
        }

        std::string obj_label(reinterpret_cast<char*>(label_value.data()), label_len);
        if (obj_label != "KEK"){
            return false;
        }

        // Optionally check class is CKO_SECRET_KEY
        // Get CKA_CLASS
        std::vector<u8> class_value;
        CK_ULONG class_len = 0;
        rv = attr_store.getAttribute(CKA_CLASS, nullptr, &class_len);
        if (rv != CKR_OK) {
            return false;
        }

        class_value.resize(class_len);
        rv = attr_store.getAttribute(CKA_CLASS, class_value.data(), &class_len);
        if (rv != CKR_OK) {
            return false;
        }

        if (class_value.size() != sizeof(CK_ULONG)) {
            return false;
        }

        CK_ULONG obj_class = 0;
        std::memcpy(&obj_class, class_value.data(), sizeof(CK_ULONG));
        if (obj_class != CKO_SECRET_KEY) {
            return false;
        }
        
        return true;
    });
    if (!result.second) {
        return {};
    }
    // Now extract the CKA_VALUE attribute
    AttributeStore attr_store(*result.second);
    std::vector<u8> key_value;
    CK_ULONG key_len = 0;
    CK_RV rv = attr_store.getAttribute(CKA_VALUE, nullptr, &key_len);
    if (rv != CKR_OK) return {};
    key_value.resize(key_len);
    rv = attr_store.getAttribute(CKA_VALUE, key_value.data(), &key_len);
    if (rv != CKR_OK) return {};
    return key_value;
}

bool Token::secure_pin_equals(const SecureBuffer& stored,
                               std::size_t stored_len,
                               const CK_CHAR* candidate,
                               CK_ULONG candidate_len) noexcept {
    // Constant-time comparison: always compare up to the larger of the two
    // lengths (capped at the stored buffer's capacity) so that timing does
    // not leak the length of the stored PIN or where the first mismatching
    // byte occurs.
    //
    // Strategy:
    //  - Compute a length-mismatch flag (non-zero if stored_len != candidate_len).
    //  - Byte-compare over `stored.byte_size()` bytes regardless of candidate_len,
    //    treating out-of-range candidate bytes as 0. This keeps the loop length
    //    constant (== capacity), independent of either input length.
    //  - OR all per-byte differences and the length-mismatch flag together.

    const u8* stored_data = stored.data();
    const std::size_t capacity = stored.byte_size();

    unsigned char diff = static_cast<unsigned char>(
        (stored_len != static_cast<std::size_t>(candidate_len)) ? 1 : 0);

    for (std::size_t i = 0; i < capacity; ++i) {
        unsigned char candidate_byte = 0;
        if (i < static_cast<std::size_t>(candidate_len)) {
            candidate_byte = static_cast<unsigned char>(candidate[i]);
        }
        unsigned char stored_byte =
            (i < stored_len) ? static_cast<unsigned char>(stored_data[i]) : 0;

        diff |= static_cast<unsigned char>(stored_byte ^ candidate_byte);
    }

    return diff == 0;
}

CK_RV Token::initialize_user_pin(const CK_CHAR* pin, CK_ULONG pinLen) {
    std::lock_guard<std::mutex> lock(user_pin_mutex_);
    if (user_pin_set_.load() == CK_TRUE) {
        return CKR_USER_PIN_ALREADY_INITIALIZED;
    }
    if (static_cast<std::size_t>(pinLen) > user_pin_.byte_size()) {
        return CKR_PIN_LEN_RANGE;
    }
    // FIX: previously wrote at offset = sizeof(CK_CHAR) (i.e. offset 1),
    // which shifted the PIN by one byte and left byte 0 untouched/garbage.
    // The PIN must start at offset 0.
    user_pin_.write(0, reinterpret_cast<const u8*>(pin), pinLen);
    user_pin_len_ = pinLen;
    user_pin_set_.store(CK_TRUE);
    return CKR_OK;
}

CK_RV Token::initialize_so_pin(const CK_CHAR* pin, CK_ULONG pinLen) {
    std::lock_guard<std::mutex> lock(so_pin_mutex_);
    if (so_pin_set_.load() == CK_TRUE) {
        return CKR_SO_PIN_ALREADY_INITIALIZED;
    }
    if (static_cast<std::size_t>(pinLen) > so_pin_.byte_size()) {
        return CKR_PIN_LEN_RANGE;
    }
    so_pin_.write(0, reinterpret_cast<const u8*>(pin), pinLen);
    so_pin_len_ = pinLen;
    so_pin_set_.store(CK_TRUE);
    return CKR_OK;
}

CK_RV Token::set_user_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    std::lock_guard<std::mutex> lock(user_pin_mutex_);
    if (user_pin_set_.load() == CK_FALSE) {
        return CKR_USER_PIN_NOT_INITIALIZED;
    }
    // FIX: compare against user_pin_len_ (actual stored length), not
    // user_pin_.size() (== 256, the buffer capacity). The old check
    // `oldLen != user_pin_.size()` would reject every real PIN.
    // Also use a constant-time comparison.
    if (!secure_pin_equals(user_pin_, user_pin_len_, oldPin, oldLen)) {
        return CKR_PIN_INCORRECT;
    }
    if (static_cast<std::size_t>(newLen) > user_pin_.byte_size()) {
        return CKR_PIN_LEN_RANGE;
    }
    user_pin_.write(0, reinterpret_cast<const u8*>(newPin), newLen);
    user_pin_len_ = newLen;
    return CKR_OK;
}

CK_RV Token::set_so_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    std::lock_guard<std::mutex> lock(so_pin_mutex_);
    if (so_pin_set_.load() == CK_FALSE) {
        return CKR_SO_PIN_NOT_INITIALIZED;
    }
    if (!secure_pin_equals(so_pin_, so_pin_len_, oldPin, oldLen)) {
        return CKR_PIN_INCORRECT;
    }
    if (static_cast<std::size_t>(newLen) > so_pin_.byte_size()) {
        return CKR_PIN_LEN_RANGE;
    }
    so_pin_.write(0, reinterpret_cast<const u8*>(newPin), newLen);
    so_pin_len_ = newLen;
    return CKR_OK;
}

CK_RV Token::verify_user_pin(const CK_CHAR* pin, CK_ULONG pinLen) {
    std::lock_guard<std::mutex> lock(user_pin_mutex_);
    if (user_pin_set_.load() == CK_FALSE) {
        return CKR_USER_PIN_NOT_INITIALIZED;
    }
    if (!secure_pin_equals(user_pin_, user_pin_len_, pin, pinLen)) {
        return CKR_PIN_INCORRECT;
    }
    return CKR_OK;
}

CK_RV Token::verify_so_pin(const CK_CHAR* pin, CK_ULONG pinLen) {
    std::lock_guard<std::mutex> lock(so_pin_mutex_);
    if (so_pin_set_.load() == CK_FALSE) {
        return CKR_SO_PIN_NOT_INITIALIZED;
    }
    if (!secure_pin_equals(so_pin_, so_pin_len_, pin, pinLen)) {
        return CKR_PIN_INCORRECT;
    }
    return CKR_OK;
}

CK_RV Token::change_user_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    return set_user_pin(oldPin, oldLen, newPin, newLen);
}

CK_RV Token::change_so_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    return set_so_pin(oldPin, oldLen, newPin, newLen);
}

CK_RV Token::login(CK_USER_TYPE userType, const CK_CHAR* pin, CK_ULONG pinLen) {
    // Token::login() only VERIFIES the PIN. Recording "this session is now
    // logged in as USER/SO" is the Session's responsibility — PKCS#11 allows
    // multiple sessions with independent login states, so that state cannot
    // live here.
    if (userType == CKU_USER) {
        return verify_user_pin(pin, pinLen);
    } else if (userType == CKU_SO) {
        return verify_so_pin(pin, pinLen);
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

void Token::increment_session_count() {
    session_count_.fetch_add(1);
}

void Token::decrement_session_count() {
    if (session_count_.load() > 0) {
        session_count_.fetch_sub(1);
    }
}

void Token::increment_rw_session_count() {
    rw_session_count_.fetch_add(1);
}

void Token::decrement_rw_session_count() {
    if (rw_session_count_.load() > 0) {
        rw_session_count_.fetch_sub(1);
    }
}

} // namespace vhsm::keystore