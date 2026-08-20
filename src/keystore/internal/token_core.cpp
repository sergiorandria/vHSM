#include "token_core.h"

#include <cstring>

namespace vhsm::keystore::internal {

v_TokenCore_M1::v_TokenCore_M1(const std::string &label, const std::string &id,
                               const IHsmClock &clock)
    : v_label_(label), v_id_(id), v_session_count_(0), v_rw_session_count_(0),
      v_token_initialized_(CK_FALSE), v_user_pin_set_(CK_FALSE),
      v_so_pin_set_(CK_FALSE), v_user_login_required_(CK_TRUE),
      v_so_login_required_(CK_TRUE), v_clock_(clock),
      v_last_pin_op_at_(clock.now()) {}

v_TokenCore_M1::~v_TokenCore_M1() {
  // Zero out PINs. See Token::~Token() rationale: this is safe only because
  // the Token is already unreachable when its core is destroyed.
  v_user_pin_.wipe();
  v_so_pin_.wipe();
}

const std::string &v_TokenCore_M1::v_get_label() const noexcept {
  return v_label_;
}

const std::string &v_TokenCore_M1::v_get_id() const noexcept { return v_id_; }

CK_ULONG v_TokenCore_M1::v_get_max_session_count() const noexcept {
  return 1024;
}

CK_ULONG v_TokenCore_M1::v_get_session_count() const noexcept {
  return v_session_count_.load();
}

CK_ULONG v_TokenCore_M1::v_get_max_rw_session_count() const noexcept {
  return 1024;
}

CK_ULONG v_TokenCore_M1::v_get_rw_session_count() const noexcept {
  return v_rw_session_count_.load();
}

CK_BBOOL v_TokenCore_M1::v_is_token_initialized() const noexcept {
  return v_token_initialized_.load();
}

CK_BBOOL v_TokenCore_M1::v_is_user_pin_set() const noexcept {
  return v_user_pin_set_.load();
}

CK_BBOOL v_TokenCore_M1::v_is_so_pin_set() const noexcept {
  return v_so_pin_set_.load();
}

CK_BBOOL v_TokenCore_M1::v_is_user_login_required() const noexcept {
  return v_user_login_required_.load();
}

CK_BBOOL v_TokenCore_M1::v_is_so_login_required() const noexcept {
  return v_so_login_required_.load();
}

std::shared_ptr<HsmObject>
v_TokenCore_M1::v_get_object(CK_OBJECT_HANDLE handle) {
  std::shared_lock<std::shared_mutex> lock(v_mutex_);
  return v_object_store_.v_get_object(handle);
}

std::shared_ptr<const HsmObject>
v_TokenCore_M1::v_get_object(CK_OBJECT_HANDLE handle) const {
  std::shared_lock<std::shared_mutex> lock(v_mutex_);
  return v_object_store_.v_get_object(handle);
}

bool v_TokenCore_M1::v_destroy_object(CK_OBJECT_HANDLE handle) {
  std::unique_lock<std::shared_mutex> lock(v_mutex_);
  return v_object_store_.v_destroy_object(handle);
}

std::vector<std::uint8_t> v_TokenCore_M1::v_get_kek() const {
  auto result = v_object_store_.v_find_object_if([&](HsmObject *obj) {
    v_AttributeStore_M1 attr_store(*obj);
    std::vector<u8> label_value;
    CK_ULONG label_len = 0;
    CK_RV rv = attr_store.v_get_attribute(CKA_LABEL, nullptr, &label_len);
    if (rv != CKR_OK)
      return false;
    label_value.resize(label_len);
    rv = attr_store.v_get_attribute(CKA_LABEL, label_value.data(), &label_len);
    if (rv != CKR_OK)
      return false;

    std::string obj_label(reinterpret_cast<char *>(label_value.data()),
                          label_len);
    if (obj_label != "KEK")
      return false;

    std::vector<u8> class_value;
    CK_ULONG class_len = 0;
    rv = attr_store.v_get_attribute(CKA_CLASS, nullptr, &class_len);
    if (rv != CKR_OK)
      return false;
    class_value.resize(class_len);
    rv = attr_store.v_get_attribute(CKA_CLASS, class_value.data(), &class_len);
    if (rv != CKR_OK)
      return false;
    if (class_value.size() != sizeof(CK_ULONG))
      return false;

    CK_ULONG obj_class = 0;
    std::memcpy(&obj_class, class_value.data(), sizeof(CK_ULONG));
    if (obj_class != CKO_SECRET_KEY)
      return false;
    return true;
  });
  if (!result.second)
    return {};

  v_AttributeStore_M1 attr_store(*result.second);
  std::vector<u8> key_value;
  CK_ULONG key_len = 0;
  CK_RV rv = attr_store.v_get_attribute(CKA_VALUE, nullptr, &key_len);
  if (rv != CKR_OK)
    return {};
  key_value.resize(key_len);
  rv = attr_store.v_get_attribute(CKA_VALUE, key_value.data(), &key_len);
  if (rv != CKR_OK)
    return {};
  return key_value;
}

void v_TokenCore_M1::v_restore_state(
    CK_BBOOL token_initialized, CK_BBOOL user_pin_set, CK_BBOOL so_pin_set,
    CK_BBOOL user_login_required, CK_BBOOL so_login_required,
    unsigned max_failed_attempts, unsigned user_failed_attempts,
    unsigned so_failed_attempts, CK_BBOOL user_pin_locked,
    CK_BBOOL so_pin_locked, const std::vector<std::uint8_t> &kek) {
  // The KEK is single-writer state: hold the shared_mutex during the object
  // store mutation to serialize against concurrent wrap/unwrap attempts.
  std::unique_lock<std::shared_mutex> lock(v_mutex_);

  v_token_initialized_.store(token_initialized);
  v_user_pin_set_.store(user_pin_set);
  v_so_pin_set_.store(so_pin_set);
  v_user_login_required_.store(user_login_required);
  v_so_login_required_.store(so_login_required);
  v_max_failed_attempts_.store(max_failed_attempts);
  v_user_failed_attempts_.store(user_failed_attempts);
  v_so_failed_attempts_.store(so_failed_attempts);
  v_user_pin_locked_.store(user_pin_locked);
  v_so_pin_locked_.store(so_pin_locked);

  // Re-create the KEK as a SECRET_KEY object labelled "KEK" — the exact shape
  // v_get_kek() looks for (CKA_LABEL, CKA_CLASS + CKA_VALUE).  If one exists
  // already (e.g. a fresh token that generated a KEK before restore), replace
  // it so the restored key wins.
  auto existing = v_object_store_.v_find_object_if([](HsmObject *obj) {
    v_AttributeStore_M1 attr_store(*obj);
    std::vector<u8> label_value;
    CK_ULONG label_len = 0;
    if (attr_store.v_get_attribute(CKA_LABEL, nullptr, &label_len) != CKR_OK)
      return false;
    label_value.resize(label_len);
    if (attr_store.v_get_attribute(CKA_LABEL, label_value.data(), &label_len) !=
        CKR_OK)
      return false;
    std::string obj_label(reinterpret_cast<char *>(label_value.data()),
                          label_len);
    return obj_label == "KEK";
  });
  if (existing.second) {
    v_object_store_.v_destroy_object(existing.first);
  }
  if (!kek.empty()) {
    auto [handle, obj] = v_object_store_.v_create_object<HsmObject>(
        ObjectType::SECRET_KEY, /*sensitive=*/false, /*extractable=*/true,
        /*token=*/false, /*private=*/false);
    (void)handle;
    const CK_ULONG cls = CKO_SECRET_KEY;
    obj->setAttribute(CKA_CLASS, reinterpret_cast<const u8 *>(&cls),
                      sizeof(cls));
    const u8 label_str[] = {'K', 'E', 'K'};
    obj->setAttribute(CKA_LABEL, label_str, sizeof(label_str));
    obj->setAttribute(CKA_VALUE, kek.data(), kek.size());
  }
}

bool v_TokenCore_M1::v_secure_pin_equals(const SecureBuffer &stored,
                                         std::size_t stored_len,
                                         const CK_CHAR *candidate,
                                         CK_ULONG candidate_len) noexcept {
  const u8 *stored_data = stored.data();
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

void v_TokenCore_M1::v_touch_pin_op() noexcept {
  v_last_pin_op_at_ = v_clock_.now();
}

HsmTimePoint v_TokenCore_M1::v_last_pin_op_at() const noexcept {
  return v_last_pin_op_at_;
}

CK_RV v_TokenCore_M1::v_initialize_user_pin(const CK_CHAR *pin,
                                            CK_ULONG pinLen) {
  v_touch_pin_op();
  std::lock_guard<std::mutex> lock(v_user_pin_mutex_);
  if (v_user_pin_set_.load() == CK_TRUE) {
    return CKR_USER_PIN_ALREADY_INITIALIZED;
  }
  if (static_cast<std::size_t>(pinLen) > v_user_pin_.byte_size()) {
    return CKR_PIN_LEN_RANGE;
  }
  v_user_pin_.write(0, reinterpret_cast<const u8 *>(pin), pinLen);
  v_user_pin_len_ = pinLen;
  v_user_pin_set_.store(CK_TRUE);
  v_user_failed_attempts_.store(0);
  v_user_pin_locked_.store(CK_FALSE);
  return CKR_OK;
}

CK_RV v_TokenCore_M1::v_initialize_so_pin(const CK_CHAR *pin, CK_ULONG pinLen) {
  v_touch_pin_op();
  std::lock_guard<std::mutex> lock(v_so_pin_mutex_);
  if (v_so_pin_set_.load() == CK_TRUE) {
    return CKR_SO_PIN_ALREADY_INITIALIZED;
  }
  if (static_cast<std::size_t>(pinLen) > v_so_pin_.byte_size()) {
    return CKR_PIN_LEN_RANGE;
  }
  v_so_pin_.write(0, reinterpret_cast<const u8 *>(pin), pinLen);
  v_so_pin_len_ = pinLen;
  v_so_pin_set_.store(CK_TRUE);
  v_so_failed_attempts_.store(0);
  v_so_pin_locked_.store(CK_FALSE);
  return CKR_OK;
}

CK_RV v_TokenCore_M1::v_set_user_pin(const CK_CHAR *oldPin, CK_ULONG oldLen,
                                     const CK_CHAR *newPin, CK_ULONG newLen) {
  v_touch_pin_op();
  std::lock_guard<std::mutex> lock(v_user_pin_mutex_);
  if (v_user_pin_set_.load() == CK_FALSE) {
    return CKR_USER_PIN_NOT_INITIALIZED;
  }
  if (!v_secure_pin_equals(v_user_pin_, v_user_pin_len_, oldPin, oldLen)) {
    return CKR_PIN_INCORRECT;
  }
  if (static_cast<std::size_t>(newLen) > v_user_pin_.byte_size()) {
    return CKR_PIN_LEN_RANGE;
  }
  v_user_pin_.write(0, reinterpret_cast<const u8 *>(newPin), newLen);
  v_user_pin_len_ = newLen;
  v_user_failed_attempts_.store(0);
  v_user_pin_locked_.store(CK_FALSE);
  return CKR_OK;
}

CK_RV v_TokenCore_M1::v_set_so_pin(const CK_CHAR *oldPin, CK_ULONG oldLen,
                                   const CK_CHAR *newPin, CK_ULONG newLen) {
  v_touch_pin_op();
  std::lock_guard<std::mutex> lock(v_so_pin_mutex_);
  if (v_so_pin_set_.load() == CK_FALSE) {
    return CKR_SO_PIN_NOT_INITIALIZED;
  }
  if (!v_secure_pin_equals(v_so_pin_, v_so_pin_len_, oldPin, oldLen)) {
    return CKR_PIN_INCORRECT;
  }
  if (static_cast<std::size_t>(newLen) > v_so_pin_.byte_size()) {
    return CKR_PIN_LEN_RANGE;
  }
  v_so_pin_.write(0, reinterpret_cast<const u8 *>(newPin), newLen);
  v_so_pin_len_ = newLen;
  v_so_failed_attempts_.store(0);
  v_so_pin_locked_.store(CK_FALSE);
  return CKR_OK;
}

CK_RV v_TokenCore_M1::v_verify_pin_with_lockout(
    const SecureBuffer &stored, std::size_t stored_len,
    const CK_CHAR *candidate, CK_ULONG candidate_len, CK_BBOOL pin_set,
    CK_RV not_initialized_rv, unsigned max_attempts,
    std::atomic<unsigned> &counter, std::atomic<CK_BBOOL> &locked,
    std::mutex &mutex) {
  std::lock_guard<std::mutex> lock(mutex);
  if (locked.load() == CK_TRUE) {
    return CKR_PIN_LOCKED;
  }
  if (pin_set == CK_FALSE) {
    return not_initialized_rv;
  }
  if (!v_secure_pin_equals(stored, stored_len, candidate, candidate_len)) {
    unsigned n = counter.load() + 1;
    counter.store(n);
    if (n >= max_attempts) {
      locked.store(CK_TRUE);
      return CKR_PIN_LOCKED;
    }
    return CKR_PIN_INCORRECT;
  }
  counter.store(0);
  locked.store(CK_FALSE);
  return CKR_OK;
}

CK_RV v_TokenCore_M1::v_verify_user_pin(const CK_CHAR *pin, CK_ULONG pinLen) {
  v_touch_pin_op();
  return v_verify_pin_with_lockout(
      v_user_pin_, v_user_pin_len_, pin, pinLen, v_user_pin_set_.load(),
      CKR_USER_PIN_NOT_INITIALIZED, v_max_failed_attempts_.load(),
      v_user_failed_attempts_, v_user_pin_locked_, v_user_pin_mutex_);
}

CK_RV v_TokenCore_M1::v_verify_so_pin(const CK_CHAR *pin, CK_ULONG pinLen) {
  v_touch_pin_op();
  return v_verify_pin_with_lockout(
      v_so_pin_, v_so_pin_len_, pin, pinLen, v_so_pin_set_.load(),
      CKR_SO_PIN_NOT_INITIALIZED, v_max_failed_attempts_.load(),
      v_so_failed_attempts_, v_so_pin_locked_, v_so_pin_mutex_);
}

CK_RV v_TokenCore_M1::v_change_user_pin(const CK_CHAR *oldPin, CK_ULONG oldLen,
                                        const CK_CHAR *newPin,
                                        CK_ULONG newLen) {
  return v_set_user_pin(oldPin, oldLen, newPin, newLen);
}

CK_RV v_TokenCore_M1::v_change_so_pin(const CK_CHAR *oldPin, CK_ULONG oldLen,
                                      const CK_CHAR *newPin, CK_ULONG newLen) {
  return v_set_so_pin(oldPin, oldLen, newPin, newLen);
}

CK_RV v_TokenCore_M1::v_login(CK_USER_TYPE userType, const CK_CHAR *pin,
                              CK_ULONG pinLen) {
  // Only verifies the PIN; per-session login state is the Session's job.
  if (userType == CKU_USER) {
    return v_verify_user_pin(pin, pinLen);
  } else if (userType == CKU_SO) {
    return v_verify_so_pin(pin, pinLen);
  }
  return CKR_USER_TYPE_INVALID;
}

CK_RV v_TokenCore_M1::v_logout(CK_USER_TYPE userType) {
  if (userType == CKU_USER || userType == CKU_SO) {
    return CKR_OK;
  }
  return CKR_USER_TYPE_INVALID;
}

void v_TokenCore_M1::v_increment_session_count() {
  v_session_count_.fetch_add(1);
}

void v_TokenCore_M1::v_decrement_session_count() {
  if (v_session_count_.load() > 0) {
    v_session_count_.fetch_sub(1);
  }
}

void v_TokenCore_M1::v_increment_rw_session_count() {
  v_rw_session_count_.fetch_add(1);
}

void v_TokenCore_M1::v_decrement_rw_session_count() {
  if (v_rw_session_count_.load() > 0) {
    v_rw_session_count_.fetch_sub(1);
  }
}

void v_TokenCore_M1::v_set_max_failed_attempts(unsigned max) {
  v_max_failed_attempts_.store(max);
  // Raising the threshold never unlocks; lowering it re-evaluates existing
  // counters against the new bound so a misconfigured threshold alone cannot
  // permanently brick the token.
  if (v_user_failed_attempts_.load() >= max)
    v_user_pin_locked_.store(CK_TRUE);
  if (v_so_failed_attempts_.load() >= max)
    v_so_pin_locked_.store(CK_TRUE);
}

unsigned v_TokenCore_M1::v_max_failed_attempts() const noexcept {
  return v_max_failed_attempts_.load();
}

CK_BBOOL v_TokenCore_M1::v_is_user_pin_locked() const noexcept {
  return v_user_pin_locked_.load();
}

CK_BBOOL v_TokenCore_M1::v_is_so_pin_locked() const noexcept {
  return v_so_pin_locked_.load();
}

unsigned v_TokenCore_M1::v_user_failed_attempts() const noexcept {
  return v_user_failed_attempts_.load();
}

unsigned v_TokenCore_M1::v_so_failed_attempts() const noexcept {
  return v_so_failed_attempts_.load();
}

} // namespace vhsm::keystore::internal
