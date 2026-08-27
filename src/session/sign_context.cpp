#include "sign_context.h"

namespace vhsm::session {
SignContext::SignContext(CK_MECHANISM_TYPE mech, CK_OBJECT_HANDLE key)
    : m_mechanism(mech), m_key_handle(key), m_app_context_json() {
  if (key == CKR_OBJECT_HANDLE_INVALID) {
    throw std::invalid_argument("SignContext: invalid key handle");
  }
}

void SignContext::update(const uint8_t *data, size_t len) {
  if (!data && len > 0) {
    throw std::invalid_argument(
        "SignContext: null data pointer with positive length");
  }
  if (len > 0) {
    m_accumulator.insert(m_accumulator.end(), data, data + len);
  }
}

void SignContext::clear() noexcept { m_accumulator.clear(); }
} // namespace vhsm::session
