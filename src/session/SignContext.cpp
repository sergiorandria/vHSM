#include "../core/error.h"
#include "SignContext.h"

namespace vhsm::session {
SignContext::SignContext(CK_MECHANISM_TYPE mech, CK_OBJECT_HANDLE key)
    : m_mechanism(mech), m_key_handle(key), m_app_context_json() {
    if (key == CKR_OBJECT_HANDLE_INVALID) {
        throw CryptoException("SignContext: Clé de signature invalide.");
    }
}

void SignContext::update(const uint8_t* data, size_t len) {
    if (!data && len > 0) {
        throw CryptoException("SignContext: Pointeur de données nul avec une longueur positive.");
    }
    if (len > 0) {
        m_accumulator.insert(m_accumulator.end(), data, data + len);
    }
}

void SignContext::clear() noexcept {
    m_accumulator.clear();
}
}