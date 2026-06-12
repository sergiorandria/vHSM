#include "SignContext.h"
// --- SignContext ---
SignContext::SignContext(Mechanism mech, ObjectHandle key)
    : m_mechanism(mech), m_key_handle(key) {
    if (key == INVALID_HANDLE) {
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