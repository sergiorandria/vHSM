#include "FindContext.h"

// --- FindContext ---
FindContext::FindContext(std::vector<ObjectHandle> initial_matches)
    : m_matches(std::move(initial_matches)), m_current_index(0) {}

bool FindContext::has_next() const noexcept {
    return m_current_index < m_matches.size();
}

ObjectHandle FindContext::next() {
    if (!has_next()) {
        throw HsmException("FindContext: Fin de la liste de correspondance atteinte (C_FindObjectsInit non valide).");
    }
    return m_matches[m_current_index++];
}

void FindContext::reset() noexcept {
    m_current_index = 0;
}