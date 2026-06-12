#include "FindContext.h"
#include "../core/error.h"

namespace vhsm::session {
FindContext::FindContext(std::vector<CK_OBJECT_HANDLE> initial_matches)
    : m_matches(std::move(initial_matches)), m_current_index(0) {}

bool FindContext::has_next() const noexcept {
    return m_current_index < m_matches.size();
}

CK_OBJECT_HANDLE FindContext::next() {
    if (!has_next()) {
        throw HsmException("FindContext: Fin de la liste de correspondance atteinte (C_FindObjectsInit non valide).");
    }
    return m_matches[m_current_index++];
}

void FindContext::reset() noexcept {
    m_current_index = 0;
}
}