#include "find_context.h"
#include <stdexcept>

namespace vhsm::session {
FindContext::FindContext(std::vector<CK_OBJECT_HANDLE> initial_matches)
    : m_matches(std::move(initial_matches)), m_current_index(0) {}

bool FindContext::has_next() const noexcept {
  return m_current_index < m_matches.size();
}

CK_OBJECT_HANDLE FindContext::next() {
  if (!has_next()) {
    throw std::out_of_range(
        "FindContext::next(): no matches remain; call has_next() first");
  }
  return m_matches[m_current_index++];
}

void FindContext::reset() noexcept { m_current_index = 0; }
} // namespace vhsm::session
