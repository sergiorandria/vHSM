#ifndef VHSM_FIND_CONTEXT_H
#define VHSM_FIND_CONTEXT_H

#include "../core/types.h"
#include "OpContext.h"
#include <vector>
#include <memory>

namespace vhsm::session {
/// FindContext provides a lightweight, sequential iterator over a set of
/// object handles produced by a find operation. It is intended to be used by
/// session-layer code that implements C_FindObjects* style operations.
///
/// Key points:
/// - Constructed with the initial list of matching `ObjectHandle`s.
/// - Supports has_next() / next() iteration and reset() to rewind the cursor.
/// - `next()` will throw `HsmException` if called when no elements remain.
/// - The object is non-copyable (to avoid accidental duplication of the
///   iteration state) but is movable.
class FindContext: public OpContext {
public:
    explicit FindContext(std::vector<CK_OBJECT_HANDLE> initial_matches);
    
    ~FindContext() = default;
    FindContext(const FindContext&) = delete;
    FindContext& operator=(const FindContext&) = delete;
    FindContext(FindContext&&) noexcept = default;
    FindContext& operator=(FindContext&&) noexcept = default;

    /// Return true while there are remaining matches to be consumed.
    bool has_next() const noexcept;

    /// Return the next ObjectHandle and advance the internal cursor.
    /// Throws HsmException if no matches remain.
    CK_OBJECT_HANDLE next();

    /// Reset the internal cursor to the beginning so iteration can start over.
    void reset() noexcept;

private:
    std::vector<CK_OBJECT_HANDLE> m_matches;
    size_t m_current_index{0};
};
} // namespace vhsm::session
#endif // VHSM_FIND_CONTEXT_H