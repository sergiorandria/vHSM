#ifndef VHSM_FIND_CONTEXT_H
#define VHSM_FIND_CONTEXT_H

#include "../domain/core/kernel_types.h"
#include "../domain/pkcs11/pkcs11_types.h"
#include "op_context.h"
#include <memory>
#include <vector>

namespace vhsm::session {
/// WHY FindContext provides an iterator interface: PKCS#11 C_FindObjects*
/// operations return multiple matching object handles incrementally.
/// C_FindObjectsInit initializes a search, C_FindObjects fetches the next
/// batch, C_FindObjectsFinal closes the search. FindContext encapsulates this
/// iteration pattern with has_next() / next() for type safety.
///
/// WHY store the full match list upfront: FindContext is constructed with all
/// matching handles (computed by the caller via object store search). This
/// simplifies the interface: no stateful search continuation needed. The object
/// store can be released immediately after the search completes; FindContext
/// holds the results.
///
/// WHY non-copyable but movable: Iteration state (the cursor m_current_index)
/// should not be accidentally duplicated. Two copies with the same m_matches
/// but different cursors would be confusing (are they independent iterations?).
/// Move is allowed to let callers transfer ownership without copying.
///
/// WHY throw std::out_of_range on next() when empty: Calling next() without checking
/// has_next() is a logic error. Throwing makes the error explicit
/// (fail-closed). Some callers may catch the exception; others rely on the
/// check.
class FindContext : public OpContext {
public:
  // WHY explicit constructor: FindContext requires an initial match list.
  // Making the constructor explicit prevents accidental implicit conversions
  // (vector → FindContext).
  explicit FindContext(std::vector<CK_OBJECT_HANDLE> initial_matches);

  ~FindContext() = default;

  // WHY non-copyable: Iteration state (cursor) shouldn't be duplicated. Copying
  // a FindContext halfway through iteration would be confusing (both copies
  // have the same m_matches but potentially different cursors).
  FindContext(const FindContext &) = delete;
  FindContext &operator=(const FindContext &) = delete;

  // WHY movable: Allows transfer of ownership without copying. Useful for
  // returning FindContext from a function or storing in a container.
  FindContext(FindContext &&) noexcept = default;
  FindContext &operator=(FindContext &&) noexcept = default;

  /// WHY has_next() is const noexcept: Checking for more results shouldn't
  /// throw or modify state. const signals "this is a query, not a mutation".
  /// Return true while there are remaining matches to be consumed.
  bool has_next() const noexcept;

  /// WHY next() returns a single handle (not a batch): Callers may want to
  /// process one handle at a time (e.g., C_FindObjects returns
  /// CK_OBJECT_HANDLE[ulMaxObjectCount], a variable-size array). next() lets
  /// them fetch one at a time, simplifying the API. Throws std::out_of_range if no
  /// matches remain (fail-closed: better than returning a sentinel or null).
  /// Return the next ObjectHandle and advance the internal cursor.
  /// Throws std::out_of_range if no matches remain.
  CK_OBJECT_HANDLE next();

  /// WHY reset() is separate: Sometimes applications want to start a find
  /// operation over (iterate the same results again). reset() lets them do so
  /// without reconstructing the FindContext. Reset the internal cursor to the
  /// beginning so iteration can start over.
  void reset() noexcept;

private:
  // WHY m_matches is immutable: The list of matching handles doesn't change
  // after construction. Making it const (or protecting it) would help, but for
  // now it's private (so only member functions access it).
  std::vector<CK_OBJECT_HANDLE> m_matches;

  // WHY m_current_index tracks position: Simple cursor-based iteration.
  // Incrementing m_current_index on next() advances through m_matches.
  // has_next() checks if the cursor hasn't reached the end.
  size_t m_current_index{0};
};
} // namespace vhsm::session
#endif // VHSM_FIND_CONTEXT_H