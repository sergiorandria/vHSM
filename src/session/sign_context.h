#ifndef vHSM_SIGN_CONTEXT_H
#define vHSM_SIGN_CONTEXT_H

#include "../domain/core/kernel_types.h"
#include "../domain/pkcs11/pkcs11_types.h"
#include "op_context.h"
#include <memory>
#include <vector>

namespace vhsm::session {
/// WHY SignContext accumulates data before signing: PKCS#11 allows two modes:
/// 1. C_Sign: Single operation (data → signature in one call)
/// 2. C_SignInit + C_SignUpdate + C_SignFinal: Multi-part operation (append
/// data incrementally, then finalize) SignContext supports multi-part mode by
/// accumulating bytes in m_accumulator. When C_SignFinal is called, it passes
/// the accumulated data to CryptoEngine::sign(). This lets applications sign
/// large files without loading the entire file into memory at once (streaming
/// fashion, though the accumulator does hold it internally).
///
/// WHY store mechanism and key_handle: Signing requires both the key (to sign
/// with) and the mechanism (algorithm: RSA-PKCS, ECDSA-SHA256, etc.). Storing
/// them in the context ensures they're available when C_SignFinal is called
/// (possibly much later).
///
/// WHY throw std::invalid_argument on invalid key_handle: If the handle is
/// INVALID_HANDLE (0), the signing will fail anyway. Throwing early (in the
/// constructor) catches the bug immediately and provides a clear error message.
/// Better than deferring the error to C_SignFinal (where the context for
/// debugging is lost).
class SignContext : public OpContext {
public:
  // WHY constructor takes mechanism and key_handle: These are fixed for the
  // operation. You can't change the key or algorithm mid-operation. They're set
  // at C_SignInit and remain constant through multiple C_SignUpdate calls.
  SignContext(CK_MECHANISM_TYPE mech, CK_OBJECT_HANDLE key);
  ~SignContext() override = default;

  /// WHY update appends bytes: Each C_SignUpdate call appends more bytes to the
  /// accumulator. By C_SignFinal, we have the complete input. This supports
  /// streaming (append now, sign later) without the application allocating a
  /// single large buffer. Append raw bytes to the signing accumulator.
  void update(const uint8_t *data, size_t len);

  /// WHY clear() is noexcept: Callers may need to clear a context on error
  /// without throwing. noexcept signals that this operation can't fail. Useful
  /// for cleanup in destructors or error handlers. Clear accumulated input
  /// bytes.
  void clear() noexcept;

  /// WHY data() returns const vector: Callers need to inspect the accumulated
  /// bytes (for logging, validation, or passing to CryptoEngine). const ensures
  /// they can't accidentally modify the accumulator. [[nodiscard]] catches
  /// accidental ignoring. Access the accumulated data buffer (read-only).
  const std::vector<uint8_t> &data() const noexcept { return m_accumulator; }

  // WHY const accessors: These fields are fixed after construction and never
  // change. const methods signal "these don't modify the context".
  CK_MECHANISM_TYPE mechanism() const noexcept { return m_mechanism; }
  CK_OBJECT_HANDLE key_handle() const noexcept { return m_key_handle; }

  /// WHY app_context_json: Optional application-provided JSON context (e.g.,
  /// document metadata, audit info). Forwarded to signature records for
  /// auditability. The application decides what to include; the SignContext
  /// just carries it through. Set application context JSON (optional, forwarded
  /// to signature records).
  void set_app_context_json(const std::string &json) {
    m_app_context_json = json;
  }

  /// Get application context JSON.
  const std::string &app_context_json() const noexcept {
    return m_app_context_json;
  }

private:
  CK_MECHANISM_TYPE m_mechanism;
  CK_OBJECT_HANDLE m_key_handle;

  // WHY m_accumulator as std::vector: Simple, resizable buffer for accumulated
  // data. No special memory-locking needed here (the data is only sensitive
  // during signing). After C_SignFinal returns the signature, the accumulator
  // is cleared.
  std::vector<uint8_t> m_accumulator;

  // WHY m_app_context_json: Opaque string (JSON format) provided by the
  // application. SignContext just stores and returns it; the signature store
  // includes it in audit records.
  std::string m_app_context_json;
};
} // namespace vhsm::session
#endif