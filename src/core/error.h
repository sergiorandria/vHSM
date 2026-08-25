#ifndef VHSM_CORE_ERROR_H
#define VHSM_CORE_ERROR_H

#include <stdexcept>
#include <string>

// ─── Error handling convention ─────────────────────────────────────────────
//
// Three layers, three mechanisms:
//
//   pkcs11/ (extern "C")     → CK_RV return codes (C ABI requirement).
//                              VHSM_C_TRY/VHSM_C_CATCH shield maps std::
//                              exceptions to CKR_* before they cross.
//
//   internal C++ layers       → std:: exception types (this header's macros
//                              + DbError). The shield maps them:
//                                invalid_argument → CKR_ARGUMENTS_BAD
//                                out_of_range      → CKR_BUFFER_TOO_SMALL
//                                bad_alloc         → CKR_HOST_MEMORY
//                                runtime_error     → CKR_GENERAL_ERROR
//
//   abi/result.h              → Result<T> for future ABI boundaries where
//                              exceptions must not be used at all. Not yet
//                              adopted in production code.
//
// Usage rules:
// - Caller-supplied precondition failure → throw std::invalid_argument
//   (use VHSM_CHECK_ARG)
// - Operational failure (I/O, auth, state) → throw std::runtime_error
//   (use VHSM_CHECK_MSG)
// - Database failure → throw DbError with appropriate Kind
// - Buffer/index bounds → throw std::out_of_range

// ─── Macros ────────────────────────────────────────────────────────────────

/// Check a condition and throw std::runtime_error if false.
/// For operational failures: I/O errors, authentication failures,
/// unexpected state. Maps to CKR_GENERAL_ERROR via the C ABI shield.
#define VHSM_CHECK(condition)                                                  \
  do {                                                                         \
    if (!(condition)) {                                                        \
      throw std::runtime_error(std::string("Check failed: ") + #condition +    \
                               std::string(" at ") + __FILE__ +                \
                               std::string(":") + std::to_string(__LINE__));   \
    }                                                                          \
  } while (0)

/// Check a condition and throw std::runtime_error with a custom message.
/// Same mapping as VHSM_CHECK but with caller-provided context text.
#define VHSM_CHECK_MSG(condition, msg)                                         \
  do {                                                                         \
    if (!(condition)) {                                                        \
      throw std::runtime_error(std::string(msg) + std::string(" at ") +        \
                               __FILE__ + std::string(":") +                   \
                               std::to_string(__LINE__));                      \
    }                                                                          \
  } while (0)

/// Check a caller-supplied argument and throw std::invalid_argument if false.
/// Maps to CKR_ARGUMENTS_BAD via the C ABI shield — NOT CKR_GENERAL_ERROR.
/// Use for null pointers, wrong sizes, invalid enum values, etc.
/// For operational failures use VHSM_CHECK_MSG instead.
#define VHSM_CHECK_ARG(condition, msg)                                         \
  do {                                                                         \
    if (!(condition)) {                                                        \
      throw std::invalid_argument(std::string(msg) + std::string(" at ") +     \
                                  __FILE__ + ":" + std::to_string(__LINE__));  \
    }                                                                          \
  } while (0)

// ─── DbError ───────────────────────────────────────────────────────────────

/// Database errors with classified error kinds.
///
/// WHY enum Kind inside DbError: Callers can catch (DbError& e) and inspect
/// e.kind() to determine the root cause (SchemaError = corrupt schema;
/// ConnectionError = network issue; TransactionError = deadlock). This is
/// richer than a generic database exception and allows callers to decide
/// whether to retry, fail fast, or escalate.
class DbError : public std::runtime_error {
public:
  enum class Kind {
    SchemaError,      // Table/column missing or wrong type
    ConstraintError,  // Unique/foreign key violation
    ConnectionError,  // Network issue, pool exhausted
    TransactionError, // Deadlock, rollback required
    IoError           // Disk full, permissions, etc.
  };

  DbError(Kind kind, const std::string &message)
      : std::runtime_error(message), kind_(kind) {}

  Kind kind() const { return kind_; }

private:
  Kind kind_;
};

#endif // VHSM_CORE_ERROR_H
