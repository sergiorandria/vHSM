#ifndef VHSM_CORE_ERROR_H
#define VHSM_CORE_ERROR_H

#include <stdexcept>
#include <string>

// WHY exception hierarchy instead of flat error codes: PKCS#11 defines error codes (CKR_*),
// but C++ programs throw exceptions. The hierarchy (HsmException → CryptoException, DbError)
// allows callers to catch domain-specific errors without inspecting error codes.
// Example: catch (CryptoException&) handles all cryptographic failures; catch (DbError&)
// handles all database issues. This enables fine-grained error recovery strategies.
//
// WHY VHSM_CHECK macro embeds file/line: Production code needs debugging context.
// Embedding __FILE__ and __LINE__ in the exception message provides immediate attribution
// (which function, which file, which line failed). This beats printf debugging and manual
// stack traces in most scenarios. The macro expands at compile time (zero runtime overhead
// compared to manual throw statements with formatted messages).

/// Macro to check a condition and throw std::runtime_error if false.
/// Includes the condition expression, file, and line number in the error message.
#define VHSM_CHECK(condition) \
    do { \
        if (!(condition)) { \
            throw std::runtime_error(std::string("Check failed: ") + #condition \
                + std::string(" at ") + __FILE__ + std::string(":") + std::to_string(__LINE__)); \
        } \
    } while (0)

/// Macro to check a condition and throw std::runtime_error with a custom message if false.
/// Includes the custom message, file, and line number in the error message.
///
/// WHY separate from VHSM_CHECK: Sometimes a default message (condition expression) isn't
/// helpful. VHSM_CHECK_MSG lets the caller provide context-specific text (e.g., "KeyWrap: 
/// KEK must be 32 bytes"). This makes errors immediately actionable without reading source code.
#define VHSM_CHECK_MSG(condition, msg) \
    do { \
        if (!(condition)) { \
            throw std::runtime_error(std::string(msg) \
                + std::string(" at ") + __FILE__ + std::string(":") + std::to_string(__LINE__)); \
        } \
    } while (0)

#define VHSM_CHECK_PTR_MSG(condition, msg) \
    do { \
        if (!(condition)) { \
            throw std::runtime_error(std::string(msg) \
                + std::string(" at ") + __FILE__ + std::string(":") + std::to_string(__LINE__)); \
        } \
    } while (0)

/// Base class for session-related errors.
/// Encapsulates an explanatory message.
///
/// WHY exception hierarchy: HsmException is the base; CryptoException and DbError inherit.
/// Callers can catch (HsmException&) to handle all HSM-related errors uniformly, or catch
/// specific subclasses to apply specialized recovery logic. This is the standard C++ pattern
/// for domain-specific error hierarchies.
class HsmException : public std::runtime_error {
public:
    explicit HsmException(const std::string& message) : std::runtime_error(message) {}
};

/// Errors originating from cryptographic operations (signature, digest, etc.).
///
/// WHY separate CryptoException: Cryptographic failures (invalid key, bad signature)
/// are distinct from database errors or system errors. Applications sign transactions
/// frequently; if a signature fails, the system should log it differently than if the
/// database connection dropped. Fine-grained exception types enable that distinction.
class CryptoException : public HsmException {
public:
    explicit CryptoException(const std::string& message) : HsmException(message) {}
};

/// Version/compatibility errors.
class VersionException : public std::runtime_error {
public: 
    explicit VersionException(const std::string& message) : std::runtime_error(message) {}
};

/// Database errors with classified error kinds.
///
/// WHY enum Kind inside DbError: Callers can catch (DbError& e) and inspect e.kind()
/// to determine the root cause (SchemaError = corrupt schema; ConnectionError = network
/// issue; TransactionError = deadlock). This is richer than a generic database exception
/// and allows callers to decide whether to retry, fail fast, or escalate.
class DbError : public std::runtime_error {
public:
    // WHY Kind enum: Classifies database failures so recovery strategies can be tailored.
    // ConnectionError might retry; SchemaError should escalate to DBA; ConstraintError
    // might indicate corrupt data that needs repair.
    enum class Kind {
        SchemaError,        // Table/column missing or wrong type
        ConstraintError,    // Unique/foreign key violation
        ConnectionError,    // Network issue, pool exhausted
        TransactionError,   // Deadlock, rollback required
        IoError             // Disk full, permissions, etc.
    };

    DbError(Kind kind, const std::string& message)
        : std::runtime_error(message), kind_(kind) {}

    Kind kind() const { return kind_; }

private:
    Kind kind_;
};

#endif // VHSM_CORE_ERROR_H