#ifndef vHSM_SIGN_CONTEXT_H
#define vHSM_SIGN_CONTEXT_H

#include "Types.h"
#include "OpContext.h"
#include <vector>
#include <memory>

// ============================================================================
// Session operation context base
// ============================================================================

/// OpContext is the abstract base class for operation-specific contexts
/// (sign, verify, encrypt, etc.). It provides a small polymorphic handle
/// allowing operation state to be stored and passed around in the session
/// layer. Implementations are non-copyable and moveable.


// ============================================================================
// SignContext
// ============================================================================
/// SignContext accumulates input data for a signing operation and stores the
/// mechanism and key handle to be used when the actual signing primitive is
/// invoked by higher-level code.
///
/// Behavior:
/// - Constructed with the chosen Mechanism and the ObjectHandle of the key.
/// - Throws CryptoException if the provided key handle is INVALID_HANDLE.
/// - update() appends bytes to an internal accumulator; passing a null
///   pointer with a positive length is an error and throws CryptoException.
/// - clear() removes accumulated data without throwing.
class SignContext : public OpContext {
public:
    SignContext(Mechanism mech, ObjectHandle key);
    ~SignContext() override = default;

    /// Append raw bytes to the signing accumulator.
    void update(const uint8_t* data, size_t len);

    /// Clear accumulated input bytes.
    void clear() noexcept;

    /// Access the accumulated data buffer (read-only).
    const std::vector<uint8_t>& data() const noexcept { return m_accumulator; }

    Mechanism mechanism() const noexcept { return m_mechanism; }
    ObjectHandle key_handle() const noexcept { return m_key_handle; }

private:
    Mechanism m_mechanism;
    ObjectHandle m_key_handle;
    std::vector<uint8_t> m_accumulator;
};

#endif