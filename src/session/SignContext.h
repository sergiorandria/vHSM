#ifndef vHSM_SIGN_CONTEXT_H
#define vHSM_SIGN_CONTEXT_H

#include "../core/types.h"
#include "OpContext.h"
#include <vector>
#include <memory>

namespace vhsm::session {
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
    SignContext(CK_MECHANISM_TYPE mech, CK_OBJECT_HANDLE key);
    ~SignContext() override = default;

    /// Append raw bytes to the signing accumulator.
    void update(const uint8_t* data, size_t len);

    /// Clear accumulated input bytes.
    void clear() noexcept;

    /// Access the accumulated data buffer (read-only).
    const std::vector<uint8_t>& data() const noexcept { return m_accumulator; }

    CK_MECHANISM_TYPE mechanism() const noexcept { return m_mechanism; }
    CK_OBJECT_HANDLE key_handle() const noexcept { return m_key_handle; }

    /// Set application context JSON (optional, forwarded to signature records).
    void set_app_context_json(const std::string& json) { m_app_context_json = json; }

    /// Get application context JSON.
    const std::string& app_context_json() const noexcept { return m_app_context_json; }

private:
    CK_MECHANISM_TYPE m_mechanism;
    CK_OBJECT_HANDLE m_key_handle;
    std::vector<uint8_t> m_accumulator;
    std::string m_app_context_json;
};
} // namespace vhsm::session
#endif