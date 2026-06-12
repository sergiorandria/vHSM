#ifndef vHSM_TYPES_H
#define vHSM_TYPES_H

#include <cstdint>
#include <stdexcept>
#include <string>

/// Session-related basic types and error classes used across the vHSM
/// session implementation.
///
/// These are simplified aliases inspired by PKCS#11 types:
/// - ObjectHandle: opaque identifier for objects managed by the HSM layer.
/// - Mechanism: numeric identifier for cryptographic mechanisms.
///
/// The header also declares a couple of exception types used by session
/// components to report exceptional conditions in a typed way.

// Types PKCS#11 simplified
using ObjectHandle = uint32_t;
using Mechanism = uint32_t;

constexpr ObjectHandle INVALID_HANDLE = 0;
constexpr Mechanism CKM_SHA256_RSA_PKCS = 0x00000241; // Example standard value

/// Base class for session-related errors.
/// Encapsulates an explanatory message.
class HsmException : public std::runtime_error {
public:
    explicit HsmException(const std::string& message) : std::runtime_error(message) {}
};

/// Errors originating from cryptographic operations (signature, digest, etc.).
class CryptoException : public HsmException {
public:
    explicit CryptoException(const std::string& message) : HsmException(message) {}
};

#endif