#ifndef VHSM_ABI_ERROR_H
#define VHSM_ABI_ERROR_H

#include "export.h"
#include <system_error>

// Typed errors that map 1:1 to PKCS#11 CKR_* but are transportable as
// std::error_code across the ABI (no exceptions cross the boundary).

VHSM_ABI_NAMESPACE_BEGIN

enum VHSM_API Errc {
  Ok,
  HostMemory,
  GeneralError,
  ArgumentsBad,
  BufferTooSmall,
  DeviceError,
  MechanismInvalid,
  PinIncorrect,
  SessionHandleInvalid,
  OperationNotInitialized,
  UserNotLoggedIn,
};

inline const std::error_category &vhsm_category() noexcept {
  struct VHSMErrorCategory : std::error_category {
    const char *name() const noexcept override { return "vhsm"; }
    std::string message(int ev) const override {
      switch (static_cast<Errc>(ev)) {
      case Errc::Ok:
        return "ok";
      case Errc::HostMemory:
        return "host memory";
      case Errc::GeneralError:
        return "general error";
      case Errc::ArgumentsBad:
        return "arguments bad";
      case Errc::BufferTooSmall:
        return "buffer too small";
      case Errc::DeviceError:
        return "device error";
      case Errc::MechanismInvalid:
        return "mechanism invalid";
      case Errc::PinIncorrect:
        return "pin incorrect";
      case Errc::SessionHandleInvalid:
        return "session handle invalid";
      case Errc::OperationNotInitialized:
        return "operation not initialized";
      case Errc::UserNotLoggedIn:
        return "user not logged in";
      default:
        return "unknown vhsm error";
      }
    }
  };

  static VHSMErrorCategory c;
  return c;
}
inline std::error_code make_error_code(Errc e) noexcept {
  return {static_cast<int>(e), vhsm_category()};
}

VHSM_ABI_NAMESPACE_END

namespace std {
template <> struct is_error_code_enum<vhsm::v1::Errc> : true_type {};
} // namespace std

#endif // VHSM_ABI_ERROR_H
