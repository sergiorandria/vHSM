#ifndef VHSM_CORE_HSM_INSTANCE_H
#define VHSM_CORE_HSM_INSTANCE_H

#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "macros.h"

namespace vhsm::core {

// ------------------------------------------------------------
// 1. Value Object (Immutable) — Domain layer
// ------------------------------------------------------------
class _VHSMXX_VISIBILITY(hidden) HsmInstanceId {
public:
  explicit HsmInstanceId(std::string id) noexcept;
  HsmInstanceId(const HsmInstanceId &) = default;
  HsmInstanceId(HsmInstanceId &&) noexcept = default;
  HsmInstanceId &operator=(const HsmInstanceId &) = default;
  HsmInstanceId &operator=(HsmInstanceId &&) noexcept = default;
  ~HsmInstanceId() = default;

  _VHSMXX_NODISCARD const std::string &value() const noexcept;
  bool operator==(const HsmInstanceId &other) const noexcept;
  bool operator!=(const HsmInstanceId &other) const noexcept;

private:
  std::string id_;
};

// ------------------------------------------------------------
// 2. Domain Service Interface — Port
//    Implementations live in the infrastructure layer that owns the
//    backing store (e.g., DatabaseHsmInstanceProvider in signature_store).
// ------------------------------------------------------------
class _VHSMXX_VISIBILITY(hidden) IHsmInstanceProvider {
public:
  virtual ~IHsmInstanceProvider() = default;
  _VHSMXX_NODISCARD virtual HsmInstanceId getInstanceId() const = 0;
};

// ------------------------------------------------------------
// 3. Process-wide accessors — legacy compat (used by ledger,
//    notification, pkcs11 layers). Thread-safe.
//    Prefer IHsmInstanceProvider in new code.
// ------------------------------------------------------------
void set_hsm_instance_id(std::string id);
const std::string &hsm_instance_id();

} // namespace vhsm::core

#endif // VHSM_CORE_HSM_INSTANCE_H
