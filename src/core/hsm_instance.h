#ifndef VHSM_CORE_HSM_INSTANCE_H
#define VHSM_CORE_HSM_INSTANCE_H

#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "macros.h"

// Forward declare the real DB connection in its actual namespace to avoid
// pulling heavy headers into this core header.
namespace vhsm::signature_store::db {
class IDbConnection;
}

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
// ------------------------------------------------------------
class _VHSMXX_VISIBILITY(hidden) IHsmInstanceProvider {
public:
  virtual ~IHsmInstanceProvider() = default;
  _VHSMXX_NODISCARD virtual HsmInstanceId getInstanceId() const = 0;
};

// ------------------------------------------------------------
// 3. Infrastructure Implementation (Database-backed)
// ------------------------------------------------------------
class _VHSMXX_VISIBILITY(hidden) DatabaseHsmInstanceProvider
    : public IHsmInstanceProvider {
public:
  explicit DatabaseHsmInstanceProvider(
      vhsm::signature_store::db::IDbConnection &db);

  _VHSMXX_NODISCARD HsmInstanceId getInstanceId() const override;

  // Seeds the instance ID during bootstrap. Returns true on success.
  // Invalidates the cache so the next getInstanceId() reads the new value.
  bool seedInstanceId(const HsmInstanceId &id);

private:
  vhsm::signature_store::db::IDbConnection &db_;
  mutable std::mutex mutex_;
  mutable std::optional<HsmInstanceId> cached_id_;
};

// ------------------------------------------------------------
// 4. Factory — used in the composition root
// ------------------------------------------------------------
_VHSMXX_VISIBILITY(hidden)
std::unique_ptr<IHsmInstanceProvider>
createDefaultInstanceProvider(vhsm::signature_store::db::IDbConnection &db);

// ------------------------------------------------------------
// 5. Process-wide accessors — legacy compat (used by ledger,
//    notification, pkcs11 layers). Thread-safe.
//    Prefer IHsmInstanceProvider in new code.
// ------------------------------------------------------------
void set_hsm_instance_id(std::string id);
const std::string &hsm_instance_id();

} // namespace vhsm::core

#endif // VHSM_CORE_HSM_INSTANCE_H
