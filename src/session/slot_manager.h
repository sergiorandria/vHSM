#ifndef VHSM_SESSION_SLOT_MANAGER_H
#define VHSM_SESSION_SLOT_MANAGER_H

#include "../core/system_hsm_clock.h"
#include "../keystore/slot.h"
#include "internal/slot_manager_core.h"
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace vhsm::session {

/**
 * @class SlotManager
 * @brief Manages the lifecycle and access registry of all virtual Slots.
 *
 * Injectable dependency — NOT a singleton. Owned by AppContainer (or tests).
 * Multiple instances are safe: each owns an independent slot registry.
 *
 * A backward-compat process-wide accessor (`global_slot_manager()`) is
 * provided for legacy PKCS#11 call sites during the migration to full DI.
 */
class SlotManager {
public:
  // Public constructor — injectable, not a singleton.
  SlotManager();
  ~SlotManager() = default;

  // Non-copyable, non-movable: owns mutex + slot registry. Store as
  // unique_ptr<SlotManager> in containers.
  SlotManager(const SlotManager &) = delete;
  SlotManager &operator=(const SlotManager &) = delete;

  bool register_slot(u64 slot_id);
  std::shared_ptr<keystore::Slot> get_slot(u64 slot_id) const;
  std::vector<u64> get_slot_id_list() const;
  void reset();

private:
  vhsm::SystemHsmClock v_clock_;
  vhsm::session::internal::v_SlotManagerCore_M1 v_core_;
};

// Backward-compat: returns the process-wide SlotManager set by C_Initialize.
// New code should receive SlotManager via injection instead. Marked
// deprecated so new uses are flagged at compile time.
namespace detail {
SlotManager &global_slot_manager();
void set_global_slot_manager(SlotManager *mgr);
} // namespace detail

} // namespace vhsm::session

#endif // VHSM_SESSION_SLOT_MANAGER_H
