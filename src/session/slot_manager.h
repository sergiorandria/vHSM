#ifndef VHSM_SESSION_SLOT_MANAGER_H
#define VHSM_SESSION_SLOT_MANAGER_H

#include "../core/system_hsm_clock.h"
#include "../keystore/slot.h" // Inclusion de ton composant Slot documenté
#include "internal/slot_manager_core.h"
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace vhsm::session {

/**
 * @class SlotManager
 * @brief Singleton facade that manages the lifecycle and access registry of
 *        all virtual Slots.
 *
 * This class is the thin, GLIBC-style public surface: it forwards every call
 * to the internal business-logic core
 * (vhsm::session::internal::v_SlotManagerCore_M1), which owns the slot
 * registry. See v_SlotManagerCore_M1 for the actual logic.
 */
class SlotManager {
public:
  /**
   * @brief Retrieves the global unique instance of the SlotManager.
   * @return SlotManager& Reference to the singleton instance.
   */
  static SlotManager &get_instance();

  // Delete copy and move operations to enforce strict singleton pattern
  // properties.
  SlotManager(const SlotManager &) = delete;
  SlotManager &operator=(const SlotManager &) = delete;
  SlotManager(SlotManager &&) = delete;
  SlotManager &operator=(SlotManager &&) = delete;

  bool register_slot(u64 slot_id);

  std::shared_ptr<keystore::Slot> get_slot(u64 slot_id) const;

  std::vector<u64> get_slot_id_list() const;

  void reset();

private:
  // Private constructor for singleton pattern enforcement.
  SlotManager();
  ~SlotManager() = default;

  vhsm::SystemHsmClock v_clock_;
  vhsm::session::internal::v_SlotManagerCore_M1 v_core_;
};

} // namespace vhsm::session

#endif // VHSM_SESSION_SLOT_MANAGER_H
