#ifndef VHSM_SESSION_INTERNAL_SLOT_MANAGER_CORE_H
#define VHSM_SESSION_INTERNAL_SLOT_MANAGER_CORE_H

#include "../../core/hsm_clock.h"
#include "../../keystore/slot.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace vhsm::session::internal {

// Internal business-logic core for SlotManager.
//
// Owns the slot registry (id -> Slot) and all registration / lookup logic.
// The public vhsm::session::SlotManager is a thin singleton facade that
// forwards to this core. Time is supplied via an injected IHsmClock.
class v_SlotManagerCore_M1 {
public:
  explicit v_SlotManagerCore_M1(const IHsmClock &clock);
  ~v_SlotManagerCore_M1() = default;

  v_SlotManagerCore_M1(const v_SlotManagerCore_M1 &) = delete;
  v_SlotManagerCore_M1 &operator=(const v_SlotManagerCore_M1 &) = delete;

  bool v_register_slot(u64 slot_id);
  std::shared_ptr<vhsm::keystore::Slot> v_get_slot(u64 slot_id) const;
  std::vector<u64> v_get_slot_id_list() const;
  void v_reset();

  HsmTimePoint v_last_registration_at() const noexcept;

private:
  std::unordered_map<u64, std::shared_ptr<vhsm::keystore::Slot>> v_slots_;
  mutable std::mutex v_manager_mutex_;

  const IHsmClock &v_clock_;
  HsmTimePoint v_last_registration_at_;
};

} // namespace vhsm::session::internal

#endif // VHSM_SESSION_INTERNAL_SLOT_MANAGER_CORE_H
