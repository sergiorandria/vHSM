#include "slot_manager_core.h"

namespace vhsm::session::internal {

v_SlotManagerCore_M1::v_SlotManagerCore_M1(const IHsmClock &clock)
    : v_clock_(clock), v_last_registration_at_(clock.now()) {}

bool v_SlotManagerCore_M1::v_register_slot(u64 slot_id) {
  std::lock_guard<std::mutex> lock(v_manager_mutex_);

  if (v_slots_.find(slot_id) != v_slots_.end()) {
    return false;
  }

  v_slots_[slot_id] = std::make_shared<vhsm::keystore::Slot>(slot_id);
  v_last_registration_at_ = v_clock_.now();
  return true;
}

std::shared_ptr<vhsm::keystore::Slot>
v_SlotManagerCore_M1::v_get_slot(u64 slot_id) const {
  std::lock_guard<std::mutex> lock(v_manager_mutex_);

  auto it = v_slots_.find(slot_id);
  if (it != v_slots_.end()) {
    return it->second;
  }

  return nullptr;
}

std::vector<u64> v_SlotManagerCore_M1::v_get_slot_id_list() const {
  std::lock_guard<std::mutex> lock(v_manager_mutex_);

  std::vector<u64> id_list;
  id_list.reserve(v_slots_.size());

  for (const auto &[slot_id, _] : v_slots_) {
    id_list.push_back(slot_id);
  }

  return id_list;
}

void v_SlotManagerCore_M1::v_reset() {
  std::lock_guard<std::mutex> lock(v_manager_mutex_);
  v_slots_.clear();
}

HsmTimePoint v_SlotManagerCore_M1::v_last_registration_at() const noexcept {
  return v_last_registration_at_;
}

} // namespace vhsm::session::internal
