#include "slot_manager.h"

namespace vhsm::session {

using namespace keystore;

namespace detail {
// Process-wide SlotManager for legacy PKCS#11 call sites during DI migration.
// Owned by AppContainer (set in C_Initialize, cleared in C_Finalize).
static SlotManager *g_slot_manager = nullptr;

SlotManager &global_slot_manager() {
  // If null (before C_Initialize), return a function-local fallback so we
  // don't crash. This should never happen in production but tests may hit it.
  static SlotManager fallback;
  return g_slot_manager ? *g_slot_manager : fallback;
}

void set_global_slot_manager(SlotManager *mgr) { g_slot_manager = mgr; }
} // namespace detail

SlotManager::SlotManager() : v_clock_(), v_core_(v_clock_) {}


bool SlotManager::register_slot(u64 slot_id) {
  return v_core_.v_register_slot(slot_id);
}

std::shared_ptr<Slot> SlotManager::get_slot(u64 slot_id) const {
  return v_core_.v_get_slot(slot_id);
}

std::vector<u64> SlotManager::get_slot_id_list() const {
  return v_core_.v_get_slot_id_list();
}

void SlotManager::reset() { v_core_.v_reset(); }

} // namespace vhsm::session
