#include "slot_manager.h"

namespace vhsm::session {

using namespace keystore;

SlotManager& SlotManager::get_instance() {
    // Garantit une initialisation unique et thread-safe (Meyers' Singleton)
    static SlotManager instance;
    return instance;
}

SlotManager::SlotManager()
    : v_clock_()
    , v_core_(v_clock_)
{
}

bool SlotManager::register_slot(u64 slot_id) {
    return v_core_.v_register_slot(slot_id);
}

std::shared_ptr<Slot> SlotManager::get_slot(u64 slot_id) const {
    return v_core_.v_get_slot(slot_id);
}

std::vector<u64> SlotManager::get_slot_id_list() const {
    return v_core_.v_get_slot_id_list();
}

void SlotManager::reset() {
    v_core_.v_reset();
}

} // namespace vhsm
