#include "slot_manager.h"

namespace vhsm::session {

using namespace keystore;

SlotManager& SlotManager::get_instance() {
    // Garantit une initialisation unique et thread-safe (Meyers' Singleton)
    static SlotManager instance;
    return instance;
}

bool SlotManager::register_slot(uint64_t slot_id) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    
    // On vérifie si le slot existe déjà dans notre map
    if (slots_.find(slot_id) != slots_.end()) {
        return false; 
    }

    // Allocation et insertion du nouveau Slot
    slots_[slot_id] = std::make_shared<Slot>(slot_id);
    return true;
}

std::shared_ptr<Slot> SlotManager::get_slot(uint64_t slot_id) const {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    
    auto it = slots_.find(slot_id);
    if (it != slots_.end()) {
        return it->second;
    }
    
    return nullptr; 
}

std::vector<uint64_t> SlotManager::get_slot_id_list() const {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    
    std::vector<uint64_t> id_list;
    id_list.reserve(slots_.size());
    
    for (const auto& [slot_id, _] : slots_) {
        id_list.push_back(slot_id);
    }
    
    return id_list;
}

void SlotManager::reset() {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    slots_.clear();
}

} // namespace vhsm