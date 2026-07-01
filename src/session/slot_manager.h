#ifndef VHSM_SESSION_SLOT_MANAGER_H
#define VHSM_SESSION_SLOT_MANAGER_H

#include <memory>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <cstdint>
#include "../keystore/slot.h"  // Inclusion de ton composant Slot documenté

namespace vhsm::session {

/**
 * @class SlotManager
 * @brief Singleton class that manages the lifecycle and access registry of all virtual Slots.
 *
 * The SlotManager is responsible for initializing, storing, and retrieving Slot instances 
 * within the vHSM. It ensures thread-safe operations when applications query available slots 
 * or when tokens are dynamically mapped to slots during system startup or administration.
 */
class SlotManager {
public:
    /**
     * @brief Retrieves the global unique instance of the SlotManager.
     * @return SlotManager& Reference to the singleton instance.
     */
    static SlotManager& get_instance();

    // Delete copy and move operations to enforce strict singleton pattern properties.
    SlotManager(const SlotManager&) = delete;
    SlotManager& operator=(const SlotManager&) = delete;
    SlotManager(SlotManager&&) = delete;
    SlotManager& operator=(SlotManager&&) = delete;

    /**
     * @brief Registers and initializes a new slot within the manager.
     * @param slot_id The unique numerical identifier for the new slot.
     * @return true if registration succeeded, false if the slot_id already exists.
     */
    bool register_slot(u64 slot_id);

    /**
     * @brief Retrieves a specific slot by its unique identifier.
     * @param slot_id The identifier of the target slot.
     * @return std::shared_ptr<Slot> Pointer to the Slot instance, or nullptr if not found.
     */
    std::shared_ptr<keystore::Slot> get_slot(u64 slot_id) const;

    /**
     * @brief Compiles a list of all currently registered slot identifiers.
     * @return std::vector<u64> A list containing all valid slot IDs.
     */
    std::vector<u64> get_slot_id_list() const;

    /**
     * @brief Clears all registered slots from memory. Chiefly used for resetting tests.
     */
    void reset();

private:
    // Private constructor for singleton pattern enforcement.
    SlotManager() = default;
    ~SlotManager() = default;

    /**
     * @brief Internal registry mapping unique Slot IDs to their shared pointer instances.
     */
    std::unordered_map<u64, std::shared_ptr<keystore::Slot>> slots_;

    /**
     * @brief Mutex guarding the internal slots registry mapping from concurrent modifications.
     */
    mutable std::mutex manager_mutex_;
};

} // namespace vhsm

#endif // VHSM_SESSION_SLOT_MANAGER_H