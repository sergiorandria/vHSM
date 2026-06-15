#ifndef VHSM_SESSION_SLOT_H
#define VHSM_SESSION_SLOT_H

#include <memory>
#include <string>
#include <mutex>
#include <cstdint>

#include "token.h"
#include "../core/types.h" 
#include "../core/error.h"

namespace vhsm::keystore {

/**
 * @brief Forward declaration to break compilation dependencies and prevent cyclic inclusions.
 */

/**
 * @class Slot
 * @brief Represents a logical or virtual reader slot within the vHSM, adhering to the PKCS#11 standard.
 *
 * The Slot class acts as a structural interface that can optionally host a single virtual 
 * cryptographic token. In a multi-session architecture, application clients do not interact 
 * with tokens directly; instead, they target a specific SlotID. 
 * This class provides thread-safe operations to manage the token's lifecycle (insertion and removal) 
 * and exposes standardized capability flags required to fulfill system info queries like C_GetSlotInfo.
 *
 * @note This class is non-copyable to prevent concurrent race conditions and ensure mutex uniqueness.
 */
class Slot {
public:
    /**
     * @brief Constructs a virtual slot with a unique identifier.
     * @param slot_id The numerical ID assigned to this slot interface (e.g., 0, 1, 2...).
     */
    explicit Slot(uint64_t slot_id);

    /**
     * @brief Default destructor. Cleans up slot resources.
     */
    ~Slot() = default;

    // Delete copy operations to protect against concurrent hazards and duplicate mutexes.
    Slot(const Slot&) = delete;
    Slot& operator=(const Slot&) = delete;

    /**
     * @brief Retrieves the unique slot identification number.
     * @return uint64_t The slot identifier.
     */
    uint64_t get_id() const { return slot_id_; }

    /**
     * @brief Checks whether a virtual cryptographic token is currently inserted in this slot.
     * @return true if a token is present, false otherwise.
     */
    bool is_token_present() const;
    
    /**
     * @brief Safely attaches a cryptographic token to this slot.
     * @param token Shared pointer to the token instance to insert.
     */
    void insert_token(std::shared_ptr<Token> token);

    /**
     * @brief Detaches and releases the current token from the slot.
     */
    void remove_token();
    
    /**
     * @brief Retrieves a thread-safe reference pointer to the active token.
     * @return std::shared_ptr<token> Pointer to the token, or nullptr if the slot is empty.
     */
    std::shared_ptr<Token> get_token() const;

    /**
     * @brief Gets the structural text description of the slot.
     * @return std::string The description string.
     */
    std::string get_description() const { return description_; }

    /**
     * @brief Gets the manufacturer identifier string.
     * @return std::string The manufacturer ID.
     */
    std::string get_manufacturer() const { return manufacturer_id_; }

    /**
     * @brief Computes and returns standard PKCS#11 capability flags for this slot.
     * @return uint64_t Bitmask containing CKF_REMOVABLE_DEVICE, CKF_HW_SLOT, and CKF_TOKEN_PRESENT.
     */
    uint64_t get_flags() const;

private:
    uint64_t slot_id_;
    std::shared_ptr<Token> token_;
    
    std::string description_;
    std::string manufacturer_id_;
    std::string hardware_version_; 
    std::string firmware_version_; 
    
    /**
     * @brief Mutex protecting the internal token state pointer during runtime hot-plugging operations.
     */
    mutable std::mutex slot_mutex_;
};

} // namespace vhsm::keystore

#endif // VHSM_SESSION_SLOT_H