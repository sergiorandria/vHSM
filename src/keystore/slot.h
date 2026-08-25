#ifndef VHSM_SESSION_SLOT_H
#define VHSM_SESSION_SLOT_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "../core/error.h"
#include "../domain/core/kernel_types.h"
#include "../domain/pkcs11/pkcs11_types.h"
#include "token.h"

namespace vhsm::keystore {

/**
 * @class Slot
 * @brief Represents a logical or virtual reader slot within the vHSM, adhering
 * to the PKCS#11 standard.
 *
 * The Slot class acts as a structural interface that can optionally host a
 * single virtual cryptographic token. In a multi-session architecture,
 * application clients do not interact with tokens directly; instead, they
 * target a specific SlotID. This class provides thread-safe operations to
 * manage the token's lifecycle (insertion and removal) and exposes standardized
 * capability flags required to fulfill system info queries like C_GetSlotInfo.
 *
 * @note This class is non-copyable to prevent concurrent race conditions and
 * ensure mutex uniqueness.
 *
 * WHY Slot abstraction: PKCS#11 models hardware readers (USB tokens, smart
 * cards, HSMs) as "slots". Even though vHSM is software, we follow the same
 * model for API compatibility. A Slot can contain a Token; applications
 * interact with the Slot (by ID), and the Slot routes requests to the Token.
 * This lets us implement multi-token scenarios later (e.g., different tokens on
 * different slots).
 *
 * WHY non-copyable: Each Slot has a unique slot_id and its own mutex. Copying
 * would violate identity constraints (two slots with the same ID could exist).
 * Non-copyable enforces that slots are managed (heap-allocated, referenced by
 * shared_ptr) and never duplicated.
 *
 * WHY thread-safe token insertion/removal: Applications can request slot info,
 * insert a token, and submit transactions concurrently. We use shared_ptr so
 * existing transactions using a token won't crash if the token is removed. The
 * mutex serializes insert/remove operations.
 */
class Slot {
public:
  /**
   * @brief Constructs a virtual slot with a unique identifier.
   * @param slot_id The numerical ID assigned to this slot interface (e.g., 0,
   * 1, 2...).
   *
   * WHY slot_id is immutable: The ID is the Slot's identity. Allowing changes
   * would break references. Applications use slot_id to find Slots (e.g., in a
   * factory). Immutability is enforced by making it const (via constructor
   * assignment only).
   */
  explicit Slot(u64 slot_id);

  /**
   * @brief Default destructor. Cleans up slot resources.
   */
  ~Slot() = default;

  // WHY delete copy: Same reason as Token. Each Slot has a unique mutex and
  // identity. Copying would duplicate the mutex (breaking synchronization) and
  // identity.
  Slot(const Slot &) = delete;
  Slot &operator=(const Slot &) = delete;

  /**
   * @brief Retrieves the unique slot identification number.
   * @return u64 The slot identifier.
   */
  u64 get_id() const { return slot_id_; }

  /**
   * @brief Checks whether a virtual cryptographic token is currently inserted
   * in this slot.
   * @return true if a token is present, false otherwise.
   *
   * WHY separate from get_token(): is_token_present() returns a boolean without
   * allocating a shared_ptr. Callers that only need to know "is a token here?"
   * avoid overhead.
   */
  bool is_token_present() const;

  /**
   * @brief Safely attaches a cryptographic token to this slot.
   * @param token Shared pointer to the token instance to insert.
   *
   * WHY take shared_ptr: The caller and this Slot both hold references to the
   * token. shared_ptr manages lifetime (last to release destroys it). If the
   * caller releases while we hold, the token stays alive. If we remove and the
   * caller still holds, the token stays alive until the caller releases too.
   */
  void insert_token(std::shared_ptr<Token> token);

  /**
   * @brief Detaches and releases the current token from the slot.
   *
   * WHY this just releases, doesn't destroy: The token may still be in use by
   * existing transactions. shared_ptr keeps it alive until the last transaction
   * completes. Clients see "token removed" but the object doesn't disappear
   * from under them.
   */
  void remove_token();

  /**
   * @brief Retrieves a thread-safe reference pointer to the active token.
   * @return std::shared_ptr<token> Pointer to the token, or nullptr if the slot
   * is empty.
   *
   * WHY return shared_ptr: The caller gets a reference that keeps the token
   * alive even if the slot is removed (or another thread removes it). This is
   * the key to lock-free design: transactions don't need to hold the
   * slot_mutex_ while using the token.
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
   * @brief Computes and returns standard PKCS#11 capability flags for this
   * slot.
   * @return u64 Bitmask containing CKF_REMOVABLE_DEVICE, CKF_HW_SLOT, and
   * CKF_TOKEN_PRESENT.
   *
   * WHY computed on-the-fly (not cached): Flags may change (e.g., token is
   * inserted/removed). Computing them on demand is cheap (a few bitwise ops)
   * and always accurate. Caching would require invalidation logic when token
   * state changes.
   */
  u64 get_flags() const;

  /**
   * @brief Define the firmware version. Should be newer than the current
   * version
   * @return
   */
  void define_firmware_version(const struct version &);

private:
  // WHY u64 slot_id_: const would be cleaner, but shared_ptr member forces us
  // to allow moves. Moving a const member is error-prone. u64 is small and we
  // just ensure it never changes after construction.
  u64 slot_id_;

  // WHY shared_ptr<Token>: Applications hold tokens across async calls.
  // shared_ptr ensures the token survives token removal (app still has a
  // reference).
  std::shared_ptr<Token> token_;

  // WHY these metadata fields: PKCS#11 queries require slot description,
  // manufacturer, and version info. Storing them here means quick answers to
  // C_GetSlotInfo.
  std::string description_;
  std::string manufacturer_id_;
  struct version hardware_version_;
  struct version firmware_version_;

  /**
   * @brief Mutex protecting the internal token state pointer during runtime
   * hot-plugging operations.
   *
   * WHY slot_mutex_ is mutable: get_token() is const (query-only), but it locks
   * slot_mutex_ to safely read token_. mutable allows const methods to modify
   * mutable fields (the mutex). This is a common pattern for fine-grained const
   * semantics.
   */
  mutable std::mutex slot_mutex_;
};

} // namespace vhsm::keystore

#endif // VHSM_SESSION_SLOT_H