#ifndef VHSM_KEYSTORE_KEY_STATE_H
#define VHSM_KEYSTORE_KEY_STATE_H

#include "../domain/pkcs11/pkcs11_types.h"
#include <cstdint>

namespace vhsm::keystore {

// Lifecycle states for key material. Anchors plan/PLANv5.md §3.2 ("Key
// lifecycle states: active, rotating, revoked") and §6 ("Rotation and
// revocation tested").
enum class KeyState : u8 {
  Active = 0,   // fully usable
  Rotating = 1, // superseded: still valid for VERIFY/DECRYPT during the overlap
                // window, but must not produce NEW signatures.
  Revoked = 2,  // fully disabled; fail-closed on any cryptographic use.
};

// Vendor attribute carrying the lifecycle state on an HsmObject. Mirrors the
// existing CKA_VHSM_* private-key attributes so it serializes with the object
// through the attribute store (no extra persistence work required).
inline constexpr CK_ATTRIBUTE_TYPE CKA_VHSM_KEY_STATE = 0x81000004UL;

// WHY these predicates (see plan §3.2): a Rotating key must remain able to
// VERIFY signatures it previously produced and DECRYPT data encrypted to it,
// but a rotated signing key must not sign new data. Revoked disables all use.
inline bool key_can_sign(KeyState s)    { return s == KeyState::Active; }
inline bool key_can_decrypt(KeyState s) { return s != KeyState::Revoked; }
inline bool key_can_verify(KeyState s)  { return s != KeyState::Revoked; }
inline bool key_can_wrap(KeyState s)    { return s != KeyState::Revoked; }
inline bool key_is_revoked(KeyState s)  { return s == KeyState::Revoked; }

} // namespace vhsm::keystore

#endif // VHSM_KEYSTORE_KEY_STATE_H
