#ifndef VHSM_KEYSTORE_KEY_ROTATION_H
#define VHSM_KEYSTORE_KEY_ROTATION_H

#include "hsm_object.h"
#include "key_state.h"
#include "key_wrap.h"

#include <span>
#include <vector>

namespace vhsm::keystore {

// Convenience lifecycle transitions. Each sets the vendor state attribute
// (CKA_VHSM_KEY_STATE) on the object; because the attribute is serialized with
// the object, the transition persists across token save/restore. Any object
// without the attribute reads as Active (see HsmObject::getKeyState).
inline void key_revoke(HsmObject &o) noexcept {
  o.setKeyState(KeyState::Revoked);
}
inline void key_mark_rotating(HsmObject &o) noexcept {
  o.setKeyState(KeyState::Rotating);
}
inline void key_activate(HsmObject &o) noexcept {
  o.setKeyState(KeyState::Active);
}

// KEK rotation primitive: re-encrypt a wrapped key blob under a NEW key
// encryption key. Unwraps with the old KEK, then re-wraps with the new one.
// Throws std::runtime_error (from KeyWrap) if the old blob fails its integrity
// check — fail-closed, so a corrupted or wrong-KEK blob is never re-wrapped.
std::vector<u8> key_rewrap_wrapped(const KeyWrap &oldKw, const KeyWrap &newKw,
                                   std::span<const u8> wrapped);

} // namespace vhsm::keystore

#endif // VHSM_KEYSTORE_KEY_ROTATION_H
