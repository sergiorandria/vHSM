#include "key_rotation.h"

namespace vhsm::keystore {

std::vector<u8> key_rewrap_wrapped(const KeyWrap &oldKw, const KeyWrap &newKw,
                                   std::span<const u8> wrapped) {
  std::vector<u8> raw = oldKw.unwrap(
      std::vector<u8>(wrapped.data(), wrapped.data() + wrapped.size()));
  return newKw.wrap(raw);
}

} // namespace vhsm::keystore
