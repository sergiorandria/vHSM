#ifndef VHSM_PERSISTENCE_LE_BYTES_H
#define VHSM_PERSISTENCE_LE_BYTES_H

#include <cstdint>
#include <vector>

namespace vhsm::persistence {

// Little-endian (de)serialization helpers. The vault and token-snapshot
// formats are explicitly little-endian so the same bytes are portable across
// x86_64 and ARM64. These live here (instead of being copy-pasted into
// vault.cpp and token_serializer.cpp) so the two on-disk layouts stay
// byte-compatible.

inline void put_le32(std::vector<std::uint8_t> &out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v & 0xFF));
  out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}

inline std::uint32_t get_le32(const std::uint8_t *p) {
  return static_cast<std::uint32_t>(p[0]) |
         (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) |
         (static_cast<std::uint32_t>(p[3]) << 24);
}

inline void put_le64(std::vector<std::uint8_t> &out, std::uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
  }
}

inline std::uint64_t get_le64(const std::uint8_t *p) {
  std::uint64_t v = 0;
  for (int i = 7; i >= 0; --i) {
    v = (v << 8) | p[i];
  }
  return v;
}

}  // namespace vhsm::persistence

#endif  // VHSM_PERSISTENCE_LE_BYTES_H
