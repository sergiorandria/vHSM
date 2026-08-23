#ifndef VHSM_CORE_PAL_H
#define VHSM_CORE_PAL_H

// PAL — Platform Abstraction Layer (DDD Infrastructure)
// Centralizes Windows/POSIX divergences so domain and application layers stay
// platform-agnostic. New code should use these helpers instead of raw
// mlock/VirtualLock/open/flock.

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include <cstddef>

namespace vhsm::pal {

// Memory locking — prevents swapping of sensitive buffers (KEK, DRBG state).
inline bool lock_memory(void* addr, std::size_t len) noexcept {
#ifdef _WIN32
  return ::VirtualLock(addr, len) != 0;
#else
  return ::mlock(addr, len) == 0;
#endif
}

inline void unlock_memory(void* addr, std::size_t len) noexcept {
#ifdef _WIN32
  ::VirtualUnlock(addr, len);
#else
  ::munlock(addr, len);
#endif
}

} // namespace vhsm::pal

#endif // VHSM_CORE_PAL_H
