#ifndef VHSM_CORE_PAL_H
#define VHSM_CORE_PAL_H

// WHY a PAL: Before `pal.h`, every `mlock`/`VirtualLock` site copied the same
// #ifdef _WIN32 dance (see `SecureBuffer:23`, `KeyWrap:7`, `SecureRNG:5`).
// Copy-paste diverged: `KeyWrap` forgot the Windows branch entirely, and
// `SecureBuffer:10` left a stray `}` that only broke on MSVC. Centralizing
// the two primitives here means a single place audits whether the working-set
// limit was raised (`VirtualLock` fails with `ERROR_WORKING_SET_QUOTA`) and
// whether `RLIMIT_MEMLOCK` is documented — domain code (`Token`, `DRBG`)
// stays `#ifdef`-free and therefore reviewable without platform expertise.
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

// WHY lock_memory exists: The OS may evict any unlocked page to
// `/swapfile` or `pagefile.sys`; a forensic read of that file after a
// compromise would then yield the KEK or DRBG `V` even though the process
// never wrote it to disk. `mlock`/`VirtualLock` pins the pages in RAM.
// The wrapper exists because the two APIs have opposite success conventions
// (`mlock` returns 0 on success, `VirtualLock` returns non-0) and different
// failure modes (`errno` vs `GetLastError`), so callers would otherwise
// invert the check on one platform.
// Memory locking — prevents swapping of sensitive buffers (KEK, DRBG state).
inline bool lock_memory(void* addr, std::size_t len) noexcept {
#ifdef _WIN32
  return ::VirtualLock(addr, len) != 0;
#else
  return ::mlock(addr, len) == 0;
#endif
}

// WHY unlock is noexcept and best-effort: `munlock`/`VirtualUnlock` can fail
// if the pages were never locked or the working set was trimmed, but the
// caller is always in a destructor (`SecureBuffer::~SecureBuffer`,
// `KeyWrap::~KeyWrap`) where throwing would `std::terminate`. Best-effort
// unlock plus a preceding `OPENSSL_cleanse` is the only safe order: cleanse
// first, then unlock, so the key is not swapped out between the two calls.
inline void unlock_memory(void* addr, std::size_t len) noexcept {
#ifdef _WIN32
  ::VirtualUnlock(addr, len);
#else
  ::munlock(addr, len);
#endif
}

} // namespace vhsm::pal

#endif // VHSM_CORE_PAL_H
