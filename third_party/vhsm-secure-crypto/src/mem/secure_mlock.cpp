#include "vhsm/scrypto/mem.h"
#include <stdexcept>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#endif

namespace vhsm::scrypto {

void mlock_mem(void *addr, size_t len) {
  if (!addr || len == 0)
    return;
#ifdef _WIN32
  if (!VirtualLock(addr, len)) {
    throw std::runtime_error("mlock_mem: VirtualLock failed");
  }
#else
  if (mlock(addr, len) != 0) {
    // Fail-closed: if we cannot lock, we still throw but caller may decide.
    // For hardening we throw — prevents swap leakage being silent.
    throw std::runtime_error(std::string("mlock failed: ") + strerror(errno));
  }
#endif
}
void munlock_mem(void *addr, size_t len) noexcept {
  if (!addr || len == 0)
    return;
#ifdef _WIN32
  VirtualUnlock(addr, len);
#else
  munlock(addr, len);
#endif
}

} // namespace vhsm::scrypto
