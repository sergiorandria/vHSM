#include "vhsm/scrypto/mem.h"
#include <cstring>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <strings.h> // explicit_bzero
#endif

namespace vhsm::scrypto {

void cleanse(void *ptr, size_t len) noexcept {
  if (!ptr || len == 0)
    return;
#if defined(_WIN32)
  SecureZeroMemory(ptr, len);
#else
#if defined(__GLIBC__) &&                                                      \
    (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
  explicit_bzero(ptr, len);
#else
  volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
  while (len--)
    *p++ = 0;
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
#endif
}

SecureBytes::SecureBytes(size_t n) { resize(n); }
SecureBytes::~SecureBytes() noexcept { clear(); }

SecureBytes::SecureBytes(SecureBytes &&o) noexcept
    : ptr_(o.ptr_), len_(o.len_), cap_(o.cap_) {
  o.ptr_ = nullptr;
  o.len_ = 0;
  o.cap_ = 0;
}
SecureBytes &SecureBytes::operator=(SecureBytes &&o) noexcept {
  if (this != &o) {
    clear();
    ptr_ = o.ptr_;
    len_ = o.len_;
    cap_ = o.cap_;
    o.ptr_ = nullptr;
    o.len_ = 0;
    o.cap_ = 0;
  }
  return *this;
}
void SecureBytes::resize(size_t n) {
  if (n == 0) {
    clear();
    return;
  }
  if (n <= cap_) {
    len_ = n;
    return;
  }
  // allocate new, mlock, copy
  uint8_t *np = new uint8_t[n];
  mlock_mem(np, n);
  if (ptr_ && len_ > 0)
    std::memcpy(np, ptr_, std::min(len_, n));
  clear();
  ptr_ = np;
  len_ = n;
  cap_ = n;
}
void SecureBytes::clear() noexcept {
  if (ptr_) {
    cleanse(ptr_, cap_);
    munlock_mem(ptr_, cap_);
    delete[] ptr_;
    ptr_ = nullptr;
    len_ = 0;
    cap_ = 0;
  }
}

} // namespace vhsm::scrypto
