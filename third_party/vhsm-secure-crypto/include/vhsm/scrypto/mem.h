#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vhsm::scrypto {

// Overwrite memory with zeros in a way the compiler cannot elide.
// Uses explicit_bzero / SecureZeroMemory / volatile barrier.
void cleanse(void *ptr, size_t len) noexcept;

// RAII cleanser for vectors/strings
template <typename T> void cleanse_vec(std::vector<T> &v) noexcept {
  if (!v.empty())
    cleanse(v.data(), v.size() * sizeof(T));
}
inline void cleanse_str(std::string &s) noexcept {
  if (!s.empty())
    cleanse(s.data(), s.size());
}

// mlock / VirtualLock wrappers — throw on failure (fail-closed, not silent)
void mlock_mem(void *addr, size_t len);
void munlock_mem(void *addr, size_t len) noexcept;

// Secure buffer that mlocks and cleanses on destruction (for KEK, DRBG state)
class SecureBytes {
public:
  explicit SecureBytes(size_t n = 0);
  ~SecureBytes() noexcept;
  SecureBytes(const SecureBytes &) = delete;
  SecureBytes &operator=(const SecureBytes &) = delete;
  SecureBytes(SecureBytes &&o) noexcept;
  SecureBytes &operator=(SecureBytes &&o) noexcept;
  uint8_t *data() noexcept { return ptr_; }
  const uint8_t *data() const noexcept { return ptr_; }
  size_t size() const noexcept { return len_; }
  void resize(size_t n);
  void clear() noexcept;

private:
  uint8_t *ptr_ = nullptr;
  size_t len_ = 0;
  size_t cap_ = 0;
};

} // namespace vhsm::scrypto
