#ifndef FABRIC_CRYPTO_SECURE_STRING_H
#define FABRIC_CRYPTO_SECURE_STRING_H

#include <openssl/crypto.h>

#include <cstddef>
#include <string>

namespace fabric {
namespace crypto {

// A std::string that scrubs its own backing store with OPENSSL_cleanse on every
// path out of scope — including moves and exceptions. A plain std::string is
// the wrong container for key material: the optimizer is entitled to elide a
// memset immediately before a buffer's lifetime ends, so "wipe then free"
// silently stops wiping. Hold anything sensitive (private keys, pre-master
// secrets, wrapping keys) in this type so there is exactly one place that
// implements "erase sensitive memory" rather than N call sites that might
// forget.
class SecureString {
public:
  SecureString() = default;
  explicit SecureString(std::string data) : data_(std::move(data)) {}
  ~SecureString() { wipe(); }

  // Copyable so that value types holding a SecureString (e.g. Identity)
  // remain regular value types. Each copy is an independent buffer that wipes
  // itself on destruction — strictly safer than the plain std::string it
  // replaces, which also copied but never wiped.
  SecureString(const SecureString &other) : data_(other.data_) {}
  SecureString &operator=(const SecureString &other) {
    if (this != &other) {
      wipe();
      data_ = other.data_;
    }
    return *this;
  }

  SecureString(SecureString &&other) noexcept : data_(std::move(other.data_)) {
    other.data_.clear();
  }
  SecureString &operator=(SecureString &&other) noexcept {
    if (this != &other) {
      wipe();
      data_ = std::move(other.data_);
      other.data_.clear();
    }
    return *this;
  }

  const char *data() const noexcept { return data_.data(); }
  std::size_t size() const noexcept { return data_.size(); }
  bool empty() const noexcept { return data_.empty(); }

  // Expose the underlying string by reference for callers that need a
  // std::string (e.g. OpenSSL PEM APIs). The bytes are still wiped when this
  // object is destroyed.
  const std::string &str() const noexcept { return data_; }

  // Wipe the live copy. Safe to call on a moved-from (now-empty) instance.
  void wipe() noexcept {
    if (!data_.empty()) {
      OPENSSL_cleanse(data_.data(), data_.size());
    }
  }

private:
  std::string data_;
};

}  // namespace crypto
}  // namespace fabric

#endif  // FABRIC_CRYPTO_SECURE_STRING_H
