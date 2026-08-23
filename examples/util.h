#ifndef EXAMPLES_UTIL_H
#define EXAMPLES_UTIL_H

// Small helpers shared by the example clients. They exist to keep sensitive
// handling and input validation in exactly one place instead of copy-pasted
// (and drifted) across every example.

#include <openssl/crypto.h>

#include <fstream>
#include <sstream>
#include <string>

namespace examples {

// RAII holder for sensitive material (private keys, wrapping/master keys).
// Wipes its backing store with OPENSSL_cleanse on every exit path, including
// moves and exceptions. A plain std::string is the wrong tool here: the
// optimizer is allowed to (and at -O2 does) elide a memset just before a
// buffer's lifetime ends, so "wipe then free" silently stops wiping.
class SecureString {
public:
  SecureString() = default;
  explicit SecureString(std::string data) : data_(std::move(data)) {}
  ~SecureString() { wipe(); }

  SecureString(const SecureString &) = delete;
  SecureString &operator=(const SecureString &) = delete;

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

  const char *data() const { return data_.data(); }
  std::size_t size() const { return data_.size(); }
  bool empty() const { return data_.empty(); }

  // Zero the live copy. NOTE: once this buffer has been copied into a
  // fabric::identity::Identity, that SDK object still holds a plaintext
  // std::string copy it never wipes — see the documented limitation of
  // Identity. This only shrinks the window the example itself owns.
  void wipe() noexcept {
    if (!data_.empty()) {
      OPENSSL_cleanse(data_.data(), data_.size());
    }
  }

private:
  std::string data_;
};

inline std::string readFile(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw std::runtime_error("cannot open file: " + path);
  }
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// Read a sensitive file into a SecureString. Non-empty check is deliberate:
// an empty key/cert file means the wrong path was passed, and we must not
// hand a zero-length blob to the crypto layer (which would fail opaquely).
inline SecureString readSecureFile(const std::string &path) {
  SecureString s(readFile(path));
  if (s.empty()) {
    throw std::runtime_error("file is empty: " + path);
  }
  return s;
}

// PEM guard: never hand an unvalidated blob to the crypto layer. If the
// content doesn't even contain a "-----BEGIN" header it is the wrong file,
// truncated, or corrupted — reject it loudly rather than let OpenSSL produce
// a cryptic "bad base64" / "no start line" deep in the stack.
inline void expectPem(const std::string &content, const std::string &what) {
  if (content.find("-----BEGIN") == std::string::npos) {
    throw std::runtime_error(what + ": content is not PEM-encoded");
  }
}

inline bool isHex(const std::string &s) {
  return !s.empty() &&
         s.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
}

inline void expectMasterKeyHex(const std::string &s) {
  if (s.size() != 64 || !isHex(s)) {
    throw std::runtime_error(
        "master key must be 64 hex characters (32 bytes), got " +
        std::to_string(s.size()));
  }
}

} // namespace examples

#endif // EXAMPLES_UTIL_H
