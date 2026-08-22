#include "fabric/identity/wallet.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <concepts>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <optional>
#include <ranges>
#include <shared_mutex>
#include <span>
#include <thread>
#include <unordered_map>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace fabric::identity {

// Error category
namespace {
class WalletErrorCategory final : public std::error_category {
public:
  [[nodiscard]] const char *name() const noexcept override {
    return "fabric.wallet";
  }

  [[nodiscard]] std::string message(int ev) const override {
    switch (static_cast<WalletErrc>(ev)) {
    case WalletErrc::InvalidLabel:
      return "invalid identity label";
    case WalletErrc::KeyUnavailable:
      return "master key not available";
    case WalletErrc::NotFound:
      return "identity not found";
    case WalletErrc::IoError:
      return "filesystem I/O error";
    case WalletErrc::CryptoError:
      return "AEAD authentication failed (corrupt or tampered data)";
    case WalletErrc::LockTimeout:
      return "timed out acquiring wallet lock";
    case WalletErrc::AlreadyExists:
      return "identity already exists";
    }
    return "unknown wallet error";
  }
};
} // namespace

const std::error_category &walletCategory() noexcept {
  static const WalletErrorCategory category;
  return category;
}

std::error_code make_error_code(const WalletErrc&& e) noexcept {
  return {static_cast<int>(e), walletCategory()};
}

namespace {

// A minimal, allocation-free scope guard (à la gsl::final_action), used
// anywhere a cleanup step (close an fd, remove a temp file) must run on
// every exit path — including the early-return error paths — without
// duplicating that step at each return statement.
template <std::invocable F> class ScopeExit {
public:
  explicit ScopeExit(F action) noexcept : action_(std::move(action)) {}
  ~ScopeExit() {
    if (active_)
      action_();
  }
  ScopeExit(const ScopeExit &) = delete;
  ScopeExit &operator=(const ScopeExit &) = delete;
  void release() noexcept { active_ = false; }

private:
  F action_;
  bool active_ = true;
};

// Constrains a type to a contiguous range of 1-byte elements (char,
// unsigned char, std::byte, ...). Used to accept "anything byte-shaped"
// (std::string, std::string_view, std::vector<std::byte>, std::array<...>)
// through a single conversion point instead of ad-hoc reinterpret_casts
// scattered through the file.
template <typename R>
concept ByteRange =
    std::ranges::contiguous_range<R> && std::ranges::sized_range<R> &&
    (sizeof(std::ranges::range_value_t<R>) == 1);

template <ByteRange R>
[[nodiscard]] std::span<const std::byte> toBytes(const R &r) noexcept {
  return std::as_bytes(std::span(r));
}

// A byte buffer that is guaranteed to be wiped on every path out of scope,
// including moves-from and exceptions. Key material and plaintext identity
// data live in this type end to end so there is exactly one place that
// implements "erase sensitive memory" rather than N call sites that might
// forget to.
class SecureBytes {
public:
  SecureBytes() = default;
  explicit SecureBytes(std::size_t n) : data_(n) {}

  SecureBytes(const SecureBytes &) = delete;
  SecureBytes &operator=(const SecureBytes &) = delete;

  SecureBytes(SecureBytes &&other) noexcept : data_(std::move(other.data_)) {
    other.data_.clear();
  }
  SecureBytes &operator=(SecureBytes &&other) noexcept {
    if (this != &other) {
      wipe();
      data_ = std::move(other.data_);
      other.data_.clear();
    }
    return *this;
  }

  ~SecureBytes() { wipe(); }

  [[nodiscard]] std::span<std::byte> span() noexcept { return data_; }
  [[nodiscard]] std::span<const std::byte> span() const noexcept {
    return data_;
  }
  [[nodiscard]] std::byte *data() noexcept { return data_.data(); }
  [[nodiscard]] const std::byte *data() const noexcept { return data_.data(); }
  [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
  [[nodiscard]] bool empty() const noexcept { return data_.empty(); }

  void resize(std::size_t n) { data_.resize(n); }
  void append(std::span<const std::byte> extra) {
    data_.insert(data_.end(), extra.begin(), extra.end());
  }

private:
  void wipe() noexcept {
    if (!data_.empty()) {
      // OPENSSL_cleanse routes the write through a volatile function
      // pointer internally, which is what keeps the store alive under
      // optimization. A plain memset() immediately before a buffer's
      // lifetime ends is exactly the kind of "dead store" a real compiler
      // is entitled to (and, at -O2, does) eliminate — the whole point of
      // wiping key material would be silently compiled away. Routing
      // through OPENSSL_cleanse is the standard, portable way around that.
      OPENSSL_cleanse(data_.data(), data_.size());
    }
  }

  std::vector<std::byte> data_;
};

[[nodiscard]] std::optional<SecureBytes> hexDecode(std::string_view hex) {
  constexpr auto nibble = [](char c) constexpr -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  if (hex.size() % 2 != 0)
    return std::nullopt;
  SecureBytes out(hex.size() / 2);
  auto span = out.span();
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int hi = nibble(hex[i]);
    const int lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0)
      return std::nullopt;
    span[i / 2] = static_cast<std::byte>((hi << 4) | lo);
  }
  return out;
}

[[nodiscard]] constexpr bool isValidLabelChar(char c) noexcept {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

[[nodiscard]] bool isValidLabel(std::string_view label) noexcept {
  if (label.empty() || label.size() > 128) [[unlikely]]
    return false;
  if (label == "." || label == "..") [[unlikely]]
    return false;
  return std::ranges::all_of(label, isValidLabelChar);
}

// magic + version identify the format; nonce + tag are GCM's IV and
// authentication tag. Packed and static_assert'd so the struct's layout
// exactly matches what's written to disk regardless of the platform's
// default struct alignment/padding rules.
inline constexpr std::array<char, 4> kMagic = {'F', 'H', 'W', '2'};
inline constexpr std::uint8_t kVersion =
    2; // v2: AAD-bound to label (see aeadEncrypt)
inline constexpr std::size_t kNonceLen = 12;
inline constexpr std::size_t kTagLen = 16;
inline constexpr std::size_t kKeyLen = 32;

#pragma pack(push, 1)
struct FileHeader {
  std::array<char, 4> magic;
  std::uint8_t version;
  std::array<std::byte, kNonceLen> nonce;
  std::array<std::byte, kTagLen> tag;
};
#pragma pack(pop)

static_assert(sizeof(FileHeader) == 4 + 1 + kNonceLen + kTagLen,
              "FileHeader must be tightly packed to match the on-disk format");
static_assert(std::is_trivially_copyable_v<FileHeader>);

// Binding the label into GCM's AAD means the authentication tag no longer
// just certifies "this ciphertext wasn't corrupted" — it certifies "this
// ciphertext was produced for *this exact label*". Without this, an
// attacker with filesystem write access (a bug elsewhere, a bad restore, a
// racing process) could rename alice.id to bob.id and get("bob") would
// return alice's identity: the GCM tag alone says nothing about which
// filename it's supposed to live under.

struct EvpCtxDeleter {
  void operator()(EVP_CIPHER_CTX *ctx) const noexcept {
    EVP_CIPHER_CTX_free(ctx);
  }
};
using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCtxDeleter>;

[[nodiscard]] Result<void> aeadEncrypt(std::span<const std::byte> key,
                                       std::span<const std::byte> aad,
                                       std::span<const std::byte> plaintext,
                                       SecureBytes &out) {
  static_assert(sizeof(unsigned char) == sizeof(std::byte));

  EvpCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  FileHeader header{
      .magic = kMagic, .version = kVersion, .nonce = {}, .tag = {}};
  if (RAND_bytes(reinterpret_cast<unsigned char *>(header.nonce.data()),
                 static_cast<int>(header.nonce.size())) != 1) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  const auto *keyPtr = reinterpret_cast<const unsigned char *>(key.data());
  const auto *noncePtr =
      reinterpret_cast<const unsigned char *>(header.nonce.data());

  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(header.nonce.size()),
                          nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, keyPtr, noncePtr) != 1)
      [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  int ignoredLen = 0;
  if (!aad.empty() &&
      EVP_EncryptUpdate(ctx.get(), nullptr, &ignoredLen,
                        reinterpret_cast<const unsigned char *>(aad.data()),
                        static_cast<int>(aad.size())) != 1) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  SecureBytes ciphertext(plaintext.size());
  int len = 0;
  if (!plaintext.empty() &&
      EVP_EncryptUpdate(
          ctx.get(), reinterpret_cast<unsigned char *>(ciphertext.data()), &len,
          reinterpret_cast<const unsigned char *>(plaintext.data()),
          static_cast<int>(plaintext.size())) != 1) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }
  int finalLen = 0;
  if (EVP_EncryptFinal_ex(
          ctx.get(), reinterpret_cast<unsigned char *>(ciphertext.data()) + len,
          &finalLen) != 1) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                          static_cast<int>(header.tag.size()),
                          header.tag.data()) != 1) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  out.resize(0);
  out.append(std::as_bytes(std::span(&header, 1)));
  out.append(ciphertext.span());
  return {};
}

[[nodiscard]] Result<SecureBytes> aeadDecrypt(std::span<const std::byte> key,
                                              std::span<const std::byte> aad,
                                              std::span<const std::byte> blob) {
  if (blob.size() < sizeof(FileHeader)) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  FileHeader header;
  std::memcpy(&header, blob.data(), sizeof(FileHeader));
  if (header.magic != kMagic || header.version != kVersion) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  const auto ciphertext = blob.subspan(sizeof(FileHeader));

  EvpCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  const auto *keyPtr = reinterpret_cast<const unsigned char *>(key.data());
  const auto *noncePtr =
      reinterpret_cast<const unsigned char *>(header.nonce.data());

  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(header.nonce.size()),
                          nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, keyPtr, noncePtr) != 1)
      [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  int ignoredLen = 0;
  if (!aad.empty() &&
      EVP_DecryptUpdate(ctx.get(), nullptr, &ignoredLen,
                        reinterpret_cast<const unsigned char *>(aad.data()),
                        static_cast<int>(aad.size())) != 1) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  SecureBytes plaintext(ciphertext.size());
  int len = 0;
  if (!ciphertext.empty() &&
      EVP_DecryptUpdate(
          ctx.get(), reinterpret_cast<unsigned char *>(plaintext.data()), &len,
          reinterpret_cast<const unsigned char *>(ciphertext.data()),
          static_cast<int>(ciphertext.size())) != 1) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                          static_cast<int>(header.tag.size()),
                          header.tag.data()) != 1) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  int finalLen = 0;
  if (EVP_DecryptFinal_ex(
          ctx.get(), reinterpret_cast<unsigned char *>(plaintext.data()) + len,
          &finalLen) != 1) [[unlikely]] {
    // Authentication failed — corruption, wrong key, or tampering. `plaintext`
    // currently holds unauthenticated bytes that must never be trusted or
    // returned to a caller; SecureBytes's destructor wipes them the instant
    // this function returns, so nothing unauthenticated escapes this scope.
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }

  return plaintext;
}

// The previous format joined fields with NUL separators, which is fragile:
// it silently misparses if a certificate or key ever legitimately contains a
// NUL byte. Length-prefixing removes that assumption entirely.

[[nodiscard]] std::array<std::byte, 4> encodeLength(std::uint32_t n) noexcept {
  if constexpr (std::endian::native != std::endian::big) {
    n = std::byteswap(n);
  }
  std::array<std::byte, 4> out;
  std::memcpy(out.data(), &n, 4);
  return out;
}

[[nodiscard]] std::uint32_t
decodeLength(std::span<const std::byte> bytes) noexcept {
  std::uint32_t n;
  std::memcpy(&n, bytes.data(), 4);
  if constexpr (std::endian::native != std::endian::big) {
    n = std::byteswap(n);
  }
  return n;
}

[[nodiscard]] SecureBytes serializeIdentity(const Identity &id) {
  SecureBytes out;
  const auto appendField = [&out](std::string_view field) {
    const std::array<std::byte, 4> lenBytes =
        encodeLength(static_cast<std::uint32_t>(field.size()));
    out.append(std::as_bytes(std::span(lenBytes)));
    out.append(toBytes(field));
  };
  appendField(id.getMSPID());
  appendField(id.getCertificate());
  appendField(id.getPrivateKey());
  return out;
}

[[nodiscard]] std::optional<std::unique_ptr<Identity>>
deserializeIdentity(std::span<const std::byte> remaining) {
  const auto readField = [&remaining](std::string &out) -> bool {
    if (remaining.size() < 4)
      return false;
    const std::uint32_t len = decodeLength(remaining.first(4));
    remaining = remaining.subspan(4);
    if (remaining.size() < len)
      return false;
    out.assign(reinterpret_cast<const char *>(remaining.data()), len);
    remaining = remaining.subspan(len);
    return true;
  };
  std::string msp, cert, key;
  if (!readField(msp) || !readField(cert) || !readField(key))
    return std::nullopt;
  return std::make_unique<Identity>(std::move(msp), std::move(cert),
                                    std::move(key));
}

[[nodiscard]] Result<void>
ensureWalletDirectory(const std::filesystem::path &dir) {
  namespace fs = std::filesystem;
  std::error_code ec;
  if (!fs::exists(dir, ec)) {
    fs::create_directories(dir, ec);
    if (ec) [[unlikely]]
      return std::unexpected(ec);
  } else if (ec) [[unlikely]] {
    return std::unexpected(ec);
  }
  // Only the wallet directory itself is touched. The previous implementation
  // walked and chmod'd every path component, which meant the *first* time it
  // ran against a not-yet-existing path it would silently narrow permissions
  // on ancestor directories it neither owns nor understands the purpose of.
  fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
  if (ec) [[unlikely]]
    return std::unexpected(ec);
  return {};
}

[[nodiscard]] Result<void>
writeFileAtomic(const std::filesystem::path &finalPath,
                std::span<const std::byte> data) {
  namespace fs = std::filesystem;
  fs::path tmp = finalPath;
  tmp += ".tmp";

  std::error_code ignored;
  fs::remove(tmp,
             ignored); // best-effort: clear a stale temp from a crashed writer

  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
                        static_cast<mode_t>(0600));
  if (fd < 0) [[unlikely]] {
    return std::unexpected(std::error_code(errno, std::generic_category()));
  }
  ScopeExit closeFd([fd] { ::close(fd); });

  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t written = ::write(fd, data.data() + off, data.size() - off);
    if (written < 0) [[unlikely]] {
      if (errno == EINTR)
        continue;
      fs::remove(tmp, ignored);
      return std::unexpected(std::error_code(errno, std::generic_category()));
    }
    off += static_cast<std::size_t>(written);
  }

  if (::fsync(fd) != 0) [[unlikely]] {
    fs::remove(tmp, ignored);
    return std::unexpected(std::error_code(errno, std::generic_category()));
  }
  closeFd.release();
  if (::close(fd) != 0) [[unlikely]] {
    fs::remove(tmp, ignored);
    return std::unexpected(std::error_code(errno, std::generic_category()));
  }

  std::error_code permEc;
  fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write,
                  fs::perm_options::replace, permEc);
  if (permEc) [[unlikely]] {
    fs::remove(tmp, ignored);
    return std::unexpected(permEc);
  }

  std::error_code renameEc;
  fs::rename(tmp, finalPath, renameEc); // atomic on the same filesystem
  if (renameEc) [[unlikely]] {
    fs::remove(tmp, ignored);
    return std::unexpected(renameEc);
  }
  return {};
}

void secureDelete(const std::filesystem::path &path) noexcept {
  const int fd = ::open(path.c_str(), O_WRONLY);
  if (fd >= 0) {
    struct stat st{};
    if (::fstat(fd, &st) == 0 && st.st_size > 0) {
      static constexpr std::size_t kChunk = 4096;
      const std::array<std::byte, kChunk> zeros{};
      std::size_t total = static_cast<std::size_t>(st.st_size);
      std::size_t off = 0;
      while (off < total) {
        const std::size_t chunk = std::min(kChunk, total - off);
        const ssize_t w = ::write(fd, zeros.data(), chunk);
        if (w <= 0)
          break;
        off += static_cast<std::size_t>(w);
      }
      ::fsync(fd);
    }
    ::close(fd);
  }
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
}

// Two independent layers, because they guarantee different things:
//
//  1. DirectoryLockRegistry hands out one std::shared_mutex per canonical
//     wallet directory, shared by every CustomHardenedWallet instance (and
//     therefore every thread) in this process that points at that
//     directory. This is what actually protects concurrent threads in the
//     same process — flock() cannot, because a flock() held by one open
//     file description does not exclude a *different* open file description
//     obtained by another thread open()-ing the same lock file, even though
//     both live in the same process.
//
//  2. ProcessFileLock wraps flock() with a bounded, backing-off retry loop,
//     giving mutual exclusion across distinct processes (and a bounded
//     wait instead of blocking forever if another process holds the lock
//     and stalls or dies without releasing it via something other than
//     process exit).

class DirectoryLockRegistry {
public:
  static DirectoryLockRegistry &instance() {
    static DirectoryLockRegistry registry;
    return registry;
  }

  [[nodiscard]] std::shared_ptr<std::shared_mutex>
  mutexFor(const std::filesystem::path &dir) {
    std::lock_guard guard(mapMutex_);
    auto [it, inserted] = mutexes_.try_emplace(dir);
    if (inserted)
      it->second = std::make_shared<std::shared_mutex>();
    return it->second;
  }

private:
  std::mutex mapMutex_;
  std::unordered_map<std::filesystem::path, std::shared_ptr<std::shared_mutex>>
      mutexes_;
};

enum class LockMode { Shared, Exclusive };

class ProcessFileLock {
public:
  ProcessFileLock(const std::filesystem::path &lockPath, LockMode mode,
                  std::chrono::milliseconds timeout) {
    fd_ =
        ::open(lockPath.c_str(), O_WRONLY | O_CREAT, static_cast<mode_t>(0600));
    if (fd_ < 0) [[unlikely]]
      return;

    const int operation =
        (mode == LockMode::Exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::chrono::milliseconds backoff{1};
    for (;;) {
      if (::flock(fd_, operation) == 0) {
        locked_ = true;
        return;
      }
      if (errno != EWOULDBLOCK) [[unlikely]]
        return;
      if (std::chrono::steady_clock::now() >= deadline)
        return;
      std::this_thread::sleep_for(backoff);
      backoff = std::min(backoff * 2, std::chrono::milliseconds(50));
    }
  }

  ~ProcessFileLock() {
    if (fd_ >= 0) {
      if (locked_)
        ::flock(fd_, LOCK_UN);
      ::close(fd_);
    }
  }

  ProcessFileLock(const ProcessFileLock &) = delete;
  ProcessFileLock &operator=(const ProcessFileLock &) = delete;

  [[nodiscard]] bool acquired() const noexcept { return locked_; }

private:
  int fd_ = -1;
  bool locked_ = false;
};

} // namespace

namespace {
// A transparent hash lets the unordered_map be looked up by string_view
// directly (find/contains, and — since C++23 — erase), so a lookup by label
// never has to materialize a temporary std::string just to satisfy the
// container's key type.
struct StringHash {
  using is_transparent = void;
  [[nodiscard]] std::size_t operator()(std::string_view sv) const noexcept {
    return std::hash<std::string_view>{}(sv);
  }
};
} // namespace

class InMemoryWallet::Impl {
public:
  mutable std::shared_mutex mutex;
  std::unordered_map<std::string, Identity, StringHash, std::equal_to<>>
      identities;
};

InMemoryWallet::InMemoryWallet() : pimpl_(std::make_unique<Impl>()) {}
InMemoryWallet::~InMemoryWallet() = default;

Result<void> InMemoryWallet::put(std::string_view label,
                                 const Identity &identity) {
  if (!isValidLabel(label)) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::InvalidLabel));
  }
  std::unique_lock lock(pimpl_->mutex);
  auto [it, inserted] =
      pimpl_->identities.try_emplace(std::string(label), identity);
  if (!inserted) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::AlreadyExists));
  }
  return {};
}

Result<std::unique_ptr<Identity>> InMemoryWallet::get(std::string_view label) {
  std::shared_lock lock(pimpl_->mutex);
  const auto it = pimpl_->identities.find(label);
  if (it == pimpl_->identities.end()) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::NotFound));
  }
  return std::make_unique<Identity>(it->second);
}

Result<void> InMemoryWallet::deleteIdentity(std::string_view label) {
  std::unique_lock lock(pimpl_->mutex);
  // Heterogeneous find() (C++20) works via the transparent hash; erase() by
  // key would too under the full C++23 rules (P2077), but at the time of
  // writing libstdc++'s unordered_map hasn't caught up to that overload —
  // find-then-erase-by-iterator is the portable equivalent.
  const auto it = pimpl_->identities.find(label);
  if (it == pimpl_->identities.end()) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::NotFound));
  }
  pimpl_->identities.erase(it);
  return {};
}

bool InMemoryWallet::exists(std::string_view label) {
  std::shared_lock lock(pimpl_->mutex);
  return pimpl_->identities.contains(label);
}

std::vector<std::string> InMemoryWallet::list() {
  std::shared_lock lock(pimpl_->mutex);
  std::vector<std::string> result;
  result.reserve(pimpl_->identities.size());
  for (const auto &[label, unused] : pimpl_->identities)
    result.push_back(label);
  return result;
}

class CustomHardenedWallet::Impl {
public:
  Impl(std::filesystem::path baseDirectory, Options opts)
      : options(std::move(opts)) {
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(baseDirectory, ec);
    dir = ec ? std::move(baseDirectory) : std::move(canonical);
    rwLock = DirectoryLockRegistry::instance().mutexFor(dir);
    loadMasterKey();
  }

  void loadMasterKey() {
    const char *env = std::getenv(options.masterKeyEnvVar.c_str());
    if (!env) {
      keyValid = false;
      return;
    }
    std::string hex(env);
    ScopeExit cleanseHex([&hex] { OPENSSL_cleanse(hex.data(), hex.size()); });
    std::erase_if(hex, [](unsigned char c) { return std::isspace(c) != 0; });

    auto decoded = hexDecode(hex);
    if (!decoded || decoded->size() != kKeyLen) {
      keyValid = false;
      return;
    }
    masterKey = std::move(*decoded);
    keyValid = true;
  }

  [[nodiscard]] std::filesystem::path pathFor(std::string_view label) const {
    return dir / (std::string(label) + ".id");
  }

  [[nodiscard]] std::filesystem::path lockPath() const { return dir / ".lock"; }

  Options options;
  bool keyValid = false;
  SecureBytes masterKey;
  std::filesystem::path dir;
  std::shared_ptr<std::shared_mutex> rwLock;
};

Result<CustomHardenedWallet>
CustomHardenedWallet::create(std::filesystem::path baseDirectory) {
  return create(std::move(baseDirectory), Options{});
}

Result<CustomHardenedWallet>
CustomHardenedWallet::create(std::filesystem::path baseDirectory,
                             Options options) {
  auto impl =
      std::make_unique<Impl>(std::move(baseDirectory), std::move(options));
  if (auto r = ensureWalletDirectory(impl->dir); !r) [[unlikely]] {
    return std::unexpected(r.error());
  }
  return CustomHardenedWallet(std::move(impl));
}

CustomHardenedWallet::CustomHardenedWallet(std::unique_ptr<Impl> impl) noexcept
    : pimpl_(std::move(impl)) {}
CustomHardenedWallet::~CustomHardenedWallet() = default;
CustomHardenedWallet::CustomHardenedWallet(CustomHardenedWallet &&) noexcept =
    default;
CustomHardenedWallet &
CustomHardenedWallet::operator=(CustomHardenedWallet &&) noexcept = default;

bool CustomHardenedWallet::hasMasterKey() const noexcept {
  return pimpl_->keyValid;
}

Result<void> CustomHardenedWallet::put(std::string_view label,
                                       const Identity &identity) {
  if (!isValidLabel(label)) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::InvalidLabel));
  }
  if (!pimpl_->keyValid) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::KeyUnavailable));
  }

  std::unique_lock intraProcess(*pimpl_->rwLock);
  const ProcessFileLock interProcess(pimpl_->lockPath(), LockMode::Exclusive,
                                     pimpl_->options.lockTimeout);
  if (!interProcess.acquired()) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::LockTimeout));
  }

  const SecureBytes plaintext = serializeIdentity(identity);
  SecureBytes blob;
  if (auto r = aeadEncrypt(pimpl_->masterKey.span(), toBytes(label),
                           plaintext.span(), blob);
      !r) [[unlikely]] {
    return std::unexpected(r.error());
  }
  return writeFileAtomic(pimpl_->pathFor(label), blob.span());
}

Result<std::unique_ptr<Identity>>
CustomHardenedWallet::get(std::string_view label) {
  if (!isValidLabel(label)) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::InvalidLabel));
  }
  if (!pimpl_->keyValid) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::KeyUnavailable));
  }

  std::shared_lock intraProcess(*pimpl_->rwLock);
  const ProcessFileLock interProcess(pimpl_->lockPath(), LockMode::Shared,
                                     pimpl_->options.lockTimeout);
  if (!interProcess.acquired()) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::LockTimeout));
  }

  const auto path = pimpl_->pathFor(label);
  std::error_code sizeEc;
  const auto size = std::filesystem::file_size(path, sizeEc);
  if (sizeEc) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::NotFound));
  }

  std::vector<std::byte> blob(size);
  std::ifstream file(path, std::ios::binary);
  if (!file) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::IoError));
  }
  file.read(reinterpret_cast<char *>(blob.data()),
            static_cast<std::streamsize>(blob.size()));
  if (!file) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::IoError));
  }

  auto plaintext = aeadDecrypt(pimpl_->masterKey.span(), toBytes(label), blob);
  if (!plaintext) [[unlikely]] {
    return std::unexpected(plaintext.error());
  }

  auto identity = deserializeIdentity(plaintext->span());
  if (!identity) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::CryptoError));
  }
  return std::move(*identity);
}

Result<void> CustomHardenedWallet::deleteIdentity(std::string_view label) {
  if (!isValidLabel(label)) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::InvalidLabel));
  }

  std::unique_lock intraProcess(*pimpl_->rwLock);
  const ProcessFileLock interProcess(pimpl_->lockPath(), LockMode::Exclusive,
                                     pimpl_->options.lockTimeout);
  if (!interProcess.acquired()) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::LockTimeout));
  }

  const auto path = pimpl_->pathFor(label);
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) [[unlikely]] {
    return std::unexpected(make_error_code(WalletErrc::NotFound));
  }
  secureDelete(path);
  return {};
}

bool CustomHardenedWallet::exists(std::string_view label) {
  if (!isValidLabel(label)) [[unlikely]]
    return false;
  std::shared_lock intraProcess(*pimpl_->rwLock);
  std::error_code ec;
  return std::filesystem::exists(pimpl_->pathFor(label), ec);
}

std::vector<std::string> CustomHardenedWallet::list() {
  std::shared_lock intraProcess(*pimpl_->rwLock);
  std::vector<std::string> result;
  static constexpr std::string_view kSuffix = ".id";

  std::error_code ec;
  for (const auto &entry : std::filesystem::directory_iterator(
           pimpl_->dir,
           std::filesystem::directory_options::skip_permission_denied, ec)) {
    std::error_code typeEc;
    if (!entry.is_regular_file(typeEc) || typeEc)
      continue;
    const auto filename = entry.path().filename().string();
    if (!filename.ends_with(kSuffix))
      continue;
    const std::string candidate =
        filename.substr(0, filename.size() - kSuffix.size());
    // Never trust a filename blindly: only surface names that would also
    // pass the same validation put()/get() enforce on the way in.
    if (isValidLabel(candidate)) {
      result.push_back(candidate);
    }
  }
  return result;
}

} // namespace fabric::identity