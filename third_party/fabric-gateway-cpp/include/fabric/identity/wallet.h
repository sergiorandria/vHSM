#ifndef FABRIC_IDENTITY_WALLET_H
#define FABRIC_IDENTITY_WALLET_H

#include "identity.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace fabric::identity {

// Error handling
//
// Every failure mode is surfaced explicitly through std::error_code rather
// than collapsed into bool/nullptr. This matters most for get(): "label not
// found" and "label present but failed to authenticate" (wrong key,
// corruption, or a tampered/swapped file) are fundamentally different events
// — the second one is potentially an active attack — and must never be
// conflated behind a single nullptr return the way the previous version did.
enum class WalletErrc {
  InvalidLabel = 1,
  KeyUnavailable,
  NotFound,
  IoError,
  CryptoError,   // AEAD authentication failed: corrupt, wrong key, or tampered
  LockTimeout,   // could not acquire the wallet lock within the configured timeout
  AlreadyExists,
};

[[nodiscard]] const std::error_category& walletCategory() noexcept;
[[nodiscard]] std::error_code make_error_code(const WalletErrc&& e) noexcept;

}  // namespace fabric::identity

template <>
struct std::is_error_code_enum<fabric::identity::WalletErrc> : std::true_type {};

namespace fabric::identity {

template <typename T>
using Result = std::expected<T, std::error_code>;

// Wallet interface
class Wallet {
public:
  virtual ~Wallet() = default;

  virtual Result<void> put(std::string_view label, const Identity& identity) = 0;
  virtual Result<std::unique_ptr<Identity>> get(std::string_view label) = 0;
  virtual Result<void> deleteIdentity(std::string_view label) = 0;
  [[nodiscard]] virtual bool exists(std::string_view label) = 0;
  [[nodiscard]] virtual std::vector<std::string> list() = 0;
};

// In-memory wallet
//
// Thread-safe (std::shared_mutex: concurrent readers, exclusive writers).
// No persistence, no at-rest protection — for tests and short-lived clients.
class InMemoryWallet final : public Wallet {
public:
  InMemoryWallet();
  ~InMemoryWallet() override;

  InMemoryWallet(const InMemoryWallet&) = delete;
  InMemoryWallet& operator=(const InMemoryWallet&) = delete;

  Result<void> put(std::string_view label, const Identity& identity) override;
  Result<std::unique_ptr<Identity>> get(std::string_view label) override;
  Result<void> deleteIdentity(std::string_view label) override;
  [[nodiscard]] bool exists(std::string_view label) override;
  [[nodiscard]] std::vector<std::string> list() override;

private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;
};

// Hardened filesystem wallet
//
// Each identity is persisted as a single AES-256-GCM encrypted blob (one file
// per label), with the label bound in as AEAD associated data so a file
// cannot be silently swapped onto a different label without detection. The
// wrapping key is read once from an environment variable and held only in a
// self-wiping buffer. On top of encryption:
//
//   - strict label validation (charset allow-list, no path separators/"..")
//     prevents path traversal out of the wallet directory;
//   - 0700 on the wallet directory, 0600 on identity files — and only the
//     wallet directory itself is ever chmod'd, never its parents;
//   - atomic writes via temp file + fsync + atomic rename, so a crash mid
//     write can never leave a partially-written (and thus decryptable-junk)
//     identity behind;
//   - best-effort secure deletion (overwrite with zeros before unlink);
//   - two independent locking layers: a std::shared_mutex per canonical
//     wallet directory (shared process-wide via a registry, so it correctly
//     serializes *threads within this process*, which a bare flock() cannot
//     do — flock() locks are scoped to the open file description, not the
//     process, so two threads that each open() the lock file independently
//     do not exclude each other) plus a bounded, backing-off flock() for
//     mutual exclusion *across processes*.
//
// Construction can fail (missing permissions, read-only filesystem, ...), so
// there is no public throwing constructor — use create().
class CustomHardenedWallet final : public Wallet {
public:
  struct Options {
    std::string masterKeyEnvVar = "FABRIC_WALLET_MASTER_KEY";
    std::chrono::milliseconds lockTimeout{5000};
  };

  // Two overloads rather than a defaulted `Options{}` parameter: a default
  // argument is evaluated in the "complete-class context" of its *outermost*
  // enclosing class, but Options's own default member initializers are only
  // available once — and here they'd need to be visible strictly before
  // that point, at the close of the nested class, which conflicts with how
  // GCC (correctly, per the standard's ordering rules for nested classes)
  // sequences the two. Concretely: `Options options = {}` does not compile
  // here. Splitting into two overloads sidesteps the ordering trap entirely
  // — the `Options{}` in the .cpp forwarding call sits in a function body,
  // where the class is unambiguously complete.
  [[nodiscard]] static Result<CustomHardenedWallet> create(std::filesystem::path baseDirectory);
  [[nodiscard]] static Result<CustomHardenedWallet> create(std::filesystem::path baseDirectory,
                                                             Options options);

  ~CustomHardenedWallet() override;
  CustomHardenedWallet(const CustomHardenedWallet&) = delete;
  CustomHardenedWallet& operator=(const CustomHardenedWallet&) = delete;
  CustomHardenedWallet(CustomHardenedWallet&&) noexcept;
  CustomHardenedWallet& operator=(CustomHardenedWallet&&) noexcept;

  Result<void> put(std::string_view label, const Identity& identity) override;
  Result<std::unique_ptr<Identity>> get(std::string_view label) override;
  Result<void> deleteIdentity(std::string_view label) override;
  [[nodiscard]] bool exists(std::string_view label) override;
  [[nodiscard]] std::vector<std::string> list() override;

  // True if a usable master key was found in the environment. put()/get()
  // require this; exists()/list()/deleteIdentity() do not.
  [[nodiscard]] bool hasMasterKey() const noexcept;

private:
  class Impl;
  // Impl is a private nested type: only wallet.cpp can name it, which means
  // only wallet.cpp can actually construct the argument needed to call this
  // constructor. That makes it safe to leave technically "callable" —
  // there's no ceremony of friend declarations needed to keep external code
  // from bypassing create().
  explicit CustomHardenedWallet(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> pimpl_;
};

}  // namespace fabric::identity

#endif  // FABRIC_IDENTITY_WALLET_H