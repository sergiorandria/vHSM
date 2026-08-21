#ifndef FABRIC_IDENTITY_WALLET_H
#define FABRIC_IDENTITY_WALLET_H

#include "identity.h"
#include <memory>
#include <string>
#include <vector>

namespace fabric {
namespace identity {

/**
 * Abstract wallet interface for storing and retrieving identities.
 */
class Wallet {
public:
  virtual ~Wallet() = default;

  /**
   * Put an identity into the wallet.
   * @param label Label to identify the identity
   * @param identity Identity to store
   * @return True if successful
   */
  virtual bool put(const std::string &label, const Identity &identity) = 0;

  /**
   * Get an identity from the wallet.
   * @param label Label identifying the identity
   * @return Identity if found, nullptr otherwise
   */
  virtual std::unique_ptr<Identity> get(const std::string &label) = 0;

  /**
   * Delete an identity from the wallet.
   * @param label Label identifying the identity to delete
   * @return True if successful
   */
  virtual bool deleteIdentity(const std::string &label) = 0;

  /**
   * Check if an identity exists in the wallet.
   * @param label Label to check
   * @return True if identity exists
   */
  virtual bool exists(const std::string &label) = 0;

  /**
   * List all labels in the wallet.
   * @return Vector of identity labels
   */
  virtual std::vector<std::string> list() = 0;
};

/**
 * In-memory wallet implementation.
 *
 * Identities are held in a process-local map. Suitable for tests and
 * short-lived clients; no persistence and no at-rest protection.
 */
class InMemoryWallet : public Wallet {
public:
  InMemoryWallet();
  ~InMemoryWallet() override;

  bool put(const std::string &label, const Identity &identity) override;
  std::unique_ptr<Identity> get(const std::string &label) override;
  bool deleteIdentity(const std::string &label) override;
  bool exists(const std::string &label) override;
  std::vector<std::string> list() override;

private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;
};

/**
 * Hardened file-system wallet.
 *
 * Each identity is persisted as a single AES-256-GCM encrypted blob (one file
 * per label). The wrapping key is read once from an environment variable, so
 * key material is never stored on disk in cleartext. On top of encryption the
 * implementation enforces:
 *
 *   - strict label validation (no path separators, no "..", safe charset only)
 *     to prevent path-traversal out of the wallet directory;
 *   - 0700 on the wallet directory and 0600 on identity files;
 *   - atomic writes via a temp file + fsync + atomic rename, so a crash mid
 *     write cannot leave a partially written (decryptable) identity behind;
 *   - best-effort secure deletion (overwrite with zeros before unlink);
 *   - an exclusive flock around every operation to avoid concurrent
 *     read/modify/write races (TOCTOU) on the wallet directory.
 *
 * Operations that only need to know about file presence (exists/list/
 * deleteIdentity) work without the master key. put()/get() require a valid
 * 32-byte (64 hex char) master key in the configured environment variable.
 */
class CustomHardenedWallet : public Wallet {
public:
  /**
   * @param baseDirectory Directory where encrypted identities are stored.
   *        Created with mode 0700 if it does not already exist.
   * @param masterKeyEnvVar Name of the environment variable that holds the
   *        master key as 64 hex characters (32 bytes) for AES-256.
   */
  explicit CustomHardenedWallet(
      const std::string &baseDirectory,
      const std::string &masterKeyEnvVar = "FABRIC_WALLET_MASTER_KEY");
  ~CustomHardenedWallet() override;

  bool put(const std::string &label, const Identity &identity) override;
  std::unique_ptr<Identity> get(const std::string &label) override;
  bool deleteIdentity(const std::string &label) override;
  bool exists(const std::string &label) override;
  std::vector<std::string> list() override;

  /**
   * True if a usable master key was found in the environment. put()/get()
   * require this; exists()/list()/deleteIdentity() do not.
   */
  bool hasMasterKey() const;

private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;
};

}  // namespace identity
}  // namespace fabric

#endif  // FABRIC_IDENTITY_WALLET_H
