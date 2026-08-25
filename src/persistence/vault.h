#ifndef VHSM_PERSISTENCE_VAULT_H
#define VHSM_PERSISTENCE_VAULT_H

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "../domain/core/kernel_types.h"
#include "vault_format.h"

// WHY a Vault: PLAN.md Phase 7 requires encrypted-at-rest storage of sensitive
// token state (KEK, wrapped keys, integrity anchors).  The Vault is the
// on-disk envelope: it encrypts a caller-supplied payload (typically the output
// of TokenSerializer) with AES-256-GCM, keyed by a key that is *derived* from
// a password via PBKDF2 — never stored on disk.  The file format, KDF
// parameters and migration hooks live in vault_format.h / migrations.h.
//
// WHY GCM + PBKDF2: GCM gives authenticated encryption (confidentiality plus
// tamper detection in one pass); PBKDF2 slows down offline brute-force of a
// weak vault password.  The vault also exposes the DB HMAC key derivation
// (PLAN.md) which reuses the same derived key via HKDF — see kdf.h.
//
// The password is held in memory for the lifetime of the Vault object so
// save() can re-salt on each write (see save() rationale). It is zeroed in the
// destructor.
namespace vhsm::persistence {

class Vault {
public:
  // Opens an existing vault file and verifies its header + GCM tag.
  // Throws std::runtime_error if the file is missing, not a vault, or the
  // password does not decrypt it.
  Vault(const std::filesystem::path &path, const std::string &password);

  // Creates a brand new vault file at `path` (fails if it already exists)
  // containing `initial_payload` encrypted with a freshly derived key.
  // Throws std::runtime_error on I/O or crypto failure.
  static Vault create(const std::filesystem::path &path,
                      const std::string &password,
                      const std::vector<u8> &initial_payload);

  // Saves `payload` into the vault file using an atomic write
  // (temp file + fsync + rename).  Returns immediately on success.
  void save(const std::vector<u8> &payload);

  // Decrypts and returns the payload stored in the vault file.
  std::vector<u8> load() const;

  // The on-disk format version (currently K_VAULT_FORMAT_VERSION).
  std::uint32_t version() const noexcept;

  // True if the file was successfully opened and authenticated.
  bool is_valid() const noexcept { return valid_; }

private:
  // Internal constructor for create(): records path/password without reading
  // the (not-yet-existing) file.  `valid_` stays false until save() persists.
  Vault(const std::filesystem::path &path, const std::string &password,
        bool /*unused*/);

  // Reads the file and derives/returns the key for the given salt+iterations
  // encoded in the header.
  std::vector<u8> make_key(const std::vector<u8> &salt,
                           std::uint32_t iterations) const;

  std::filesystem::path path_;
  std::string password_;
  std::uint32_t version_ = K_VAULT_FORMAT_VERSION;
  bool valid_ = false;
};

} // namespace vhsm::persistence

#endif // VHSM_PERSISTENCE_VAULT_H