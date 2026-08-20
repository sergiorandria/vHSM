#ifndef VHSM_PERSISTENCE_MIGRATIONS_H
#define VHSM_PERSISTENCE_MIGRATIONS_H

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "../core/types.h"

// WHY a migration framework: PLAN.md Phase 7 requires that vault-format or
// payload-layout changes can be applied forward without user intervention.  A
// registry of (from_version -> upgrade) lets us add a v2 layout later and
// still read v1 vaults on open.  Each migration transforms a raw payload blob,
// so the Vault layer never has to know what the payload means.
namespace vhsm::persistence {

// A migration upgrades the token-snapshot/payload from `from` to `from + 1`.
// It receives the raw bytes as stored and returns the upgraded bytes.
using MigrationFn = std::function<std::vector<u8>(std::vector<u8>)>;

class MigrationRegistry {
public:
  // The process-wide registry.
  static MigrationRegistry &instance();

  // Registers an upgrade from `from` to `from+1`. Returns false (and does not
  // register) if a migration for `from` already exists.
  bool register_migration(std::uint32_t from, MigrationFn fn);

  // Applies all registered migrations to bring `data` (which is at version
  // `from`) up to the current `target` version. If any step is missing,
  // throws std::runtime_error pointing at the gap. A blob already at the
  // target version is returned unchanged.
  std::vector<u8> migrate(std::vector<u8> data, std::uint32_t from,
                          std::uint32_t target) const;

  // Highest registered migration source version + 1, or 1 if none are
  // registered (the initial format is v1). Useful for tests to sanity-check.
  std::uint32_t current_version() const noexcept;

  // Removes all registered migrations (test helper only).
  void clear() noexcept;

public:
  MigrationRegistry() = default;

private:
  std::map<std::uint32_t, MigrationFn> fns_;
};

} // namespace vhsm::persistence

#endif // VHSM_PERSISTENCE_MIGRATIONS_H