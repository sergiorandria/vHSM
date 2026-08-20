#include "migrations.h"

#include <algorithm>
#include <stdexcept>

#include "../core/error.h"

namespace vhsm::persistence {

MigrationRegistry &MigrationRegistry::instance() {
  static MigrationRegistry reg;
  return reg;
}

bool MigrationRegistry::register_migration(std::uint32_t from, MigrationFn fn) {
  VHSM_CHECK_MSG(fn != nullptr, "register_migration: null migration function");
  auto [it, inserted] = fns_.emplace(from, std::move(fn));
  (void)it;
  return inserted;
}

std::vector<u8> MigrationRegistry::migrate(std::vector<u8> data,
                                           std::uint32_t from,
                                           std::uint32_t target) const {
  if (from == target)
    return data;
  if (from > target) {
    throw std::runtime_error("migrate: cannot downgrade (from > target)");
  }

  std::uint32_t current = from;
  while (current < target) {
    auto it = fns_.find(current);
    if (it == fns_.end()) {
      throw std::runtime_error(
          "migrate: no migration registered from version " +
          std::to_string(current));
    }
    data = it->second(std::move(data));
    ++current;
  }
  return data;
}

std::uint32_t MigrationRegistry::current_version() const noexcept {
  // The max registered "from" version migrates to from+1; if nothing is
  // registered we are still at v1 (the initial format).
  std::uint32_t max_from = 0;
  for (const auto &[from, fn] : fns_) {
    (void)fn;
    max_from = (from > max_from) ? from : max_from;
  }
  return max_from + 1;
}

void MigrationRegistry::clear() noexcept { fns_.clear(); }

} // namespace vhsm::persistence