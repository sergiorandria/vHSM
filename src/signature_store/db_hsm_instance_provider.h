// Database-backed HsmInstanceProvider — lives in signature_store (not core)
// so that core does not depend on the DB layer. This breaks the circular
// dependency: core → signature_store → core.
//

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
// The port (IHsmInstanceProvider) stays in core/hsm_instance.h; this is the
// infrastructure adapter that implements it using IDbConnection.

#include "../core/hsm_instance.h"
#include "db_connection.h"

#include <mutex>
#include <stdexcept>
#include <string>

namespace vhsm::core {

class DatabaseHsmInstanceProvider : public IHsmInstanceProvider {
public:
  explicit DatabaseHsmInstanceProvider(
      vhsm::signature_store::db::IDbConnection &db)
      : db_(db) {}

  _VHSMXX_NODISCARD HsmInstanceId getInstanceId() const override {
    {
      std::lock_guard<std::mutex> lk(mutex_);
      if (cached_id_) {
        return *cached_id_;
      }
    }

    auto rs = db_.query("SELECT value FROM db_meta WHERE key = ?",
                        std::vector<std::string>{"instance_id"});
    std::string uuid;
    if (!rs.empty() && !rs.rows_.empty()) {
      auto v = rs.get<std::string>(rs.rows_[0], 0);
      if (v)
        uuid = *v;
    }
    if (uuid.empty()) {
      throw std::runtime_error("HSM instance ID not seeded.");
    }
    HsmInstanceId fresh(std::move(uuid));
    {
      std::lock_guard<std::mutex> lk(mutex_);
      cached_id_.emplace(fresh);
    }
    return fresh;
  }

  bool seedInstanceId(const HsmInstanceId &id) {
    try {
      db_.exec("INSERT INTO db_meta(key, value) VALUES(?, ?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value;",
               std::vector<std::string>{"instance_id", id.value()});
    } catch (...) {
      return false;
    }
    {
      std::lock_guard<std::mutex> lk(mutex_);
      cached_id_.reset();
      cached_id_.emplace(id);
    }
    return true;
  }

private:
  vhsm::signature_store::db::IDbConnection &db_;
  mutable std::mutex mutex_;
  mutable std::optional<HsmInstanceId> cached_id_;
};

std::unique_ptr<IHsmInstanceProvider>
createDefaultInstanceProvider(vhsm::signature_store::db::IDbConnection &db) {
  return std::make_unique<DatabaseHsmInstanceProvider>(db);
}

} // namespace vhsm::core

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
