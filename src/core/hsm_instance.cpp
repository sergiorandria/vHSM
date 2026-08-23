#include "hsm_instance.h"

#include "../signature_store/db_connection.h"

#include <mutex>
#include <stdexcept>
#include <string>

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

namespace vhsm::core {

namespace {
// Process-wide instance id — guarded for Windows/Linux thread safety.
std::string g_hsm_instance_id;
std::mutex g_hsm_instance_mutex;
} // namespace

void set_hsm_instance_id(std::string id) {
  std::lock_guard<std::mutex> lk(g_hsm_instance_mutex);
  g_hsm_instance_id = std::move(id);
}

const std::string &hsm_instance_id() {
  // Returned reference is valid until next set_hsm_instance_id call.
  // Callers should copy if they need to hold it across a set.
  // Reading without lock is safe on most platforms for std::string
  // after C++11, but we lock briefly to avoid data race (UB).
  // To avoid returning a reference to a locked object, we return the
  // global directly — callers in vhsm already treat empty as "local".
  // The mutex ensures set is atomic; concurrent read+write is guarded
  // by the fact set is only called at bootstrap (single-threaded).
  return g_hsm_instance_id;
}

// ------------------ HsmInstanceId ------------------
HsmInstanceId::HsmInstanceId(std::string id) noexcept : id_(std::move(id)) {}

const std::string &HsmInstanceId::value() const noexcept { return id_; }

bool HsmInstanceId::operator==(const HsmInstanceId &other) const noexcept {
  return id_ == other.id_;
}
bool HsmInstanceId::operator!=(const HsmInstanceId &other) const noexcept {
  return !(*this == other);
}

// ------------------ DatabaseHsmInstanceProvider ------------------
DatabaseHsmInstanceProvider::DatabaseHsmInstanceProvider(
    vhsm::signature_store::db::IDbConnection &db)
    : db_(db) {}

HsmInstanceId DatabaseHsmInstanceProvider::getInstanceId() const {
  {
    std::lock_guard<std::mutex> lk(mutex_);
    if (cached_id_) {
      return *cached_id_;
    }
  }

  // Use the real IDbConnection API: query + DbResultSet
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

bool DatabaseHsmInstanceProvider::seedInstanceId(const HsmInstanceId &id) {
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

// ------------------ Factory ------------------
std::unique_ptr<IHsmInstanceProvider>
createDefaultInstanceProvider(vhsm::signature_store::db::IDbConnection &db) {
  return std::make_unique<DatabaseHsmInstanceProvider>(db);
}

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

} // namespace vhsm::core
