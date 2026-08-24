#ifndef vHSM_SIGNATURE_STORE_SQLITE_CONNECTION_H
#define vHSM_SIGNATURE_STORE_SQLITE_CONNECTION_H

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

#include "db_connection.h"
#include "db_result_set.h"
#include "db_row.h"

// SqliteConnection — IDbConnection backed by a single sqlite3 handle
namespace vhsm::signature_store {
namespace db {

class SqliteConnection : public IDbConnection {
public:
  explicit SqliteConnection(const std::string &path);
  ~SqliteConnection() override;

  // Non-copyable, non-movable (holds raw pointer + mutex).
  SqliteConnection(const SqliteConnection &) = delete;
  SqliteConnection &operator=(const SqliteConnection &) = delete;

  // IDbConnection
  DbResultSet query(const std::string &sql,
                    const std::vector<std::string> &params = {}) override;
  i64 exec(const std::string &sql,
           const std::vector<std::string> &params = {}) override;
  void
  with_transaction(const std::function<void(IDbTransaction &)> &func) override;

private:
  sqlite3 *db_ = nullptr;
  std::mutex mutex_;
  // Statement cache: SQL text -> prepared statement. Protected by mutex_.
  // LRU eviction at 32 entries to bound memory; hot statements (insert,
  // update_ledger, etc.) stay cached across C_Sign calls.
  std::unordered_map<std::string, sqlite3_stmt*> v_stmt_cache_;
  static constexpr size_t kCacheLimit = 32;

  sqlite3_stmt* v_get_cached_stmt(const std::string &sql);
  void v_evict_one();

  // exec without acquiring the mutex — caller must hold it.
  i64 exec_locked(const std::string &sql,
                  const std::vector<std::string> &params);
  void exec_raw(const char *sql);
  void enable_wal();
  void exec_pragma(const char *pragma_sql);
};

} // namespace db
} // namespace vhsm::signature_store

#endif // vHSM_SIGNATURE_STORE_SQLITE_CONNECTION_H
