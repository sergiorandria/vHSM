#include "sqlite_connection.h"
#include "sqlite_transaction.h"

#include <sqlite3.h>
#include <stdexcept>
#include <string>

#include "../core/error.h"
#include "StmtGuard.h"
#include "sqlite_helpers.h"

namespace vhsm::signature_store {
namespace db {

SqliteConnection::SqliteConnection(const std::string &path) {
  int rc = sqlite3_open_v2(path.c_str(), &db_,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                               SQLITE_OPEN_FULLMUTEX,
                           nullptr);

  if (rc != SQLITE_OK) {
    // db_ may still be non-null even on failure; sqlite3_close it.
    std::string msg = "sqlite3_open_v2(";
    msg += path;
    msg += "): ";
    msg += db_ ? sqlite3_errmsg(db_) : sqlite3_errstr(rc);
    if (db_)
      sqlite3_close(db_);
    db_ = nullptr;
    throw DbError(DbError::Kind::ConnectionError, std::move(msg));
  }

  // Enable WAL journal mode for better concurrency.
  enable_wal();

  // Foreign key enforcement is off by default in SQLite; turn it on.
  exec_pragma("PRAGMA foreign_keys = ON;");

  // Use a 5-second busy timeout so that concurrent writers retry
  // rather than immediately returning SQLITE_BUSY.
  sqlite3_busy_timeout(db_, 5000);
}

SqliteConnection::~SqliteConnection() {
  // Finalize all cached statements before closing db
  for (auto &kv : v_stmt_cache_) {
    sqlite3_finalize(kv.second);
  }
  v_stmt_cache_.clear();
  if (db_) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

sqlite3_stmt* SqliteConnection::v_get_cached_stmt(const std::string &sql) {
  auto it = v_stmt_cache_.find(sql);
  if (it != v_stmt_cache_.end()) {
    sqlite3_stmt *stmt = it->second;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    return stmt;
  }
  if (v_stmt_cache_.size() >= K_CACHE_LIMIT) {
    v_evict_one();
  }
  sqlite3_stmt *raw = nullptr;
  int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw, nullptr);
  if (rc != SQLITE_OK) {
    internal::throw_sqlite_error(db_, rc, "prepare (cached)");
  }
  v_stmt_cache_.emplace(sql, raw);
  return raw;
}

void SqliteConnection::v_evict_one() {
  // Simple eviction: erase first element (unordered_map iteration)
  auto it = v_stmt_cache_.begin();
  if (it != v_stmt_cache_.end()) {
    sqlite3_finalize(it->second);
    v_stmt_cache_.erase(it);
  }
}

DbResultSet SqliteConnection::query(const std::string &sql,
                                    const std::vector<std::string> &params) {
  std::lock_guard<std::mutex> lock(mutex_);

  // Dynamic SQL (e.g., query_log with varying WHERE) is not cacheable
  // because it builds different strings each time. We still cache it but it
  // will just be a miss and then evicted; overhead is minimal.
  sqlite3_stmt *raw = v_get_cached_stmt(sql);
  internal::bind_params(db_, raw, params);
  // collect_rows will step through raw, but we must not finalize cached stmt
  // Instead, we collect and then reset for next use. We use a custom guard
  // that resets instead of finalizing for cached stmts.
  DbResultSet result = internal::collect_rows(db_, raw);
  // Reset for next use (collect_rows leaves stmt at DONE)
  sqlite3_reset(raw);
  sqlite3_clear_bindings(raw);
  return result;
}

i64 SqliteConnection::exec(const std::string &sql,
                           const std::vector<std::string> &params) {
  std::lock_guard<std::mutex> lock(mutex_);
  return exec_locked(sql, params);
}

void SqliteConnection::with_transaction(
    const std::function<void(IDbTransaction &)> &func) {
  std::lock_guard<std::mutex> lock(mutex_);

  exec_raw("BEGIN;");
  try {
    SqliteTransaction tx(db_);
    func(tx);
    exec_raw("COMMIT;");
  } catch (...) {
    // Best-effort rollback; ignore errors since we're already
    // unwinding from an exception.
    try {
      exec_raw("ROLLBACK;");
    } catch (...) {
    }
    throw;
  }
}

i64 SqliteConnection::exec_locked(const std::string &sql,
                                  const std::vector<std::string> &params) {
  sqlite3_stmt *raw = v_get_cached_stmt(sql);
  internal::bind_params(db_, raw, params);

  int rc = sqlite3_step(raw);
  if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
    // Reset before throwing so stmt is reusable
    sqlite3_reset(raw);
    sqlite3_clear_bindings(raw);
    internal::throw_sqlite_error(db_, rc, "step (exec)");
  }
  i64 changes = static_cast<i64>(sqlite3_changes(db_));
  sqlite3_reset(raw);
  sqlite3_clear_bindings(raw);
  return changes;
}

void SqliteConnection::exec_raw(const char *sql) {
  char *errmsg = nullptr;
  int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
  if (rc != SQLITE_OK) {
    std::string msg = sql;
    msg += ": ";
    if (errmsg) {
      msg += errmsg;
      sqlite3_free(errmsg);
    } else {
      msg += sqlite3_errstr(rc);
    }
    throw DbError(DbError::Kind::IoError, std::move(msg));
  }
}

void SqliteConnection::enable_wal() {
  sqlite3_stmt *raw = nullptr;
  int rc =
      sqlite3_prepare_v2(db_, "PRAGMA journal_mode=WAL;", -1, &raw, nullptr);
  if (rc != SQLITE_OK) {
    internal::throw_sqlite_error(db_, rc, "PRAGMA journal_mode=WAL (prepare)");
  }
  StmtGuard guard(raw);

  rc = sqlite3_step(raw);
  if (rc == SQLITE_ROW) {
    const unsigned char *mode = sqlite3_column_text(raw, 0);
    if (!mode || std::string(reinterpret_cast<const char *>(mode)) != "wal") {
      // Not fatal: WAL may be unavailable on some VFS (e.g., network
      // mounts).  Log a warning in production; here we continue.
    }
    // drain remaining rows
    while (sqlite3_step(raw) == SQLITE_ROW) {
    }
  }
}

void SqliteConnection::exec_pragma(const char *pragma_sql) {
  char *errmsg = nullptr;
  int rc = sqlite3_exec(db_, pragma_sql, nullptr, nullptr, &errmsg);
  if (rc != SQLITE_OK) {
    std::string msg = pragma_sql;
    msg += ": ";
    if (errmsg) {
      msg += errmsg;
      sqlite3_free(errmsg);
    }
    // Pragma failures are non-fatal — log and continue.
    (void)msg;
  }
}

} // namespace db
} // namespace vhsm::signature_store
