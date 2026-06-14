#include "sqlite_connection.h"
#include "sqlite_transaction.h"

#include <sqlite3.h>
#include <string>
#include <stdexcept>

#include "StmtGuard.h"
#include "sqlite_helpers.h"
#include "../core/error.h"

namespace vhsm::signature_store {
    namespace db {

        SqliteConnection::SqliteConnection(const std::string& path) {
            int rc = sqlite3_open_v2(
                path.c_str(),
                &db_,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                nullptr);

            if (rc != SQLITE_OK) {
                // db_ may still be non-null even on failure; sqlite3_close it.
                std::string msg = "sqlite3_open_v2(";
                msg += path;
                msg += "): ";
                msg += db_ ? sqlite3_errmsg(db_) : sqlite3_errstr(rc);
                if (db_) sqlite3_close(db_);
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
            if (db_) {
                sqlite3_close(db_);
                db_ = nullptr;
            }
        }

        DbResultSet SqliteConnection::query(const std::string& sql, const std::vector<std::string>& params) {
            std::lock_guard<std::mutex> lock(mutex_);

            sqlite3_stmt* raw = nullptr;
            int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw, nullptr);
            if (rc != SQLITE_OK) {
                internal::throw_sqlite_error(db_, rc, "prepare (query)");
            }
            StmtGuard guard(raw);

            internal::bind_params(db_, raw, params);
            return internal::collect_rows(db_, raw);
        }

        i64 SqliteConnection::exec(const std::string& sql, const std::vector<std::string>& params) {
            std::lock_guard<std::mutex> lock(mutex_);
            return exec_locked(sql, params);
        }

        void SqliteConnection::with_transaction(const std::function<void(IDbTransaction&)>& func) {
            std::lock_guard<std::mutex> lock(mutex_);

            exec_raw("BEGIN;");
            try {
                SqliteTransaction tx(db_);
                func(tx);
                exec_raw("COMMIT;");
            } catch (...) {
                // Best-effort rollback; ignore errors since we're already
                // unwinding from an exception.
                try { exec_raw("ROLLBACK;"); } catch (...) {}
                throw;
            }
        }

        i64 SqliteConnection::exec_locked(const std::string& sql, const std::vector<std::string>& params) {
            sqlite3_stmt* raw = nullptr;
            int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw, nullptr);
            if (rc != SQLITE_OK) {
                internal::throw_sqlite_error(db_, rc, "prepare (exec)");
            }
            StmtGuard guard(raw);

            internal::bind_params(db_, raw, params);

            rc = sqlite3_step(raw);
            if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
                internal::throw_sqlite_error(db_, rc, "step (exec)");
            }

            return static_cast<i64>(sqlite3_changes(db_));
        }

        void SqliteConnection::exec_raw(const char* sql) {
            char* errmsg = nullptr;
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
            sqlite3_stmt* raw = nullptr;
            int rc = sqlite3_prepare_v2(
                db_, "PRAGMA journal_mode=WAL;", -1, &raw, nullptr);
            if (rc != SQLITE_OK) {
                internal::throw_sqlite_error(db_, rc, "PRAGMA journal_mode=WAL (prepare)");
            }
            StmtGuard guard(raw);

            rc = sqlite3_step(raw);
            if (rc == SQLITE_ROW) {
                const unsigned char* mode = sqlite3_column_text(raw, 0);
                if (!mode || std::string(reinterpret_cast<const char*>(mode)) != "wal") {
                    // Not fatal: WAL may be unavailable on some VFS (e.g., network
                    // mounts).  Log a warning in production; here we continue.
                }
                // drain remaining rows
                while (sqlite3_step(raw) == SQLITE_ROW) {}
            }
        }

        void SqliteConnection::exec_pragma(const char* pragma_sql) {
            char* errmsg = nullptr;
            int rc = sqlite3_exec(db_, pragma_sql, nullptr, nullptr, &errmsg);
            if (rc != SQLITE_OK) {
                std::string msg = pragma_sql;
                msg += ": ";
                if (errmsg) { msg += errmsg; sqlite3_free(errmsg); }
                // Pragma failures are non-fatal — log and continue.
                (void)msg;
            }
        }

    }
}
