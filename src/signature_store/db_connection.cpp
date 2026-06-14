// db_connection.cpp — SQLite backend for IDbConnection / IDbTransaction
//
// One physical file per process — SQLite in WAL mode with a single shared
// connection, protected by a mutex.  This is intentional for the embedded
// single-process model described in the plan.  The IDbConnection interface
// lets future phases swap in a PostgreSQL or MySQL backend without touching
// any higher-level code.
//
// Build dependency: sqlite3 (link with -lsqlite3)
// Requires C++20.

#include "db_connection.h"
#include "StmtGuard.h"

#include "../core/error.h"


#include <sqlite3.h>

#include <cassert>
#include <mutex>
#include <string>
#include <vector>

namespace vhsm::signature_store {
namespace db {

// Internal helpers
namespace {

// Throw a DbError whose message is prefixed with context and suffixed with the
// SQLite error string for the given db handle.
[[noreturn]] void throw_sqlite_error(sqlite3* db, int rc, const char* context) {
    std::string msg = context;
    msg += ": ";
    if (db) {
        msg += sqlite3_errmsg(db);
    } else {
        msg += sqlite3_errstr(rc);
    }

    throw DbError(DbError::Kind::IoError, std::move(msg));
}

// Bind a vector of string parameters to a prepared statement.
// SQLite uses 1-based indices.
void bind_params(sqlite3* db, sqlite3_stmt* stmt, const std::vector<std::string>& params) {
    for (int i = 0; i < static_cast<int>(params.size()); ++i) {
        // SQLITE_TRANSIENT tells SQLite to make its own copy of the string.
        int rc = sqlite3_bind_text(stmt, i + 1, params[i].c_str(), static_cast<int>(params[i].size()), SQLITE_TRANSIENT);
        if (rc != SQLITE_OK) {
            throw_sqlite_error(db, rc, "sqlite3_bind_text");
        }
    }
}

// Step a prepared statement to completion and collect all result rows.
DbResultSet collect_rows(sqlite3* db, sqlite3_stmt* stmt) {
    std::vector<DbRow> rows;

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int ncols = sqlite3_column_count(stmt);
        std::vector<std::string> values;
        values.reserve(ncols);

        for (int c = 0; c < ncols; ++c) {
            // sqlite3_column_text returns NULL for SQL NULL values.
            // We represent SQL NULL as the empty string here; callers that
            // need to distinguish NULL from "" should add a sentinel or use
            // a separate optional<string> layer in a future refactor.
            const unsigned char* text = sqlite3_column_text(stmt, c);
            values.emplace_back(text ? reinterpret_cast<const char*>(text) : "");
        }

        rows.emplace_back(std::move(values));
    }

    if (rc != SQLITE_DONE) {
        throw_sqlite_error(db, rc, "sqlite3_step");
    }

    return DbResultSet(std::move(rows));
}

} // namespace

// SqliteTransaction — IDbTransaction backed by an open sqlite3*
//
// Constructed by SqliteConnection::with_transaction() after BEGIN is issued.
// Does NOT own the sqlite3 handle (lifetime managed by SqliteConnection).
// Does NOT issue COMMIT/ROLLBACK itself — that stays in with_transaction().
class SqliteTransaction : public IDbTransaction {
public:
    // conn_mutex must already be held by the calling thread for the duration
    // of this object's lifetime.  SqliteConnection::with_transaction() holds
    // it via std::lock_guard before constructing this.
    explicit SqliteTransaction(sqlite3* db) : db_(db) {
        assert(db_ != nullptr);
    }

    DbResultSet query(const std::string& sql, const std::vector<std::string>& params = {}) override {
        sqlite3_stmt* raw = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw, nullptr);
        
        if (rc != SQLITE_OK) {
            throw_sqlite_error(db_, rc, "prepare (tx query)");
        }

        StmtGuard guard(raw);

        bind_params(db_, raw, params);
        return collect_rows(db_, raw);
    }

    i64 exec(const std::string& sql, const std::vector<std::string>& params = {}) override {
        sqlite3_stmt* raw = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw, nullptr);
        if (rc != SQLITE_OK) {
            throw_sqlite_error(db_, rc, "prepare (tx exec)");
        }
        StmtGuard guard(raw);

        bind_params(db_, raw, params);

        rc = sqlite3_step(raw);
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            throw_sqlite_error(db_, rc, "step (tx exec)");
        }

        return static_cast<i64>(sqlite3_changes(db_));
    }

private:
    sqlite3* db_; // non-owning
};

// ─────────────────────────────────────────────────────────────────────────────
// SqliteConnection — IDbConnection backed by a single sqlite3 handle
// ─────────────────────────────────────────────────────────────────────────────

class SqliteConnection : public IDbConnection {
public:
    // Open (or create) a SQLite database at the given path.
    // Use ":memory:" for an in-process, in-memory database (tests).
    //
    // WAL mode is enabled immediately so that readers never block writers
    // and concurrent access from multiple threads within the same process
    // is safe under the serialised mutex we hold.
    explicit SqliteConnection(const std::string& path) {
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

    ~SqliteConnection() override {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    // Non-copyable, non-movable (holds raw pointer + mutex).
    SqliteConnection(const SqliteConnection&)            = delete;
    SqliteConnection& operator=(const SqliteConnection&) = delete;

    // ── IDbConnection ────────────────────────────────────────────────────────

    DbResultSet query(const std::string& sql,
                      const std::vector<std::string>& params = {}) override {
        std::lock_guard<std::mutex> lock(mutex_);

        sqlite3_stmt* raw = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw, nullptr);
        if (rc != SQLITE_OK) {
            throw_sqlite_error(db_, rc, "prepare (query)");
        }
        StmtGuard guard(raw);

        bind_params(db_, raw, params);
        return collect_rows(db_, raw);
    }

    i64 exec(const std::string& sql,
             const std::vector<std::string>& params = {}) override {
        std::lock_guard<std::mutex> lock(mutex_);
        return exec_locked(sql, params);
    }

    void with_transaction(
        const std::function<void(IDbTransaction&)>& func) override {

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

private:
    sqlite3*   db_    = nullptr;
    std::mutex mutex_;

    // exec without acquiring the mutex — caller must hold it.
    i64 exec_locked(const std::string& sql,
                    const std::vector<std::string>& params) {
        sqlite3_stmt* raw = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw, nullptr);
        if (rc != SQLITE_OK) {
            throw_sqlite_error(db_, rc, "prepare (exec)");
        }
        StmtGuard guard(raw);

        bind_params(db_, raw, params);

        rc = sqlite3_step(raw);
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            throw_sqlite_error(db_, rc, "step (exec)");
        }

        return static_cast<i64>(sqlite3_changes(db_));
    }

    // Execute a single raw SQL string with no parameters and no result rows.
    // Must be called with mutex_ held.
    void exec_raw(const char* sql) {
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

    void enable_wal() {
        // WAL mode is sticky per database file; the PRAGMA returns the current
        // mode after the request — verify it actually switched.
        sqlite3_stmt* raw = nullptr;
        int rc = sqlite3_prepare_v2(
            db_, "PRAGMA journal_mode=WAL;", -1, &raw, nullptr);
        if (rc != SQLITE_OK) {
            throw_sqlite_error(db_, rc, "PRAGMA journal_mode=WAL (prepare)");
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

    void exec_pragma(const char* pragma_sql) {
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
};

// ─────────────────────────────────────────────────────────────────────────────
// Factory function — the only symbol clients need to call
// ─────────────────────────────────────────────────────────────────────────────

std::unique_ptr<IDbConnection> make_sqlite_connection(const std::string& path) {
    return std::make_unique<SqliteConnection>(path);
}

}  // namespace db
}  // namespace vhsm::signature_store