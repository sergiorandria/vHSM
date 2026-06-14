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
#include "sqlite_connection.h"
#include "../core/error.h"

#include <sqlite3.h>

#include <memory>
#include <string>
#include <vector>

namespace vhsm::signature_store {
    namespace db {
        // ─────────────────────────────────────────────────────────────────────────────
        // Factory function — the only symbol clients need to call
        // ─────────────────────────────────────────────────────────────────────────────

        std::unique_ptr<IDbConnection> make_sqlite_connection(const std::string& path) {
            return std::make_unique<SqliteConnection>(path);
        }

    }  // namespace db
}  // namespace vhsm::signature_store