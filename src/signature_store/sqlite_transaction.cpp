#include "sqlite_transaction.h"

#include <sqlite3.h>

#include "StmtGuard.h"
#include "sqlite_helpers.h"
#include "../core/error.h"

namespace vhsm::signature_store {
    namespace db {

        SqliteTransaction::SqliteTransaction(sqlite3* db) : db_(db) {
            assert(db_ != nullptr);
        }

        DbResultSet SqliteTransaction::query(const std::string& sql, const std::vector<std::string>& params) {
            sqlite3_stmt* raw = nullptr;
            int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw, nullptr);

            if (rc != SQLITE_OK) {
                internal::throw_sqlite_error(db_, rc, "prepare (tx query)");
            }

            StmtGuard guard(raw);

            internal::bind_params(db_, raw, params);
            return internal::collect_rows(db_, raw);
        }

        i64 SqliteTransaction::exec(const std::string& sql, const std::vector<std::string>& params) {
            sqlite3_stmt* raw = nullptr;
            int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw, nullptr);
            if (rc != SQLITE_OK) {
                internal::throw_sqlite_error(db_, rc, "prepare (tx exec)");
            }
            StmtGuard guard(raw);

            internal::bind_params(db_, raw, params);

            rc = sqlite3_step(raw);
            if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
                internal::throw_sqlite_error(db_, rc, "step (tx exec)");
            }

            return static_cast<i64>(sqlite3_changes(db_));
        }

    }
}
