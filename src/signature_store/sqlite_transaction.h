#ifndef vHSM_SIGNATURE_STORE_SQLITE_TRANSACTION_H
#define vHSM_SIGNATURE_STORE_SQLITE_TRANSACTION_H

#include <string>
#include <vector>
#include <cassert>

#include <sqlite3.h>

#include "StmtGuard.h"

#include "db_row.h"
#include "db_result_set.h"
#include "db_transaction.h"
#include "sqlite_helpers.h"

// SqliteTransaction — IDbTransaction backed by an open sqlite3*
//
// Constructed by SqliteConnection::with_transaction() after BEGIN is issued.
// Does NOT own the sqlite3 handle (lifetime managed by SqliteConnection).
// Does NOT issue COMMIT/ROLLBACK itself — that stays in with_transaction().
namespace vhsm::signature_store {
    namespace db {

        class SqliteTransaction : public IDbTransaction {
            public:
                // conn_mutex must already be held by the calling thread for the duration
                // of this object's lifetime.  SqliteConnection::with_transaction() holds
                // it via std::lock_guard before constructing this.
                explicit SqliteTransaction(sqlite3* db);

                DbResultSet query(const std::string& sql, const std::vector<std::string>& params = {}) override;

                i64 exec(const std::string& sql, const std::vector<std::string>& params = {}) override;

            private:
                sqlite3* db_; // non-owning
        };


    }
}
#endif