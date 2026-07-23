#ifndef vHSM_SIGNATURE_STORE_SQLITE_CONNECTION_H
#define vHSM_SIGNATURE_STORE_SQLITE_CONNECTION_H

#include <string>
#include <vector>
#include <mutex>

struct sqlite3;

#include "db_row.h"
#include "db_result_set.h"
#include "db_connection.h"

// SqliteConnection — IDbConnection backed by a single sqlite3 handle
namespace vhsm::signature_store {
    namespace db {

        class SqliteConnection : public IDbConnection {
            public:
                explicit SqliteConnection(const std::string& path);
                ~SqliteConnection() override;

                // Non-copyable, non-movable (holds raw pointer + mutex).
                SqliteConnection(const SqliteConnection&)            = delete;
                SqliteConnection& operator=(const SqliteConnection&) = delete;

                // IDbConnection
                DbResultSet query(const std::string& sql, const std::vector<std::string>& params = {}) override;
                i64 exec(const std::string& sql, const std::vector<std::string>& params = {}) override;
                void with_transaction(const std::function<void(IDbTransaction&)>& func) override;

            private:
                sqlite3*   db_    = nullptr;
                std::mutex mutex_;

                // exec without acquiring the mutex — caller must hold it.
                i64 exec_locked(const std::string& sql, const std::vector<std::string>& params);
                void exec_raw(const char* sql);
                void enable_wal();
                void exec_pragma(const char* pragma_sql);
        };

    }  // namespace db
}  // namespace vhsm::signature_store

#endif  // vHSM_SIGNATURE_STORE_SQLITE_CONNECTION_H