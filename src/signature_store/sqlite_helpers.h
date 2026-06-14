// sqlite_helpers.h
#ifndef vHSM_SIGNATURE_STORE_SQLITE_HELPERS_H
#define vHSM_SIGNATURE_STORE_SQLITE_HELPERS_H

#include <sqlite3.h>
#include <string>
#include <vector>
#include "db_result_set.h" 

namespace vhsm::signature_store::db::internal {

    // Declaration of the error helper function.
    [[noreturn]] void throw_sqlite_error(sqlite3* db, int rc, const char* context);

    // Declaration of the parameter binding helper.
    void bind_params(sqlite3* db, sqlite3_stmt* stmt, const std::vector<std::string>& params);

    // Declaration of the row collection helper.
    DbResultSet collect_rows(sqlite3* db, sqlite3_stmt* stmt);

} // namespace vhsm::signature_store::db::internal

#endif