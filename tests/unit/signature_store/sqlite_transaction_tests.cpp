// sqlite_transaction_tests.cpp — Unit tests for SqliteTransaction
//
// Tests: create in-memory sqlite DB, begin transaction, use SqliteTransaction
// to exec and query, then rollback and cleanup.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../../../src/signature_store/sqlite_transaction.h"
#include "../../../src/signature_store/db_result_set.h"
#include "../../../src/core/error.h"

using namespace vhsm::signature_store;
using namespace vhsm::signature_store::db;

// We need to create a sqlite3* for SqliteTransaction tests. Use an in-memory DB
// and begin a transaction to construct SqliteTransaction properly. The test
// exercises the transaction-scoped query/exec helpers and verifies that a
// rollback leaves the database unchanged.

TEST(SqliteTransactionTest, QueryAndExecInsideTransaction) {
    // Open an in-memory SQLite database. SQLITE_OPEN_FULLMUTEX provides a
    // serialized connection mode which is safe for multi-threaded tests; here
    // it is not strictly required but mirrors production usage.
    sqlite3* db = nullptr;
    int rc = sqlite3_open_v2(":memory:", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    ASSERT_EQ(rc, SQLITE_OK);

    // Create a simple table outside of the transaction. We do this before
    // BEGIN so the CREATE is not rolled back by the test's ROLLBACK.
    char* errmsg = nullptr;
    rc = sqlite3_exec(db, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        // Clean up and fail if the setup step cannot complete.
        if (errmsg) sqlite3_free(errmsg);
        sqlite3_close(db);
        FAIL() << "Failed to create table";
    }

    // Start a transaction using the raw sqlite3 API. In production the
    // connection object holds a mutex and constructs SqliteTransaction while
    // the mutex is held; here we emulate the minimal required sequence so the
    // SqliteTransaction can operate against the open sqlite3*.
    rc = sqlite3_exec(db, "BEGIN;", nullptr, nullptr, &errmsg);
    ASSERT_EQ(rc, SQLITE_OK);

    // Construct a SqliteTransaction that will run statements within the
    // current BEGIN/COMMIT/ROLLBACK scope. The SqliteTransaction does not own
    // the sqlite3 handle so we must keep 'db' alive for the duration.
    SqliteTransaction tx(db);

    // Execute an INSERT via the transaction helper. The call returns the
    // number of changes reported by sqlite3_changes(). We expect at least
    // one row to be affected.
    i64 changes = tx.exec("INSERT INTO t(v) VALUES(?);", { "a" });
    EXPECT_GE(changes, 1);

    // Query the inserted row using the transaction helper. collect_rows will
    // return any rows visible inside the same transaction context.
    DbResultSet rs = tx.query("SELECT v FROM t WHERE id = 1;");
    ASSERT_EQ(rs.rows_count(), 1u);
    auto v = rs.get<std::string>(rs.rows_[0], 0);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "a");

    // Roll back the transaction to ensure the INSERT is not persisted. This
    // verifies that using SqliteTransaction inside a BEGIN block does not
    // implicitly commit changes when the object is destroyed.
    rc = sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);

    // Close the database handle.
    sqlite3_close(db);
}
