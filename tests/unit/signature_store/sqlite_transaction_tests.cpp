#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../../../src/signature_store/sqlite_transaction.h"
#include "../../../src/signature_store/db_result_set.h"
#include "../../../src/core/error.h"

using namespace vhsm::signature_store;
using namespace vhsm::signature_store::db;

// We need to create a sqlite3* for SqliteTransaction tests. Use an in-memory DB
// and begin a transaction to construct SqliteTransaction properly.

TEST(SqliteTransactionTest, QueryAndExecInsideTransaction) {
    sqlite3* db = nullptr;
    int rc = sqlite3_open_v2(":memory:", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    ASSERT_EQ(rc, SQLITE_OK);

    // Create a table outside transaction
    char* errmsg = nullptr;
    rc = sqlite3_exec(db, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        if (errmsg) sqlite3_free(errmsg);
        sqlite3_close(db);
        FAIL() << "Failed to create table";
    }

    // Begin transaction
    rc = sqlite3_exec(db, "BEGIN;", nullptr, nullptr, &errmsg);
    ASSERT_EQ(rc, SQLITE_OK);

    SqliteTransaction tx(db);

    i64 changes = tx.exec("INSERT INTO t(v) VALUES(?);", { "a" });
    EXPECT_GE(changes, 1);

    DbResultSet rs = tx.query("SELECT v FROM t WHERE id = 1;");
    ASSERT_EQ(rs.rows_count(), 1u);
    auto v = rs.get<std::string>(rs.rows_[0], 0);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "a");

    // Cleanup: rollback and close
    rc = sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);
    sqlite3_close(db);
}
