#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../../../src/signature_store/sqlite_connection.h"
#include "../../../src/signature_store/db_result_set.h"
#include "../../../src/core/error.h"

using namespace vhsm::signature_store;
using namespace vhsm::signature_store::db;

TEST(SqliteConnectionTest, OpenInMemory_CreateInsertQuery) {
    SqliteConnection conn(":memory:");

    // Create table
    conn.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);");

    // Insert a row
    i64 changes = conn.exec("INSERT INTO t(val) VALUES(?);", { "hello" });
    EXPECT_GE(changes, 1);

    // Query the row
    DbResultSet rs = conn.query("SELECT val FROM t WHERE id = 1;");
    ASSERT_EQ(rs.rows_count(), 1u);
    auto v = rs.get<std::string>(rs.rows_[0], 0);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "hello");
}

TEST(SqliteConnectionTest, WithTransactionCommit) {
    SqliteConnection conn(":memory:");
    conn.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);");

    conn.with_transaction([&](IDbTransaction& tx) {
        i64 c = tx.exec("INSERT INTO t(v) VALUES(?);", { "x" });
        EXPECT_GE(c, 1);
    });

    DbResultSet rs = conn.query("SELECT COUNT(*) FROM t;");
    ASSERT_EQ(rs.rows_count(), 1u);
    auto cnt = rs.get<i64>(rs.rows_[0], 0);
    ASSERT_TRUE(cnt.has_value());
    EXPECT_EQ(*cnt, 1);
}

TEST(SqliteConnectionTest, WithTransactionRollbackOnException) {
    SqliteConnection conn(":memory:");
    conn.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);");

    EXPECT_THROW(
        conn.with_transaction([&](IDbTransaction& tx) {
            tx.exec("INSERT INTO t(v) VALUES(?);", { "x" });
            throw std::runtime_error("boom");
        }),
        std::runtime_error);

    DbResultSet rs = conn.query("SELECT COUNT(*) FROM t;");
    ASSERT_EQ(rs.rows_count(), 1u);
    auto cnt = rs.get<i64>(rs.rows_[0], 0);
    // After rollback the count should be 0
    ASSERT_TRUE(cnt.has_value());
    EXPECT_EQ(*cnt, 0);
}
