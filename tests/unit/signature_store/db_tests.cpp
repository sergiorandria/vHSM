// db_tests.cpp — Unit tests for db_row, db_connection (DbResultSet), db_schema
//
// Build: g++ -std=c++20 db_tests.cpp db_row.cpp db_schema.cpp -I.. -lgtest -lgtest_main -pthread -o db_tests
// Or add to CMake test target.
//
// Or with CMake (recommended):
//   add_executable(db_tests db_tests.cpp db_row.cpp db_schema.cpp)
//   target_link_libraries(db_tests PRIVATE GTest::gtest_main vhsm_db)
// =============================================================================

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include "../../../src/core/error.h"
#include "../../../src/signature_store/db_connection.h"
#include "../../../src/signature_store/db_row.h"
#include "../../../src/signature_store/db_schema.h"

using namespace vhsm::signature_store;

namespace vhsm::signature_store::db {

// ─────────────────────────────────────────────────────────────────────────────
// Helpers / fakes
// ─────────────────────────────────────────────────────────────────────────────

// Minimal in-memory fake transaction used by FakeDbConnection below.
class FakeTransaction : public IDbTransaction {
public:
    explicit FakeTransaction(
        std::unordered_map<std::string, std::vector<DbRow>>& tables,
        std::vector<std::string>& exec_log)
        : tables_(tables), exec_log_(exec_log) {}

    DbResultSet query(const std::string& sql,
                      const std::vector<std::string>& params = {}) override {
        // Minimal routing used by DbSchema internals:
        //   "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?;"
        if (sql.find("sqlite_master") != std::string::npos && params.size() == 1) {
            bool exists = tables_.count(params[0]) > 0;
            return DbResultSet({ DbRow({ exists ? "1" : "0" }) });
        }
        //   "SELECT value FROM db_meta WHERE key=?;"
        if (sql.find("FROM db_meta") != std::string::npos && params.size() == 1) {
            auto it = tables_.find("db_meta");
            if (it == tables_.end()) return DbResultSet{};
            for (const auto& row : it->second) {
                auto k = row.get_string(0);
                if (k && *k == params[0]) {
                    auto v = row.get_string(1);
                    return DbResultSet({ DbRow({ v.value_or("") }) });
                }
            }
            return DbResultSet{};
        }
        return DbResultSet{};
    }

    i64 exec(const std::string& sql,
             const std::vector<std::string>& params = {}) override {
        exec_log_.push_back(sql);
        // Track table creation for table_exists checks.
        auto create_pos = sql.find("CREATE TABLE IF NOT EXISTS ");
        if (create_pos != std::string::npos) {
            auto name_start = create_pos + std::string("CREATE TABLE IF NOT EXISTS ").size();
            auto name_end   = sql.find(' ', name_start);
            if (name_end == std::string::npos) name_end = sql.find('\n', name_start);
            if (name_end == std::string::npos) name_end = sql.find('(', name_start);
            if (name_end != std::string::npos) {
                std::string table_name = sql.substr(name_start, name_end - name_start);
                // Strip leading whitespace/newlines that may appear in multi-line SQL.
                auto first = table_name.find_first_not_of(" \t\r\n");
                if (first != std::string::npos) table_name = table_name.substr(first);
                tables_[table_name] = {};  // mark as existing
            }
        }
        // Track INSERT INTO db_meta(key,value) VALUES(?,?)
        if (sql.find("INSERT INTO db_meta") != std::string::npos && params.size() == 2) {
            tables_["db_meta"].push_back(DbRow({ params[0], params[1] }));
        }
        // Track UPDATE db_meta SET value='N' WHERE key='schema_version'
        if (sql.find("UPDATE db_meta SET value=") != std::string::npos) {
            // For migration tests: update schema_version row.
            auto& rows = tables_["db_meta"];
            for (auto& row : rows) {
                if (row.get_string(0) == std::string("schema_version")) {
                    // Extract the new value from the SQL string.
                    // Simple pattern: value='N'
                    auto eq = sql.find("value='");
                    if (eq != std::string::npos) {
                        auto vstart = eq + 7;
                        auto vend   = sql.find('\'', vstart);
                        if (vend != std::string::npos) {
                            std::string newval = sql.substr(vstart, vend - vstart);
                            row = DbRow({ "schema_version", newval });
                        }
                    }
                }
            }
        }
        return 0;
    }

private:
    std::unordered_map<std::string, std::vector<DbRow>>& tables_;
    std::vector<std::string>& exec_log_;
};

// A fake IDbConnection that stores everything in memory.
// exec_log() lets tests assert which SQL statements were executed.
class FakeDbConnection : public IDbConnection {
public:
    DbResultSet query(const std::string& sql,
                      const std::vector<std::string>& params = {}) override {
        FakeTransaction tx(tables_, exec_log_);
        return tx.query(sql, params);
    }

    i64 exec(const std::string& sql,
             const std::vector<std::string>& params = {}) override {
        FakeTransaction tx(tables_, exec_log_);
        return tx.exec(sql, params);
    }

    void with_transaction(const std::function<void(IDbTransaction&)>& func) override {
        FakeTransaction tx(tables_, exec_log_);
        func(tx);
    }

    const std::vector<std::string>& exec_log() const { return exec_log_; }

    bool has_table(const std::string& name) const {
        return tables_.count(name) > 0;
    }

    // Expose internal state for seeding meta rows between tests.
    void seed_meta(const std::string& key, const std::string& value) {
        tables_["db_meta"].push_back(DbRow({ key, value }));
    }

private:
    std::unordered_map<std::string, std::vector<DbRow>> tables_;
    std::vector<std::string> exec_log_;
};

// ─────────────────────────────────────────────────────────────────────────────
// DbRow tests
// ─────────────────────────────────────────────────────────────────────────────

class DbRowTest : public ::testing::Test {};

TEST_F(DbRowTest, ColumnCount_ReturnsCorrectCount) {
    DbRow row({ "a", "b", "c" });
    EXPECT_EQ(row.column_count(), 3u);
}

TEST_F(DbRowTest, ColumnCount_EmptyRow) {
    DbRow row({});
    EXPECT_EQ(row.column_count(), 0u);
}

TEST_F(DbRowTest, GetString_ValidIndex) {
    DbRow row({ "hello", "world" });
    EXPECT_EQ(row.get_string(0), "hello");
    EXPECT_EQ(row.get_string(1), "world");
}

TEST_F(DbRowTest, GetString_OutOfBounds_ReturnsNullopt) {
    DbRow row({ "only" });
    EXPECT_EQ(row.get_string(1), std::nullopt);
    EXPECT_EQ(row.get_string(100), std::nullopt);
}

TEST_F(DbRowTest, GetString_EmptyString_ReturnsSome) {
    DbRow row({ "" });
    auto val = row.get_string(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, "");
}

TEST_F(DbRowTest, GetI64_ValidPositive) {
    DbRow row({ "42" });
    auto val = row.get_i64(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, 42);
}

TEST_F(DbRowTest, GetI64_ValidNegative) {
    DbRow row({ "-1000000" });
    auto val = row.get_i64(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, -1000000);
}

TEST_F(DbRowTest, GetI64_Zero) {
    DbRow row({ "0" });
    auto val = row.get_i64(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, 0);
}

TEST_F(DbRowTest, GetI64_MaxI64) {
    DbRow row({ "9223372036854775807" });
    auto val = row.get_i64(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, std::numeric_limits<i64>::max());
}

TEST_F(DbRowTest, GetI64_NonNumeric_ReturnsNullopt) {
    DbRow row({ "abc" });
    EXPECT_EQ(row.get_i64(0), std::nullopt);
}

TEST_F(DbRowTest, GetI64_PartialNumeric_ReturnsNullopt) {
    // "123abc" has trailing garbage — from_chars stops at 'a', ptr != end.
    DbRow row({ "123abc" });
    EXPECT_EQ(row.get_i64(0), std::nullopt);
}

TEST_F(DbRowTest, GetI64_EmptyString_ReturnsNullopt) {
    DbRow row({ "" });
    EXPECT_EQ(row.get_i64(0), std::nullopt);
}

TEST_F(DbRowTest, GetI64_OutOfBounds_ReturnsNullopt) {
    DbRow row({ "1" });
    EXPECT_EQ(row.get_i64(5), std::nullopt);
}

TEST_F(DbRowTest, GetDouble_ValidFloat) {
    DbRow row({ "3.14" });
    auto val = row.get_double(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_NEAR(*val, 3.14, 1e-9);
}

TEST_F(DbRowTest, GetDouble_ValidInteger) {
    DbRow row({ "42" });
    auto val = row.get_double(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_DOUBLE_EQ(*val, 42.0);
}

TEST_F(DbRowTest, GetDouble_NegativeFloat) {
    DbRow row({ "-0.001" });
    auto val = row.get_double(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_NEAR(*val, -0.001, 1e-12);
}

TEST_F(DbRowTest, GetDouble_NonNumeric_ReturnsNullopt) {
    DbRow row({ "not_a_number" });
    EXPECT_EQ(row.get_double(0), std::nullopt);
}

TEST_F(DbRowTest, GetDouble_OutOfBounds_ReturnsNullopt) {
    DbRow row({ "1.0" });
    EXPECT_EQ(row.get_double(2), std::nullopt);
}

TEST_F(DbRowTest, GetBool_ZeroIsFalse) {
    DbRow row({ "0" });
    auto val = row.get_bool(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_FALSE(*val);
}

TEST_F(DbRowTest, GetBool_OneIsTrue) {
    DbRow row({ "1" });
    auto val = row.get_bool(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_TRUE(*val);
}

TEST_F(DbRowTest, GetBool_LowercaseFalse) {
    DbRow row({ "false" });
    auto val = row.get_bool(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_FALSE(*val);
}

TEST_F(DbRowTest, GetBool_LowercaseTrue) {
    DbRow row({ "true" });
    auto val = row.get_bool(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_TRUE(*val);
}

TEST_F(DbRowTest, GetBool_UppercaseFALSE) {
    DbRow row({ "FALSE" });
    auto val = row.get_bool(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_FALSE(*val);
}

TEST_F(DbRowTest, GetBool_UppercaseTRUE) {
    DbRow row({ "TRUE" });
    auto val = row.get_bool(0);
    ASSERT_TRUE(val.has_value());
    EXPECT_TRUE(*val);
}

TEST_F(DbRowTest, GetBool_InvalidValue_ReturnsNullopt) {
    for (const char* bad : { "yes", "no", "2", "-1", "", "True", "False" }) {
        DbRow row({ bad });
        EXPECT_EQ(row.get_bool(0), std::nullopt) << "input: " << bad;
    }
}

TEST_F(DbRowTest, GetBool_OutOfBounds_ReturnsNullopt) {
    DbRow row({ "1" });
    EXPECT_EQ(row.get_bool(1), std::nullopt);
}

TEST_F(DbRowTest, MultiColumn_AllTypesInOneRow) {
    DbRow row({ "hello", "99", "2.718", "1" });
    EXPECT_EQ(row.get_string(0), "hello");
    EXPECT_EQ(row.get_i64(1), i64(99));
    ASSERT_TRUE(row.get_double(2).has_value());
    EXPECT_NEAR(*row.get_double(2), 2.718, 1e-9);
    EXPECT_EQ(row.get_bool(3), true);
}

// ─────────────────────────────────────────────────────────────────────────────
// DbResultSet tests (via db_connection.h)
// ─────────────────────────────────────────────────────────────────────────────

class DbResultSetTest : public ::testing::Test {
protected:
    DbResultSet make_rs(std::vector<DbRow> rows) {
        return DbResultSet(std::move(rows));
    }
};

TEST_F(DbResultSetTest, DefaultConstruct_IsEmpty) {
    DbResultSet rs;
    EXPECT_TRUE(rs.empty());
    EXPECT_EQ(rs.rows_count(), 0u);
}

TEST_F(DbResultSetTest, RowsCount_MatchesInput) {
    DbResultSet rs(make_rs({ DbRow({ "a" }), DbRow({ "b" }), DbRow({ "c" }) }));
    EXPECT_EQ(rs.rows_count(), 3u);
    EXPECT_FALSE(rs.empty());
}

TEST_F(DbResultSetTest, Get_String) {
    DbResultSet rs({ DbRow({ "value", "42" }) });
    auto v = rs.get<std::string>(rs.rows_[0], 0);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "value");
}

TEST_F(DbResultSetTest, Get_I64) {
    DbResultSet rs({ DbRow({ "777" }) });
    auto v = rs.get<i64>(rs.rows_[0], 0);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 777);
}

TEST_F(DbResultSetTest, Get_Double) {
    DbResultSet rs({ DbRow({ "1.5" }) });
    auto v = rs.get<double>(rs.rows_[0], 0);
    ASSERT_TRUE(v.has_value());
    EXPECT_DOUBLE_EQ(*v, 1.5);
}

TEST_F(DbResultSetTest, Get_Bool) {
    DbResultSet rs({ DbRow({ "true" }) });
    auto v = rs.get<bool>(rs.rows_[0], 0);
    ASSERT_TRUE(v.has_value());
    EXPECT_TRUE(*v);
}

TEST_F(DbResultSetTest, Get_OutOfBoundsColumn_ReturnsNullopt) {
    DbResultSet rs({ DbRow({ "x" }) });
    EXPECT_EQ(rs.get<std::string>(rs.rows_[0], 5), std::nullopt);
}

TEST_F(DbResultSetTest, DirectRowsAccess) {
    DbResultSet rs({ DbRow({ "first" }), DbRow({ "second" }) });
    ASSERT_EQ(rs.rows_.size(), 2u);
    EXPECT_EQ(rs.rows_[0].get_string(0), "first");
    EXPECT_EQ(rs.rows_[1].get_string(0), "second");
}

// ─────────────────────────────────────────────────────────────────────────────
// DbSchema — sql_create_* content tests
// ─────────────────────────────────────────────────────────────────────────────

class DbSchemaContentTest : public ::testing::Test {
protected:
    FakeDbConnection conn_;
    db::DbSchema schema_{ conn_ };
};

TEST_F(DbSchemaContentTest, SqlCreateSignatureRecords_ContainsRekorColumns) {
    auto sql = schema_.sql_create_signature_records();
    EXPECT_NE(sql.find("rekor_entry_uuid"), std::string::npos);
    EXPECT_NE(sql.find("rekor_log_index"),  std::string::npos);
    EXPECT_NE(sql.find("rekor_set_b64"),    std::string::npos);
    EXPECT_NE(sql.find("rekor_status"),     std::string::npos);
}

TEST_F(DbSchemaContentTest, SqlCreateSignatureRecords_RekorStatusHasCorrectCheck) {
    auto sql = schema_.sql_create_signature_records();
    EXPECT_NE(sql.find("PENDING"),   std::string::npos);
    EXPECT_NE(sql.find("COMMITTED"), std::string::npos);
    EXPECT_NE(sql.find("FAILED"),    std::string::npos);
    EXPECT_NE(sql.find("DISABLED"),  std::string::npos);
}

TEST_F(DbSchemaContentTest, SqlCreateSignatureRecords_NoIntegrityHmac) {
    // Per the updated design: integrity_hmac dropped from signature_records.
    // This test enforces that decision.
    auto sql = schema_.sql_create_signature_records();
    EXPECT_EQ(sql.find("integrity_hmac"), std::string::npos)
        << "integrity_hmac should not exist in signature_records (dropped per Rekor-only design)";
}

TEST_F(DbSchemaContentTest, SqlCreateSignatureRecords_CoreColumnsPresent) {
    auto sql = schema_.sql_create_signature_records();
    for (const char* col : { "id", "created_at", "slot_id", "token_label",
                               "key_id", "key_fingerprint", "mechanism",
                               "payload_digest", "signature_b64", "session_handle",
                               "user_label", "app_context" }) {
        EXPECT_NE(sql.find(col), std::string::npos) << "Missing column: " << col;
    }
}

TEST_F(DbSchemaContentTest, SqlCreateSignatureVerifications_HasRekorOutcome) {
    auto sql = schema_.sql_create_signature_verifications();
    EXPECT_NE(sql.find("rekor_outcome"), std::string::npos);
    EXPECT_NE(sql.find("PROOF_OK"),      std::string::npos);
    EXPECT_NE(sql.find("PROOF_FAILED"),  std::string::npos);
    EXPECT_NE(sql.find("NOT_CHECKED"),   std::string::npos);
}

TEST_F(DbSchemaContentTest, SqlCreateKeyRekorRegistry_RequiredColumns) {
    auto sql = schema_.sql_create_key_rekor_registry();
    for (const char* col : { "id", "key_fingerprint", "event_type",
                               "occurred_at", "rekor_entry_uuid",
                               "rekor_log_index", "rekor_status" }) {
        EXPECT_NE(sql.find(col), std::string::npos) << "Missing column: " << col;
    }
    EXPECT_NE(sql.find("CREATED"), std::string::npos);
    EXPECT_NE(sql.find("RETIRED"), std::string::npos);
}

TEST_F(DbSchemaContentTest, SqlCreateIndexes_IncludesRekorIndexes) {
    auto sql = schema_.sql_create_indexes();
    EXPECT_NE(sql.find("idx_sig_rekor_uuid"),   std::string::npos);
    EXPECT_NE(sql.find("idx_sig_rekor_status"), std::string::npos);
    EXPECT_NE(sql.find("idx_krr_fingerprint"),  std::string::npos);
}

TEST_F(DbSchemaContentTest, SqlCreateDbMeta_PrimaryKeyOnKey) {
    auto sql = schema_.sql_create_db_meta();
    EXPECT_NE(sql.find("key"), std::string::npos);
    EXPECT_NE(sql.find("value"), std::string::npos);
    EXPECT_NE(sql.find("PRIMARY KEY"), std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// DbSchema — bootstrap() behaviour
// ─────────────────────────────────────────────────────────────────────────────

class DbSchemaBootstrapTest : public ::testing::Test {
protected:
    FakeDbConnection conn_;
    DbSchema schema_{ conn_ };
};

TEST_F(DbSchemaBootstrapTest, Bootstrap_FreshDb_CreatesAllTables) {
    schema_.bootstrap();
    for (const char* tbl : { "db_meta", "signature_records",
                               "signature_verifications",
                               "notification_subscribers",
                               "notification_log",
                               "key_rekor_registry" }) {
        EXPECT_TRUE(conn_.has_table(tbl)) << "Expected table: " << tbl;
    }
}

TEST_F(DbSchemaBootstrapTest, Bootstrap_FreshDb_SetsSchemaVersion) {
    schema_.bootstrap();
    int v = schema_.current_version();
    EXPECT_EQ(v, kCurrentSchemaVersion);
}

TEST_F(DbSchemaBootstrapTest, Bootstrap_FreshDb_ExecsCreateStatements) {
    schema_.bootstrap();
    const auto& log = conn_.exec_log();
    bool found_sig = false;
    bool found_meta = false;
    for (const auto& s : log) {
        if (s.find("signature_records") != std::string::npos) found_sig  = true;
        if (s.find("db_meta")           != std::string::npos) found_meta = true;
    }
    EXPECT_TRUE(found_sig)  << "Expected CREATE TABLE ... signature_records in exec log";
    EXPECT_TRUE(found_meta) << "Expected CREATE TABLE ... db_meta in exec log";
}

TEST_F(DbSchemaBootstrapTest, Bootstrap_AlreadyAtCurrentVersion_IsNoop) {
    // Pre-seed meta so current_version() returns kCurrentSchemaVersion.
    conn_.seed_meta("schema_version", std::to_string(kCurrentSchemaVersion));
    // Also mark db_meta as existing so table_exists() returns true.
    // (FakeDbConnection.has_table checks tables_ map.)

    // We need table_exists("db_meta") to return true.
    // Seed all expected tables so verify_schema works too.
    for (const char* tbl : { "db_meta", "signature_records",
                               "signature_verifications",
                               "notification_subscribers",
                               "notification_log",
                               "key_rekor_registry" }) {
        conn_.exec("CREATE TABLE IF NOT EXISTS " + std::string(tbl) + " (x TEXT);");
    }
    conn_.exec_log();  // don't care about pre-seed log

    // Now bootstrap should be a no-op (no additional CREATEs).
    // We can't easily clear the log, but we verify no exception is thrown.
    EXPECT_NO_THROW(schema_.bootstrap());
}

TEST_F(DbSchemaBootstrapTest, Bootstrap_FutureVersion_ThrowsDbError) {
    // If the DB reports a version *newer* than kCurrentSchemaVersion, bootstrap
    // must throw rather than silently proceed.
    conn_.seed_meta("schema_version",
                    std::to_string(kCurrentSchemaVersion + 1));
    for (const char* tbl : { "db_meta", "signature_records",
                               "signature_verifications",
                               "notification_subscribers",
                               "notification_log",
                               "key_rekor_registry" }) {
        conn_.exec("CREATE TABLE IF NOT EXISTS " + std::string(tbl) + " (x TEXT);");
    }
    EXPECT_THROW(schema_.bootstrap(), DbError);
}

// ─────────────────────────────────────────────────────────────────────────────
// DbSchema — current_version()
// ─────────────────────────────────────────────────────────────────────────────

class DbSchemaVersionTest : public ::testing::Test {
protected:
    FakeDbConnection conn_;
    DbSchema schema_{ conn_ };
};

TEST_F(DbSchemaVersionTest, CurrentVersion_NoMetaTable_ReturnsMinusOne) {
    // No tables seeded → table_exists("db_meta") returns false → -1.
    EXPECT_EQ(schema_.current_version(), -1);
}

TEST_F(DbSchemaVersionTest, CurrentVersion_MetaTableExistsButNoRow_ReturnsMinusOne) {
    conn_.exec("CREATE TABLE IF NOT EXISTS db_meta (x TEXT);");
    // No schema_version row inserted.
    EXPECT_EQ(schema_.current_version(), -1);
}

TEST_F(DbSchemaVersionTest, CurrentVersion_AfterBootstrap_ReturnsCurrentSchemaVersion) {
    schema_.bootstrap();
    EXPECT_EQ(schema_.current_version(), kCurrentSchemaVersion);
}

// ─────────────────────────────────────────────────────────────────────────────
// DbSchema — verify_schema()
// ─────────────────────────────────────────────────────────────────────────────

class DbSchemaVerifyTest : public ::testing::Test {
protected:
    FakeDbConnection conn_;
    DbSchema schema_{ conn_ };
};

TEST_F(DbSchemaVerifyTest, VerifySchema_AfterBootstrap_ReturnsTrue) {
    schema_.bootstrap();
    std::string err;
    EXPECT_TRUE(schema_.verify_schema(err));
    EXPECT_TRUE(err.empty());
}

TEST_F(DbSchemaVerifyTest, VerifySchema_MissingTable_ReturnsFalseWithReason) {
    // Bootstrap, then check against a fresh connection that has no tables.
    FakeDbConnection empty_conn;
    DbSchema empty_schema(empty_conn);
    std::string err;
    EXPECT_FALSE(empty_schema.verify_schema(err));
    EXPECT_FALSE(err.empty());
    EXPECT_NE(err.find("Missing table"), std::string::npos);
}

TEST_F(DbSchemaVerifyTest, VerifySchema_WrongSchemaVersion_ReturnsFalseWithReason) {
    schema_.bootstrap();
    // Manually corrupt schema_version in meta.
    // We re-create a schema against a connection seeded with wrong version.
    FakeDbConnection bad_conn;
    for (const char* tbl : { "db_meta", "signature_records",
                               "signature_verifications",
                               "notification_subscribers",
                               "notification_log",
                               "key_rekor_registry" }) {
        bad_conn.exec("CREATE TABLE IF NOT EXISTS " + std::string(tbl) + " (x TEXT);");
    }
    bad_conn.seed_meta("schema_version", "0");  // wrong version
    DbSchema bad_schema(bad_conn);
    std::string err;
    EXPECT_FALSE(bad_schema.verify_schema(err));
    EXPECT_NE(err.find("Schema version mismatch"), std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// DbSchema — migrate() — v1 → v2
// ─────────────────────────────────────────────────────────────────────────────

class DbSchemaMigrateTest : public ::testing::Test {
protected:
    // Simulate a v1 database: all base tables exist, no Rekor columns.
    // We do this by seeding db_meta with schema_version=1 and marking all v1
    // tables as present (key_rekor_registry NOT present — it's a v2 addition).
    FakeDbConnection conn_;
    DbSchema schema_{ conn_ };

    void SetUp() override {
        for (const char* tbl : { "db_meta", "signature_records",
                                   "signature_verifications",
                                   "notification_subscribers",
                                   "notification_log" }) {
            conn_.exec("CREATE TABLE IF NOT EXISTS " + std::string(tbl) + " (x TEXT);");
        }
        conn_.seed_meta("schema_version", "1");
    }
};

TEST_F(DbSchemaMigrateTest, Bootstrap_FromV1_RunsMigration) {
    // bootstrap() detects v1 < kCurrentSchemaVersion (2) → calls migrate().
    EXPECT_NO_THROW(schema_.bootstrap());
    // After migration, key_rekor_registry must exist.
    EXPECT_TRUE(conn_.has_table("key_rekor_registry"));
}

TEST_F(DbSchemaMigrateTest, Bootstrap_FromV1_AltersSignatureRecords) {
    schema_.bootstrap();
    const auto& log = conn_.exec_log();
    bool found_alter = false;
    for (const auto& s : log) {
        if (s.find("ALTER TABLE signature_records") != std::string::npos) {
            found_alter = true;
            break;
        }
    }
    EXPECT_TRUE(found_alter) << "Expected ALTER TABLE signature_records in exec log";
}

TEST_F(DbSchemaMigrateTest, Migrate_AlreadyAtCurrentVersion_IsNoop) {
    // Bump meta to current version manually.
    conn_.seed_meta("schema_version", std::to_string(kCurrentSchemaVersion));
    // Override the v1 entry — re-seed is simplest by checking current_version return.
    // We can't easily mutate the fake; instead create a fresh connection at current ver.
    FakeDbConnection current_conn;
    for (const char* tbl : { "db_meta", "signature_records",
                               "signature_verifications",
                               "notification_subscribers",
                               "notification_log",
                               "key_rekor_registry" }) {
        current_conn.exec("CREATE TABLE IF NOT EXISTS " + std::string(tbl) + " (x TEXT);");
    }
    current_conn.seed_meta("schema_version", std::to_string(kCurrentSchemaVersion));
    DbSchema current_schema(current_conn);
    // migrate() from current version returns from_version immediately.
    EXPECT_EQ(current_schema.migrate(), kCurrentSchemaVersion);
}

// ─────────────────────────────────────────────────────────────────────────────
// Namespace / constant tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(DbSchemaConstantsTest, TableNameConstants_AreCorrect) {
    EXPECT_EQ(table::kSignatureRecords,         "signature_records");
    EXPECT_EQ(table::kSignatureVerifications,   "signature_verifications");
    EXPECT_EQ(table::kNotificationSubscribers,  "notification_subscribers");
    EXPECT_EQ(table::kNotificationLog,          "notification_log");
    EXPECT_EQ(table::kKeyRekorRegistry,         "key_rekor_registry");
    EXPECT_EQ(table::kDbMeta,                   "db_meta");
}

TEST(DbSchemaConstantsTest, MetaKeyConstants_AreCorrect) {
    EXPECT_EQ(meta_key::kSchemaVersion,  "schema_version");
    EXPECT_EQ(meta_key::kHmacKeyWrapped, "hmac_key_wrapped");
    EXPECT_EQ(meta_key::kCreatedAt,      "created_at");
    EXPECT_EQ(meta_key::kInstanceId,     "instance_id");
}

TEST(DbSchemaConstantsTest, RekorStatusConstants_AreCorrect) {
    EXPECT_EQ(rekor_status::kPending,   "PENDING");
    EXPECT_EQ(rekor_status::kCommitted, "COMMITTED");
    EXPECT_EQ(rekor_status::kFailed,    "FAILED");
    EXPECT_EQ(rekor_status::kDisabled,  "DISABLED");
}

TEST(DbSchemaConstantsTest, CurrentSchemaVersion_IsTwo) {
    EXPECT_EQ(kCurrentSchemaVersion, 2);
}

}  // namespace vhsm::signature_store::db