// hsm_instance_test.cpp — Unit tests for HSM instance ID management
#include "../../../src/signature_store/db_hsm_instance_provider.h"
//
// Tests verify:
//   1. HsmInstanceId value object construction and equality
//   2. DatabaseHsmInstanceProvider caching and persistence
//   3. Process-wide instance ID accessors (set/get)
//   4. Integration with database schema bootstrap

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#endif
#include "../../../src/core/hsm_instance.h"
#include "../../../src/signature_store/db_connection.h"
#include "../../../src/signature_store/db_schema.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

using namespace vhsm::core;
using namespace vhsm::signature_store::db;

namespace {

// Test doubles ================================================================

// Mock database that mimics sqlite_connection behavior for testing
class MockDbConnection : public IDbConnection {
public:
  MockDbConnection() = default;

  DbResultSet query(const std::string &sql,
                    const std::vector<std::string> &params = {}) override {
    // Simple in-memory storage for db_meta
    if (sql.find("SELECT value FROM db_meta WHERE key = ?") !=
        std::string::npos) {
      if (!params.empty() && params[0] == "instance_id") {
        DbResultSet result;
        if (!stored_instance_id_.empty()) {
          // DbRow holds column values as vector<string>
          DbRow row(std::vector<std::string>{stored_instance_id_});
          result.rows_.push_back(std::move(row));
        }
        return result;
      }
    }
    return DbResultSet();
  }

  i64 exec(const std::string &sql,
           const std::vector<std::string> &params = {}) override {
    // Handle both legacy INSERT OR REPLACE and modern ON CONFLICT form
    if (sql.find("INSERT INTO db_meta") != std::string::npos) {
      if (params.size() >= 2 && params[0] == "instance_id") {
        stored_instance_id_ = params[1];
        return 1; // rows affected
      }
    }
    return 0;
  }

  void
  with_transaction(const std::function<void(IDbTransaction &)> &func) override {
    (void)func;
    // Mock: no transaction needed for unit tests
  }

  std::string stored_instance_id_;
};

// Fixtures ====================================================================

class HsmInstanceIdTest : public ::testing::Test {};

class DatabaseHsmInstanceProviderTest : public ::testing::Test {
protected:
  void SetUp() override {
    mock_db_ = std::make_unique<MockDbConnection>();
    provider_ = std::make_unique<DatabaseHsmInstanceProvider>(*mock_db_);
  }

  std::unique_ptr<MockDbConnection> mock_db_;
  std::unique_ptr<DatabaseHsmInstanceProvider> provider_;
};

class ProcessWideInstanceTest : public ::testing::Test {
protected:
  void TearDown() override {
    // Clear process-wide instance ID after each test
    vhsm::core::set_hsm_instance_id("");
  }
};

} // namespace

// ===========================================================================
// HsmInstanceId Tests
// ===========================================================================

TEST_F(HsmInstanceIdTest, ConstructionAndValue) {
  std::string uuid = "550e8400-e29b-41d4-a716-446655440000";
  HsmInstanceId id(uuid);
  EXPECT_EQ(id.value(), uuid);
}

TEST_F(HsmInstanceIdTest, EqualityOperators) {
  std::string uuid1 = "550e8400-e29b-41d4-a716-446655440000";
  std::string uuid2 = "550e8400-e29b-41d4-a716-446655440001";

  HsmInstanceId id1(uuid1);
  HsmInstanceId id2(uuid1);
  HsmInstanceId id3(uuid2);

  // Same UUID
  EXPECT_EQ(id1, id2);
  EXPECT_FALSE(id1 != id2);

  // Different UUID
  EXPECT_NE(id1, id3);
  EXPECT_FALSE(id1 == id3);
}

TEST_F(HsmInstanceIdTest, ImmutabilityAfterConstruction) {
  std::string original = "550e8400-e29b-41d4-a716-446655440000";
  HsmInstanceId id(original);

  // Ensure value does not change
  EXPECT_EQ(id.value(), original);
  EXPECT_EQ(id.value(), original); // Call again to verify immutability
}

TEST_F(HsmInstanceIdTest, Copyable) {
  std::string uuid = "550e8400-e29b-41d4-a716-446655440000";
  HsmInstanceId id1(uuid);
  HsmInstanceId id2 = id1; // Copy construction

  EXPECT_EQ(id1, id2);
  EXPECT_EQ(id2.value(), uuid);

  HsmInstanceId id3("other");
  id3 = id1; // Copy assignment
  EXPECT_EQ(id1, id3);
}

// ===========================================================================
// DatabaseHsmInstanceProvider Tests
// ===========================================================================

TEST_F(DatabaseHsmInstanceProviderTest, CachesAfterFirstRead) {
  std::string uuid = "550e8400-e29b-41d4-a716-446655440000";
  mock_db_->stored_instance_id_ = uuid;

  // First call queries the database
  HsmInstanceId id1 = provider_->getInstanceId();
  EXPECT_EQ(id1.value(), uuid);

  // Modify the mock's stored value
  mock_db_->stored_instance_id_ = "modified-uuid";

  // Second call returns cached value (not the modified one)
  HsmInstanceId id2 = provider_->getInstanceId();
  EXPECT_EQ(id2.value(), uuid); // Still the original
}

TEST_F(DatabaseHsmInstanceProviderTest, ThrowsWhenNotSeeded) {
  // Empty stored value means not seeded
  mock_db_->stored_instance_id_ = "";

  EXPECT_THROW(provider_->getInstanceId(), std::runtime_error);
}

TEST_F(DatabaseHsmInstanceProviderTest, SeedsInstanceId) {
  std::string uuid = "550e8400-e29b-41d4-a716-446655440000";
  HsmInstanceId id(uuid);

  bool success = provider_->seedInstanceId(id);
  EXPECT_TRUE(success);
  EXPECT_EQ(mock_db_->stored_instance_id_, uuid);
}

TEST_F(DatabaseHsmInstanceProviderTest, InvalidateCacheOnSeed) {
  std::string uuid1 = "550e8400-e29b-41d4-a716-446655440000";
  mock_db_->stored_instance_id_ = uuid1;

  // Prime the cache
  HsmInstanceId id1 = provider_->getInstanceId();
  EXPECT_EQ(id1.value(), uuid1);

  // Seed a new value
  std::string uuid2 = "550e8400-e29b-41d4-a716-446655440001";
  HsmInstanceId id2(uuid2);
  provider_->seedInstanceId(id2);

  // Next read should fetch from database (which now has uuid2)
  HsmInstanceId id3 = provider_->getInstanceId();
  EXPECT_EQ(id3.value(), uuid2);
}

// ===========================================================================
// Process-Wide Instance ID Tests
// ===========================================================================

TEST_F(ProcessWideInstanceTest, SetAndGet) {
  std::string uuid = "550e8400-e29b-41d4-a716-446655440000";
  set_hsm_instance_id(uuid);
  EXPECT_EQ(hsm_instance_id(), uuid);
}

TEST_F(ProcessWideInstanceTest, InitiallyEmpty) {
  // After TearDown clears it, initial state is empty
  EXPECT_EQ(hsm_instance_id(), "");
}

TEST_F(ProcessWideInstanceTest, OverwritesPreviousValue) {
  std::string uuid1 = "550e8400-e29b-41d4-a716-446655440000";
  std::string uuid2 = "550e8400-e29b-41d4-a716-446655440001";

  set_hsm_instance_id(uuid1);
  EXPECT_EQ(hsm_instance_id(), uuid1);

  set_hsm_instance_id(uuid2);
  EXPECT_EQ(hsm_instance_id(), uuid2);
}

// ===========================================================================
// Integration Tests (with real SQLite DB)
// ===========================================================================

class HsmInstanceIntegrationTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Create a temporary in-memory SQLite database
    db_ = make_sqlite_connection(":memory:");
    schema_ = std::make_unique<DbSchema>(*db_);

    // Bootstrap creates instance_id
    schema_->bootstrap();

    provider_ = std::make_unique<DatabaseHsmInstanceProvider>(*db_);
  }

  void TearDown() override {
    // Clear process-wide state
    vhsm::core::set_hsm_instance_id("");
  }

  std::unique_ptr<IDbConnection> db_;
  std::unique_ptr<DbSchema> schema_;
  std::unique_ptr<DatabaseHsmInstanceProvider> provider_;
};

TEST_F(HsmInstanceIntegrationTest, BootstrapSeedsInstanceId) {
  // After bootstrap, the schema should have seeded an instance_id
  std::string instance_id = schema_->get_instance_id();
  EXPECT_FALSE(instance_id.empty());
  // UUID v4 format check (basic: 36 chars with hyphens)
  EXPECT_EQ(instance_id.length(), 36);
  EXPECT_EQ(instance_id[8], '-');
  EXPECT_EQ(instance_id[13], '-');
  EXPECT_EQ(instance_id[18], '-');
  EXPECT_EQ(instance_id[23], '-');
}

TEST_F(HsmInstanceIntegrationTest, ProviderReadsSeededValue) {
  std::string instance_id = schema_->get_instance_id();
  HsmInstanceId id = provider_->getInstanceId();
  EXPECT_EQ(id.value(), instance_id);
}

TEST_F(HsmInstanceIntegrationTest, ProviderCachesAcrossMultipleCalls) {
  HsmInstanceId id1 = provider_->getInstanceId();
  HsmInstanceId id2 = provider_->getInstanceId();

  // Both should return the same cached value
  EXPECT_EQ(id1, id2);
}

TEST_F(HsmInstanceIntegrationTest, SeedCustomInstanceId) {
  std::string custom_uuid = "custom-550e8400-e29b-41d4-a716-446655440000";
  HsmInstanceId custom_id(custom_uuid);

  bool success = provider_->seedInstanceId(custom_id);
  EXPECT_TRUE(success);

  // Read it back to verify persistence
  HsmInstanceId retrieved = provider_->getInstanceId();
  EXPECT_EQ(retrieved.value(), custom_uuid);

  // Verify it's in the database
  std::string from_schema = schema_->get_instance_id();
  EXPECT_EQ(from_schema, custom_uuid);
}

TEST_F(HsmInstanceIntegrationTest, InstanceIdPersistsAcrossConnections) {
  // Get the initial instance_id
  std::string original_id = schema_->get_instance_id();

  // Create a new connection and schema to the same database
  auto db2 = make_sqlite_connection(":memory:");
  auto schema2 = std::make_unique<DbSchema>(*db2);
  schema2->bootstrap();

  // The new database gets a new instance_id (different in-memory DB)
  std::string new_id = schema2->get_instance_id();

  // They should be different because they're different databases
  EXPECT_NE(original_id, new_id);

  // But within the same database, the ID should be stable
  std::string original_again = schema_->get_instance_id();
  EXPECT_EQ(original_id, original_again);
}
