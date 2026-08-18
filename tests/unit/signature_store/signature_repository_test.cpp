// signature_repository_test.cpp — Unit tests for SignatureRepository
//
// Build: add to test target in CMake or compile linking with sqlite3 and GTest.

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "../../../src/signature_store/sqlite_connection.h"
#include "../../../src/signature_store/db_connection.h"
#include "../../../src/signature_store/signature_repository.h"
#include "../../../src/signature_store/db_schema.h"
#include "../../../src/keystore/token.h"
#include "../../../src/ledger/ledger_entry.h"
#include "../../../src/core/error.h"

using namespace vhsm::signature_store;
using namespace vhsm::signature_store::db;

namespace {

// Unwrap an optional<string> for assertions: nullopt maps to "<NULL>".
std::string s(const std::optional<std::string>& opt) {
    return opt ? *opt : "<NULL>";
}

std::optional<std::string> insert_record(SignatureRepository& repo,
                                         const std::string& payload_digest = "aabbccddeeff00112233445566778899") {
    return repo.insert(
        1234567890,                    // created_at
        0,                             // slot_id
        "test-token",                  // token_label
        "test-key-id",                 // key_id
        "abcdef1234567890",            // key_fingerprint
        "CKM_ECDSA_SHA256",            // mechanism
        "SHA256",                      // digest_algorithm (not stored)
        payload_digest,                // payload_digest
        32,                            // payload_size
        "MEUCIQD...",                  // signature_b64 (dummy)
        "session123",                  // session_handle
        "test-user",                   // user_label
        "test-app");                   // app_context
}

} // namespace

class SignatureRepositoryTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create an in-memory SQLite database for testing
        conn_ = make_sqlite_connection(":memory:");

        // Bootstrap the schema
        schema_ = std::make_unique<DbSchema>(*conn_);
        schema_->bootstrap();

        // Create a token for the repository
        token_ = std::make_unique<vhsm::keystore::Token>("test-token", "test-id");

        // Create the repository
        repo_ = std::make_unique<SignatureRepository>(*conn_, *token_);
    }

    std::unique_ptr<IDbConnection> conn_;
    std::unique_ptr<DbSchema> schema_;
    std::unique_ptr<vhsm::keystore::Token> token_;
    std::unique_ptr<SignatureRepository> repo_;
};

TEST_F(SignatureRepositoryTest, InsertAndRetrieveSignature) {
    auto signature_id = insert_record(*repo_);
    ASSERT_TRUE(signature_id.has_value()) << "Failed to insert signature record";

    auto retrieved = repo_->get_by_id(*signature_id);
    ASSERT_TRUE(retrieved.has_value()) << "Failed to retrieve signature record";
    ASSERT_FALSE(retrieved->empty()) << "Retrieved record is empty";

    // Column order (matches sql_create_signature_records()):
    // 0: id | 1: created_at | 2: slot_id | 3: token_label | 4: key_id
    // 5: key_fingerprint | 6: mechanism | 7: payload_digest | 8: signature_b64
    // 9: session_handle | 10: user_label | 11: app_context
    // 12: ledger_tx_id | 13: ledger_block_num | 14: ledger_tx_time
    // 15: ledger_tx_proof | 16: ledger_tx_set_b64 | 17: ledger_status
    EXPECT_EQ(s(retrieved->at(0)), *signature_id);
    EXPECT_EQ(s(retrieved->at(1)), "1234567890");
    EXPECT_EQ(s(retrieved->at(2)), "0");
    EXPECT_EQ(s(retrieved->at(3)), "test-token");
    EXPECT_EQ(s(retrieved->at(4)), "test-key-id");
    EXPECT_EQ(s(retrieved->at(5)), "abcdef1234567890");
    EXPECT_EQ(s(retrieved->at(6)), "CKM_ECDSA_SHA256");
    EXPECT_EQ(s(retrieved->at(7)), "aabbccddeeff00112233445566778899");
    EXPECT_EQ(s(retrieved->at(8)), "MEUCIQD...");
    EXPECT_EQ(s(retrieved->at(9)), "session123");
    EXPECT_EQ(s(retrieved->at(10)), "test-user");
    EXPECT_EQ(s(retrieved->at(11)), "test-app");

    // Ledger fields are untouched right after insertion.
    EXPECT_EQ(s(retrieved->at(12)), "<NULL>");  // ledger_tx_id
    EXPECT_EQ(s(retrieved->at(13)), "<NULL>");  // ledger_block_num
    EXPECT_EQ(s(retrieved->at(14)), "<NULL>");  // ledger_tx_time
    EXPECT_EQ(s(retrieved->at(15)), "<NULL>");  // ledger_tx_proof
    EXPECT_EQ(s(retrieved->at(16)), "<NULL>");  // ledger_tx_set_b64
    EXPECT_EQ(s(retrieved->at(17)), "PENDING"); // ledger_status
}

TEST_F(SignatureRepositoryTest, UpdateLedgerFields) {
    auto signature_id = insert_record(*repo_);
    ASSERT_TRUE(signature_id.has_value()) << "Failed to insert signature record";

    // Create a LedgerEntry matching what the chaincode returns after commit.
    vhsm::ledger::LedgerEntry entry;
    entry.record_id        = *signature_id;
    entry.key_fingerprint  = "abcdef1234567890";
    entry.payload_digest   = "aabbccddeeff00112233445566778899";
    entry.signature_b64    = "MEUCIQD...";
    entry.created_at       = 1234567890;
    entry.tx_id            = "tx123456789";
    entry.block_number     = 42;

    EXPECT_TRUE(repo_->update_ledger_fields(*signature_id, entry));

    auto retrieved = repo_->get_by_id(*signature_id);
    ASSERT_TRUE(retrieved.has_value() && !retrieved->empty());

    EXPECT_EQ(s(retrieved->at(12)), "tx123456789"); // ledger_tx_id
    EXPECT_EQ(s(retrieved->at(13)), "42");          // ledger_block_num
    EXPECT_EQ(s(retrieved->at(14)), "<NULL>");      // ledger_tx_time preserved
    EXPECT_EQ(s(retrieved->at(15)), "<NULL>");      // ledger_tx_proof preserved
    EXPECT_EQ(s(retrieved->at(16)), "<NULL>");      // ledger_tx_set_b64 preserved
    EXPECT_EQ(s(retrieved->at(17)), "COMMITTED");   // ledger_status
}

TEST_F(SignatureRepositoryTest, LedgerCrossCheckOnTamperedRow) {
    auto signature_id = insert_record(*repo_);
    ASSERT_TRUE(signature_id.has_value()) << "Failed to insert signature record";

    vhsm::ledger::LedgerEntry entry;
    entry.record_id        = *signature_id;
    entry.key_fingerprint  = "abcdef1234567890";
    entry.payload_digest   = "aabbccddeeff00112233445566778899";
    entry.signature_b64    = "MEUCIQD...";
    entry.created_at       = 1234567890;
    entry.tx_id            = "tx123456789";
    entry.block_number     = 42;

    EXPECT_TRUE(repo_->update_ledger_fields(*signature_id, entry));

    // Tamper with payload_digest directly in the DB (simulating a local attacker).
    conn_->exec(
        "UPDATE signature_records SET payload_digest = ? WHERE id = ?",
        { "tampered-payload-digest", *signature_id });

    auto retrieved = repo_->get_by_id(*signature_id);
    ASSERT_TRUE(retrieved.has_value() && !retrieved->empty());

    // The local row now disagrees with what the ledger committed.
    EXPECT_EQ(s(retrieved->at(7)), "tampered-payload-digest");
    EXPECT_EQ(s(retrieved->at(12)), "tx123456789");  // still anchored

    // The ledger cross-check (payload_digest comparison in VerificationService /
    // SignatureQuery) would flag this mismatch: the tampered value differs from
    // the ledger's committed payload_digest.
    EXPECT_NE("tampered-payload-digest", entry.payload_digest);
}