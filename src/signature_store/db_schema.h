#ifndef VHSM_SIGSTORE_DB_SCHEMA_H
#define VHSM_SIGSTORE_DB_SCHEMA_H

#include <string>
#include <string_view>
#include <cstdint>

#include "db_connection.h"

namespace vhsm::signature_store {
namespace db {
// Schema version
// Bumped whenever a migration adds or changes a table.
// Migration N upgrades from version N-1 to version N.
inline constexpr int kCurrentSchemaVersion = 4;

// v1 — initial schema (signature_records, signature_verifications,
//       notification_subscribers, notification_log, db_meta)
// v2 — Rekor columns on signature_records and signature_verifications,
//       new key_rekor_registry table
// v3 — Added rekor_integrated_time and rekor_inclusion_proof columns to signature_records
// v4 — Replace Rekor columns with ledger columns, drop integrity_hmac from signature_records


// Table name constants
namespace table {
    inline constexpr std::string_view kSignatureRecords         = "signature_records";
    inline constexpr std::string_view kSignatureVerifications   = "signature_verifications";
    inline constexpr std::string_view kNotificationSubscribers  = "notification_subscribers";
    inline constexpr std::string_view kNotificationLog          = "notification_log";
    inline constexpr std::string_view kKeyRekorRegistry         = "key_rekor_registry";
    inline constexpr std::string_view kDbMeta                   = "db_meta";
}

// db_meta key constants
namespace meta_key {
    inline constexpr std::string_view kSchemaVersion   = "schema_version";
    inline constexpr std::string_view kHmacKeyWrapped  = "hmac_key_wrapped";   // AES-wrap of DB HMAC key
    inline constexpr std::string_view kCreatedAt       = "created_at";         // epoch ms
    inline constexpr std::string_view kInstanceId      = "instance_id";        // UUID v4
}

// Rekor status values (mirror the SQL CHECK constraint)
namespace rekor_status {
    inline constexpr std::string_view kPending   = "PENDING";
    inline constexpr std::string_view kCommitted = "COMMITTED";
    inline constexpr std::string_view kFailed    = "FAILED";
    inline constexpr std::string_view kDisabled  = "DISABLED";  // Rekor turned off at build time
}

// DbSchema — manages schema bootstrap and migrations
class DbSchema {
public:
    explicit DbSchema(IDbConnection& conn);

    // bootstrap()
    //
    // Called once on first startup (or after ":memory:" is opened in tests).
    // Creates all tables, indexes, and seeds db_meta with:
    //   - schema_version = kCurrentSchemaVersion
    //   - instance_id    = freshly generated UUID v4
    //   - created_at     = current epoch ms
    //   - hmac_key_wrapped = placeholder (filled in by db_hmac_key.cpp after KEK is ready)
    //
    // If the schema already exists at the current version, this is a no-op.
    // If the schema exists at an older version, calls migrate() automatically.
    //
    // Throws DbError on any failure.

    void bootstrap();

    // migrate()
    //
    // Runs all pending migrations from the current DB schema_version up to
    // kCurrentSchemaVersion.  Each migration step is wrapped in its own
    // transaction so a failure leaves the DB at the last successful version.
    //
    // Called automatically by bootstrap() when the DB already exists.
    // Can also be called explicitly (e.g. by vhsm-admin for controlled upgrades).
    //
    // Returns the version the DB was at before migration.
    int migrate();

    // current_version()
    //
    // Reads schema_version from db_meta.
    // Returns -1 if db_meta does not exist (uninitialized DB).
    int current_version();

    // verify_schema()
    //
    // Checks that every expected table and column exists.
    // Useful as a startup sanity check and in integration tests.
    // Returns true if the schema is intact; false with reason written to `out_error`.
    bool verify_schema(std::string& out_error);

    // SQL fragments (public so sql/ files can be generated from them)
    // These return backend-appropriate SQL for the connection's backend.

    // Full CREATE TABLE statements for the current version.
    std::string sql_create_signature_records()        const;
    std::string sql_create_signature_verifications()  const;
    std::string sql_create_notification_subscribers() const;
    std::string sql_create_notification_log()         const;
    std::string sql_create_key_rekor_registry()       const;
    std::string sql_create_db_meta()                  const;

    // CREATE INDEX statements.
    std::string sql_create_indexes()                  const;

private:
    IDbConnection& conn_;

    // Internal helpers
    bool table_exists(const std::string& table_name);
    void set_meta(const std::string& key, const std::string& value);
    std::string get_meta(const std::string& key);

    // Migration steps — one method per version bump.
    // Will be removed in future update.
    void migrate_v1_to_v2();  // Adds Rekor columns + key_rekor_registry
    void migrate_v2_to_v3();  // Adds rekor_integrated_time and rekor_inclusion_proof columns
    void migrate_v3_to_v4();  // Replace Rekor columns with ledger columns, drop integrity_hmac
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_DB_SCHEMA_H