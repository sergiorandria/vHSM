#ifndef VHSM_SIGSTORE_DB_SCHEMA_H
#define VHSM_SIGSTORE_DB_SCHEMA_H

#include <cstdint>
#include <string>
#include <string_view>

#include "db_connection.h"

namespace vhsm::signature_store {
namespace db {
// Schema version
// Bumped whenever a migration adds or changes a table.
// Migration N upgrades from version N-1 to version N.
inline constexpr int K_CURRENT_SCHEMA_VERSION = 6;

// v1 — initial schema (signature_records, signature_verifications,
//       notification_subscribers, notification_log, db_meta)
// v2 — Rekor staging columns (removed in v4; legacy installs only)
// v3 — more Rekor staging columns (removed in v4; legacy installs only)
// v4 — Hyperledger Fabric ledger columns, no Rekor, no integrity_hmac
// v5 — notification_subscribers / notification_log drop integrity_hmac
//      (matches PLANv4 §8.5 "Fabric/notification" schema; no local HMAC)
// v6 — event_outbox for transactional outbox pattern (ledger + notification
//      delivery via same DB transaction as signature_records)

// Table name constants
namespace table {
inline constexpr std::string_view K_SIGNATURE_RECORDS = "signature_records";
inline constexpr std::string_view K_SIGNATURE_VERIFICATIONS =
    "signature_verifications";
inline constexpr std::string_view K_NOTIFICATION_SUBSCRIBERS =
    "notification_subscribers";
inline constexpr std::string_view K_NOTIFICATION_LOG = "notification_log";
inline constexpr std::string_view K_EVENT_OUTBOX = "event_outbox";
inline constexpr std::string_view K_DB_META = "db_meta";
} // namespace table

// db_meta key constants
namespace meta_key {
inline constexpr std::string_view K_SCHEMA_VERSION = "schema_version";
inline constexpr std::string_view K_HMAC_KEY_WRAPPED =
    "hmac_key_wrapped"; // legacy placeholder, unused
inline constexpr std::string_view K_CREATED_AT = "created_at";   // epoch ms
inline constexpr std::string_view K_INSTANCE_ID = "instance_id"; // UUID v4
} // namespace meta_key

// Ledger status values (mirror the SQL CHECK constraint)
namespace ledger_status {
inline constexpr std::string_view K_PENDING = "PENDING";
inline constexpr std::string_view K_COMMITTED = "COMMITTED";
inline constexpr std::string_view K_FAILED = "FAILED";
} // namespace ledger_status

// DbSchema — manages schema bootstrap and migrations
class DbSchema {
public:
  explicit DbSchema(IDbConnection &conn);

  // bootstrap()
  //
  // Called once on first startup (or after ":memory:" is opened in tests).
  // Creates all tables, indexes, and seeds db_meta with:
  //   - schema_version = K_CURRENT_SCHEMA_VERSION
  //   - instance_id    = freshly generated UUID v4
  //   - created_at     = current epoch ms
  //   - hmac_key_wrapped = legacy placeholder (kept for compatibility)
  //
  // If the schema already exists at the current version, this is a no-op.
  // If the schema exists at an older version, calls migrate() automatically.
  //
  // Throws DbError on any failure.

  void bootstrap();

  // migrate()
  //
  // Runs all pending migrations from the current DB schema_version up to
  // K_CURRENT_SCHEMA_VERSION.  Each migration step is wrapped in its own
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

  // get_instance_id()
  //
  // Returns the instance_id seeded in db_meta (a UUID v4 that identifies this
  // HSM/DB instance). Audit and notification producers tag events with it so
  // multi-instance deployments can correlate activity.
  std::string get_instance_id();

  // verify_schema()
  //
  // Checks that every expected table and column exists.
  // Useful as a startup sanity check and in integration tests.
  // Returns true if the schema is intact; false with reason written to
  // `out_error`.
  bool verify_schema(std::string &out_error);

  // SQL fragments (public so sql/ files can be generated from them)
  // These return backend-appropriate SQL for the connection's backend.

  // Full CREATE TABLE statements for the current version.
  std::string sql_create_signature_records() const;
  std::string sql_create_signature_verifications() const;
  std::string sql_create_notification_subscribers() const;
  std::string sql_create_notification_log() const;
  std::string sql_create_event_outbox() const;
  std::string sql_create_db_meta() const;

  // CREATE INDEX statements.
  std::string sql_create_indexes() const;

private:
  IDbConnection &conn_;

  // Internal helpers
  bool table_exists(const std::string &table_name);
  bool column_exists(const std::string &table_name,
                     const std::string &column_name);
  void set_meta(const std::string &key, const std::string &value);
  std::string get_meta(const std::string &key);

  // Migration steps — one method per version bump.
  void migrate_legacy_to_v4(); // Any pre-v4 DB → v4 ledger schema (no Rekor).
  void migrate_v4_to_v5();     // v4 → v5: drop integrity_hmac from the
                               // notification tables.
  void migrate_v5_to_v6(); // v5 → v6: create event_outbox for outbox pattern.
};

} // namespace db
} // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_DB_SCHEMA_H