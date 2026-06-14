#include "db_schema.h"

#include "../core/error.h"
#include "../core/utils.h"

#include <chrono>
#include <sstream>
#include <string>

namespace vhsm::signature_store {
namespace db {

DbSchema::DbSchema(IDbConnection& conn) : conn_(conn) {}

// SQL generation helpers
//
// We generate SQL at runtime rather than embedding static strings so that
// future backends can override individual fragments if needed.
// The column order MUST stay stable — row_integrity.cpp constructs the HMAC
// input by concatenating column values in this exact order
std::string DbSchema::sql_create_db_meta() const {
    return R"SQL(
CREATE TABLE IF NOT EXISTS db_meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);
)SQL";
}

std::string DbSchema::sql_create_signature_records() const {
    // Column ordering is canonical — do not reorder.
    // HMAC covers: id, created_at, slot_id, token_label, key_id,
    //              key_fingerprint, mechanism, payload_digest, signature_b64,
    //              session_handle, user_label, app_context,
    //              rekor_entry_uuid, rekor_log_index, rekor_set_b64, rekor_status
    //
    // integrity_hmac is excluded from its own computation (chicken-and-egg).
    // Note: PLAN_REKOR drops integrity_hmac per the user's explicit decision
    //       — Rekor provides the external tamper-evidence layer.
    return R"SQL(
CREATE TABLE IF NOT EXISTS signature_records (
    id                TEXT    NOT NULL PRIMARY KEY,
    created_at        INTEGER NOT NULL,
    slot_id           INTEGER NOT NULL,
    token_label       TEXT    NOT NULL,
    key_id            TEXT    NOT NULL,
    key_fingerprint   TEXT    NOT NULL,
    mechanism         TEXT    NOT NULL,
    payload_digest    TEXT    NOT NULL,
    signature_b64     TEXT    NOT NULL,
    session_handle    TEXT    NOT NULL,
    user_label        TEXT,
    app_context       TEXT,
    rekor_entry_uuid  TEXT,
    rekor_log_index   INTEGER,
    rekor_set_b64     TEXT,
    rekor_status      TEXT    NOT NULL DEFAULT 'PENDING'
        CHECK(rekor_status IN ('PENDING','COMMITTED','FAILED','DISABLED'))
);
)SQL";
}

std::string DbSchema::sql_create_signature_verifications() const {
    return R"SQL(
CREATE TABLE IF NOT EXISTS signature_verifications (
    id               TEXT    NOT NULL PRIMARY KEY,
    verified_at      INTEGER NOT NULL,
    signature_id     TEXT    REFERENCES signature_records(id),
    verifier_session TEXT    NOT NULL,
    outcome          TEXT    NOT NULL
        CHECK(outcome IN ('VALID','INVALID','KEY_NOT_FOUND','ERROR')),
    rekor_outcome    TEXT
        CHECK(rekor_outcome IN ('PROOF_OK','PROOF_FAILED','NOT_CHECKED')),
    error_detail     TEXT
);
)SQL";
}

std::string DbSchema::sql_create_notification_subscribers() const {
    return R"SQL(
CREATE TABLE IF NOT EXISTS notification_subscribers (
    id            TEXT    NOT NULL PRIMARY KEY,
    name          TEXT    NOT NULL,
    channel       TEXT    NOT NULL
        CHECK(channel IN ('email','webhook','grpc_push')),
    address       TEXT    NOT NULL,
    min_severity  TEXT    NOT NULL
        CHECK(min_severity IN ('INFO','WARN','CRITICAL')),
    event_filter  TEXT,
    enabled       INTEGER NOT NULL DEFAULT 1
        CHECK(enabled IN (0,1)),
    integrity_hmac TEXT   NOT NULL
);
)SQL";
}

std::string DbSchema::sql_create_notification_log() const {
    return R"SQL(
CREATE TABLE IF NOT EXISTS notification_log (
    id            TEXT    NOT NULL PRIMARY KEY,
    sent_at       INTEGER NOT NULL,
    event_id      TEXT    NOT NULL,
    subscriber_id TEXT    REFERENCES notification_subscribers(id),
    outcome       TEXT    NOT NULL
        CHECK(outcome IN ('DELIVERED','RETRYING','FAILED','SKIPPED')),
    attempt_count INTEGER NOT NULL DEFAULT 1,
    error_detail  TEXT,
    integrity_hmac TEXT   NOT NULL
);
)SQL";
}

std::string DbSchema::sql_create_key_rekor_registry() const {
    return R"SQL(
CREATE TABLE IF NOT EXISTS key_rekor_registry (
    id               TEXT    NOT NULL PRIMARY KEY,
    key_fingerprint  TEXT    NOT NULL,
    event_type       TEXT    NOT NULL
        CHECK(event_type IN ('CREATED','RETIRED')),
    occurred_at      INTEGER NOT NULL,
    rekor_entry_uuid TEXT,
    rekor_log_index  INTEGER,
    rekor_status     TEXT    NOT NULL DEFAULT 'PENDING'
        CHECK(rekor_status IN ('PENDING','COMMITTED','FAILED')),
    integrity_hmac   TEXT    NOT NULL
);
)SQL";
}

std::string DbSchema::sql_create_indexes() const {
    return R"SQL(
CREATE INDEX IF NOT EXISTS idx_sig_key_id
    ON signature_records(key_id);

CREATE INDEX IF NOT EXISTS idx_sig_created_at
    ON signature_records(created_at);

CREATE INDEX IF NOT EXISTS idx_sig_token_label
    ON signature_records(token_label);

CREATE INDEX IF NOT EXISTS idx_sig_payload
    ON signature_records(payload_digest);

CREATE INDEX IF NOT EXISTS idx_sig_rekor_uuid
    ON signature_records(rekor_entry_uuid);

CREATE INDEX IF NOT EXISTS idx_sig_rekor_status
    ON signature_records(rekor_status);

CREATE INDEX IF NOT EXISTS idx_krr_fingerprint
    ON key_rekor_registry(key_fingerprint);

CREATE INDEX IF NOT EXISTS idx_nlog_event_id
    ON notification_log(event_id);

CREATE INDEX IF NOT EXISTS idx_nlog_subscriber
    ON notification_log(subscriber_id);
)SQL";
}


bool DbSchema::table_exists(const std::string& table_name) {
    // SQLite: query sqlite_master.  PG: pg_tables.  MySQL: information_schema.
    // This implementation targets SQLite (the default backend).
    auto rs = conn_.query(
        "SELECT COUNT(*) FROM sqlite_master "
        "WHERE type='table' AND name=?;",
        { table_name });
    if (rs.empty()) {
        return false;
    }

    auto count = rs.get<int64_t>(rs.rows_[0], 0);
    return count.value_or(0) > 0;
}

void DbSchema::set_meta(const std::string& key, const std::string& value) {
    conn_.exec(
        "INSERT INTO db_meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value;",
        { key, value });
}

std::string DbSchema::get_meta(const std::string& key) {
    auto rs = conn_.query(
        "SELECT value FROM db_meta WHERE key=?;",
        { key });
    if (rs.empty() || rs.rows_.empty()) return "";
    auto val = rs.get<std::string>(rs.rows_[0], 0);
    return val.value_or("");
}


int DbSchema::current_version() {
    if (!table_exists("db_meta")) return -1;
    std::string v = get_meta(std::string(meta_key::kSchemaVersion));
    if (v.empty()) return -1;
    try { return std::stoi(v); } catch (...) { return -1; }
}

void DbSchema::bootstrap() {
    int version = current_version();

    if (version == kCurrentSchemaVersion) {
        // Schema is already at the target version — nothing to do.
        return;
    }

    if (version > kCurrentSchemaVersion) {
        throw DbError(DbError::Kind::SchemaError,
                      "DB schema version " + std::to_string(version) +
                      " is newer than compiled version " +
                      std::to_string(kCurrentSchemaVersion) +
                      ". Upgrade the vhsm binary.");
    }

    if (version == -1) {
        // Brand-new DB — create all tables from scratch.
        conn_.with_transaction([this](IDbTransaction& tx) {
            // Core meta table first (needed by set_meta below).
            tx.exec(sql_create_db_meta());

            // Signature tables.
            tx.exec(sql_create_signature_records());
            tx.exec(sql_create_signature_verifications());

            // Notification tables.
            tx.exec(sql_create_notification_subscribers());
            tx.exec(sql_create_notification_log());

            // Rekor key lifecycle table.
            tx.exec(sql_create_key_rekor_registry());

            // Indexes.
            // Execute each statement individually — SQLite does not support
            // multiple statements in a single exec() call.
            std::istringstream idx_stream(sql_create_indexes());
            std::string stmt;
            while (std::getline(idx_stream, stmt, ';')) {
                // Trim whitespace.
                auto first = stmt.find_first_not_of(" \t\r\n");
                if (first == std::string::npos) continue;
                stmt = stmt.substr(first);
                if (!stmt.empty()) {
                    tx.exec(stmt + ";");
                }
            }

            // Seed db_meta.
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

            tx.exec("INSERT INTO db_meta(key,value) VALUES(?,?);",
                    { std::string(meta_key::kSchemaVersion),
                      std::to_string(kCurrentSchemaVersion) });
            tx.exec("INSERT INTO db_meta(key,value) VALUES(?,?);",
                    { std::string(meta_key::kInstanceId),
                      vhsm::utils::uuid_v4() });
            tx.exec("INSERT INTO db_meta(key,value) VALUES(?,?);",
                    { std::string(meta_key::kCreatedAt),
                      std::to_string(now_ms) });
            // hmac_key_wrapped is a placeholder until db_hmac_key.cpp fills it in.
            tx.exec("INSERT INTO db_meta(key,value) VALUES(?,?);",
                    { std::string(meta_key::kHmacKeyWrapped),
                      "UNSET" });
        });
        return;
    }

    // Existing DB at an older version — run migrations.
    migrate();
}

int DbSchema::migrate() {
    int from_version = current_version();
    if (from_version < 0) {
        throw DbError(DbError::Kind::SchemaError,
                      "Cannot migrate: db_meta does not exist. Call bootstrap() first.");
    }
    if (from_version == kCurrentSchemaVersion) return from_version;
    if (from_version > kCurrentSchemaVersion) {
        throw DbError(DbError::Kind::SchemaError,
                      "Cannot migrate backwards (DB at v" +
                      std::to_string(from_version) +
                      ", binary at v" + std::to_string(kCurrentSchemaVersion) + ").");
    }

    // Each step is its own transaction so failures are isolated.
    int current = from_version;

    if (current == 1) {
        migrate_v1_to_v2();
        ++current;
    }

    // Add future migrations here:
    // if (current == 2) { migrate_v2_to_v3(); ++current; }

    return from_version;
}

// Migration v1 → v2
//
// What changed in v2:
//   - signature_records gains 4 Rekor columns (rekor_entry_uuid,
//     rekor_log_index, rekor_set_b64, rekor_status)
//   - signature_verifications gains rekor_outcome column
//   - key_rekor_registry table is new
//   - Two new indexes on signature_records
//   - One new index on key_rekor_registry
// Will be removed in future update when Rekor integration is complete and stable.

void DbSchema::migrate_v1_to_v2() {
    conn_.with_transaction([this](IDbTransaction& tx) {
        // --- signature_records ---
        tx.exec("ALTER TABLE signature_records ADD COLUMN rekor_entry_uuid TEXT;");
        tx.exec("ALTER TABLE signature_records ADD COLUMN rekor_log_index INTEGER;");
        tx.exec("ALTER TABLE signature_records ADD COLUMN rekor_set_b64 TEXT;");
        // SQLite does not support DEFAULT in ALTER TABLE ADD COLUMN for some
        // old versions, so we add without default then update existing rows.
        tx.exec("ALTER TABLE signature_records ADD COLUMN rekor_status TEXT "
                "NOT NULL DEFAULT 'DISABLED';");
        // Backfill: rows from before Rekor integration get DISABLED so they
        // don't block the retry queue.
        tx.exec("UPDATE signature_records SET rekor_status='DISABLED' "
                "WHERE rekor_status IS NULL;");

        // --- signature_verifications ---
        tx.exec("ALTER TABLE signature_verifications ADD COLUMN rekor_outcome TEXT;");

        // --- key_rekor_registry ---
        tx.exec(sql_create_key_rekor_registry());

        // --- new indexes ---
        tx.exec("CREATE INDEX IF NOT EXISTS idx_sig_rekor_uuid "
                "ON signature_records(rekor_entry_uuid);");
        tx.exec("CREATE INDEX IF NOT EXISTS idx_sig_rekor_status "
                "ON signature_records(rekor_status);");
        tx.exec("CREATE INDEX IF NOT EXISTS idx_krr_fingerprint "
                "ON key_rekor_registry(key_fingerprint);");

        // Bump schema version.
        tx.exec("UPDATE db_meta SET value='2' WHERE key='schema_version';");
    });
}

// verify_schema
bool DbSchema::verify_schema(std::string& out_error) {
    // Minimal check: confirm that each expected table exists.
    // A production-grade implementation would also verify column names and types
    // via PRAGMA table_info() or information_schema.
    const std::string_view expected_tables[] = {
        table::kDbMeta,
        table::kSignatureRecords,
        table::kSignatureVerifications,
        table::kNotificationSubscribers,
        table::kNotificationLog,
        table::kKeyRekorRegistry,
    };

    for (const auto& tbl : expected_tables) {
        if (!table_exists(std::string(tbl))) {
            out_error = "Missing table: ";
            out_error += tbl;
            return false;
        }
    }

    // Verify schema version in db_meta.
    int v = current_version();
    if (v != kCurrentSchemaVersion) {
        out_error = "Schema version mismatch: DB has v" + std::to_string(v) +
                    ", expected v" + std::to_string(kCurrentSchemaVersion);
        return false;
    }

    out_error.clear();
    return true;
}

}  // namespace db
}  // namespace vhsm::signature_store
