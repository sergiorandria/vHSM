#include "db_schema.h"

#include "../core/error.h"
#include "../core/utils.h"

#include <chrono>
#include <sstream>
#include <string>
#include <vector>

namespace vhsm::signature_store {
namespace db {

namespace {
std::string join(const std::vector<std::string> &parts,
                 const std::string &sep) {
  std::string out;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i != 0)
      out += sep;
    out += parts[i];
  }
  return out;
}
} // namespace

DbSchema::DbSchema(IDbConnection &conn) : conn_(conn) {}

// SQL generation helpers
//
// We generate SQL at runtime rather than embedding static strings so that
// future backends can override individual fragments if needed.
// The column order MUST stay stable — signature_repository.cpp and
// verification_service.cpp address columns by their position in this order.
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
  // No integrity_hmac column — the Fabric ledger provides tamper evidence.
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
    ledger_tx_id      TEXT,
    ledger_block_num  INTEGER,
    ledger_tx_time    TEXT,
    ledger_tx_proof   TEXT,
    ledger_tx_set_b64 TEXT,
    ledger_status     TEXT    NOT NULL DEFAULT 'PENDING'
        CHECK(ledger_status IN ('PENDING','COMMITTED','FAILED'))
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
    ledger_outcome   TEXT
        CHECK(ledger_outcome IN ('MATCH','MISMATCH','NOT_FOUND','NOT_CHECKED')),
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
        CHECK(enabled IN (0,1))
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
    error_detail  TEXT
);
)SQL";
}

std::string DbSchema::sql_create_event_outbox() const {
  return R"SQL(
CREATE TABLE IF NOT EXISTS event_outbox (
    id            TEXT    NOT NULL PRIMARY KEY,
    created_at    INTEGER NOT NULL,
    event_type    TEXT    NOT NULL,
    aggregate_id  TEXT    NOT NULL,
    payload       TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'PENDING'
        CHECK(status IN ('PENDING','DISPATCHED','FAILED')),
    retry_count   INTEGER NOT NULL DEFAULT 0
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

CREATE INDEX IF NOT EXISTS idx_sig_ledger_tx_id
    ON signature_records(ledger_tx_id);

CREATE INDEX IF NOT EXISTS idx_sig_ledger_status
    ON signature_records(ledger_status);

CREATE INDEX IF NOT EXISTS idx_nlog_event_id
    ON notification_log(event_id);

CREATE INDEX IF NOT EXISTS idx_nlog_subscriber
    ON notification_log(subscriber_id);

CREATE INDEX IF NOT EXISTS idx_outbox_status
    ON event_outbox(status);

CREATE INDEX IF NOT EXISTS idx_outbox_aggregate
    ON event_outbox(aggregate_id);
)SQL";
}

bool DbSchema::table_exists(const std::string &table_name) {
  // SQLite: query sqlite_master.  PG: pg_tables.  MySQL: information_schema.
  // This implementation targets SQLite (the default backend).
  auto rs = conn_.query("SELECT COUNT(*) FROM sqlite_master "
                        "WHERE type='table' AND name=?;",
                        {table_name});
  if (rs.empty()) {
    return false;
  }

  auto count = rs.get<i64>(rs.rows_[0], 0);
  return count.value_or(0) > 0;
}

bool DbSchema::column_exists(const std::string &table_name,
                             const std::string &column_name) {
  // Requires SQLite >= 3.16 (table-valued pragma function).
  auto rs =
      conn_.query("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?;",
                  {table_name, column_name});
  if (rs.empty()) {
    return false;
  }
  auto count = rs.get<i64>(rs.rows_[0], 0);
  return count.value_or(0) > 0;
}

void DbSchema::set_meta(const std::string &key, const std::string &value) {
  conn_.exec("INSERT INTO db_meta(key, value) VALUES(?, ?) "
             "ON CONFLICT(key) DO UPDATE SET value=excluded.value;",
             {key, value});
}

std::string DbSchema::get_meta(const std::string &key) {
  auto rs = conn_.query("SELECT value FROM db_meta WHERE key=?;", {key});
  if (rs.empty() || rs.rows_.empty()) {
    return "";
  }

  auto val = rs.get<std::string>(rs.rows_[0], 0);
  return val.value_or("");
}

int DbSchema::current_version() {
  if (!table_exists("db_meta"))
    return -1;
  std::string v = get_meta(std::string(meta_key::K_SCHEMA_VERSION));
  if (v.empty())
    return -1;
  try {
    return std::stoi(v);
  } catch (...) {
    return -1;
  }
}

std::string DbSchema::get_instance_id() {
  return get_meta(std::string(meta_key::K_INSTANCE_ID));
}

void DbSchema::bootstrap() {
  int version = current_version();

  if (version == K_CURRENT_SCHEMA_VERSION) {
    // Schema is already at the target version — nothing to do.
    return;
  }

  if (version > K_CURRENT_SCHEMA_VERSION) {
    throw DbError(DbError::Kind::SchemaError,
                  "DB schema version " + std::to_string(version) +
                      " is newer than compiled version " +
                      std::to_string(K_CURRENT_SCHEMA_VERSION) +
                      ". Upgrade the vhsm binary.");
  }

  if (version == -1) {
    // Brand-new DB — create all tables from scratch.
    conn_.with_transaction([this](IDbTransaction &tx) {
      // Core meta table first (needed by set_meta below).
      tx.exec(sql_create_db_meta());

      // Signature tables.
      tx.exec(sql_create_signature_records());
      tx.exec(sql_create_signature_verifications());

      // Notification tables.
      tx.exec(sql_create_notification_subscribers());
      tx.exec(sql_create_notification_log());

      // Event outbox (transactional outbox for ledger + notification).
      tx.exec(sql_create_event_outbox());

      // Indexes.
      // Execute each statement individually — SQLite does not support
      // multiple statements in a single exec() call.
      std::istringstream idx_stream(sql_create_indexes());
      std::string stmt;
      while (std::getline(idx_stream, stmt, ';')) {
        // Trim whitespace.
        auto first = stmt.find_first_not_of(" \t\r\n");
        if (first == std::string::npos)
          continue;
        stmt = stmt.substr(first);
        if (!stmt.empty()) {
          tx.exec(stmt + ";");
        }
      }

      // Seed db_meta.
      auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();

      tx.exec("INSERT INTO db_meta(key,value) VALUES(?,?);",
              {std::string(meta_key::K_SCHEMA_VERSION),
               std::to_string(K_CURRENT_SCHEMA_VERSION)});
      tx.exec("INSERT INTO db_meta(key,value) VALUES(?,?);",
              {std::string(meta_key::K_INSTANCE_ID), vhsm::utils::uuid_v4()});
      tx.exec("INSERT INTO db_meta(key,value) VALUES(?,?);",
              {std::string(meta_key::K_CREATED_AT), std::to_string(now_ms)});
      // hmac_key_wrapped is a legacy placeholder; no HMAC scheme is used.
      tx.exec("INSERT INTO db_meta(key,value) VALUES(?,?);",
              {std::string(meta_key::K_HMAC_KEY_WRAPPED), "UNSET"});
    });
    return;
  }

  // Existing DB at an older version — run migrations.
  migrate();
}

int DbSchema::migrate() {
  int from_version = current_version();
  if (from_version < 0) {
    throw DbError(
        DbError::Kind::SchemaError,
        "Cannot migrate: db_meta does not exist. Call bootstrap() first.");
  }
  if (from_version == K_CURRENT_SCHEMA_VERSION)
    return from_version;
  if (from_version > K_CURRENT_SCHEMA_VERSION) {
    throw DbError(DbError::Kind::SchemaError,
                  "Cannot migrate backwards (DB at v" +
                      std::to_string(from_version) + ", binary at v" +
                      std::to_string(K_CURRENT_SCHEMA_VERSION) + ").");
  }

  // Versions 1, 2 and 3 were the Rekor-era schemas.  The Fabric-ledger schema
  // (v4) replaces them in a single, deterministic transformation that maps
  // any legacy Rekor columns onto the ledger columns when present, and drops
  // integrity_hmac and the key lifecycle (key_rekor_registry) table.
  migrate_legacy_to_v4();

  // v4 → v5: drop the now-unused integrity_hmac column from the notification
  // tables (there is no local HMAC chain in the aggregate design).
  migrate_v4_to_v5();

  // v5 → v6: create event_outbox for transactional outbox pattern.
  migrate_v5_to_v6();

  return from_version;
}

// Migration (any pre-v4) → v4
//
// v4 converts the Rekor-era schema to the Hyperledger Fabric ledger schema:
//   - signature_records: rekor_* columns → ledger_* columns, integrity_hmac
//     dropped
//   - signature_verifications: rekor_outcome → ledger_outcome
//   - key_rekor_registry table is dropped
//   - index set rebuilt for the ledger columns
//
// The transformation is implemented as "create new table → copy (mapping
// legacy columns when present) → drop → rename", which is the only way SQLite
// can alter columns/CHECK constraints.

void DbSchema::migrate_legacy_to_v4() {
  conn_.with_transaction([this](IDbTransaction &tx) {
    const bool has_rekor_cols =
        column_exists("signature_records", "rekor_entry_uuid");
    const bool has_rekor_outcome =
        column_exists("signature_verifications", "rekor_outcome");

    // --- signature_records ---
    tx.exec(R"SQL(
            CREATE TABLE signature_records_new (
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
                ledger_tx_id      TEXT,
                ledger_block_num  INTEGER,
                ledger_tx_time    TEXT,
                ledger_tx_proof   TEXT,
                ledger_tx_set_b64 TEXT,
                ledger_status     TEXT    NOT NULL DEFAULT 'PENDING'
                    CHECK(ledger_status IN ('PENDING','COMMITTED','FAILED'))
            );
        )SQL");

    // Column mapping for the data copy.  Legacy Rekor columns are mapped
    // onto their ledger equivalents when present; clean pre-Rekor DBs leave
    // the ledger fields NULL/PENDING.
    const std::vector<std::string> new_cols = {"id",
                                               "created_at",
                                               "slot_id",
                                               "token_label",
                                               "key_id",
                                               "key_fingerprint",
                                               "mechanism",
                                               "payload_digest",
                                               "signature_b64",
                                               "session_handle",
                                               "user_label",
                                               "app_context",
                                               "ledger_tx_id",
                                               "ledger_block_num",
                                               "ledger_tx_time",
                                               "ledger_tx_proof",
                                               "ledger_tx_set_b64",
                                               "ledger_status"};

    std::vector<std::string> src_cols;
    if (has_rekor_cols) {
      src_cols = {"id",
                  "created_at",
                  "slot_id",
                  "token_label",
                  "key_id",
                  "key_fingerprint",
                  "mechanism",
                  "payload_digest",
                  "signature_b64",
                  "session_handle",
                  "user_label",
                  "app_context",
                  "rekor_entry_uuid",
                  "rekor_log_index",
                  "rekor_integrated_time",
                  "rekor_inclusion_proof",
                  "rekor_set_b64",
                  "COALESCE(rekor_status,'PENDING')"};
    } else {
      src_cols = {"id",
                  "created_at",
                  "slot_id",
                  "token_label",
                  "key_id",
                  "key_fingerprint",
                  "mechanism",
                  "payload_digest",
                  "signature_b64",
                  "session_handle",
                  "user_label",
                  "app_context",
                  "NULL",
                  "NULL",
                  "NULL",
                  "NULL",
                  "NULL",
                  "'PENDING'"};
    }

    std::string copy = "INSERT INTO signature_records_new (" +
                       join(new_cols, ", ") + ") SELECT " +
                       join(src_cols, ", ") + " FROM signature_records;";
    tx.exec(copy);
    tx.exec("DROP TABLE signature_records;");
    tx.exec("ALTER TABLE signature_records_new RENAME TO signature_records;");

    // --- signature_verifications ---
    tx.exec(R"SQL(
            CREATE TABLE signature_verifications_new (
                id               TEXT    NOT NULL PRIMARY KEY,
                verified_at      INTEGER NOT NULL,
                signature_id     TEXT    REFERENCES signature_records(id),
                verifier_session TEXT    NOT NULL,
                outcome          TEXT    NOT NULL
                    CHECK(outcome IN ('VALID','INVALID','KEY_NOT_FOUND','ERROR')),
                ledger_outcome   TEXT
                    CHECK(ledger_outcome IN ('MATCH','MISMATCH','NOT_FOUND','NOT_CHECKED')),
                error_detail     TEXT
            );
        )SQL");

    std::string v_src;
    if (has_rekor_outcome) {
      // Map legacy Rekor proof outcomes onto ledger cross-check outcomes.
      v_src =
          ("SELECT id, verified_at, signature_id, verifier_session, outcome, "
           "CASE rekor_outcome WHEN 'PROOF_OK' THEN 'MATCH' "
           "WHEN 'PROOF_FAILED' THEN 'MISMATCH' "
           "WHEN 'NOT_CHECKED' THEN 'NOT_CHECKED' ELSE NULL END, "
           "error_detail FROM signature_verifications;");
    } else {
      v_src =
          ("SELECT id, verified_at, signature_id, verifier_session, outcome, "
           "NULL, error_detail FROM signature_verifications;");
    }
    tx.exec("INSERT INTO signature_verifications_new ("
            "id, verified_at, signature_id, verifier_session, outcome, "
            "ledger_outcome, error_detail) " +
            v_src);
    tx.exec("DROP TABLE signature_verifications;");
    tx.exec("ALTER TABLE signature_verifications_new RENAME TO "
            "signature_verifications;");

    // --- drop the legacy key lifecycle table ---
    if (table_exists("key_rekor_registry")) {
      tx.exec("DROP TABLE key_rekor_registry;");
    }

    // --- Rebuild the index set ---
    std::string idx_sql = sql_create_indexes();
    std::istringstream idx_stream(idx_sql);
    std::string stmt;
    while (std::getline(idx_stream, stmt, ';')) {
      auto first = stmt.find_first_not_of(" \t\r\n");
      if (first == std::string::npos)
        continue;
      stmt = stmt.substr(first);
      if (!stmt.empty()) {
        tx.exec(stmt + ";");
      }
    }

    // --- Bump schema version ---
    tx.exec("UPDATE db_meta SET value='4' WHERE key='schema_version';");
  });
}

// Migration v4 → v5
//
// v5 drops integrity_hmac from notification_subscribers and notification_log
// (matching PLANv4 §8; a single Fabric ledger provides integrity now).  SQLite
// cannot DROP COLUMN on older versions, so each table is rebuilt: create new →
// copy the surviving columns → drop → rename.
void DbSchema::migrate_v4_to_v5() {
  // Hoist column checks out of the transaction: within with_transaction the
  // connection mutex is held, so conn_.query() cannot be re-entered.
  const bool subs_has_hmac =
      column_exists("notification_subscribers", "integrity_hmac");
  const bool log_has_hmac = column_exists("notification_log", "integrity_hmac");

  conn_.with_transaction([&](IDbTransaction &tx) {
    // --- notification_subscribers ---
    if (subs_has_hmac) {
      tx.exec(R"SQL(
                CREATE TABLE notification_subscribers_new (
                    id            TEXT    NOT NULL PRIMARY KEY,
                    name          TEXT    NOT NULL,
                    channel       TEXT    NOT NULL
                        CHECK(channel IN ('email','webhook','grpc_push')),
                    address       TEXT    NOT NULL,
                    min_severity  TEXT    NOT NULL
                        CHECK(min_severity IN ('INFO','WARN','CRITICAL')),
                    event_filter  TEXT,
                    enabled       INTEGER NOT NULL DEFAULT 1
                        CHECK(enabled IN (0,1))
                );
            )SQL");
      tx.exec(R"SQL(
                INSERT INTO notification_subscribers_new (
                    id, name, channel, address, min_severity, event_filter, enabled
                ) SELECT id, name, channel, address, min_severity, event_filter, enabled
                  FROM notification_subscribers;
            )SQL");
      tx.exec("DROP TABLE notification_subscribers;");
      tx.exec("ALTER TABLE notification_subscribers_new RENAME TO "
              "notification_subscribers;");
      tx.exec(sql_create_indexes());
    }

    // --- notification_log ---
    if (log_has_hmac) {
      tx.exec(R"SQL(
                CREATE TABLE notification_log_new (
                    id            TEXT    NOT NULL PRIMARY KEY,
                    sent_at       INTEGER NOT NULL,
                    event_id      TEXT    NOT NULL,
                    subscriber_id TEXT    REFERENCES notification_subscribers(id),
                    outcome       TEXT    NOT NULL
                        CHECK(outcome IN ('DELIVERED','RETRYING','FAILED','SKIPPED')),
                    attempt_count INTEGER NOT NULL DEFAULT 1,
                    error_detail  TEXT
                );
            )SQL");
      tx.exec(R"SQL(
                INSERT INTO notification_log_new (
                    id, sent_at, event_id, subscriber_id, outcome, attempt_count, error_detail
                ) SELECT id, sent_at, event_id, subscriber_id, outcome, attempt_count, error_detail
                  FROM notification_log;
            )SQL");
      tx.exec("DROP TABLE notification_log;");
      tx.exec("ALTER TABLE notification_log_new RENAME TO notification_log;");
      tx.exec(sql_create_indexes());
    }

    tx.exec("UPDATE db_meta SET value='5' WHERE key='schema_version';");
  });
}

void DbSchema::migrate_v5_to_v6() {
  conn_.with_transaction([this](IDbTransaction &tx) {
    tx.exec(sql_create_event_outbox());
    // Create indexes for the new table
    std::string idx_sql = sql_create_indexes();
    std::istringstream idx_stream(idx_sql);
    std::string stmt;
    while (std::getline(idx_stream, stmt, ';')) {
      auto first = stmt.find_first_not_of(" \t\r\n");
      if (first == std::string::npos)
        continue;
      stmt = stmt.substr(first);
      if (!stmt.empty() && stmt.find("event_outbox") != std::string::npos) {
        tx.exec(stmt + ";");
      }
    }
    tx.exec("UPDATE db_meta SET value='6' WHERE key='schema_version';");
  });
}

// verify_schema
bool DbSchema::verify_schema(std::string &out_error) {
  const std::string_view expected_tables[] = {
      table::K_DB_META,
      table::K_SIGNATURE_RECORDS,
      table::K_SIGNATURE_VERIFICATIONS,
      table::K_NOTIFICATION_SUBSCRIBERS,
      table::K_NOTIFICATION_LOG,
      table::K_EVENT_OUTBOX,
  };

  for (const auto &tbl : expected_tables) {
    if (!table_exists(std::string(tbl))) {
      out_error = "Missing table: ";
      out_error += tbl;
      return false;
    }
  }

  // Verify schema version in db_meta.
  int v = current_version();
  if (v != K_CURRENT_SCHEMA_VERSION) {
    out_error = "Schema version mismatch: DB has v" + std::to_string(v) +
                ", expected v" + std::to_string(K_CURRENT_SCHEMA_VERSION);
    return false;
  }

  out_error.clear();
  return true;
}

} // namespace db
} // namespace vhsm::signature_store