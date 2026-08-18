-- vHSM SQLite schema (schema_version = 4)
-- Hyperledger Fabric ledger anchoring replaces the Rekor/HMAC integrity chain.
-- No integrity_hmac anywhere on the signature tables — the Fabric ledger is the
-- tamper-evidence source of truth.

CREATE TABLE IF NOT EXISTS db_meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signature_records (
    id                TEXT    NOT NULL PRIMARY KEY,
    created_at        INTEGER NOT NULL,
    slot_id           INTEGER NOT NULL,
    token_label       TEXT    NOT NULL,
    key_id            TEXT    NOT NULL,
    key_fingerprint   TEXT    NOT NULL,
    mechanism         TEXT    NOT NULL,
    payload_digest    TEXT    NOT NULL,
    signature_b64     TEXT    NOT NULL,   -- kept for retrieval without a ledger round-trip
    session_handle    TEXT    NOT NULL,
    user_label        TEXT,
    app_context       TEXT,
    ledger_tx_id      TEXT,               -- nullable: filled in later by the async ledger worker
    ledger_block_num  INTEGER,            -- block height at commitment
    ledger_tx_time    TEXT,
    ledger_tx_proof   TEXT,
    ledger_tx_set_b64 TEXT,
    ledger_status     TEXT    NOT NULL DEFAULT 'PENDING'
        CHECK(ledger_status IN ('PENDING','COMMITTED','FAILED'))
);

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

CREATE INDEX IF NOT EXISTS idx_sig_key_id        ON signature_records(key_id);
CREATE INDEX IF NOT EXISTS idx_sig_created_at    ON signature_records(created_at);
CREATE INDEX IF NOT EXISTS idx_sig_token_label   ON signature_records(token_label);
CREATE INDEX IF NOT EXISTS idx_sig_payload       ON signature_records(payload_digest);
CREATE INDEX IF NOT EXISTS idx_sig_ledger_tx_id  ON signature_records(ledger_tx_id);
CREATE INDEX IF NOT EXISTS idx_sig_ledger_status ON signature_records(ledger_status);
CREATE INDEX IF NOT EXISTS idx_nlog_event_id     ON notification_log(event_id);
CREATE INDEX IF NOT EXISTS idx_nlog_subscriber   ON notification_log(subscriber_id);