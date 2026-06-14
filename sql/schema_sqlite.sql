CREATE TABLE signature_records (
    id                TEXT    PRIMARY KEY,
    created_at        INTEGER NOT NULL,
    slot_id           INTEGER NOT NULL,
    token_label       TEXT    NOT NULL,
    key_id            TEXT    NOT NULL,
    key_fingerprint   TEXT    NOT NULL,
    mechanism         TEXT    NOT NULL,
    payload_digest    TEXT    NOT NULL,
    signature_b64     TEXT    NOT NULL,   -- keep: needed for retrieval without Rekor
    session_handle    TEXT    NOT NULL,
    user_label        TEXT,
    app_context       TEXT,
    rekor_entry_uuid  TEXT,               -- nullable: filled in later by Phase 5
    rekor_log_index   INTEGER,
    rekor_set_b64     TEXT,
    rekor_status      TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(rekor_status IN ('PENDING','COMMITTED','FAILED','DISABLED'))
    -- NO integrity_hmac (drop the HMAC chain, per your earlier reasoning)
);