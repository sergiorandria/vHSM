# Virtual HSM — Implementation Plan
## (with Database-Backed Signature Store & Notification System)

> **Team size:** 3 engineers  
> **Version:** 2.0 (reviewed & extended)  
> **Status:** Draft — open questions require resolution before Phase 1 starts

---

## Table of Contents

1. [Overview](#overview)
2. [Goals](#goals)
3. [Non-Goals](#non-goals)
4. [Architecture](#architecture)
5. [Notification System](#notification-system) ← *new*
6. [Database Schema](#database-schema)
7. [Module Breakdown](#module-breakdown)
8. [Directory Structure](#directory-structure)
9. [Build System](#build-system)
10. [Dependencies](#dependencies)
11. [Implementation Phases](#implementation-phases)
12. [Security Considerations](#security-considerations)
13. [Testing Strategy](#testing-strategy)
14. [Team Responsibilities](#team-responsibilities) ← *new*
15. [Open Questions](#open-questions)
16. [Caveats & Risk Register](#caveats--risk-register) ← *new*

---

## Overview

A **Virtual HSM (Hardware Security Module)** is a software-based emulation of a physical HSM
providing cryptographic key management, secure key storage, and cryptographic operations within a
tamper-resistant software boundary.

This plan extends the baseline virtual HSM with two integrated capabilities:

1. **Database Signature Store** — every signing operation produces a persisted, queryable
   `SignatureRecord` row, enabling audit trails, non-repudiation proofs, signature replay/verification
   workflows, and compliance reporting — all without any signature leaving the HSM trust boundary in
   an unauthenticated form.

2. **Notification System** — every database write (signature creation, key rotation, verification
   event, integrity alert) triggers a fan-out notification to all subscribed parties. This is the
   mechanism by which the three team members (and any configured external system) are alerted to
   state changes in the HSM.

> **Reviewer note:** The original plan was strong on crypto and persistence but silent on
> notifications and team-specific concerns. The additions below are non-optional if the stated goal
> ("every person concerned gets a notification") is to be satisfied.

---

## Goals

- Emulate core HSM functionality: key generation, storage, signing, encryption, and access control
- Expose a **PKCS#11 v2.40** compatible C API (the industry-standard HSM interface)
- **Persist every signing operation to a relational database** (SQLite embedded / PostgreSQL / MySQL)
- **Allow callers to query, verify, and audit signatures via a Signature Store API**
- **Notify all subscribed parties on every database mutation** (signature created, key rotated,
  integrity alert, verification failure)
- Protect key material in-memory using encrypted secure enclaves (software boundary)
- Support multi-slot, multi-session, multi-user models
- Provide a gRPC management + signature query API for administration
- Be portable across Linux, macOS, and Windows

---

## Non-Goals

- Physical tamper resistance (by definition — this is a virtual HSM)
- FIPS 140-2/3 certification (though design should be certification-ready)
- HSM clustering / HA replication (out of scope for v1)
- Storing raw plaintext key material in the database (never)
- Real-time push notifications to end-users outside the team (v2 scope)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Application                     │
│               (via PKCS#11 C API / .so / .dll)              │
└──────────────────────┬──────────────────────────────────────┘
                       │  C function calls
┌──────────────────────▼──────────────────────────────────────┐
│                  PKCS#11 Facade Layer                       │
│    C_SignInit / C_Sign / C_SignFinal  (and all others)      │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Session & Slot Manager                         │
│      Tracks open sessions, login state, active ops          │
└──────┬───────────────────────────────────────┬──────────────┘
       │                                       │
┌──────▼────────────┐               ┌──────────▼──────────────┐
│   Crypto Engine   │               │      Key Store           │
│  (OpenSSL ≥ 3.0)  │               │   (Encrypted Vault)      │
│  RSA / ECC / AES  │               │  slots / tokens / objects│
└──────┬────────────┘               └──────────┬──────────────┘
       │  raw signature bytes                  │  wrapped key blobs
       │                                       │
┌──────▼───────────────────────────────────────▼──────────────┐
│               Signature Dispatcher                          │
│  Enriches result → builds SignatureRecord → fans out to:    │
│   (a) DB Signature Store   (b) File Vault   (c) Audit Log   │
│   (d) Notification Bus  ← NEW                               │
└──────┬──────────────────────────────┬───────────────────────┘
       │                              │
┌──────▼──────────────────┐  ┌────────▼──────────────────────┐
│   DB Signature Store    │  │   Notification Bus             │
│  SQLite / PG / MySQL    │  │  (in-process event emitter)    │
│  SignatureRecord rows   │  │  Topics: SIGN / KEY / ALERT    │
│  + integrity HMAC col   │  └────────┬──────────────────────┘
└─────────────────────────┘           │
       │                    ┌─────────▼──────────────────────┐
┌──────▼──────────────────┐ │   Notification Dispatcher      │
│  Signature Query API    │ │  Resolves subscribers → routes │
│  lookup/verify/audit    │ │  to each delivery channel      │
│  (gRPC / REST)          │ └─────┬──────────┬───────────────┘
└─────────────────────────┘       │          │
                         ┌────────▼──┐  ┌────▼──────────────┐
                         │  Email    │  │  Webhook / gRPC    │
                         │  Adapter  │  │  Push Adapter      │
                         └───────────┘  └───────────────────┘
```

**Key addition — Notification Bus:**  
After every `SignatureDispatcher::dispatch()` call, the bus emits a typed event. The
`NotificationDispatcher` reads a subscriber registry (stored in `db_meta` or a separate config file)
and routes the event to each registered delivery channel. For a 3-person team the immediate channels
are email and an internal webhook/gRPC push; the adapters are pluggable so additional channels
(Slack, PagerDuty, etc.) can be added in v2 without touching the core.

---

## Notification System

> This section is entirely new. It addresses the primary requirement: *"when an update occurs every
> person concerned gets a notification."*

### Event Types

| Event                   | Trigger                                                        | Severity |
|-------------------------|----------------------------------------------------------------|----------|
| `SIGN_CREATED`          | New `SignatureRecord` inserted into DB                         | INFO     |
| `VERIFY_COMPLETED`      | Verification attempt logged in `signature_verifications`       | INFO     |
| `VERIFY_FAILED`         | Verification outcome is `INVALID` or `ERROR`                  | WARN     |
| `KEY_ROTATED`           | Signing key replaced via admin RPC                             | WARN     |
| `KEY_DESTROYED`         | `C_DestroyObject` called on a key object                       | WARN     |
| `INTEGRITY_ALERT`       | `CheckDbIntegrity` finds tampered rows                         | CRITICAL |
| `DB_WRITE_FAILED`       | Signature Dispatcher could not persist a record                | CRITICAL |
| `ADMIN_LOGIN`           | SO or USER authenticated via gRPC admin                        | INFO     |
| `PIN_LOCKOUT`           | Failed-attempt counter exceeded threshold                      | WARN     |

### Notification Payload (JSON)

```json
{
  "event_id":    "uuid-v4",
  "event_type":  "SIGN_CREATED",
  "severity":    "INFO",
  "timestamp":   "2025-06-09T12:34:56.789Z",
  "source":      "slot:0/token:MyToken",
  "actor":       "user_label or SO_PIN session",
  "summary":     "Signature 3f2a… created for key 7b1c… (ECDSA-SHA256)",
  "detail":      { "signature_id": "…", "key_fingerprint": "…", "payload_digest": "…" },
  "hsm_instance":"instance_id from db_meta"
}
```

### Subscriber Registry

Stored in `notification_subscribers` table (separate from `db_meta` to keep concerns clean):

```sql
CREATE TABLE notification_subscribers (
    id           TEXT    PRIMARY KEY,   -- UUID
    name         TEXT    NOT NULL,      -- "Alice", "Bob", "Carol"
    channel      TEXT    NOT NULL,      -- "email" | "webhook" | "grpc_push"
    address      TEXT    NOT NULL,      -- email addr, webhook URL, or gRPC endpoint
    min_severity TEXT    NOT NULL       -- "INFO" | "WARN" | "CRITICAL"
      CHECK(min_severity IN ('INFO','WARN','CRITICAL')),
    event_filter TEXT,                  -- JSON array of event types; NULL = all
    enabled      INTEGER NOT NULL DEFAULT 1,
    integrity_hmac TEXT  NOT NULL
);
```

Each of the three team members registers at least one subscription. The `min_severity` field
prevents INFO noise from flooding email while still delivering CRITICAL alerts.

### Delivery Guarantees

- **At-least-once delivery** is the target for WARN/CRITICAL events. The dispatcher retries up to 3
  times with exponential backoff before logging a `NOTIFICATION_FAILED` audit entry.
- **Best-effort (fire-and-forget)** is acceptable for INFO events to avoid blocking the signing hot
  path.
- Delivery is **asynchronous** — the notification write never blocks `C_Sign` returning to the
  caller. A bounded in-memory queue (capacity 1024) decouples the signing path from network I/O.

### Caveat — Notification vs. Atomicity

The notification and the DB write are **not atomic**. It is possible for the DB write to succeed
and the notification to fail (queue overflow, adapter error). This is intentional: the DB is the
source of truth; notifications are a courtesy. Operators should use `CheckDbIntegrity` and the
admin `GetAuditLog` RPC as the authoritative record, not notifications alone.

---

## Database Schema

The database is the authoritative record of all signing operations. Key material is **never** stored
here — only public key fingerprints, digests, and opaque wrapped ciphertext of the signature.

### Table: `signature_records`

```sql
CREATE TABLE signature_records (
    id               TEXT     PRIMARY KEY,          -- UUID v4, generated by HSM
    created_at       INTEGER  NOT NULL,             -- Unix epoch milliseconds (UTC)
    slot_id          INTEGER  NOT NULL,             -- HSM slot that performed the op
    token_label      TEXT     NOT NULL,             -- Token label (human-readable)
    key_id           TEXT     NOT NULL,             -- CKA_ID of the signing key (hex)
    key_fingerprint  TEXT     NOT NULL,             -- SHA-256 of SubjectPublicKeyInfo (hex)
    mechanism        TEXT     NOT NULL,             -- e.g. "CKM_ECDSA", "CKM_RSA_PKCS_PSS"
    digest_algorithm TEXT     NOT NULL,             -- e.g. "SHA-256"
    payload_digest   TEXT     NOT NULL,             -- SHA-256 of the signed data (hex)
    payload_size     INTEGER  NOT NULL,             -- Byte length of the original payload
    signature_b64    TEXT     NOT NULL,             -- Base64(DER-encoded signature bytes)
    session_handle   TEXT     NOT NULL,             -- CK_SESSION_HANDLE (hex)
    user_label       TEXT,                          -- CKU_USER label if authenticated
    app_context      TEXT,                          -- Optional caller-supplied JSON metadata
    integrity_hmac   TEXT     NOT NULL              -- HMAC-SHA256(all other columns, DB_HMAC_KEY)
);

CREATE INDEX idx_sig_key_id      ON signature_records(key_id);
CREATE INDEX idx_sig_created_at  ON signature_records(created_at);
CREATE INDEX idx_sig_token_label ON signature_records(token_label);
CREATE INDEX idx_sig_payload     ON signature_records(payload_digest);
```

### Table: `signature_verifications`

Logs every verification attempt for forensic audit.

```sql
CREATE TABLE signature_verifications (
    id               TEXT     PRIMARY KEY,
    verified_at      INTEGER  NOT NULL,
    signature_id     TEXT     REFERENCES signature_records(id),
    verifier_session TEXT     NOT NULL,
    outcome          TEXT     NOT NULL
        CHECK(outcome IN ('VALID','INVALID','KEY_NOT_FOUND','ERROR')),
    error_detail     TEXT,
    integrity_hmac   TEXT     NOT NULL
);
```

### Table: `notification_subscribers` *(new)*

See [Notification System](#notification-system) above for full definition.

### Table: `notification_log` *(new)*

```sql
CREATE TABLE notification_log (
    id              TEXT     PRIMARY KEY,
    sent_at         INTEGER  NOT NULL,
    event_id        TEXT     NOT NULL,
    subscriber_id   TEXT     REFERENCES notification_subscribers(id),
    outcome         TEXT     NOT NULL
        CHECK(outcome IN ('DELIVERED','RETRYING','FAILED','SKIPPED')),
    attempt_count   INTEGER  NOT NULL DEFAULT 1,
    error_detail    TEXT,
    integrity_hmac  TEXT     NOT NULL
);
```

This table is queryable via the admin gRPC API so the team can inspect delivery history.

### Table: `db_meta`

Stores schema version and the encrypted DB HMAC key (wrapped by vault KEK).

```sql
CREATE TABLE db_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
-- Rows: schema_version, hmac_key_wrapped, created_at, instance_id
```

---

## Module Breakdown

### 1. `core/` — Core Types & Constants

**Purpose:** Shared type definitions, error codes, PKCS#11 types, and utility functions.

**Files:**
- `types.h` — `CK_*` typedefs, mechanism structs, attribute structs; adds `SignatureRecord` and
  `NotificationEvent` POD structs
- `error.h` / `error.cpp` — `HsmError` exception hierarchy, `CK_RV` mapping, `DbError` subclass
- `utils.h` / `utils.cpp` — `secure_memzero`, base64 encode/decode, hex encode/decode, UUID v4
- `secure_buffer.h` — `SecureBuffer<T>`: RAII buffer that `mlock`s and zeroes on destruction
- `clock.h` — `HsmClock` abstraction (mockable for tests); returns UTC epoch milliseconds

**Key Design Decisions:**
- `SignatureRecord` is a plain copyable struct (no crypto material); safe to pass to DB layer
- `NotificationEvent` is similarly plain; constructed by the dispatcher before the bus call
- `utils::uuid_v4()` uses `RAND_bytes` — not sequential, prevents enumeration
- `utils::secure_compare()` is constant-time for HMAC verification

---

### 2. `crypto/` — Cryptographic Engine

**Purpose:** Wraps cryptographic primitives; no key material leaves this layer in plaintext.

**Files:**
- `crypto_engine.h` / `crypto_engine.cpp` — Facade over OpenSSL EVP API; returns `SignResult`
- `aes_gcm.h` / `aes_gcm.cpp` — AES-128/256-GCM encrypt/decrypt
- `rsa.h` / `rsa.cpp` — RSA-2048/4096 keygen, sign (PKCS1v15 + PSS), verify, encrypt (OAEP)
- `ecc.h` / `ecc.cpp` — EC keygen (P-256, P-384, P-521), ECDSA sign/verify, ECDH
- `hmac.h` / `hmac.cpp` — HMAC-SHA256/384/512; `compute_row_hmac()` helper for DB integrity
- `kdf.h` / `kdf.cpp` — HKDF, PBKDF2 (PIN → KEK), key derivation for DB HMAC key
- `rng.h` / `rng.cpp` — Wraps `RAND_bytes`; injectable interface for testing
- `digest.h` / `digest.cpp` — Standalone SHA-256/384/512 for computing `payload_digest`
- `mechanisms.h` — Registry: `CKM_*` constant → `{algorithm, digest, padding}` descriptor

**`SignResult` struct** (returned by `CryptoEngine::sign()`):

```cpp
struct SignResult {
    std::vector<uint8_t> signature;      // raw DER bytes
    std::string          mechanism_str;  // "CKM_ECDSA_SHA256"
    std::string          digest_alg;     // "SHA-256"
    std::string          payload_digest; // hex SHA-256 of input
    size_t               payload_size;
};
```

**Key Design Decisions:**
- `CryptoEngine::sign()` returns a `SignResult`; the Signature Dispatcher handles DB persistence
- No raw `malloc` — use `OPENSSL_secure_malloc` for all key material
- `compute_row_hmac()` concatenates all column values deterministically before HMAC

---

### 3. `keystore/` — Key Storage & Object Model

**Purpose:** Manages HSM objects (keys, certificates, data) across slots and tokens.

**Files:**
- `hsm_object.h` — Base `HsmObject`; subclasses: `KeyObject`, `CertObject`, `DataObject`
- `token.h` / `token.cpp` — Logical HSM partition; owns objects; exposes `public_key_fingerprint()`
- `slot.h` / `slot.cpp` — Virtual slot containing a token
- `object_store.h` / `object_store.cpp` — In-memory `CK_OBJECT_HANDLE → HsmObject` map
- `attribute_store.h` — `CKA_*` attribute get/set; enforces read-only attributes
- `key_wrap.h` / `key_wrap.cpp` — AES Key Wrap (RFC 3394) for persistence
- `key_fingerprint.h` / `key_fingerprint.cpp` — SHA-256 of SubjectPublicKeyInfo DER

**Key Design Decisions:**
- `KeyObject::public_fingerprint()` computed once at keygen/import and cached
- Object handles are 64-bit random IDs — never sequential, never reused
- `CKA_SENSITIVE` / `CKA_EXTRACTABLE` fully enforced; private bytes never appear in DB rows
- Key destruction (`C_DestroyObject`) emits a `KEY_DESTROYED` event to the Notification Bus

---

### 4. `session/` — Session & Slot Manager

*(Unchanged from original — see original plan for full detail.)*

**`SignContext` additions for DB and notifications:**

```cpp
struct SignContext {
    CK_MECHANISM_TYPE mechanism;
    CK_OBJECT_HANDLE  key_handle;
    std::string       app_context_json;  // optional; forwarded into signature_records
    std::vector<uint8_t> accumulated;    // for C_SignUpdate multi-part ops
};
```

---

### 5. `signature_store/` — Database Signature Store

*(Structure unchanged from original. The following additions apply.)*

**New file: `notification_repository.h` / `notification_repository.cpp`**  
CRUD for `notification_subscribers` and `notification_log`. Provides:
- `add_subscriber(Subscriber)`
- `list_subscribers()`
- `log_notification_attempt(NotificationLogEntry)`
- `query_notification_log(filter)`

**Key Design Decisions (unchanged from original plus):**
- The DB HMAC key covers `notification_subscribers` and `notification_log` rows too (same derivation)
- `notification_log` rows are append-only; no UPDATE path exists in the repository

---

### 6. `notification/` — Notification System *(new module)*

**Purpose:** Decouple event emission from delivery. The `SignatureDispatcher` calls the bus; the bus
routes to adapters without blocking the signing critical path.

**Files:**
- `notification_event.h` — `NotificationEvent` struct and `EventType` enum
- `notification_bus.h` / `notification_bus.cpp` — Lock-free SPSC ring buffer (capacity 1024);
  producer: `SignatureDispatcher`; consumer: `NotificationDispatcher` on background thread
- `notification_dispatcher.h` / `notification_dispatcher.cpp` — Reads from bus; resolves
  subscribers from `NotificationRepository`; routes to adapters; writes to `notification_log`
- `adapters/email_adapter.h` / `email_adapter.cpp` — SMTP/STARTTLS delivery via libcurl
- `adapters/webhook_adapter.h` / `webhook_adapter.cpp` — HTTP POST (JSON payload) via libcurl
- `adapters/grpc_push_adapter.h` / `grpc_push_adapter.cpp` — Streams events over an open gRPC
  server-side-streaming RPC; useful for the team's own tooling

**`NotificationEvent` struct:**

```cpp
struct NotificationEvent {
    std::string  event_id;       // UUID v4
    EventType    type;           // SIGN_CREATED, VERIFY_FAILED, etc.
    Severity     severity;       // INFO | WARN | CRITICAL
    int64_t      timestamp;      // epoch ms
    std::string  source;         // "slot:N/token:label"
    std::string  actor;          // user_label or "SO"
    std::string  summary;        // short human-readable
    std::string  detail_json;    // JSON payload
    std::string  hsm_instance;   // instance_id from db_meta
};
```

**Key Design Decisions:**
- The notification bus is **in-process only** for v1. It does not persist events across process
  restarts. If the process crashes between signing and delivery, the event is lost. The DB row is
  the recovery mechanism.
- Background dispatcher thread is started by `C_Initialize` and stopped by `C_Finalize`
- Adapter failures are caught and logged to `notification_log`; they never propagate to the signing
  path
- Subscriber resolution is cached in memory with a 60-second TTL to avoid per-event DB reads

**Caveat — Email deliverability:** SMTP from a local process is often blocked by firewalls and
spam filters. For production consider routing through an SMTP relay (SendGrid, SES, Postfix). The
`email_adapter` should accept a `smtp_relay_url` in config.

---

### 7. `pkcs11/` — PKCS#11 Facade (Public C API)

**Modified `C_Sign` flow (updated):**

```
C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
  │
  ├─ 1. Validate session, op context, key handle
  ├─ 2. CryptoEngine::sign(key, mechanism, pData)  →  SignResult
  ├─ 3. Copy raw signature bytes into pSignature
  ├─ 4. SignatureDispatcher::dispatch(session, SignResult, context)
  │       ├─ Build SignatureRecord (UUID, timestamps, fingerprint, b64, HMAC)
  │       ├─ SignatureRepository::insert(record)    ← DB write (sync or async)
  │       ├─ AuditLog::append(record.id, "C_SIGN")
  │       └─ NotificationBus::publish(SIGN_CREATED, ...)  ← non-blocking enqueue
  └─ 5. Return CKR_OK
```

**Key Design Decisions (unchanged plus):**
- `NotificationBus::publish()` is a non-blocking ring-buffer enqueue. If the buffer is full, the
  event is dropped and a `NOTIFICATION_OVERFLOW` counter is incremented (observable via admin RPC)
- `C_Sign` never returns `CKR_DEVICE_ERROR` due to a notification failure — only DB write failure
  triggers that, when `require_db_write=true`

---

### 8. `persistence/` — Encrypted File Vault

*(Unchanged from original plan. See original for vault format, KEK derivation, and atomic write.)*

---

### 9. `admin/` — Management & Signature Query API (gRPC)

**Updated gRPC Service Definition:**

```protobuf
service HsmAdmin {
  // Token management
  rpc InitToken(InitTokenRequest)        returns (InitTokenResponse);
  rpc ListSlots(Empty)                   returns (SlotListResponse);
  rpc BackupToken(BackupRequest)         returns (BackupResponse);
  rpc RestoreToken(RestoreRequest)       returns (RestoreResponse);

  // Audit
  rpc GetAuditLog(AuditLogRequest)       returns (stream AuditEntry);

  // Signature Store
  rpc QuerySignatures(SignatureQuery)    returns (stream SignatureRecord);
  rpc GetSignature(GetSignatureRequest)  returns (SignatureRecord);
  rpc VerifySignature(VerifyRequest)     returns (VerifyResponse);
  rpc CheckDbIntegrity(Empty)            returns (IntegrityReport);
  rpc ExportSignatureCsv(SignatureQuery) returns (stream CsvChunk);

  // Notification management  ← new
  rpc AddSubscriber(Subscriber)          returns (SubscriberResponse);
  rpc ListSubscribers(Empty)             returns (SubscriberList);
  rpc RemoveSubscriber(SubscriberIdReq)  returns (Empty);
  rpc QueryNotificationLog(NLogQuery)    returns (stream NLogEntry);
  rpc TestNotify(TestNotifyRequest)      returns (TestNotifyResponse);

  // Live event stream  ← new (used by grpc_push_adapter subscribers)
  rpc StreamEvents(StreamRequest)        returns (stream NotificationEvent);
}
```

**`TestNotify` RPC** is intentionally included: it sends a synthetic `TEST` event to all active
subscribers and reports delivery outcomes. This lets the team verify end-to-end notification
plumbing before relying on it in production.

---

### 10. `tests/` — Test Suite

**Additions for notification module:**
- `unit/notification/bus_test.cpp` — ring buffer overflow, concurrent enqueue safety
- `unit/notification/dispatcher_test.cpp` — subscriber filtering by severity and event type,
  retry logic, mock adapters
- `integration/notification/email_test.cpp` — requires a local MailHog or Greenmail container
- `integration/notification/webhook_test.cpp` — local HTTP echo server
- `integration/notify_on_sign/` — `C_Sign` → `SIGN_CREATED` event delivered end-to-end

**Framework:** Google Test + Google Mock  
**Test infrastructure note:** Email and webhook tests need Docker Compose services in CI. Define
these in a `docker-compose.test.yml` at project root so any team member can run `make test-full`
locally.

---

## Directory Structure

```
virtual-hsm/
├── CMakeLists.txt
├── PLAN.md
├── README.md
├── docker-compose.test.yml          ← new (MailHog, Postgres, MySQL for integration tests)
├── include/
│   └── pkcs11/
│       └── pkcs11.h
├── src/
│   ├── core/
│   │   ├── types.h                  # + SignatureRecord, NotificationEvent structs
│   │   ├── error.h / error.cpp
│   │   ├── utils.h / utils.cpp      # + uuid_v4(), base64, hex
│   │   ├── secure_buffer.h
│   │   └── clock.h
│   ├── crypto/
│   │   ├── crypto_engine.h / .cpp
│   │   ├── aes_gcm.h / .cpp
│   │   ├── rsa.h / .cpp
│   │   ├── ecc.h / .cpp
│   │   ├── hmac.h / .cpp
│   │   ├── kdf.h / .cpp
│   │   ├── digest.h / .cpp
│   │   ├── rng.h / .cpp
│   │   └── mechanisms.h
│   ├── keystore/
│   │   ├── hsm_object.h
│   │   ├── token.h / .cpp
│   │   ├── slot.h / .cpp
│   │   ├── object_store.h / .cpp
│   │   ├── attribute_store.h
│   │   ├── key_wrap.h / .cpp
│   │   └── key_fingerprint.h / .cpp
│   ├── session/
│   │   ├── session.h / .cpp
│   │   ├── session_manager.h / .cpp
│   │   ├── slot_manager.h / .cpp
│   │   ├── access_control.h
│   │   ├── find_context.h
│   │   └── op_context.h
│   ├── signature_store/
│   │   ├── db_config.h
│   │   ├── db_connection.h / .cpp
│   │   ├── db_schema.h / .cpp
│   │   ├── db_hmac_key.h / .cpp
│   │   ├── row_integrity.h / .cpp
│   │   ├── signature_repository.h / .cpp
│   │   ├── signature_dispatcher.h / .cpp
│   │   ├── signature_query.h / .cpp
│   │   ├── verification_service.h / .cpp
│   │   └── notification_repository.h / .cpp   ← new
│   ├── notification/                           ← new module
│   │   ├── notification_event.h
│   │   ├── notification_bus.h / .cpp
│   │   ├── notification_dispatcher.h / .cpp
│   │   └── adapters/
│   │       ├── email_adapter.h / .cpp
│   │       ├── webhook_adapter.h / .cpp
│   │       └── grpc_push_adapter.h / .cpp
│   ├── pkcs11/
│   │   ├── pkcs11.h
│   │   ├── p11_init.cpp
│   │   ├── p11_slot.cpp
│   │   ├── p11_session.cpp
│   │   ├── p11_object.cpp
│   │   ├── p11_crypto.cpp
│   │   ├── p11_keygen.cpp
│   │   ├── p11_wrap.cpp
│   │   ├── p11_random.cpp
│   │   └── function_list.cpp
│   ├── persistence/
│   │   ├── vault.h / .cpp
│   │   ├── vault_format.h
│   │   ├── token_serializer.h / .cpp
│   │   └── migrations.h / .cpp
│   └── admin/
│       ├── admin_server.h / .cpp
│       └── audit_log.h / .cpp
├── tests/
│   ├── unit/
│   │   ├── crypto/
│   │   ├── keystore/
│   │   ├── session/
│   │   ├── signature_store/
│   │   └── notification/               ← new
│   ├── integration/
│   │   ├── pkcs11/
│   │   ├── signature_store/
│   │   ├── verify_flow/
│   │   ├── persistence/
│   │   └── notification/               ← new
│   ├── conformance/
│   └── fuzz/
├── proto/
│   └── admin.proto
├── sql/
│   ├── schema_sqlite.sql
│   ├── schema_postgres.sql
│   └── schema_mysql.sql
├── tools/
│   └── vhsm-admin/
├── cmake/
│   ├── FindOpenSSL.cmake
│   ├── FindSQLite3.cmake
│   ├── FindPostgreSQL.cmake
│   ├── FindCURL.cmake                  ← new (for email/webhook adapters)
│   └── CompilerFlags.cmake
└── third_party/
    ├── googletest/
    ├── grpc/
    ├── sqlpp11/
    └── libcurl/                        ← new
```

---

## Build System

**CMake ≥ 3.21** with the following targets:

| Target              | Output             | Description                                         |
|---------------------|--------------------|-----------------------------------------------------|
| `vhsm`              | `libvhsm.so/.dll`  | Main PKCS#11 shared library (with DB + notify)      |
| `vhsm_static`       | `libvhsm.a`        | Static library for embedding                        |
| `vhsm_admin_server` | Binary             | gRPC admin + signature query + event stream server  |
| `vhsm_admin_cli`    | Binary             | CLI admin tool                                      |
| `vhsm_tests`        | Binary             | Full test suite                                     |

**CMake options:**

```cmake
option(VHSM_DB_BACKEND      "Database backend: sqlite|postgres|mysql"  "sqlite")
option(VHSM_ASYNC_DB        "Use async write queue for DB"              OFF)
option(VHSM_REQUIRE_DB      "Fail C_Sign if DB write fails"             ON)
option(VHSM_ADMIN_GRPC      "Build gRPC admin server"                   ON)
option(VHSM_NOTIFY_EMAIL    "Build email notification adapter"          ON)
option(VHSM_NOTIFY_WEBHOOK  "Build webhook notification adapter"        ON)
option(VHSM_NOTIFY_BUS_SIZE "Notification ring buffer capacity"         1024)
```

**Compiler Flags (hardening):**

```cmake
-Wall -Wextra -Werror
-fstack-protector-strong
-D_FORTIFY_SOURCE=2
-fPIE -pie
-Wl,-z,relro,-z,now
```

---

## Dependencies

| Library              | Version    | Purpose                              | License            |
|----------------------|------------|--------------------------------------|--------------------|
| OpenSSL              | ≥ 3.0      | All cryptographic primitives         | Apache-2.0         |
| SQLite3              | ≥ 3.42     | Embedded DB backend (default)        | Public Domain      |
| libpqxx              | ≥ 7.8      | PostgreSQL backend (optional)        | BSD-3              |
| mysql-connector-cpp  | ≥ 8.1      | MySQL backend (optional)             | GPL-2 / Commercial |
| protobuf             | ≥ 3.21     | Token serialization                  | BSD-3              |
| gRPC                 | ≥ 1.50     | Admin + Signature + Event Stream API | Apache-2.0         |
| spdlog               | ≥ 1.11     | Structured logging                   | MIT                |
| nlohmann/json        | ≥ 3.11     | Config parsing, `app_context`        | MIT                |
| libcurl              | ≥ 7.88     | Email (SMTP) and webhook adapters    | MIT/curl           |
| Google Test          | ≥ 1.13     | Unit & integration tests             | BSD-3              |

> **⚠ Caveat — MySQL license:** `mysql-connector-cpp` is GPL-2 unless you purchase a commercial
> license. If the final build is linked into a non-GPL product, use PostgreSQL or SQLite instead, or
> obtain a commercial MySQL connector license before starting Phase 4.

---

## Implementation Phases

### Phase 1 — Crypto Foundation (Week 1–2)
*Assignable to one engineer; no inter-team dependencies.*

- [x] Set up CMake project skeleton with DB backend options and notification build flags
- [x] Implement `core/secure_buffer.h` with `mlock` support
- [x] Implement `core/clock.h` (mockable UTC epoch)
- [x] Implement `utils::uuid_v4()`, `base64_encode/decode`, `hex_encode/decode`
- [x] Implement `crypto/rng.cpp`, `crypto/digest.cpp`
- [x] Implement `crypto/aes_gcm.cpp` with NIST test vectors
- [x] Implement `crypto/rsa.cpp` — keygen, sign (PSS + PKCS1v15), verify, OAEP
- [x] Implement `crypto/ecc.cpp` — keygen (P-256/384/521), ECDSA, ECDH
- [x] Implement `crypto/hmac.cpp`, `crypto/kdf.cpp` — including `compute_row_hmac()`
- [x] Define `SignResult` and `NotificationEvent` structs in `core/types.h`
- [x] Unit tests for all crypto primitives (NIST/RFC vectors)

### Phase 2 — Key Store & Object Model (Week 3)
*Can run in parallel with Phase 1 after `core/types.h` is agreed.*

- [x] Define `HsmObject` hierarchy 
- [ ] Implement `key_fingerprint.cpp` (SHA-256 of SPKI DER) (Gilbert)
- [ ] Implement `ObjectStore` with handle allocation (Sergio)
- [ ] Implement `AttributeStore` with `CKA_SENSITIVE` / `CKA_EXTRACTABLE` enforcement
- [x] Implement `key_wrap.cpp` (RFC 3394) (Tanjona) 
- [ ] Unit tests for attribute enforcement and fingerprint computation

### Phase 3 — Session & Slot Management (Week 4)
- [ ] Implement `Slot`, `Token`, `Session` with `app_context_json` in `SignContext`
- [ ] Implement `SessionManager` (thread-safe)
- [ ] Implement `FindContext` and `OpContext` including `SignContext` accumulator
- [ ] Unit tests for concurrent sessions and `SignContext` lifecycle

### Phase 4 — Database Signature Store (Week 5–6)
*Highest risk phase — unblock DB backend decision before starting.*

- [ ] Implement `db_connection.cpp` with SQLite backend; add PG/MySQL stubs
- [ ] Write and validate `sql/schema_sqlite.sql`, `schema_postgres.sql`, `schema_mysql.sql`
  (include `notification_subscribers` and `notification_log` tables)
- [ ] Implement `db_schema.cpp`: bootstrap, seed `db_meta`, migration runner
- [ ] Implement `db_hmac_key.cpp`: derive from KEK via HKDF, load into `SecureBuffer`
- [ ] Implement `row_integrity.cpp`: `compute_hmac()` / `verify_hmac()` for all record types
- [ ] Implement `signature_repository.cpp` and `notification_repository.cpp`
- [ ] Implement `signature_dispatcher.cpp` with `NotificationBus::publish()` call
- [ ] Implement `verification_service.cpp`
- [ ] Unit tests: round-trips, tamper detection, query filters, HMAC negative cases
- [ ] Integration tests: SQLite full flow, async write queue

### Phase 5 — Notification System (Week 7) ← *new phase*
*Can partially overlap with Phase 4 if team splits.*

- [ ] Implement `notification_event.h` with `EventType` enum and severity levels
- [ ] Implement `notification_bus.cpp` — lock-free ring buffer (SPSCQueue or `std::atomic` head/tail)
- [ ] Implement `notification_dispatcher.cpp` — background thread, subscriber resolution, retry logic
- [ ] Implement `adapters/email_adapter.cpp` — libcurl SMTP with STARTTLS
- [ ] Implement `adapters/webhook_adapter.cpp` — HTTP POST via libcurl
- [ ] Implement `adapters/grpc_push_adapter.cpp` — server-side streaming gRPC
- [ ] Wire `NotificationBus::publish()` calls into `SignatureDispatcher`, `KeyStore` key destruction,
  and `VerificationService`
- [ ] Unit tests: bus overflow, dispatcher retry, adapter mock delivery
- [ ] Integration tests: `C_Sign` → email delivered to MailHog, webhook echo received
- [ ] Manual test: all 3 team members receive a `SIGN_CREATED` notification end-to-end

### Phase 6 — PKCS#11 Facade with DB + Notify Integration (Week 8)
- [ ] Implement all `C_*` functions
- [ ] Wire `C_Sign` / `C_SignFinal` → `SignatureDispatcher::dispatch()`
- [ ] Implement `require_db_write` enforcement: return `CKR_DEVICE_ERROR` on DB failure
- [ ] `C_Initialize` starts notification background thread; `C_Finalize` drains and stops it
- [ ] Integration tests: `C_Sign` produces DB row + delivers notification
- [ ] Conformance tests (OASIS PKCS#11 suite)

### Phase 7 — Persistence Layer (Week 9)
- [ ] Implement `Vault` with AES-256-GCM and PBKDF2
- [ ] Derive DB HMAC key from vault KEK using HKDF
- [ ] Implement `TokenSerializer` with protobuf
- [ ] Implement atomic write (temp file + rename)
- [ ] Add migration framework
- [ ] Round-trip integration tests

### Phase 8 — Admin gRPC + Signature Query API (Week 10)
- [ ] Define `admin.proto` with all RPCs including notification management and `StreamEvents`
- [ ] Implement `AdminServer` with mTLS enforcement
- [ ] Implement `QuerySignatures`, `VerifySignature`, `CheckDbIntegrity`, `ExportSignatureCsv`
- [ ] Implement `AddSubscriber`, `ListSubscribers`, `RemoveSubscriber`, `QueryNotificationLog`,
  `TestNotify`, `StreamEvents`
- [ ] Build `vhsm-admin` CLI tool
- [ ] Admin API integration tests + notify round-trip test
- [ ] Run `TestNotify` against all 3 team member subscriptions; confirm end-to-end delivery

### Phase 9 — Hardening & Release (Week 11–12)
- [ ] libFuzzer targets: PKCS#11 input, vault parsing, DB row deserialization, query params,
  notification event deserialization
- [ ] AddressSanitizer + UBSan + TSan CI pass
- [ ] Static analysis (clang-tidy, cppcheck)
- [ ] Performance benchmarks: signs/sec with SQLite sync, async queue, PG; notification throughput
- [ ] Security review: key material lifecycle, DB HMAC key in memory, notification channel security
- [ ] Documentation and README

---

## Security Considerations

| Threat                                    | Mitigation                                                                         |
|-------------------------------------------|------------------------------------------------------------------------------------|
| Key material in plaintext memory          | `SecureBuffer` with `mlock`, `memzero` on free                                     |
| PIN brute force                           | PBKDF2 600k iterations + failed-attempt lockout counter                            |
| Key extraction via `C_GetAttributeValue`  | `CKA_SENSITIVE` prevents private key export                                        |
| Vault file tampering                      | AES-256-GCM authentication tag covers entire blob                                  |
| DB row tampering (signature forgery)      | Per-row `integrity_hmac` with HKDF-derived secret key                              |
| DB HMAC key disclosure                    | Never stored on disk; derived in-memory from vault KEK at startup                  |
| Unrecorded signatures returned to caller  | `require_db_write=true` returns `CKR_DEVICE_ERROR` on DB failure                  |
| Timing side-channels                      | Constant-time `secure_compare()`, OpenSSL `BN_MONT_CTX`                           |
| Session replay / TOCTOU                   | Session handles are random 64-bit IDs checked on every call                        |
| Signature ID enumeration                  | UUIDs generated from `RAND_bytes`, not sequential integers                         |
| Audit log tampering                       | HMAC-chained append-only log; `CheckDbIntegrity` RPC for full scan                 |
| DB transport interception (PG/MySQL)      | `tls_mode = verify-full` enforced; cert pinning recommended                        |
| Admin API abuse                           | mTLS client certificates required for all admin RPCs                               |
| Memory disclosure (swap)                  | `mlock()` on all `SecureBuffer` instances including DB HMAC key                    |
| Notification channel eavesdropping        | Email uses STARTTLS; webhook targets must be HTTPS; gRPC uses TLS                  |
| Notification impersonation                | Outbound email signed with DKIM (SMTP relay responsibility); webhook uses HMAC sig  |
| Subscriber registry tampering             | `notification_subscribers` rows protected by same `integrity_hmac` scheme          |
| Notification overflow (event loss)        | Ring buffer overflow increments observable counter; CRITICAL events logged to audit |

---

## Testing Strategy

- **Unit tests:** Every crypto primitive against NIST/RFC vectors; every `SignatureRecord` and
  `NotificationEvent` HMAC scenario
- **Tamper tests:** Mutate each DB column individually, verify detection; test NULL injection
- **Requirement tests:** `C_Sign` with `require_db_write=true` when DB is offline → `CKR_DEVICE_ERROR`
- **Round-trip tests:** `C_Sign` → DB row → `VerifySignature` RPC → `VALID`
- **Notification tests:** `C_Sign` → `SIGN_CREATED` → email delivered to MailHog container
- **Overflow tests:** Flood the notification bus beyond capacity; verify no crash, counter incremented
- **State machine tests:** Session login/logout, invalid-state rejections, multi-part `C_SignUpdate`
- **Conformance tests:** Full PKCS#11 OASIS suite; all `CK_RV` paths covered
- **Fuzzing:** libFuzzer on PKCS#11 input, vault deserialization, DB query params, notification events
- **Sanitizers:** ASan, UBSan, TSan in CI on every PR

---

## Team Responsibilities

Since you are three engineers, a suggested ownership split (adjust as needed):

| Area                                             | Owner   | Backup  |
|--------------------------------------------------|---------|---------|
| `core/`, `crypto/`, `keystore/`                  | Eng A   | Eng B   |
| `session/`, `pkcs11/` (PKCS#11 facade)           | Eng B   | Eng A   |
| `signature_store/`, `persistence/`               | Eng C   | Eng B   |
| `notification/` (bus, dispatcher, adapters)      | Eng A   | Eng C   |
| `admin/` (gRPC server + proto)                   | Eng C   | Eng B   |
| CI / CMake / Docker Compose test infra           | Eng B   | Eng A   |
| Security review (final pass)                     | All 3   | —       |

**Important:** The three team members must each register a subscriber entry during Phase 5 manual
testing (Step: "all 3 team members receive a `SIGN_CREATED` notification end-to-end"). This
validates the notification plumbing before it matters in production.

---

## Open Questions

*(Original questions retained; new ones added below.)*

1. **Async vs sync DB writes:** Should `async_db_write` ever be the default? What are acceptable
   delivery guarantees for high-throughput signing workloads?

2. **Payload storage policy:** Should the original payload optionally be stored (encrypted) in the
   DB alongside the digest, to support full self-contained verification?

3. **Key rotation impact:** When a signing key is rotated or destroyed, `VerifySignature` returns
   `KEY_NOT_FOUND`. Should the public key be archived separately?

4. **DB backend priority:** SQLite for single-process; PG/MySQL for daemon mode. Which is primary
   for v1? **(Must resolve before Phase 4.)**

5. **Multi-process access:** Single-process in-library, or IPC daemon (unix socket) so multiple
   processes share one DB connection pool?

6. **Soft delete vs hard delete:** Should `C_DestroyObject` zero-wipe immediately or soft-delete
   with a recovery window?

7. **FIPS mode:** Restrict to approved algorithms only via a build flag?

8. **PIN policy:** Minimum length, complexity, lockout threshold — configurable via `db_meta` or
   hardcoded?

9. **Notification channel priority:** For the team of 3, is email sufficient for v1, or should
   the webhook and gRPC push adapters be built in parallel? **(New — resolve before Phase 5.)**

10. **Notification persistence across restarts:** The in-process ring buffer loses undelivered
    events on crash. Should undelivered WARN/CRITICAL events be checkpointed to the DB before
    delivery? **(New — important for CRITICAL events.)**

11. **SMTP relay configuration:** Does the team have an SMTP relay (SendGrid, SES, corporate SMTP)
    available, or will email delivery be tested only via MailHog locally? **(New — blocks Phase 5
    integration tests.)**

12. **Notification auth for webhooks:** Should outbound webhook POST include an HMAC signature
    header (e.g., `X-VHSM-Signature: HMAC-SHA256(secret, payload)`) so the receiver can verify
    authenticity? **(New — recommended yes.)**

---

## Caveats & Risk Register

| # | Risk                                              | Likelihood | Impact   | Mitigation                                                                          |
|---|---------------------------------------------------|------------|----------|-------------------------------------------------------------------------------------|
| 1 | MySQL GPL license incompatibility                 | Medium     | High     | Default to SQLite/PG; audit linking before shipping                                 |
| 2 | `mlock` quota limits in containers / CI           | High       | Medium   | Test `mlock` failure path; fall back gracefully with a warning; document ulimits    |
| 3 | Email delivery blocked by firewall/spam           | High       | Medium   | Require SMTP relay config; test via MailHog in CI only; document relay requirement  |
| 4 | Notification event loss on crash                  | Medium     | Low-Med  | DB is authoritative; document that notifications are best-effort; see Open Q 10     |
| 5 | Ring buffer overflow under high signing load      | Low        | Low      | Observable counter; CRITICAL events also written to audit log                        |
| 6 | gRPC push adapter keeps connections open forever  | Medium     | Medium   | Add keepalive + connection timeout; reconnect logic in adapter                       |
| 7 | 3-person team: bus factor = 1 on crypto module    | High       | Critical | Enforce code review from ≥2 engineers on all `crypto/` changes; document internals  |
| 8 | SQLite WAL mode + multi-thread contention         | Low        | Medium   | Use connection pool min=2, enable WAL, test with TSan                               |
| 9 | PKCS#11 conformance gaps blocking integration     | Medium     | High     | Run OASIS conformance suite from day 1 of Phase 6, not only at release              |
|10 | Subscriber registry grows unbounded               | Low        | Low      | Add `max_subscribers` config; add `enabled` flag for soft-disable                   |

---

*End of PLAN.md — v2.0*
