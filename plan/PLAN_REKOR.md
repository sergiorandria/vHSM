# Virtual HSM — Implementation Plan
## (with Database-Backed Signature Store, Notification System & Rekor Transparency Log)

> **Team size:** 3 engineers  
> **Version:** 3.0 (Rekor/Sigstore integration added)  
> **Status:** Draft — open questions require resolution before Phase 1 starts

---

## Table of Contents

1. [Overview](#overview)
2. [Goals](#goals)
3. [Non-Goals](#non-goals)
4. [Architecture](#architecture)
5. [Rekor Integration](#rekor-integration) ← *new*
6. [Notification System](#notification-system)
7. [Database Schema](#database-schema)
8. [Module Breakdown](#module-breakdown)
9. [Directory Structure](#directory-structure)
10. [Build System](#build-system)
11. [Dependencies](#dependencies)
12. [Implementation Phases](#implementation-phases)
13. [Security Considerations](#security-considerations)
14. [Testing Strategy](#testing-strategy)
15. [Team Responsibilities](#team-responsibilities)
16. [Open Questions](#open-questions)
17. [Caveats & Risk Register](#caveats--risk-register)

---

## Overview

A **Virtual HSM (Hardware Security Module)** is a software-based emulation of a physical HSM
providing cryptographic key management, secure key storage, and cryptographic operations within a
tamper-resistant software boundary.

This plan extends the baseline virtual HSM with three integrated capabilities:

1. **Database Signature Store** — every signing operation produces a persisted, queryable
   `SignatureRecord` row, enabling audit trails, non-repudiation proofs, signature replay/verification
   workflows, and compliance reporting — all without any signature leaving the HSM trust boundary in
   an unauthenticated form.

2. **Notification System** — every database write (signature creation, key rotation, verification
   event, integrity alert) triggers a fan-out notification to all subscribed parties. This is the
   mechanism by which the three team members (and any configured external system) are alerted to
   state changes in the HSM.

3. **Rekor Transparency Log** ← *new* — every signing operation is additionally committed to a
   Rekor append-only transparency log (self-hosted). Rekor is an open-source, cryptographically
   verifiable ledger from the Sigstore project. Each commitment produces a **Rekor Entry UUID** and
   an **Inclusion Proof** (Merkle path) stored alongside the local DB row. This provides an
   independent, tamper-evident witness that cannot be silently altered by any single administrator —
   directly addressing the self-referential HMAC weakness of the local DB scheme.

> **Why Rekor instead of a full blockchain?** Rekor is a production-grade, battle-tested
> transparency log already used to secure the npm, PyPI, and Maven package ecosystems. It provides
> the exact properties needed here — append-only, independently verifiable, Merkle-proof anchored —
> without the operational overhead of running a full consensus network. A self-hosted Rekor instance
> can be stood up with a single Docker Compose service and backed by any Trillian-compatible
> log server.

---

## Goals

- Emulate core HSM functionality: key generation, storage, signing, encryption, and access control
- Expose a **PKCS#11 v2.40** compatible C API (the industry-standard HSM interface)
- **Persist every signing operation to a relational database** (SQLite embedded / PostgreSQL / MySQL)
- **Allow callers to query, verify, and audit signatures via a Signature Store API**
- **Notify all subscribed parties on every database mutation** (signature created, key rotated,
  integrity alert, verification failure)
- **Commit every signing event to a self-hosted Rekor transparency log** ← *new*
- **Store the Rekor Entry UUID and Merkle inclusion proof alongside each DB row** ← *new*
- **Register public keys in Rekor at key creation; record retirement events at key destruction** ← *new*
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
- Running a multi-node Rekor cluster (v1 uses a single self-hosted instance; HA Rekor is v2 scope)

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
│   (d) Notification Bus     (e) Rekor Client  ← NEW         │
└──────┬──────────────────────┬────────────────┬──────────────┘
       │                      │                │
┌──────▼──────────────────┐  │  ┌─────────────▼──────────────┐
│   DB Signature Store    │  │  │   Rekor Client  ← NEW      │
│  SQLite / PG / MySQL    │  │  │  hashedrekord entries       │
│  SignatureRecord rows   │  │  │  + rekor_entry_uuid col     │
│  + rekor_entry_uuid col │  │  │  + inclusion_proof col      │
│  + inclusion_proof col  │  │  └─────────────┬──────────────┘
│  + integrity_hmac col   │  │                │  HTTP REST
└─────────────────────────┘  │  ┌─────────────▼──────────────┐
       │                     │  │  Self-hosted Rekor Server  │
┌──────▼──────────────────┐  │  │  (Docker Compose service)  │
│  Signature Query API    │  │  │  Trillian + MySQL backend  │
│  lookup/verify/audit    │  │  │  Append-only Merkle log    │
│  + Rekor proof verify   │  │  └────────────────────────────┘
│  (gRPC / REST)          │  │
└─────────────────────────┘  │
                    ┌────────▼──────────────────────┐
                    │   Notification Bus            │
                    │  (in-process event emitter)   │
                    │  Topics: SIGN / KEY / ALERT   │
                    └────────┬──────────────────────┘
                             │
                    ┌────────▼──────────────────────┐
                    │   Notification Dispatcher     │
                    │  Resolves subscribers → routes│
                    └─────┬──────────┬──────────────┘
                          │          │
                 ┌────────▼──┐  ┌────▼──────────────┐
                 │  Email    │  │  Webhook / gRPC   │
                 │  Adapter  │  │  Push Adapter     │
                 └───────────┘  └───────────────────┘
```

---

## Rekor Integration

### What Rekor Is

Rekor (part of the [Sigstore](https://sigstore.dev) project) is an **append-only, cryptographically
verifiable transparency log**. It stores signed attestations as **log entries**, each of which
receives:

- A **log index** (monotonically increasing integer)
- An **entry UUID** (SHA-256 of the leaf hash)
- A **Signed Entry Timestamp (SET)** — a signature over the entry by Rekor's own signing key,
  proving the entry existed at a specific time
- An **inclusion proof** — the Merkle path from the entry's leaf hash to the current signed tree head

Once an entry is in Rekor it **cannot be removed or altered** without invalidating all subsequent
tree heads. This is the tamper-evidence property that the local HMAC scheme cannot provide on its own.

### Entry Type Used: `hashedrekord`

The vHSM uses the `hashedrekord` entry type, which records:

```json
{
  "apiVersion": "0.0.1",
  "kind": "hashedrekord",
  "spec": {
    "data": {
      "hash": {
        "algorithm": "sha256",
        "value": "<payload_digest from SignatureRecord>"
      }
    },
    "signature": {
      "content": "<signature_b64 from SignatureRecord>",
      "publicKey": {
        "content": "<base64-encoded SubjectPublicKeyInfo PEM>"
      }
    }
  }
}
```

This is the lightest-weight entry type: it records the hash of what was signed, the signature
itself, and the public key — exactly the fields already present in `SignatureRecord`. No raw payload
or private key material ever leaves the HSM.

### Key Lifecycle Events in Rekor

Beyond signing events, the vHSM records two key lifecycle events:

| Event            | Rekor entry kind  | When                          | What is recorded                        |
|------------------|-------------------|-------------------------------|-----------------------------------------|
| Key created      | `hashedrekord`    | After `C_GenerateKeyPair`     | Public key SPKI + key fingerprint       |
| Key retired      | `hashedrekord`    | After `C_DestroyObject`       | Signed retirement notice + fingerprint  |

The **retirement entry** solves Open Question #3 (key archival): any verifier can look up the public
key by fingerprint in Rekor even after it has been destroyed locally.

### Self-hosted Rekor — Docker Compose

```yaml
# docker-compose.rekor.yml  (added to project root)
services:
  trillian-log-server:
    image: gcr.io/projectsigstore/trillian_log_server:latest
    ports: ["8090:8090", "8091:8091"]
    depends_on: [trillian-db]

  trillian-log-signer:
    image: gcr.io/projectsigstore/trillian_log_signer:latest
    depends_on: [trillian-db]

  trillian-db:
    image: mariadb:10.5
    environment:
      MYSQL_DATABASE: trillian
      MYSQL_ROOT_PASSWORD: zaphod

  rekor-server:
    image: gcr.io/projectsigstore/rekor-server:latest
    ports: ["3000:3000"]
    command:
      - rekor-server
      - --trillian_log_server.address=trillian-log-server
      - --trillian_log_server.port=8090
      - --enable_retrieve_api=true
    depends_on: [trillian-log-server]
```

The vHSM config (`vhsm.conf`) gains a `[rekor]` section:

```toml
[rekor]
enabled       = true
server_url    = "http://localhost:3000"
timeout_ms    = 5000
async         = true          # non-blocking: post to Rekor after C_Sign returns
require_entry = false         # if true, C_Sign fails when Rekor is unreachable
public_key_pem = "/etc/vhsm/rekor_verify.pub"  # Rekor server's own public key for SET verification
```

### The `rekor/` Module — New C++ Module

**Files:**

- `rekor_client.h` / `rekor_client.cpp` — HTTP REST client (via libcurl) for Rekor API
- `rekor_entry.h` — `RekorEntry` struct and `InclusionProof` struct
- `rekor_verifier.h` / `rekor_verifier.cpp` — verifies a Signed Entry Timestamp and Merkle proof
  against the Rekor server's public key

**`RekorEntry` struct:**

```cpp
struct InclusionProof {
    int64_t              log_index;
    std::string          tree_id;
    std::string          root_hash;       // hex
    std::vector<std::string> hashes;     // Merkle path (hex)
};

struct RekorEntry {
    std::string          entry_uuid;      // 64-char hex
    int64_t              log_index;
    std::string          integrated_time; // RFC3339
    std::string          body_b64;        // raw entry body
    std::string          set_b64;         // Signed Entry Timestamp (base64 DER)
    InclusionProof       proof;
};
```

**`RekorClient` interface:**

```cpp
class RekorClient {
public:
    // POST /api/v1/log/entries  → returns RekorEntry on success
    std::optional<RekorEntry> create_entry(const HashedRekordPayload& payload);

    // GET /api/v1/log/entries?logIndex=N  → retrieve by index
    std::optional<RekorEntry> get_entry_by_index(int64_t index);

    // GET /api/v1/log/entries/{uuid}  → retrieve by UUID
    std::optional<RekorEntry> get_entry(const std::string& uuid);

    // Verify the SET signature and Merkle inclusion proof locally
    bool verify_entry(const RekorEntry& entry);
};
```

### Updated `C_Sign` Flow with Rekor

```
C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
  │
  ├─ 1. Validate session, op context, key handle
  ├─ 2. CryptoEngine::sign(key, mechanism, pData)  →  SignResult
  ├─ 3. Copy raw signature bytes into pSignature
  ├─ 4. SignatureDispatcher::dispatch(session, SignResult, context)
  │       ├─ Build SignatureRecord (UUID, timestamps, fingerprint, b64, HMAC)
  │       ├─ SignatureRepository::insert(record)         ← DB write (sync)
  │       ├─ AuditLog::append(record.id, "C_SIGN")
  │       ├─ NotificationBus::publish(SIGN_CREATED, ...) ← non-blocking enqueue
  │       └─ RekorClient::create_entry_async(payload)    ← NEW: async Rekor POST
  │               │  (background thread)
  │               ├─ POST /api/v1/log/entries → RekorEntry
  │               ├─ Verify SET signature
  │               └─ SignatureRepository::update_rekor_fields(
  │                      record.id,
  │                      entry.entry_uuid,
  │                      entry.log_index,
  │                      serialize(entry.proof))          ← DB row updated with proof
  └─ 5. Return CKR_OK  (Rekor post happens in background)
```

**Key design decision:** Rekor posting is **always async** in v1. The `C_Sign` critical path is not
blocked by a network call. If Rekor is unreachable, the local DB row exists (no data loss) and the
background worker retries with exponential backoff. `require_entry = true` (config option) changes
this: the DB write is held until Rekor confirms, at the cost of latency.

### How Rekor Solves the HMAC Self-Reference Problem

| Old scheme (v2.0)                          | New scheme (v3.0 with Rekor)                    |
|--------------------------------------------|-------------------------------------------------|
| Integrity = HMAC(row, key derived in memory) | Integrity = HMAC(row) **+** Rekor inclusion proof |
| Verifying requires trusting HSM process    | Verifying proof requires only Rekor public key  |
| Admin can re-derive HMAC key, alter row    | Altering row invalidates Merkle path in Rekor   |
| Audit trail lives in one DB               | Audit trail is anchored in an independent log   |
| Key archival: unsolved (Open Q #3)        | Public key registered in Rekor at creation      |

The HMAC scheme is **kept** — it remains useful for fast local integrity checks without a network
call. Rekor adds an **external, independent layer** that cannot be tampered with by a local attacker.

### Verifying a Signature End-to-End (New `VerifySignature` RPC flow)

```
VerifySignature(signature_id)
  │
  ├─ 1. Load SignatureRecord from DB
  ├─ 2. Verify local HMAC (fast, no network)
  ├─ 3. RekorClient::get_entry(record.rekor_entry_uuid)
  ├─ 4. RekorVerifier::verify_entry(entry)
  │       ├─ Verify SET: Ed25519(rekor_pub_key, entry.body + entry.integrated_time)
  │       └─ Verify Merkle proof: walk hashes up to root, compare to signed tree head
  ├─ 5. Cross-check: entry.payload_digest == record.payload_digest
  └─ 6. Return VerifyResponse { local_hmac: OK, rekor_proof: OK, cross_check: OK }
```

A verifier with only the Rekor server's public key (a single 32-byte Ed25519 key) can independently
confirm that a signature event occurred, **without trusting the vHSM process, its DB, or its HMAC
key**.

---

## Notification System

> This section is unchanged from v2.0 except that a new `REKOR_COMMIT_FAILED` event type is added.

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
| `REKOR_COMMIT_FAILED`   | Rekor background worker exhausted retries ← NEW               | WARN     |
| `REKOR_PROOF_INVALID`   | Merkle proof verification failed during VerifySignature ← NEW | CRITICAL |
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
  "detail":      {
    "signature_id":    "…",
    "key_fingerprint": "…",
    "payload_digest":  "…",
    "rekor_entry_uuid": "…",
    "rekor_log_index":  42
  },
  "hsm_instance":"instance_id from db_meta"
}
```

### Subscriber Registry

Stored in `notification_subscribers` table (separate from `db_meta` to keep concerns clean):

```sql
CREATE TABLE notification_subscribers (
    id           TEXT    PRIMARY KEY,
    name         TEXT    NOT NULL,
    channel      TEXT    NOT NULL,
    address      TEXT    NOT NULL,
    min_severity TEXT    NOT NULL
      CHECK(min_severity IN ('INFO','WARN','CRITICAL')),
    event_filter TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    integrity_hmac TEXT  NOT NULL
);
```

### Delivery Guarantees

- **At-least-once delivery** is the target for WARN/CRITICAL events (3 retries, exponential backoff).
- **Best-effort (fire-and-forget)** is acceptable for INFO events.
- Delivery is **asynchronous** — never blocks `C_Sign`.
- Bounded in-memory queue (capacity 1024).

### Caveat — Notification vs. Atomicity

The notification and the DB write are **not atomic**. The DB + Rekor are the joint source of truth;
notifications are a courtesy.

---

## Database Schema

### Table: `signature_records` (updated)

```sql
CREATE TABLE signature_records (
    id               TEXT     PRIMARY KEY,
    created_at       INTEGER  NOT NULL,
    slot_id          INTEGER  NOT NULL,
    token_label      TEXT     NOT NULL,
    key_id           TEXT     NOT NULL,
    key_fingerprint  TEXT     NOT NULL,
    mechanism        TEXT     NOT NULL,
    digest_algorithm TEXT     NOT NULL,
    payload_digest   TEXT     NOT NULL,
    payload_size     INTEGER  NOT NULL,
    signature_b64    TEXT     NOT NULL,
    session_handle   TEXT     NOT NULL,
    user_label       TEXT,
    app_context      TEXT,
    -- Rekor fields (nullable until async commit completes)  ← NEW
    rekor_entry_uuid TEXT,                   -- 64-char hex UUID from Rekor
    rekor_log_index  INTEGER,                -- monotonic log index
    rekor_integrated_time TEXT,              -- RFC3339 timestamp from Rekor SET
    rekor_inclusion_proof TEXT,              -- JSON-serialized InclusionProof
    rekor_set_b64    TEXT,                   -- Signed Entry Timestamp (base64)
    rekor_status     TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(rekor_status IN ('PENDING','COMMITTED','FAILED','DISABLED')),
    integrity_hmac   TEXT     NOT NULL       -- covers ALL columns including rekor fields
);

CREATE INDEX idx_sig_key_id        ON signature_records(key_id);
CREATE INDEX idx_sig_created_at    ON signature_records(created_at);
CREATE INDEX idx_sig_token_label   ON signature_records(token_label);
CREATE INDEX idx_sig_payload       ON signature_records(payload_digest);
CREATE INDEX idx_sig_rekor_uuid    ON signature_records(rekor_entry_uuid);  -- NEW
CREATE INDEX idx_sig_rekor_status  ON signature_records(rekor_status);      -- NEW
```

> **HMAC update:** When the Rekor background worker fills in the `rekor_*` fields, it recomputes
> `integrity_hmac` to cover the complete final row. The HMAC therefore commits to both the signature
> data and the Rekor proof — a verifier can check both locally.

### Table: `key_rekor_registry` ← NEW

Tracks Rekor entries for key lifecycle events.

```sql
CREATE TABLE key_rekor_registry (
    id               TEXT     PRIMARY KEY,   -- UUID
    key_fingerprint  TEXT     NOT NULL,      -- SHA-256 SPKI
    event_type       TEXT     NOT NULL
        CHECK(event_type IN ('CREATED','RETIRED')),
    occurred_at      INTEGER  NOT NULL,      -- epoch ms
    rekor_entry_uuid TEXT,
    rekor_log_index  INTEGER,
    rekor_status     TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(rekor_status IN ('PENDING','COMMITTED','FAILED')),
    integrity_hmac   TEXT     NOT NULL
);

CREATE INDEX idx_krr_fingerprint ON key_rekor_registry(key_fingerprint);
```

### Table: `signature_verifications` (unchanged)

```sql
CREATE TABLE signature_verifications (
    id               TEXT     PRIMARY KEY,
    verified_at      INTEGER  NOT NULL,
    signature_id     TEXT     REFERENCES signature_records(id),
    verifier_session TEXT     NOT NULL,
    outcome          TEXT     NOT NULL
        CHECK(outcome IN ('VALID','INVALID','KEY_NOT_FOUND','ERROR')),
    rekor_outcome    TEXT                    -- NEW: 'PROOF_OK'|'PROOF_FAILED'|'NOT_CHECKED'
        CHECK(rekor_outcome IN ('PROOF_OK','PROOF_FAILED','NOT_CHECKED')),
    error_detail     TEXT,
    integrity_hmac   TEXT     NOT NULL
);
```

### Tables: `notification_subscribers`, `notification_log`, `db_meta`

Unchanged from v2.0. See v2.0 for full definitions.

---

## Module Breakdown

### 1. `core/` — Core Types & Constants

**Changes from v2.0:** `RekorEntry` and `InclusionProof` POD structs added to `core/types.h`.
`RekorStatus` enum added (`PENDING`, `COMMITTED`, `FAILED`, `DISABLED`).

---

### 2. `crypto/` — Cryptographic Engine

**Changes from v2.0:** No changes to existing files.

New file: `ed25519_verify.h` / `ed25519_verify.cpp` — verifies Ed25519 signatures (used to verify
Rekor's Signed Entry Timestamp against the Rekor server's published public key).

---

### 3. `keystore/` — Key Storage & Object Model

**Changes from v2.0:**

- `token.cpp` — after `C_GenerateKeyPair` succeeds, enqueues a `KEY_CREATED` Rekor commitment via
  `RekorClient::create_entry_async()`
- `object_store.cpp` — after `C_DestroyObject`, enqueues a `KEY_RETIRED` Rekor commitment

---

### 4. `session/` — Session & Slot Manager

Unchanged from v2.0.

---

### 5. `signature_store/` — Database Signature Store

**Changes from v2.0:**

- `signature_repository.cpp` — `insert()` now writes `rekor_status = 'PENDING'`; new method
  `update_rekor_fields(id, RekorEntry)` fills in the Rekor columns and recomputes `integrity_hmac`
- `verification_service.cpp` — `VerifySignature` calls `RekorClient::verify_entry()` and records
  `rekor_outcome` in `signature_verifications`

New file: `rekor_retry_queue.h` / `rekor_retry_queue.cpp` — persistent queue of pending Rekor
commitments. On startup, scans for rows with `rekor_status = 'PENDING'` and re-submits them. This
ensures that Rekor commitments survive process restarts (directly addressing the crash-recovery gap
from v2.0's notification bus).

---

### 6. `rekor/` — Rekor Client Module ← NEW

**Purpose:** All interaction with the Rekor REST API and local proof verification.

**Files:**

- `rekor_entry.h` — `RekorEntry`, `InclusionProof`, `HashedRekordPayload` structs
- `rekor_client.h` / `rekor_client.cpp` — HTTP REST client (libcurl); `create_entry()`,
  `get_entry()`, `get_entry_by_index()`
- `rekor_verifier.h` / `rekor_verifier.cpp` — `verify_entry()`: verifies SET (Ed25519) and Merkle
  inclusion proof; no network call required after initial entry fetch
- `rekor_worker.h` / `rekor_worker.cpp` — Background thread that drains the async Rekor submission
  queue; exponential backoff (1s, 2s, 4s, 8s, max 60s); emits `REKOR_COMMIT_FAILED` notification
  after 5 consecutive failures

**`RekorWorker` lifecycle:**

```
C_Initialize → RekorWorker::start()   (background thread)
C_Finalize   → RekorWorker::drain_and_stop()  (flush queue, then exit)
```

**Merkle proof verification (no Rekor server needed after fetch):**

```cpp
bool RekorVerifier::verify_inclusion_proof(
    const std::string& leaf_hash,   // SHA-256 of entry body
    const InclusionProof& proof,
    const std::string& signed_tree_head_hash)
{
    // Walk the Merkle path: hash(leaf, sibling), hash(result, sibling), ...
    // Compare final root to signed_tree_head_hash
    // Verify signed_tree_head is signed by Rekor's Ed25519 key
}
```

---

### 7. `notification/` — Notification System

**Changes from v2.0:** Two new event types (`REKOR_COMMIT_FAILED`, `REKOR_PROOF_INVALID`) added to
`EventType` enum in `notification_event.h`. No structural changes.

---

### 8. `pkcs11/` — PKCS#11 Facade

**Changes from v2.0:** `C_Sign` / `C_SignFinal` flow updated — see [Updated C_Sign Flow](#updated-c_sign-flow-with-rekor).

`C_GenerateKeyPair` gains a post-keygen hook to submit the public key to Rekor.

---

### 9. `persistence/` — Encrypted File Vault

Unchanged from v2.0.

---

### 10. `admin/` — Management & Signature Query API (gRPC)

**Updated gRPC Service Definition (additions only):**

```protobuf
service HsmAdmin {
  // ... all v2.0 RPCs unchanged ...

  // Rekor management  ← NEW
  rpc GetRekorEntry(RekorEntryRequest)    returns (RekorEntryResponse);
  rpc VerifyRekorProof(VerifyRekorRequest) returns (VerifyRekorResponse);
  rpc ListPendingRekorCommits(Empty)      returns (PendingRekorList);
  rpc RetryRekorCommits(Empty)            returns (RetryRekorResponse);
  rpc GetKeyRekorHistory(KeyFingerprintReq) returns (stream KeyRekorEvent);
}
```

**`GetRekorEntry` RPC:** Given a `signature_id`, returns the `RekorEntry` (fetched live from Rekor
server) alongside the locally stored proof — useful for auditors who want to verify the chain of
custody without any HSM trust.

---

### 11. `tests/` — Test Suite

**Additions for Rekor module:**

- `unit/rekor/rekor_client_test.cpp` — mock HTTP server; test entry creation and retrieval
- `unit/rekor/rekor_verifier_test.cpp` — offline verification of SET and Merkle proof using
  pre-recorded test vectors
- `unit/rekor/rekor_worker_test.cpp` — queue drain, retry backoff, failure notification
- `integration/rekor/rekor_commit_test.cpp` — requires `docker-compose.rekor.yml` up; `C_Sign` →
  Rekor entry appears in log; verify proof
- `integration/rekor/rekor_recovery_test.cpp` — simulate crash mid-commit; restart; verify
  background worker re-submits PENDING rows
- `integration/rekor/key_lifecycle_test.cpp` — keygen → Rekor entry; destroy → retirement entry

---

## Directory Structure

```
virtual-hsm/
├── CMakeLists.txt
├── PLAN.md
├── README.md
├── docker-compose.test.yml          (MailHog, Postgres, MySQL)
├── docker-compose.rekor.yml         ← NEW (Trillian + Rekor server)
├── include/
│   └── pkcs11/
│       └── pkcs11.h
├── src/
│   ├── core/
│   │   ├── types.h                  # + RekorEntry, InclusionProof, RekorStatus
│   │   ├── error.h / error.cpp
│   │   ├── utils.h / utils.cpp
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
│   │   ├── mechanisms.h
│   │   └── ed25519_verify.h / .cpp  ← NEW (for Rekor SET verification)
│   ├── keystore/
│   │   ├── hsm_object.h
│   │   ├── token.h / .cpp           # + KEY_CREATED Rekor hook
│   │   ├── slot.h / .cpp
│   │   ├── object_store.h / .cpp    # + KEY_RETIRED Rekor hook
│   │   ├── attribute_store.h
│   │   ├── key_wrap.h / .cpp
│   │   └── key_fingerprint.h / .cpp
│   ├── session/
│   │   └── ...                      (unchanged)
│   ├── signature_store/
│   │   ├── db_config.h
│   │   ├── db_connection.h / .cpp
│   │   ├── db_schema.h / .cpp       # + key_rekor_registry table
│   │   ├── db_hmac_key.h / .cpp
│   │   ├── row_integrity.h / .cpp   # + covers rekor columns
│   │   ├── signature_repository.h / .cpp   # + update_rekor_fields()
│   │   ├── signature_dispatcher.h / .cpp   # + RekorClient::create_entry_async()
│   │   ├── signature_query.h / .cpp
│   │   ├── verification_service.h / .cpp   # + RekorVerifier call
│   │   ├── rekor_retry_queue.h / .cpp      ← NEW
│   │   └── notification_repository.h / .cpp
│   ├── rekor/                              ← NEW MODULE
│   │   ├── rekor_entry.h
│   │   ├── rekor_client.h / .cpp
│   │   ├── rekor_verifier.h / .cpp
│   │   └── rekor_worker.h / .cpp
│   ├── notification/
│   │   ├── notification_event.h     # + REKOR_COMMIT_FAILED, REKOR_PROOF_INVALID
│   │   ├── notification_bus.h / .cpp
│   │   ├── notification_dispatcher.h / .cpp
│   │   └── adapters/
│   │       ├── email_adapter.h / .cpp
│   │       ├── webhook_adapter.h / .cpp
│   │       └── grpc_push_adapter.h / .cpp
│   ├── pkcs11/
│   │   └── ...                      (+ Rekor hook in p11_crypto.cpp, p11_keygen.cpp)
│   ├── persistence/
│   │   └── ...                      (unchanged)
│   └── admin/
│       ├── admin_server.h / .cpp    # + Rekor RPCs
│       └── audit_log.h / .cpp
├── tests/
│   ├── unit/
│   │   ├── crypto/
│   │   ├── keystore/
│   │   ├── session/
│   │   ├── signature_store/
│   │   ├── notification/
│   │   └── rekor/                   ← NEW
│   ├── integration/
│   │   ├── pkcs11/
│   │   ├── signature_store/
│   │   ├── verify_flow/
│   │   ├── persistence/
│   │   ├── notification/
│   │   └── rekor/                   ← NEW
│   ├── conformance/
│   └── fuzz/
├── proto/
│   └── admin.proto                  # + Rekor RPCs
├── sql/
│   ├── schema_sqlite.sql            # + rekor columns + key_rekor_registry
│   ├── schema_postgres.sql
│   └── schema_mysql.sql
├── tools/
│   └── vhsm-admin/
├── cmake/
│   ├── FindOpenSSL.cmake
│   ├── FindSQLite3.cmake
│   ├── FindPostgreSQL.cmake
│   ├── FindCURL.cmake
│   └── CompilerFlags.cmake
└── third_party/
    ├── googletest/
    ├── grpc/
    ├── sqlpp11/
    └── libcurl/
```

---

## Build System

**CMake ≥ 3.21** with the following targets (unchanged from v2.0 plus new Rekor option):

| Target              | Output             | Description                                         |
|---------------------|--------------------|-----------------------------------------------------|
| `vhsm`              | `libvhsm.so/.dll`  | Main PKCS#11 shared library                         |
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
option(VHSM_REKOR_ENABLED   "Enable Rekor transparency log"             ON)   # NEW
option(VHSM_REKOR_REQUIRE   "Fail C_Sign if Rekor commit fails"         OFF)  # NEW
option(VHSM_REKOR_URL       "Rekor server URL"      "http://localhost:3000")  # NEW
```

---

## Dependencies

| Library              | Version    | Purpose                                    | License            |
|----------------------|------------|--------------------------------------------|--------------------|
| OpenSSL              | ≥ 3.0      | All cryptographic primitives               | Apache-2.0         |
| SQLite3              | ≥ 3.42     | Embedded DB backend (default)              | Public Domain      |
| libpqxx              | ≥ 7.8      | PostgreSQL backend (optional)              | BSD-3              |
| mysql-connector-cpp  | ≥ 8.1      | MySQL backend (optional)                   | GPL-2 / Commercial |
| protobuf             | ≥ 3.21     | Token serialization                        | BSD-3              |
| gRPC                 | ≥ 1.50     | Admin + Signature + Event Stream API       | Apache-2.0         |
| spdlog               | ≥ 1.11     | Structured logging                         | MIT                |
| nlohmann/json        | ≥ 3.11     | Config, `app_context`, Rekor JSON payloads | MIT                |
| libcurl              | ≥ 7.88     | Email (SMTP), webhook, Rekor REST client   | MIT/curl           |
| Google Test          | ≥ 1.13     | Unit & integration tests                   | BSD-3              |
| **Rekor server**     | **≥ 1.3**  | **Self-hosted transparency log**           | **Apache-2.0** ← NEW |
| **Trillian**         | **≥ 1.5**  | **Merkle log backend for Rekor**           | **Apache-2.0** ← NEW |

> **No new C++ library is required for Rekor.** The `rekor/` module uses only libcurl (already a
> dependency) for HTTP and nlohmann/json (already a dependency) for payload serialization. Ed25519
> verification uses OpenSSL EVP (already a dependency). The Rekor server itself runs as a Docker
> service — it is an **operational** dependency, not a compile-time one.

---

## Implementation Phases

### Phase 1 — Crypto Foundation (Week 1–2)

- [x] Set up CMake project skeleton with DB backend options and notification/Rekor build flags
- [x] Implement `core/secure_buffer.h` with `mlock` support
- [x] Implement `core/clock.h` (mockable UTC epoch)
- [x] Implement `utils::uuid_v4()`, `base64_encode/decode`, `hex_encode/decode`
- [x] Implement `crypto/rng.cpp`, `crypto/digest.cpp`
- [x] Implement `crypto/aes_gcm.cpp` with NIST test vectors
- [x] Implement `crypto/rsa.cpp` — keygen, sign (PSS + PKCS1v15), verify, OAEP
- [x] Implement `crypto/ecc.cpp` — keygen (P-256/384/521), ECDSA, ECDH
- [x] Implement `crypto/hmac.cpp`, `crypto/kdf.cpp`
- [x] Implement `crypto/ed25519_verify.cpp` — Ed25519 verify via OpenSSL EVP ← NEW
- [x] Define `SignatureRecord`, `NotificationEvent`, `RekorEntry`, `InclusionProof` in `core/types.h`
- [x] Unit tests for all crypto primitives (NIST/RFC vectors)

### Phase 2 — Key Store & Object Model (Week 3)

- [x] Define `HsmObject` hierarchy
- [x] Implement `key_fingerprint.cpp` (SHA-256 of SPKI DER)
- [x] Implement `ObjectStore` with handle allocation
- [x] Implement `AttributeStore` with `CKA_SENSITIVE` / `CKA_EXTRACTABLE` enforcement
- [x] Implement `key_wrap.cpp` (RFC 3394)
- [x] Unit tests for attribute enforcement and fingerprint computation

### Phase 3 — Session & Slot Management (Week 4)

- [x] Implement `Slot`, `Token`, `Session` with `app_context_json` in `SignContext`
- [x] Implement `SessionManager` (thread-safe)
- [x] Implement `FindContext` and `OpContext` including `SignContext` accumulator
- [x] Unit tests for concurrent sessions and `SignContext` lifecycle

### Phase 4 — Database Signature Store (Week 5–6)

- [x] Implement `db_connection.cpp` with SQLite backend; add PG/MySQL stubs
- [ ] Write and validate SQL schemas including `rekor_*` columns and `key_rekor_registry` table ← NEW
- [ ] Implement `db_schema.cpp`: bootstrap, seed `db_meta`, migration runner
- [ ] Implement `db_hmac_key.cpp`: derive from KEK via HKDF
- [ ] Implement `row_integrity.cpp`: HMAC covers all columns including `rekor_*` fields ← NEW
- [ ] Implement `signature_repository.cpp` with `update_rekor_fields()` method ← NEW
- [ ] Implement `rekor_retry_queue.cpp` — scan PENDING rows on startup ← NEW
- [ ] Implement `notification_repository.cpp`
- [ ] Implement `signature_dispatcher.cpp`
- [ ] Implement `verification_service.cpp`
- [ ] Unit tests: round-trips, tamper detection, HMAC on rekor fields

### Phase 5 — Rekor Client Module (Week 7) ← NEW PHASE

*Can overlap with Phase 4 if team splits. Requires `docker-compose.rekor.yml` up.*

- [ ] Stand up `docker-compose.rekor.yml` — Trillian + Rekor server locally
- [ ] Implement `rekor/rekor_entry.h` — all structs
- [ ] Implement `rekor/rekor_client.cpp` — `create_entry()`, `get_entry()` via libcurl
- [ ] Implement `rekor/rekor_verifier.cpp` — SET verification (Ed25519) + Merkle proof walk
- [ ] Implement `rekor/rekor_worker.cpp` — background thread, queue drain, retry backoff
- [ ] Wire `RekorWorker::start()` into `C_Initialize` hook (even if PKCS#11 not built yet)
- [ ] Unit tests: offline proof verification with pre-recorded vectors
- [ ] Integration tests: live Rekor entry creation, retrieval, proof verification
- [ ] Test crash-recovery: kill worker mid-commit, restart, verify PENDING rows re-submitted

### Phase 6 — Notification System (Week 8)

- [ ] Implement `notification_event.h` with new `REKOR_COMMIT_FAILED` / `REKOR_PROOF_INVALID` types
- [ ] Implement `notification_bus.cpp` — lock-free ring buffer
- [ ] Implement `notification_dispatcher.cpp` — background thread, subscriber resolution, retry
- [ ] Implement `adapters/email_adapter.cpp`, `webhook_adapter.cpp`, `grpc_push_adapter.cpp`
- [ ] Wire `NotificationBus::publish()` into `SignatureDispatcher`, `KeyStore`, `RekorWorker`
- [ ] Unit tests: bus overflow, retry, adapter mock
- [ ] Integration tests: `C_Sign` → email to MailHog; `REKOR_COMMIT_FAILED` → webhook
- [ ] Manual test: all 3 team members receive `SIGN_CREATED` + `REKOR_COMMIT_FAILED` end-to-end

### Phase 7 — PKCS#11 Facade with Full Integration (Week 9)

- [ ] Implement all `C_*` functions
- [ ] Wire `C_Sign` → `SignatureDispatcher` → `RekorWorker` queue
- [ ] Wire `C_GenerateKeyPair` → `RekorClient::create_entry_async()` (KEY_CREATED)
- [ ] Wire `C_DestroyObject` → `RekorClient::create_entry_async()` (KEY_RETIRED)
- [ ] Implement `require_db_write` and `require_rekor_entry` enforcement
- [ ] `C_Initialize` starts Rekor worker + notification dispatcher; `C_Finalize` drains both
- [ ] Integration tests: full `C_Sign` → DB → Rekor → notification pipeline
- [ ] Conformance tests (OASIS PKCS#11 suite)

### Phase 8 — Persistence Layer (Week 10)

- [ ] Implement `Vault` with AES-256-GCM and PBKDF2
- [ ] Derive DB HMAC key from vault KEK using HKDF
- [ ] Implement `TokenSerializer` with protobuf
- [ ] Implement atomic write (temp file + rename)
- [ ] Add migration framework (must handle adding `rekor_*` columns to existing DBs)
- [ ] Round-trip integration tests

### Phase 9 — Admin gRPC + Signature Query API (Week 11)

- [ ] Define `admin.proto` with all RPCs including Rekor management RPCs
- [ ] Implement `AdminServer` with mTLS enforcement
- [ ] Implement all signature query, verification, and Rekor RPCs
- [ ] Implement `ListPendingRekorCommits` and `RetryRekorCommits` admin RPCs
- [ ] Build `vhsm-admin` CLI tool
- [ ] Run `TestNotify` and `VerifyRekorProof` against all 3 subscriptions end-to-end

### Phase 10 — Hardening & Release (Week 12–13)

- [ ] libFuzzer: PKCS#11 input, vault parsing, DB row deserialization, Rekor JSON response ← NEW
- [ ] AddressSanitizer + UBSan + TSan CI pass
- [ ] Static analysis (clang-tidy, cppcheck)
- [ ] Rekor unreachable stress test: confirm async fallback, no data loss, retry convergence ← NEW
- [ ] Performance benchmarks: signs/sec with Rekor async vs sync; Rekor proof verification latency
- [ ] Security review: key material lifecycle, DB HMAC key, Rekor server public key pinning ← NEW
- [ ] Documentation and README

---

## Security Considerations

| Threat                                   | Mitigation                                                                              |
|------------------------------------------|-----------------------------------------------------------------------------------------|
| Key material in plaintext memory         | `SecureBuffer` with `mlock`, `memzero` on free                                          |
| PIN brute force                          | PBKDF2 600k iterations + failed-attempt lockout counter                                 |
| Key extraction via `C_GetAttributeValue` | `CKA_SENSITIVE` prevents private key export                                             |
| Vault file tampering                     | AES-256-GCM authentication tag covers entire blob                                       |
| DB row tampering (signature forgery)     | Per-row `integrity_hmac` + Rekor inclusion proof ← STRENGTHENED                        |
| DB HMAC key disclosure                   | Never stored on disk; derived in-memory from vault KEK at startup                       |
| Silent DB row insertion by admin         | Rekor merkle proof is an independent witness — insertion would invalidate Rekor chain   |
| Unrecorded signatures returned to caller | `require_db_write=true` returns `CKR_DEVICE_ERROR` on DB failure                       |
| Timing side-channels                     | Constant-time `secure_compare()`, OpenSSL `BN_MONT_CTX`                                |
| Session replay / TOCTOU                  | Session handles are random 64-bit IDs checked on every call                             |
| Signature ID enumeration                 | UUIDs generated from `RAND_bytes`, not sequential integers                              |
| Audit log tampering                      | HMAC-chained audit log + Rekor commitment ← STRENGTHENED                               |
| DB transport interception (PG/MySQL)     | `tls_mode = verify-full` enforced; cert pinning recommended                             |
| Admin API abuse                          | mTLS client certificates required for all admin RPCs                                   |
| Memory disclosure (swap)                 | `mlock()` on all `SecureBuffer` instances                                               |
| Notification channel eavesdropping       | Email uses STARTTLS; webhook targets must be HTTPS; gRPC uses TLS                       |
| Notification impersonation               | Outbound email DKIM-signed; webhook uses HMAC signature header                          |
| Subscriber registry tampering            | `notification_subscribers` rows protected by `integrity_hmac`                           |
| Rekor server impersonation               | Rekor server's Ed25519 public key pinned in `vhsm.conf`; SET verified locally ← NEW   |
| Rekor unreachability (DoS)               | Async by default; `require_entry=false`; PENDING rows retried on restart ← NEW         |
| Rekor log split / equivocation           | Monitor signed tree heads across independent witnesses (v2 scope) ← NEW                |

---

## Testing Strategy

- **Unit tests:** Every crypto primitive; every `SignatureRecord` and `NotificationEvent` HMAC
  scenario; offline Rekor proof verification ← NEW
- **Tamper tests:** Mutate each DB column; verify HMAC + Rekor proof cross-check catches it ← NEW
- **Requirement tests:** `C_Sign` with `require_db_write=true` when DB offline → `CKR_DEVICE_ERROR`
- **Round-trip tests:** `C_Sign` → DB row → `VerifySignature` RPC → `VALID` + `PROOF_OK` ← NEW
- **Notification tests:** `C_Sign` → `SIGN_CREATED` → email to MailHog
- **Rekor commit tests:** `C_Sign` → Rekor entry appears; proof verifiable offline ← NEW
- **Rekor recovery tests:** crash mid-commit; restart; PENDING rows re-submitted ← NEW
- **Key lifecycle tests:** keygen → Rekor KEY_CREATED entry; destroy → Rekor KEY_RETIRED ← NEW
- **Overflow tests:** Flood notification bus; verify no crash, counter incremented
- **State machine tests:** Session login/logout, invalid-state rejections
- **Conformance tests:** Full PKCS#11 OASIS suite
- **Fuzzing:** libFuzzer on PKCS#11 input, vault, DB rows, Rekor JSON responses ← NEW
- **Sanitizers:** ASan, UBSan, TSan in CI on every PR

---

## Team Responsibilities

| Area                                        | Owner | Backup |
|---------------------------------------------|-------|--------|
| `core/`, `crypto/`, `keystore/`             | Eng A | Eng B  |
| `session/`, `pkcs11/` (PKCS#11 facade)      | Eng B | Eng A  |
| `signature_store/`, `persistence/`          | Eng C | Eng B  |
| `notification/` (bus, dispatcher, adapters) | Eng A | Eng C  |
| `rekor/` (client, verifier, worker) ← NEW   | Eng B | Eng C  |
| `admin/` (gRPC server + proto)              | Eng C | Eng B  |
| `docker-compose.rekor.yml` + Rekor ops ← NEW| Eng B | Eng A  |
| CI / CMake / Docker Compose test infra      | Eng B | Eng A  |
| Security review (final pass)                | All 3 | —      |

---

## Open Questions

1. **Async vs sync DB writes:** Should `async_db_write` ever be the default?

2. **Payload storage policy:** Should the original payload optionally be stored (encrypted) in the
   DB alongside the digest?

3. **Key rotation impact:** ~~Unsolved~~ → **Resolved by Rekor** — public key registered in Rekor
   at creation; `KEY_RETIRED` entry recorded at destruction. Verifiers can retrieve by fingerprint.

4. **DB backend priority:** SQLite for single-process; PG/MySQL for daemon mode. **(Must resolve
   before Phase 4.)**

5. **Multi-process access:** Single-process in-library, or IPC daemon?

6. **Soft delete vs hard delete:** Should `C_DestroyObject` zero-wipe immediately or soft-delete?

7. **FIPS mode:** Restrict to approved algorithms only via a build flag?

8. **PIN policy:** Minimum length, complexity, lockout threshold — configurable or hardcoded?

9. **Notification channel priority:** Is email sufficient for v1, or webhook/gRPC in parallel?

10. **Notification persistence across restarts:** The in-process ring buffer loses events on crash.
    Should WARN/CRITICAL events be checkpointed to DB? **(Note: Rekor retry queue solves this for
    Rekor events specifically — PENDING rows survive restarts.)**

11. **SMTP relay configuration:** Does the team have an SMTP relay available?

12. **Notification auth for webhooks:** Should outbound webhook POST include an HMAC signature
    header?

13. **Rekor HA:** v1 uses a single self-hosted Rekor instance. What is the SLA if it goes down?
    Should the retry queue have a maximum age after which entries are marked `FAILED` and an alert
    sent? **(New — resolve before Phase 5.)**

14. **Rekor public key rotation:** Rekor's own signing key may rotate. Should the HSM fetch and
    re-pin the Rekor public key automatically, or require manual admin action? **(New.)**

15. **`require_entry` policy:** If `require_entry = true`, `C_Sign` blocks until Rekor confirms.
    What timeout is acceptable? What is the fallback if Rekor is slow? **(New.)**

---

## Caveats & Risk Register

| #  | Risk                                              | Likelihood | Impact   | Mitigation                                                                           |
|----|---------------------------------------------------|------------|----------|--------------------------------------------------------------------------------------|
| 1  | MySQL GPL license incompatibility                 | Medium     | High     | Default to SQLite/PG; audit linking before shipping                                  |
| 2  | `mlock` quota limits in containers / CI           | High       | Medium   | Test `mlock` failure path; fall back gracefully                                      |
| 3  | Email delivery blocked by firewall/spam           | High       | Medium   | Require SMTP relay config; test via MailHog in CI only                               |
| 4  | Notification event loss on crash                  | Medium     | Low-Med  | DB is authoritative; notifications are best-effort                                   |
| 5  | Ring buffer overflow under high signing load      | Low        | Low      | Observable counter; CRITICAL events also written to audit log                        |
| 6  | gRPC push adapter keeps connections open forever  | Medium     | Medium   | Add keepalive + connection timeout; reconnect logic                                  |
| 7  | 3-person team: bus factor = 1 on crypto module    | High       | Critical | Enforce ≥2-engineer review on all `crypto/` changes                                 |
| 8  | SQLite WAL mode + multi-thread contention         | Low        | Medium   | Connection pool min=2, WAL enabled, TSan tested                                      |
| 9  | PKCS#11 conformance gaps blocking integration     | Medium     | High     | Run OASIS suite from day 1 of Phase 7                                                |
| 10 | Subscriber registry grows unbounded               | Low        | Low      | `max_subscribers` config + `enabled` soft-disable flag                               |
| 11 | Rekor server unavailable (network, crash)         | Medium     | Low      | Async by default; PENDING rows retried on restart; no signing data lost ← NEW       |
| 12 | Rekor Trillian DB corruption                      | Low        | High     | Back up Trillian MySQL regularly; Rekor is append-only so corruption is detectable  |
| 13 | Rekor response spoofing (MITM)                    | Low        | High     | Pin Rekor server TLS cert + Ed25519 public key; verify SET locally ← NEW            |
| 14 | PENDING rows accumulate if Rekor down for days    | Low        | Medium   | Add max-age config; alert on PENDING count > threshold via `REKOR_COMMIT_FAILED` ← NEW |
| 15 | Rekor adds latency to `VerifySignature` RPC       | Medium     | Low      | Cache fetched entries in memory (TTL 5min); proof can be verified offline ← NEW     |

---

*End of PLAN.md — v3.0*