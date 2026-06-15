# Virtual HSM — Implementation Plan
## (with Database-Backed Signature Store, Notification System & Hyperledger Fabric Anchoring)

> **Team size:** 3 engineers
> **Version:** 4.0 (Rekor + HMAC integrity chain replaced by Hyperledger Fabric anchoring)
> **Status:** Draft — open questions require resolution before Phase 1 starts

---

## Table of Contents

1. [Overview](#overview)
2. [Goals](#goals)
3. [Non-Goals](#non-goals)
4. [Architecture](#architecture)
5. [Ledger Integration (Hyperledger Fabric)](#ledger-integration-hyperledger-fabric) ← *new*
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

This plan extends the baseline virtual HSM with two integrated capabilities:

1. **Database Signature Store** — every signing operation produces a persisted, queryable
   `SignatureRecord` row, enabling audit trails, non-repudiation proofs, signature replay/verification
   workflows, and compliance reporting — all without any signature leaving the HSM trust boundary in
   an unauthenticated form.

2. **Notification System** — every database write (signature creation, key rotation, verification
   event, ledger commitment, integrity alert) triggers a fan-out notification to all subscribed
   parties. This is the mechanism by which the three team members (and any configured external
   system) are alerted to state changes in the HSM.

3. **Hyperledger Fabric Anchoring** ← *new* — every signing operation is additionally recorded as a
   transaction on a permissioned Hyperledger Fabric network. Each record requires **endorsement from
   multiple organizations** (per the configured endorsement policy) before it is ordered and
   committed to the ledger. This is the mechanism that satisfies the core requirement: **no single
   party — including a vHSM administrator with full DB access — can alter or fabricate a signature
   record without the consent (endorsement) of the other parties.**

> **Why Fabric instead of Rekor + HMAC?** The previous design (v3.0) combined a local HMAC chain
> (self-referential — the key and the data it protects share the same trust boundary) with Rekor (an
> external transparency log, but a *single* instance/operator, and oriented toward public
> verifiability rather than multi-party consent). The actual requirement — **"no one can alter the
> database without the consent of the others"** — is a multi-party consensus problem, which Fabric's
> endorsement policy solves directly and natively. A single technology now provides the integrity
> guarantee that previously required two (Rekor + HMAC), with no local secret-key management at all.

---

## Goals

- Emulate core HSM functionality: key generation, storage, signing, encryption, and access control
- Expose a **PKCS#11 v2.40** compatible C API (the industry-standard HSM interface)
- **Persist every signing operation to a relational database** (SQLite embedded / PostgreSQL / MySQL)
- **Allow callers to query, verify, and audit signatures via a Signature Store API**
- **Notify all subscribed parties on every database mutation** (signature created, key rotated,
  integrity alert, verification failure, ledger commitment)
- **Record every signing event as a Hyperledger Fabric transaction, endorsed by multiple
  organizations** ← *new*
- **Store the Fabric transaction ID and committing block number alongside each DB row** ← *new*
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
- Running a Rekor / Sigstore transparency log (superseded by Fabric anchoring — see Overview)
- Threshold/multi-party signing of the underlying cryptographic key itself (out of scope — see
  [Open Questions](#open-questions) #3 for the distinction between "consent to record" and "consent
  to sign")
- Running more than a small (3–5 peer) Fabric test network in v1; production-scale consortium
  onboarding is v2 scope

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
│   (d) Notification Bus     (e) Fabric Ledger Client ← NEW   │
└──────┬──────────────────────┬────────────────┬──────────────┘
       │                      │                │
┌──────▼──────────────────┐  │  ┌─────────────▼──────────────┐
│   DB Signature Store    │  │  │   Fabric Ledger Client ← NEW│
│  SQLite / PG / MySQL    │  │  │  submits RecordSignature    │
│  SignatureRecord rows   │  │  │  transaction via Fabric SDK │
│  + ledger_tx_id col     │  │  │  + ledger_tx_id col          │
│  + ledger_block_num col │  │  └─────────────┬──────────────┘
└─────────────────────────┘  │                │  gRPC (Fabric Gateway)
       │                     │  ┌─────────────▼──────────────┐
┌──────▼──────────────────┐  │  │   Hyperledger Fabric Net   │
│  Signature Query API    │  │  │  Orderer + multiple Peers  │
│  lookup/verify/audit    │  │  │  Chaincode: signature_ledger│
│  + Fabric tx verify     │  │  │  Endorsement policy: N-of-M│
│  (gRPC / REST)          │  │  └────────────────────────────┘
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

## Ledger Integration (Hyperledger Fabric)

### What Fabric Provides

Hyperledger Fabric is a **permissioned blockchain framework**. Each organization in the consortium
(e.g. Jury, Université, an independent third party) runs its own **peer node**. A transaction is only
committed to the shared ledger if it satisfies the chaincode's **endorsement policy** — for example,
"endorsed by Peer-Jury AND Peer-Université". Once committed:

- The transaction is part of a block, which is cryptographically chained to the previous block
  (hash-linked), and replicated identically across every peer.
- Altering a past transaction on any single peer's copy of the ledger invalidates that peer's block
  hash chain, which immediately diverges from every other peer's chain — detectable by any
  organization at any time.
- No single organization — including whoever operates the vHSM — can unilaterally rewrite history.

This directly satisfies the core requirement: **database alteration requires the consent (re-
endorsement and re-ordering) of the other parties, which is operationally equivalent to "impossible"
for past records.**

### Chaincode: `signature_ledger`

A single chaincode (smart contract) deployed to the channel, exposing:

```go
// RecordSignature anchors a signing event. Requires endorsement per channel policy.
func (s *SignatureContract) RecordSignature(
    ctx contractapi.TransactionContextInterface,
    recordID string,
    keyFingerprint string,
    payloadDigest string,
    signatureB64 string,
    createdAt int64,
) error

// GetRecord retrieves a previously anchored record by ID for verification.
func (s *SignatureContract) GetRecord(
    ctx contractapi.TransactionContextInterface,
    recordID string,
) (*SignatureLedgerEntry, error)
```

The ledger entry stores exactly the fields needed to cross-check the local DB row:
`record_id`, `key_fingerprint`, `payload_digest`, `signature_b64`, `created_at`. This mirrors the
`hashedrekord` minimal-payload philosophy from the previous design, but committed via multi-party
consensus instead of a single transparency-log operator.

### Endorsement Policy

Configured at the channel/chaincode level, e.g.:

```
AND('JuryMSP.peer', 'UniversiteMSP.peer')
```

or, for a larger consortium:

```
OutOf(2, 'JuryMSP.peer', 'UniversiteMSP.peer', 'MinistereMSP.peer')
```

The vHSM submits a proposal; each required peer simulates the transaction and signs the result; the
client (vHSM's Fabric SDK) collects signatures and submits to the orderer for inclusion in a block.
**No record is considered final until `ledger_status = 'COMMITTED'`.**

### The `ledger/` Module — New C++ Module

**Files:**

- `ledger_client.h` / `ledger_client.cpp` — wraps the Fabric Gateway SDK (gRPC); submits
  `RecordSignature` transactions and queries `GetRecord`
- `ledger_entry.h` — `LedgerEntry` struct (mirrors chaincode return type)
- `ledger_worker.h` / `ledger_worker.cpp` — background thread draining the async submission queue;
  exponential backoff; emits `LEDGER_COMMIT_FAILED` after repeated failures

**`LedgerEntry` struct:**

```cpp
struct LedgerEntry {
    std::string record_id;
    std::string key_fingerprint;
    std::string payload_digest;
    std::string signature_b64;
    int64_t      created_at;
    std::string  tx_id;        // Fabric transaction ID
    int64_t      block_number;  // block height at commitment
};
```

**`LedgerClient` interface:**

```cpp
class LedgerClient {
public:
    // Submits RecordSignature; blocks until endorsed + committed, or times out.
    std::optional<LedgerEntry> submit_record(const SignatureRecord& record);

    // Queries GetRecord by record_id for verification.
    std::optional<LedgerEntry> get_record(const std::string& record_id);
};
```

### Updated `C_Sign` Flow with Fabric

```
C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
  │
  ├─ 1. Validate session, op context, key handle
  ├─ 2. CryptoEngine::sign(key, mechanism, pData)  →  SignResult
  ├─ 3. Copy raw signature bytes into pSignature
  ├─ 4. SignatureDispatcher::dispatch(session, SignResult, context)
  │       ├─ Build SignatureRecord (UUID, timestamps, fingerprint, b64)
  │       ├─ SignatureRepository::insert(record)         ← DB write (sync, ledger_status='PENDING')
  │       ├─ AuditLog::append(record.id, "C_SIGN")
  │       ├─ NotificationBus::publish(SIGN_CREATED, ...) ← non-blocking enqueue
  │       └─ LedgerClient::submit_record_async(record)   ← NEW: async Fabric submission
  │               │  (background thread)
  │               ├─ Propose RecordSignature → endorsing peers simulate + sign
  │               ├─ Submit to orderer → block committed
  │               └─ SignatureRepository::update_ledger_fields(
  │                      record.id, tx_id, block_number, status='COMMITTED')
  └─ 5. Return CKR_OK  (Fabric submission happens in background)
```

**Key design decision:** Fabric submission is **always async** in v1 — identical rationale to v3.0's
async Rekor posting. The `C_Sign` critical path is not blocked by endorsement/ordering latency. If the
Fabric network is unreachable, the local DB row exists (no data loss) and the background worker
retries with exponential backoff. A `require_ledger_commit = true` config option (parallel to v3.0's
`require_entry`) changes this at the cost of latency.

### How Fabric Solves the Self-Reference Problem

| Old scheme (v2.0 — local HMAC) | v3.0 (HMAC + Rekor)             | v4.0 (Fabric only)                              |
|---------------------------------|----------------------------------|---------------------------------------------------|
| Integrity = HMAC(row, key derived in memory) | + Rekor inclusion proof (single external operator) | Integrity = Fabric multi-org endorsement + hash-chained blocks |
| Verifying requires trusting HSM process | Verifying proof requires only Rekor public key | Verifying requires querying any peer's ledger copy — no shared secret anywhere |
| Admin can re-derive HMAC key, alter row | Altering row invalidates Merkle path in one log | Altering row requires re-endorsement by **other organizations**, satisfying the "consent" requirement directly |
| No local secret to manage | Local HMAC key *and* Rekor server keypair to manage | **No local cryptographic secret for integrity at all** |

### Verifying a Signature End-to-End (New `VerifySignature` RPC flow)

```
VerifySignature(signature_id)
  │
  ├─ 1. Load SignatureRecord from DB
  ├─ 2. LedgerClient::get_record(record.id)
  ├─ 3. Cross-check: ledger_entry.payload_digest   == record.payload_digest
  │                  ledger_entry.signature_b64    == record.signature_b64
  │                  ledger_entry.key_fingerprint  == record.key_fingerprint
  └─ 4. Return VerifyResponse { ledger_found: OK, cross_check: OK, tx_id, block_number }
```

A verifier with read access to **any single peer** in the consortium can independently confirm that a
signature event occurred and has not been altered — without trusting the vHSM process, its DB, or any
locally-held secret.

### Local DB Row vs. Ledger — Roles

- **Local DB (`signature_records`)**: fast-read cache for queries, dashboards, and retrieval of
  `signature_b64` (so callers don't need a Fabric round-trip for normal use). **Not the source of
  truth for integrity.**
- **Fabric ledger**: source of truth for "this record exists, in this form, with the consent of the
  required organizations, and has not been altered since." All integrity claims resolve to the
  ledger.

---

## Notification System

> This section is unchanged from v2.0 except that `REKOR_COMMIT_FAILED` / `REKOR_PROOF_INVALID` are
> replaced by `LEDGER_COMMIT_FAILED` / `LEDGER_VERIFY_FAILED`.

### Event Types

| Event                   | Trigger                                                        | Severity |
|-------------------------|------------------------------------------------------------------|----------|
| `SIGN_CREATED`          | New `SignatureRecord` inserted into DB                         | INFO     |
| `VERIFY_COMPLETED`      | Verification attempt logged in `signature_verifications`       | INFO     |
| `VERIFY_FAILED`         | Verification outcome is `INVALID` or `ERROR`                  | WARN     |
| `KEY_ROTATED`           | Signing key replaced via admin RPC                             | WARN     |
| `KEY_DESTROYED`         | `C_DestroyObject` called on a key object                       | WARN     |
| `DB_WRITE_FAILED`       | Signature Dispatcher could not persist a record                | CRITICAL |
| `LEDGER_COMMIT_FAILED`  | Fabric background worker exhausted retries ← NEW               | WARN     |
| `LEDGER_VERIFY_FAILED`  | Cross-check between DB row and ledger entry failed ← NEW       | CRITICAL |
| `ADMIN_LOGIN`           | SO or USER authenticated via gRPC admin                        | INFO     |
| `PIN_LOCKOUT`           | Failed-attempt counter exceeded threshold                      | WARN     |

> **Note:** `INTEGRITY_ALERT` (v2.0/v3.0, triggered by HMAC mismatch via `CheckDbIntegrity`) is removed
> — there is no local HMAC to check. `LEDGER_VERIFY_FAILED` is its conceptual replacement, but it can
> only be raised when a ledger lookup is performed (e.g. during `VerifySignature` or a periodic audit
> sweep), not on every local read.

### Notification Payload (JSON)

```json
{
  "event_id":    "uuid-v4",
  "event_type":  "SIGN_CREATED",
  "severity":    "INFO",
  "timestamp":   "2026-06-14T12:34:56.789Z",
  "source":      "slot:0/token:MyToken",
  "actor":       "user_label or SO_PIN session",
  "summary":     "Signature 3f2a… created for key 7b1c… (ECDSA-SHA256)",
  "detail":      {
    "signature_id":    "…",
    "key_fingerprint": "…",
    "payload_digest":  "…",
    "ledger_tx_id":    "…",
    "ledger_block_number": 128
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
    enabled      INTEGER NOT NULL DEFAULT 1
);
```

> **Integrity note:** the `integrity_hmac` column present in v2.0/v3.0 is dropped here too (see
> [Open Questions](#open-questions) #6). This table is operational configuration, not a signing
> record, and is not anchored to Fabric in v1.

### Delivery Guarantees

- **At-least-once delivery** is the target for WARN/CRITICAL events (3 retries, exponential backoff).
- **Best-effort (fire-and-forget)** is acceptable for INFO events.
- Delivery is **asynchronous** — never blocks `C_Sign`.
- Bounded in-memory queue (capacity 1024).

### Caveat — Notification vs. Atomicity

The notification and the DB write are **not atomic**. The DB + Fabric ledger are the joint source of
truth; notifications are a courtesy.

---

## Database Schema

### Table: `signature_records` (updated)

```sql
CREATE TABLE signature_records (
    id                TEXT    PRIMARY KEY,
    created_at        INTEGER NOT NULL,
    slot_id           INTEGER NOT NULL,
    token_label       TEXT    NOT NULL,
    key_id            TEXT    NOT NULL,
    key_fingerprint   TEXT    NOT NULL,
    mechanism         TEXT    NOT NULL,
    payload_digest    TEXT    NOT NULL,
    signature_b64     TEXT    NOT NULL,   -- keep: needed for retrieval without a ledger round-trip
    session_handle    TEXT    NOT NULL,
    user_label        TEXT,
    app_context       TEXT,
    ledger_tx_id      TEXT,               -- nullable: filled in later by Phase 5 (async)
    ledger_block_num  INTEGER,            -- block height at commitment
    ledger_status     TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(ledger_status IN ('PENDING','COMMITTED','FAILED','DISABLED'))
    -- NO integrity_hmac (HMAC chain dropped — superseded by Fabric multi-party endorsement)
);

CREATE INDEX idx_sig_key_id        ON signature_records(key_id);
CREATE INDEX idx_sig_created_at    ON signature_records(created_at);
CREATE INDEX idx_sig_token_label   ON signature_records(token_label);
CREATE INDEX idx_sig_payload       ON signature_records(payload_digest);
CREATE INDEX idx_sig_ledger_tx     ON signature_records(ledger_tx_id);    -- NEW
CREATE INDEX idx_sig_ledger_status ON signature_records(ledger_status);   -- NEW
```

> **No row-level integrity recomputation.** When the ledger worker fills in `ledger_tx_id` /
> `ledger_block_num` and sets `ledger_status = 'COMMITTED'`, no local digest or HMAC needs to be
> recomputed. The row's integrity claim is verified by querying the Fabric ledger directly (see
> [Verifying a Signature End-to-End](#verifying-a-signature-end-to-end-new-verifysignature-rpc-flow)).

> **Coverage caveat:** the Fabric chaincode payload anchors `record_id`, `key_fingerprint`,
> `payload_digest`, `signature_b64`, and `created_at` (see [Open Questions](#open-questions) #5 for
> whether to extend this). Columns outside that set (`user_label`, `app_context`, `session_handle`,
> `slot_id`, `token_label`) are **not individually tamper-evident** in v1 — see
> [Caveats & Risk Register](#caveats--risk-register) #11.

### Table: `signature_verifications` (unchanged in structure, minus HMAC)

```sql
CREATE TABLE signature_verifications (
    id               TEXT     PRIMARY KEY,
    verified_at      INTEGER  NOT NULL,
    signature_id     TEXT     REFERENCES signature_records(id),
    verifier_session TEXT     NOT NULL,
    outcome          TEXT     NOT NULL
        CHECK(outcome IN ('VALID','INVALID','KEY_NOT_FOUND','ERROR')),
    ledger_outcome   TEXT                    -- NEW: 'MATCH'|'MISMATCH'|'NOT_FOUND'|'NOT_CHECKED'
        CHECK(ledger_outcome IN ('MATCH','MISMATCH','NOT_FOUND','NOT_CHECKED')),
    error_detail     TEXT
    -- NO integrity_hmac
);
```

### Tables: `notification_subscribers`, `notification_log`, `db_meta`

`notification_subscribers` updated above (no `integrity_hmac`). `notification_log` and `db_meta`
unchanged from v2.0.

---

## Module Breakdown

### 1. `core/` — Core Types & Constants

**Changes from v3.0:** `RekorEntry` / `InclusionProof` removed. `LedgerEntry` POD struct added to
`core/types.h`. `LedgerStatus` enum added (`PENDING`, `COMMITTED`, `FAILED`, `DISABLED`).

---

### 2. `crypto/` — Cryptographic Engine

**Changes from v3.0:** `ed25519_verify.h/.cpp` removed (was only needed for Rekor SET verification).
`hmac.h/.cpp` retained only if still needed elsewhere (webhook auth signatures — see
[Open Questions](#open-questions) #7); otherwise removed. No other changes.

---

### 3. `keystore/` — Key Storage & Object Model

**Changes from v3.0:**

- `token.cpp` — after `C_GenerateKeyPair` succeeds, no longer enqueues a Rekor `KEY_CREATED` entry.
  Key lifecycle anchoring to Fabric is deferred — see [Open Questions](#open-questions) #4.
- `object_store.cpp` — `KEY_RETIRED` Rekor hook removed for the same reason.

---

### 4. `session/` — Session & Slot Manager

Unchanged from v2.0/v3.0.

---

### 5. `signature_store/` — Database Signature Store

**Changes from v3.0:**

- `db_hmac_key.h/.cpp` — **removed entirely**.
- `row_integrity.h/.cpp` — **removed entirely**.
- `signature_repository.cpp` — `insert()` now writes `ledger_status = 'PENDING'`; new method
  `update_ledger_fields(id, LedgerEntry)` fills in `ledger_tx_id` / `ledger_block_num` / sets
  `ledger_status = 'COMMITTED'`. No HMAC recomputation.
- `verification_service.cpp` — `VerifySignature` calls `LedgerClient::get_record()` and records
  `ledger_outcome` in `signature_verifications`.
- `rekor_retry_queue.h/.cpp` (v3.0) → renamed `ledger_retry_queue.h/.cpp` — persistent queue of
  pending Fabric submissions. On startup, scans for rows with `ledger_status = 'PENDING'` and
  re-submits them, ensuring submissions survive process restarts.

---

### 6. `ledger/` — Hyperledger Fabric Client Module ← NEW (replaces `rekor/`)

**Purpose:** All interaction with the Fabric network via the Fabric Gateway SDK.

**Files:**

- `ledger_entry.h` — `LedgerEntry` struct
- `ledger_client.h` / `ledger_client.cpp` — wraps Fabric Gateway gRPC client; `submit_record()`,
  `get_record()`
- `ledger_worker.h` / `ledger_worker.cpp` — background thread that drains the async submission queue;
  exponential backoff (1s, 2s, 4s, 8s, max 60s); emits `LEDGER_COMMIT_FAILED` notification after 5
  consecutive failures

**`LedgerWorker` lifecycle:**

```
C_Initialize → LedgerWorker::start()   (background thread)
C_Finalize   → LedgerWorker::drain_and_stop()  (flush queue, then exit)
```

**Connection model:** the vHSM authenticates to the Fabric network as a client identity belonging to
its own organization's MSP (e.g. `VHSMOrgMSP`). It does **not** hold endorsing-peer identities for the
other organizations — those peers run independently, operated by Jury / Université / etc., and
endorse (or refuse to endorse) based on their own policy evaluation. This is the mechanism that
enforces "consent of the others."

---

### 7. `notification/` — Notification System

**Changes from v3.0:** `REKOR_COMMIT_FAILED` / `REKOR_PROOF_INVALID` replaced by
`LEDGER_COMMIT_FAILED` / `LEDGER_VERIFY_FAILED` in `EventType` enum in `notification_event.h`.
`INTEGRITY_ALERT` removed (see [Notification System](#notification-system) note). No structural
changes otherwise.

---

### 8. `pkcs11/` — PKCS#11 Facade

**Changes from v3.0:** `C_Sign` / `C_SignFinal` flow updated — see
[Updated C_Sign Flow with Fabric](#updated-c_sign-flow-with-fabric). The post-keygen / post-destroy
Rekor hooks in `C_GenerateKeyPair` / `C_DestroyObject` are removed pending resolution of
[Open Questions](#open-questions) #4.

---

### 9. `persistence/` — Encrypted File Vault

Unchanged from v2.0/v3.0. **Note:** the vault KEK is no longer used to derive any DB integrity key
(that derivation step is removed — see Module 5).

---

### 10. `admin/` — Management & Signature Query API (gRPC)

**Updated gRPC Service Definition (additions/changes only):**

```protobuf
service HsmAdmin {
  // ... all v2.0 RPCs unchanged ...

  // Ledger management  ← NEW (replaces Rekor RPCs)
  rpc GetLedgerEntry(LedgerEntryRequest)        returns (LedgerEntryResponse);
  rpc VerifyLedgerRecord(VerifyLedgerRequest)   returns (VerifyLedgerResponse);
  rpc ListPendingLedgerCommits(Empty)           returns (PendingLedgerList);
  rpc RetryLedgerCommits(Empty)                 returns (RetryLedgerResponse);
}
```

**`GetLedgerEntry` RPC:** Given a `signature_id`, returns the `LedgerEntry` (fetched live from a Fabric
peer) alongside the locally stored `ledger_tx_id` / `ledger_block_num` — useful for auditors who want
to verify the chain of custody without any HSM trust, and without needing to belong to the consortium
themselves (read access to one peer's ledger is sufficient).

---

### 11. `tests/` — Test Suite

**Additions for ledger module (replaces Rekor test suites):**

- `unit/ledger/ledger_client_test.cpp` — mock Fabric Gateway; test record submission and retrieval
- `unit/ledger/ledger_worker_test.cpp` — queue drain, retry backoff, failure notification
- `integration/ledger/ledger_commit_test.cpp` — requires a local Fabric test network (e.g.
  `test-network` from `fabric-samples`) up; `C_Sign` → transaction committed; `GetRecord` returns
  matching entry
- `integration/ledger/ledger_recovery_test.cpp` — simulate crash mid-submission; restart; verify
  background worker re-submits `PENDING` rows
- `integration/ledger/endorsement_policy_test.cpp` — verify that a transaction lacking required
  endorsements is rejected by the orderer (negative test confirming the "consent" property)

---

## Directory Structure

```
virtual-hsm/
├── CMakeLists.txt
├── PLAN.md
├── README.md
├── docker-compose.test.yml          (MailHog, Postgres, MySQL)
├── network/                          ← NEW (Fabric test network config)
│   ├── docker-compose.fabric.yml     (Orderer + Peers for each org)
│   ├── configtx.yaml                 (channel + endorsement policy)
│   └── chaincode/
│       └── signature_ledger/         (Go chaincode: RecordSignature, GetRecord)
├── include/
│   └── pkcs11/
│       └── pkcs11.h
├── src/
│   ├── core/
│   │   ├── types.h                  # + LedgerEntry, LedgerStatus
│   │   ├── error.h / error.cpp
│   │   ├── utils.h / utils.cpp
│   │   ├── secure_buffer.h
│   │   └── clock.h
│   ├── crypto/
│   │   ├── crypto_engine.h / .cpp
│   │   ├── aes_gcm.h / .cpp
│   │   ├── rsa.h / .cpp
│   │   ├── ecc.h / .cpp
│   │   ├── kdf.h / .cpp
│   │   ├── digest.h / .cpp
│   │   ├── rng.h / .cpp
│   │   └── mechanisms.h
│   │   # hmac.h/.cpp, ed25519_verify.h/.cpp removed (see Open Questions #7)
│   ├── keystore/
│   │   ├── hsm_object.h
│   │   ├── token.h / .cpp
│   │   ├── slot.h / .cpp
│   │   ├── object_store.h / .cpp
│   │   ├── attribute_store.h
│   │   ├── key_wrap.h / .cpp
│   │   └── key_fingerprint.h / .cpp
│   ├── session/
│   │   └── ...                      (unchanged)
│   ├── signature_store/
│   │   ├── db_config.h
│   │   ├── db_connection.h / .cpp
│   │   ├── db_schema.h / .cpp
│   │   ├── signature_repository.h / .cpp   # + update_ledger_fields()
│   │   ├── signature_dispatcher.h / .cpp   # + LedgerClient::submit_record_async()
│   │   ├── signature_query.h / .cpp
│   │   ├── verification_service.h / .cpp   # + LedgerClient::get_record() call
│   │   ├── ledger_retry_queue.h / .cpp     ← renamed from rekor_retry_queue
│   │   └── notification_repository.h / .cpp
│   │   # db_hmac_key.h/.cpp, row_integrity.h/.cpp removed
│   ├── ledger/                              ← NEW MODULE (replaces rekor/)
│   │   ├── ledger_entry.h
│   │   ├── ledger_client.h / .cpp
│   │   └── ledger_worker.h / .cpp
│   ├── notification/
│   │   ├── notification_event.h     # LEDGER_COMMIT_FAILED, LEDGER_VERIFY_FAILED
│   │   ├── notification_bus.h / .cpp
│   │   ├── notification_dispatcher.h / .cpp
│   │   └── adapters/
│   │       ├── email_adapter.h / .cpp
│   │       ├── webhook_adapter.h / .cpp
│   │       └── grpc_push_adapter.h / .cpp
│   ├── pkcs11/
│   │   └── ...                      (Rekor hooks removed from p11_crypto.cpp, p11_keygen.cpp)
│   ├── persistence/
│   │   └── ...                      (unchanged)
│   └── admin/
│       ├── admin_server.h / .cpp    # + Ledger RPCs
│       └── audit_log.h / .cpp
├── tests/
│   ├── unit/
│   │   ├── crypto/
│   │   ├── keystore/
│   │   ├── session/
│   │   ├── signature_store/
│   │   ├── notification/
│   │   └── ledger/                  ← NEW (replaces unit/rekor/)
│   ├── integration/
│   │   ├── pkcs11/
│   │   ├── signature_store/
│   │   ├── verify_flow/
│   │   ├── persistence/
│   │   ├── notification/
│   │   └── ledger/                  ← NEW (replaces integration/rekor/)
│   ├── conformance/
│   └── fuzz/
├── proto/
│   └── admin.proto                  # + Ledger RPCs
├── sql/
│   ├── schema_sqlite.sql            # + ledger_* columns; no integrity_hmac
│   ├── schema_postgres.sql
│   └── schema_mysql.sql
├── tools/
│   └── vhsm-admin/
├── cmake/
│   ├── FindOpenSSL.cmake
│   ├── FindSQLite3.cmake
│   ├── FindPostgreSQL.cmake
│   ├── FindGRPC.cmake               ← NEW (Fabric Gateway uses gRPC)
│   └── CompilerFlags.cmake
└── third_party/
    ├── googletest/
    ├── grpc/
    ├── sqlpp11/
    └── fabric-gateway-cpp/           ← NEW (or generated from Fabric Gateway protos)
```

---

## Build System

**CMake ≥ 3.21** with the following targets:

| Target              | Output             | Description                                         |
|---------------------|--------------------|-----------------------------------------------------|
| `vhsm`              | `libvhsm.so/.dll`  | Main PKCS#11 shared library                         |
| `vhsm_static`       | `libvhsm.a`        | Static library for embedding                        |
| `vhsm_admin_server` | Binary             | gRPC admin + signature query + event stream server  |
| `vhsm_admin_cli`    | Binary             | CLI admin tool                                      |
| `vhsm_tests`        | Binary             | Full test suite                                     |

**CMake options:**

```cmake
option(VHSM_DB_BACKEND       "Database backend: sqlite|postgres|mysql"  "sqlite")
option(VHSM_ASYNC_DB         "Use async write queue for DB"              OFF)
option(VHSM_REQUIRE_DB       "Fail C_Sign if DB write fails"             ON)
option(VHSM_ADMIN_GRPC       "Build gRPC admin server"                   ON)
option(VHSM_NOTIFY_EMAIL     "Build email notification adapter"          ON)
option(VHSM_NOTIFY_WEBHOOK   "Build webhook notification adapter"        ON)
option(VHSM_NOTIFY_BUS_SIZE  "Notification ring buffer capacity"         1024)
option(VHSM_LEDGER_ENABLED   "Enable Hyperledger Fabric anchoring"       ON)   # NEW
option(VHSM_LEDGER_REQUIRE   "Fail C_Sign if Fabric commit fails"        OFF)  # NEW
option(VHSM_LEDGER_GATEWAY   "Fabric Gateway peer endpoint"  "localhost:7053")  # NEW
option(VHSM_LEDGER_CHANNEL   "Fabric channel name"           "signaturechannel") # NEW
option(VHSM_LEDGER_CHAINCODE "Fabric chaincode name"         "signature_ledger") # NEW
```

---

## Dependencies

| Library              | Version    | Purpose                                    | License            |
|----------------------|------------|--------------------------------------------|--------------------|
| OpenSSL              | ≥ 3.0      | All cryptographic primitives               | Apache-2.0         |
| SQLite3              | ≥ 3.42     | Embedded DB backend (default)              | Public Domain      |
| libpqxx              | ≥ 7.8      | PostgreSQL backend (optional)              | BSD-3              |
| mysql-connector-cpp  | ≥ 8.1      | MySQL backend (optional)                   | GPL-2 / Commercial |
| protobuf             | ≥ 3.21     | Token serialization, Fabric Gateway protos | BSD-3              |
| gRPC                 | ≥ 1.50     | Admin + Signature + Event Stream API, Fabric Gateway | Apache-2.0 |
| spdlog               | ≥ 1.11     | Structured logging                         | MIT                |
| nlohmann/json        | ≥ 3.11     | Config, `app_context`                      | MIT                |
| libcurl              | ≥ 7.88     | Email (SMTP), webhook                      | MIT/curl           |
| Google Test          | ≥ 1.13     | Unit & integration tests                   | BSD-3              |
| **Hyperledger Fabric** | **≥ 2.5** | **Permissioned blockchain network (peers, orderer)** | **Apache-2.0** ← NEW |
| **Fabric Gateway SDK** | **≥ 1.4** | **Client SDK (gRPC) for submitting/querying transactions** | **Apache-2.0** ← NEW |

> **No HTTP client needed for the ledger module.** The Fabric Gateway client uses gRPC (already a
> dependency via the admin server). Rekor's libcurl + Ed25519 verification dependencies are removed.
> The Fabric network itself (orderer, peers, chaincode containers) runs via Docker Compose — an
> **operational** dependency, not a compile-time one.

---

## Implementation Phases

### Phase 1 — Crypto Foundation (Week 1–2)

- [x] Set up CMake project skeleton with DB backend options and notification/ledger build flags
- [x] Implement `core/secure_buffer.h` with `mlock` support
- [x] Implement `core/clock.h` (mockable UTC epoch)
- [x] Implement `utils::uuid_v4()`, `base64_encode/decode`, `hex_encode/decode`
- [x] Implement `crypto/rng.cpp`, `crypto/digest.cpp`
- [x] Implement `crypto/aes_gcm.cpp` with NIST test vectors
- [x] Implement `crypto/rsa.cpp` — keygen, sign (PSS + PKCS1v15), verify, OAEP
- [x] Implement `crypto/ecc.cpp` — keygen (P-256/384/521), ECDSA, ECDH
- [x] Implement `crypto/kdf.cpp` (retain if used outside integrity scheme; otherwise drop)
- [x] Define `SignatureRecord`, `NotificationEvent`, `LedgerEntry` in `core/types.h`
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
- [ ] Write and validate SQL schemas with `ledger_*` columns, **no** `integrity_hmac` ← NEW
- [ ] Implement `db_schema.cpp`: bootstrap, seed `db_meta`, migration runner (incl. migration to drop
      `integrity_hmac` from existing v2.0/v3.0 databases) ← NEW
- [ ] Implement `signature_repository.cpp` with `update_ledger_fields()` method ← NEW
- [ ] Implement `ledger_retry_queue.cpp` — scan `PENDING` rows on startup ← NEW
- [ ] Implement `notification_repository.cpp`
- [ ] Implement `signature_dispatcher.cpp`
- [ ] Implement `verification_service.cpp`
- [ ] Unit tests: round-trips, ledger cross-check on tampered local rows

### Phase 5 — Fabric Ledger Client Module (Week 7) ← REPLACES Rekor phase

*Can overlap with Phase 4 if team splits. Requires the local Fabric test network up.*

- [ ] Stand up `network/docker-compose.fabric.yml` — orderer + peers for each org (e.g. Jury,
      Université, vHSM operator)
- [ ] Write `configtx.yaml` defining the channel and endorsement policy (e.g.
      `AND('JuryMSP.peer','UniversiteMSP.peer')`)
- [ ] Implement and deploy `chaincode/signature_ledger` (Go): `RecordSignature`, `GetRecord`
- [ ] Implement `ledger/ledger_entry.h` — `LedgerEntry` struct
- [ ] Implement `ledger/ledger_client.cpp` — `submit_record()`, `get_record()` via Fabric Gateway SDK
- [ ] Implement `ledger/ledger_worker.cpp` — background thread, queue drain, retry backoff
- [ ] Wire `LedgerWorker::start()` into `C_Initialize` hook (even if PKCS#11 not built yet)
- [ ] Integration tests: live transaction submission, retrieval, cross-check
- [ ] Negative test: transaction submitted without sufficient endorsement is rejected
- [ ] Test crash-recovery: kill worker mid-submission, restart, verify `PENDING` rows re-submitted

### Phase 6 — Notification System (Week 8)

- [ ] Implement `notification_event.h` with `LEDGER_COMMIT_FAILED` / `LEDGER_VERIFY_FAILED` types
- [ ] Implement `notification_bus.cpp` — lock-free ring buffer
- [ ] Implement `notification_dispatcher.cpp` — background thread, subscriber resolution, retry
- [ ] Implement `adapters/email_adapter.cpp`, `webhook_adapter.cpp`, `grpc_push_adapter.cpp`
- [ ] Wire `NotificationBus::publish()` into `SignatureDispatcher`, `KeyStore`, `LedgerWorker`
- [ ] Unit tests: bus overflow, retry, adapter mock
- [ ] Integration tests: `C_Sign` → email to MailHog; `LEDGER_COMMIT_FAILED` → webhook
- [ ] Manual test: all 3 team members receive `SIGN_CREATED` + `LEDGER_COMMIT_FAILED` end-to-end

### Phase 7 — PKCS#11 Facade with Full Integration (Week 9)

- [ ] Implement all `C_*` functions
- [ ] Wire `C_Sign` → `SignatureDispatcher` → `LedgerWorker` queue
- [ ] Implement `require_db_write` and `require_ledger_commit` enforcement
- [ ] `C_Initialize` starts ledger worker + notification dispatcher; `C_Finalize` drains both
- [ ] Integration tests: full `C_Sign` → DB → Fabric → notification pipeline
- [ ] Conformance tests (OASIS PKCS#11 suite)

### Phase 8 — Persistence Layer (Week 10)

- [ ] Implement `Vault` with AES-256-GCM and PBKDF2
- [ ] Implement `TokenSerializer` with protobuf
- [ ] Implement atomic write (temp file + rename)
- [ ] Add migration framework (must handle dropping `integrity_hmac` and adding `ledger_*` columns to
      existing DBs)
- [ ] Round-trip integration tests

### Phase 9 — Admin gRPC + Signature Query API (Week 11)

- [ ] Define `admin.proto` with all RPCs including Ledger management RPCs
- [ ] Implement `AdminServer` with mTLS enforcement
- [ ] Implement all signature query, verification, and Ledger RPCs
- [ ] Implement `ListPendingLedgerCommits` and `RetryLedgerCommits` admin RPCs
- [ ] Build `vhsm-admin` CLI tool
- [ ] Run `TestNotify` and `VerifyLedgerRecord` against all 3 subscriptions end-to-end

### Phase 10 — Hardening & Release (Week 12–13)

- [ ] libFuzzer: PKCS#11 input, vault parsing, DB row deserialization, Fabric Gateway responses ← NEW
- [ ] AddressSanitizer + UBSan + TSan CI pass
- [ ] Static analysis (clang-tidy, cppcheck)
- [ ] Fabric network unreachable stress test: confirm async fallback, no data loss, retry convergence
      ← NEW
- [ ] Performance benchmarks: signs/sec with ledger async vs sync; ledger query latency
- [ ] Security review: key material lifecycle, Fabric identity/MSP enrollment, endorsement policy
      correctness ← NEW
- [ ] Documentation and README

---

## Security Considerations

| Threat                                   | Mitigation                                                                                                                                           |
| ------------------------------------------| ------------------------------------------------------------------------------------------------------------------------------------------------------|
| Key material in plaintext memory         | `SecureBuffer` with `mlock`, `memzero` on free                                                                                                       |
| PIN brute force                          | PBKDF2 600k iterations + failed-attempt lockout counter                                                                                              |
| Key extraction via `C_GetAttributeValue` | `CKA_SENSITIVE` prevents private key export                                                                                                          |
| Vault file tampering                     | AES-256-GCM authentication tag covers entire blob                                                                                                    |
| DB row tampering (signature forgery)     | Fabric ledger cross-check on `payload_digest` / `signature_b64` / `key_fingerprint` ← CHANGED                                                        |
| Silent DB row insertion/edit by admin    | Requires a corresponding endorsed Fabric transaction from other organizations — single-party edits are detectable via `VerifyLedgerRecord` ← CHANGED |
| Unrecorded signatures returned to caller | `require_db_write=true` returns `CKR_DEVICE_ERROR` on DB failure                                                                                     |
| Timing side-channels                     | Constant-time `secure_compare()`, OpenSSL `BN_MONT_CTX`                                                                                              |
| Session replay / TOCTOU                  | Session handles are random 64-bit IDs checked on every call                                                                                          |
| Signature ID enumeration                 | UUIDs generated from `RAND_bytes`, not sequential integers                                                                                           |
| Audit log tampering                      | Out of scope for Fabric anchoring in v1 — see [Open Questions](#open-questions) #4 ← CHANGED                                                         |
| DB transport interception (PG/MySQL)     | `tls_mode = verify-full` enforced; cert pinning recommended                                                                                          |
| Admin API abuse                          | mTLS client certificates required for all admin RPCs                                                                                                 |
| Memory disclosure (swap)                 | `mlock()` on all `SecureBuffer` instances                                                                                                            |
| Notification channel eavesdropping       | Email uses STARTTLS; webhook targets must be HTTPS; gRPC uses TLS                                                                                    |
| Notification impersonation               | Outbound email DKIM-signed; webhook uses HMAC signature header (see Open Questions #7)                                                               |
| Subscriber registry tampering            | Not cryptographically anchored in v1 — accepted residual risk, see Risk #12 ← CHANGED                                                                |
| Fabric peer/orderer impersonation        | mTLS to Fabric network using vHSM org's enrolled identity (Fabric CA-issued cert) ← NEW                                                              |
| Fabric network unreachable (DoS)         | Async by default; `require_ledger_commit=false`; `PENDING` rows retried on restart ← NEW                                                             |
| Single-org collusion (forged history)    | Endorsement policy requires N-of-M orgs; a single org (incl. vHSM operator) cannot rewrite committed blocks ← NEW                                    |
| Fields outside ledger payload tampered   | Not individually detectable in v1 — see [Open Questions](#open-questions) #5 and Risk #11 ← NEW                                                      |

---

## Testing Strategy

- **Unit tests:** Every crypto primitive; every `SignatureRecord` and `NotificationEvent` lifecycle;
  offline `LedgerEntry` (de)serialization
- **Tamper tests:** Mutate each DB column; verify `VerifyLedgerRecord` cross-check catches mutations to
  `payload_digest` / `signature_b64` / `key_fingerprint`; document (and test for) the *expected*
  non-detection of mutations to other columns ← CHANGED
- **Requirement tests:** `C_Sign` with `require_db_write=true` when DB offline → `CKR_DEVICE_ERROR`
- **Round-trip tests:** `C_Sign` → DB row → `VerifySignature` RPC → `VALID` + `ledger_outcome=MATCH`
- **Notification tests:** `C_Sign` → `SIGN_CREATED` → email to MailHog
- **Ledger commit tests:** `C_Sign` → Fabric transaction appears in block; `GetRecord` matches DB row
- **Ledger recovery tests:** crash mid-submission; restart; `PENDING` rows re-submitted
- **Endorsement policy tests:** transaction lacking a required org's endorsement is rejected by the
  orderer ← NEW
- **Overflow tests:** Flood notification bus; verify no crash, counter incremented
- **State machine tests:** Session login/logout, invalid-state rejections
- **Conformance tests:** Full PKCS#11 OASIS suite
- **Fuzzing:** libFuzzer on PKCS#11 input, vault, DB rows, Fabric Gateway responses
- **Sanitizers:** ASan, UBSan, TSan in CI on every PR

---

## Team Responsibilities

| Area                                          | Owner | Backup |
|------------------------------------------------|-------|--------|
| `core/`, `crypto/`, `keystore/`                | Eng A | Eng B  |
| `session/`, `pkcs11/` (PKCS#11 facade)          | Eng B | Eng A  |
| `signature_store/`, `persistence/`              | Eng C | Eng B  |
| `notification/` (bus, dispatcher, adapters)     | Eng A | Eng C  |
| `ledger/` (client, worker) ← NEW                | Eng B | Eng C  |
| `admin/` (gRPC server + proto)                  | Eng C | Eng B  |
| `network/` (Fabric configtx, chaincode, ops) ← NEW | Eng B | Eng A  |
| CI / CMake / Docker Compose test infra          | Eng B | Eng A  |
| Security review (final pass)                    | All 3 | —      |

---

## Open Questions

1. **Async vs sync DB writes:** Should `async_db_write` ever be the default?

2. **Payload storage policy:** Should the original payload optionally be stored (encrypted) in the
   DB alongside the digest?

3. **Consent to record vs. consent to sign:** Fabric's endorsement policy provides "no one can alter
   or fabricate a *record of* a signing event without consent." It does **not** provide "no one can
   *cause a signing event* without consent" — that would require threshold/multi-party signing of the
   underlying key (out of scope, see Non-Goals). Confirm this distinction matches the intended
   guarantee for the project's use case (e.g. thesis defense signatures).

4. **Key lifecycle anchoring:** v3.0 anchored `KEY_CREATED` / `KEY_RETIRED` events to Rekor, which
   solved key-archival lookup-by-fingerprint. Should these lifecycle events also be recorded as Fabric
   transactions (e.g. a `RecordKeyEvent` chaincode function), or is anchoring limited to signing events
   in v1? **(Should resolve before Phase 5, since it affects the chaincode interface.)**

5. **Extending the anchored payload:** Should `RecordSignature` anchor additional fields beyond
   `payload_digest` / `signature_b64` / `key_fingerprint` / `created_at` — e.g. a hash of the *entire*
   row (covering `user_label`, `app_context`, `session_handle`, etc.) — to close the "uncovered
   columns" gap noted in [Caveats & Risk Register](#caveats--risk-register) #11? This is the
   lowest-cost way to extend tamper-evidence to all columns without reintroducing a local secret.

6. **`notification_subscribers` integrity:** With `integrity_hmac` removed, this table has no
   integrity protection in v1. Acceptable as DB-access-control-only, or should subscriber
   registrations also be recorded as Fabric transactions (consistent with the "no unilateral change"
   goal, but adds chaincode surface for a low-stakes config table)?

7. **HMAC for webhook authentication:** v2.0/v3.0 used HMAC signature headers for outbound webhook
   authenticity. If `crypto/hmac.cpp` is removed entirely (per Module 2), an alternative (e.g. mTLS for
   webhook endpoints, or retaining a minimal HMAC implementation for this unrelated purpose) must be
   chosen.

8. **DB backend priority:** SQLite for single-process; PG/MySQL for daemon mode. **(Must resolve
   before Phase 4.)**

9. **Multi-process access:** Single-process in-library, or IPC daemon?

10. **Soft delete vs hard delete:** Should `C_DestroyObject` zero-wipe immediately or soft-delete?

11. **FIPS mode:** Restrict to approved algorithms only via a build flag?

12. **PIN policy:** Minimum length, complexity, lockout threshold — configurable or hardcoded?

13. **Notification channel priority:** Is email sufficient for v1, or webhook/gRPC in parallel?

14. **Notification persistence across restarts:** The in-process ring buffer loses events on crash.
    Should WARN/CRITICAL events be checkpointed to DB? **(Note: the ledger retry queue solves this for
    ledger events specifically — `PENDING` rows survive restarts.)**

15. **SMTP relay configuration:** Does the team have an SMTP relay available?

16. **Fabric consortium membership:** Who are the required organizations in the endorsement policy
    (e.g. Jury, Université, an external/independent org)? Each requires its own MSP, CA enrollment, and
    a running peer. **(Must resolve before Phase 5 — drives `configtx.yaml`.)**

17. **Fabric network operations:** Who operates the orderer? A single orderer is itself a
    centralization point (though it cannot forge endorsements, it controls ordering/availability).
    Should v1 use a single orderer (Raft with one node) with multi-org orderer nodes deferred to v2?

18. **`require_ledger_commit` policy:** If `require_ledger_commit = true`, `C_Sign` blocks until Fabric
    confirms. What timeout is acceptable? What is the fallback if endorsement is slow or an endorsing
    peer is offline?

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
| 11 | Local row columns outside the anchored payload (`user_label`, `app_context`, `session_handle`, etc.) can be silently edited without detection ← NEW | Medium | Medium | Resolve Open Question #5 — extend anchored payload to a full-row hash if required |
| 12 | `notification_subscribers` has no integrity protection ← NEW | Low | Low | Accept as DB-access-control-only for v1, or resolve via Open Question #6 |
| 13 | Fabric network unavailable (orderer/peer down)    | Medium     | Low      | Async by default; `PENDING` rows retried on restart; no signing data lost ← NEW     |
| 14 | Required endorsing org's peer permanently offline → records stuck `PENDING` indefinitely ← NEW | Low | Medium | Add max-age config; alert on `PENDING` count > threshold via `LEDGER_COMMIT_FAILED` |
| 15 | Fabric adds latency to `VerifySignature` RPC      | Medium     | Low      | Cache fetched ledger entries in memory (TTL 5min) ← NEW                              |
| 16 | Single orderer node is a centralization/availability point ← NEW | Medium | Medium | v1 accepts single Raft orderer node; multi-org orderer set is v2 (Open Question #17) |
| 17 | Fabric MSP/CA setup complexity is non-trivial for a 3-person team ← NEW | High | Medium | Use `fabric-samples/test-network` as a starting template; allocate explicit setup time in Phase 5 |

---

*End of PLAN.md — v4.0*