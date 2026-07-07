# Signature System: Virtual HSM + Blockchain Integration

## 1. Overview

Build a service that securely generates and stores private keys in an isolated "virtual HSM" (vHSM), signs blockchain transactions/messages on request, and broadcasts them across multiple chains — without ever exposing raw private key material to the application layer.

**Goals**
- Isolate key material in a TEE/enclave or KMS-backed vault
- Support multi-chain signing (EVM, Solana, Bitcoin, etc.)
- Policy-based authorization and audit trail
- Path to threshold/MPC signing for high-value operations

---

## 2. Architecture

```
Client / App
   |
   v
[ API Gateway / Auth ] ---- Policy Engine (approvals, rate limits)
   |
   v
[ Transaction Builder ] -- builds unsigned tx, computes signing payload
   |
   v
[ vHSM Signing Service ] -- isolated enclave / KMS, holds keys
   |
   v
[ Tx Assembler ] -- attaches signature, serializes per chain
   |
   v
[ Chain Adapters / RPC ] -- broadcast to EVM / Solana / Bitcoin / etc.
   |
   v
[ Audit Log + Monitoring ]
```

---

## 3. Components

### 3.1 Virtual HSM Service
- Runtime: AWS Nitro Enclaves, Intel SGX, or software vault (HashiCorp Vault Transit, AWS/GCP KMS)
- Responsibilities:
  - Key generation (ECDSA secp256k1, Ed25519)
  - Encrypted key storage (envelope encryption, master key in KMS)
  - Sign-only API: input = hash/payload, output = signature
  - No raw key export
- Attestation: verify enclave identity before releasing key material

### 3.2 Key Management
- HD wallet derivation (BIP32/BIP44) for per-user/per-chain addresses
- Key rotation policy + procedure
- Backup/recovery via Shamir's Secret Sharing for master key
- Key lifecycle states: active, rotating, revoked

### 3.3 Policy Engine
- Per-key authorization rules (who/what can request signatures)
- Rate limiting and value thresholds
- Multi-approver workflow for high-value transactions
- Optional: migrate to MPC/TSS for distributed signing (no single key holder)

### 3.4 Transaction Builder / Adapters
- Per-chain modules:
  - EVM: RLP encoding, nonce/gas management, chain ID
  - Solana: Borsh serialization, recent blockhash
  - Bitcoin: PSBT construction, UTXO selection
- Builder produces the exact hash/payload the vHSM must sign
- Assembler reattaches signature and serializes final tx

### 3.5 Broadcast Layer
- RPC clients (Alchemy/Infura, self-hosted nodes)
- Retry/backoff, confirmation tracking
- Replay protection (nonce tracking, chain ID checks)

### 3.6 Audit & Monitoring
- Immutable log of every sign request (requester, payload hash, approver, timestamp)
- Anomaly detection (unusual amounts, destinations, frequency)
- Alerting on policy violations or enclave attestation failures

---

## 4. Tech Stack Options

| Layer | DIY Open Source | Managed |
|---|---|---|
| Key isolation | AWS Nitro Enclaves / SGX | Fireblocks, Turnkey, Dfns |
| Threshold sigs | tss-lib, multi-party-ecdsa | Fireblocks MPC |
| EVM tx | ethers.js / viem | — |
| Solana tx | @solana/web3.js | — |
| Compliance | AWS CloudHSM (FIPS 140-2/3) | Cloud HSM providers |

---

## 5. Build Phases

### Phase 1 — Core vHSM
- [ ] Stand up enclave/KMS environment
- [ ] Implement key generation + encrypted storage
- [ ] Implement sign-only API with attestation check
- [ ] Basic audit logging

### Phase 2 — Single-Chain Signing (EVM)
- [ ] Transaction builder for EVM (RLP, nonce, gas)
- [ ] Integrate vHSM signing into tx flow
- [ ] Broadcast via RPC provider
- [ ] End-to-end test on testnet

### Phase 3 — Multi-Chain Support
- [ ] Add Solana adapter (Ed25519 signing, Borsh)
- [ ] Add Bitcoin adapter (PSBT)
- [ ] Generalize chain adapter interface

### Phase 4 — Policy & Approval
- [ ] Policy engine: rules, thresholds, rate limits
- [ ] Multi-approver workflow
- [ ] Notifications/alerts

### Phase 5 — Threshold Signatures (MPC)
- [ ] Integrate TSS library
- [ ] Distribute key shares across nodes/parties
- [ ] Migrate high-value flows to threshold signing

### Phase 6 — Hardening & Compliance
- [ ] Key rotation procedures
- [ ] Disaster recovery (Shamir backup)
- [ ] Penetration testing
- [ ] Optional: move to real HSM (CloudHSM) for FIPS compliance

---

## 6. Security Checklist
- [ ] Private keys never leave vHSM/enclave boundary
- [ ] Network isolation for vHSM (no direct internet access)
- [ ] Enclave attestation verified on every startup
- [ ] All signing requests logged immutably
- [ ] Replay protection (nonce + chain ID validation)
- [ ] Rotation and revocation tested
- [ ] Multi-party approval for high-value transfers

---

## 7. Open Questions
- Which chains are in scope for v1?
- TEE-based vHSM vs managed provider (Fireblocks/Turnkey) — build vs buy?
- Compliance requirements (FIPS 140-2/3, SOC 2)?
- Expected transaction volume / latency requirements?

---

## 8. Variant: Permissioned Use Case (Jury / Thesis Defense on Hyperledger Fabric)

A separate but related deployment of the same vHSM concept: a permissioned, multi-organization setting (e.g. university departments as orgs A, B, C) where signed records (e.g. thesis metadata, jury payouts) must remain verifiable for years, and tampering by any single compromised node must be detectable by the others.

### 8.1 Architecture

```
┌─────────────────────┐
│ Jury Application    │
│ (Web/Desktop UI)    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Go Backend API      │
│ (Gin/Fiber)         │
└──────────┬──────────┘
           │
           ├─────────────────┐
           │                 │
           ▼                 ▼
┌─────────────────┐   ┌─────────────────┐
│ SoftHSM         │   │ Document Store  │
│ PKCS#11         │   │ Thesis PDFs     │
└────────┬────────┘   └────────┬────────┘
         │                     │
         ▼                     ▼
    Digital Signature      SHA256 Hash
         │                     │
         └──────────┬──────────┘
                    ▼
          ┌───────────────────┐
          │ Fabric Gateway    │
          │ Go SDK            │
          └─────────┬─────────┘
                    ▼
          ┌───────────────────┐
          │ Hyperledger Fabric│
          │ Chaincode         │
          └─────────┬─────────┘
                    ▼
          ┌───────────────────┐
          │ Distributed Ledger│
          │ (Org A, B, C peers)│
          └───────────────────┘
```

- vHSM role: SoftHSM via PKCS#11 holds each org's signing key. The Go backend signs the document hash (not the raw PDF) at submission time.
- Each organization (A, B, C) runs its own Fabric peer with its own copy of the ledger. Commit requires the endorsement policy to be satisfied (multiple orgs agree at write time).
- Document store (filesystem/S3/MinIO/IPFS) holds the actual PDFs; only the hash + signature + metadata go on-chain.

### 8.2 Threat Model

The scenario this defends against: years after a thesis defense, one node (e.g. department A) is compromised and the attacker directly modifies A's local copy of the ledger/state DB — bypassing Fabric's consensus protocol entirely (i.e. not submitting a new transaction, but editing stored data at rest). For example, A tries to make it look like a payout amount was different from what B and C recorded.

This is **not** a live "invalid signature on submission" check — it's a passive integrity violation that must be discovered later, either on a schedule or when someone happens to query the affected record.

### 8.3 Detection Design

Two independent checks, used together for defense in depth:

**Self-check (per node, no cross-peer comparison needed)**
- Every signed record's signature was computed over the *original* payload at commit time.
- If an attacker alters A's stored data, the existing signature no longer validates against the new data — and the attacker cannot forge a new valid signature without the original signer's private key (which lives in the vHSM/SoftHSM, never on the ledger node itself).
- This means A's own peer (or anyone querying A) can detect tampering by simply re-verifying: does the stored signature validate against the currently stored payload? This alone catches most realistic tampering, independent of B or C.

**Cross-check (compare across organizations)**
- Independently query the same transaction ID / key from peer A, peer B, and peer C.
- Compare returned values (and ideally block hashes, not just application-level fields).
- Since B and C's peers were never touched, any mismatch for the same transaction ID indicates tampering on whichever peer disagrees with the majority.
- This is belt-and-suspenders in case an attacker also controls key material (e.g. insider with vHSM access) and can produce a plausible-looking signature — cross-peer disagreement still flags it.

### 8.4 Reconciliation / Audit Job

This replaces a "live event listener" approach — the violation is found by an audit process, not emitted at write time.

```
                  ┌─────────────────────────────┐
                  │   Reconciliation/Audit Job   │
                  │ (scheduled or manually run)  │
                  └──────────────┬───────────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            ▼                     ▼                     ▼
     Peer A Gateway        Peer B Gateway         Peer C Gateway
            │                     │                     │
            ▼                     ▼                     ▼
   1. Verify signature   1. Verify signature   1. Verify signature
      against own data      against own data      against own data
            │                     │                     │
            └─────────────────────┼─────────────────────┘
                                  ▼
                  2. Compare values across A/B/C
                                  │
                         mismatch or invalid sig?
                                  │
                                  ▼
                  Emit IntegrityViolationDetected
                                  │
                                  ▼
                  Notify B, C, and the authority
```

**Job behavior**
- Runs on a schedule (e.g. nightly or weekly) rather than waiting for someone to notice — appropriate given violations may surface years after the original event.
- For each record (or a sampled/batched subset for large ledgers): run the self-check against each peer's copy, then the cross-check across all peers.
- On failure of either check, emit an `IntegrityViolationDetected` event with: transaction ID, which organization's peer disagreed or failed self-check, old vs. current value, and the signature verification result, so the authority has enough to act on.

**Design decisions to confirm**
- Who runs the audit job: if hosted only by one org, that org could in theory suppress results — running it independently from B and C (or from a neutral 4th observer) avoids a single point of suppression.
- Scope: full ledger reconciliation vs. targeted re-check (e.g. triggered when a jury member manually looks up their own record and notices a discrepancy) — likely want both: scheduled sweep plus on-demand lookup.
- Notification channel for the authority (email/in-app/both) and what evidence package gets attached.

### 8.5 Build Phases (Jury/Fabric Variant)

- [ ] Stand up Fabric network with orgs A, B, C, each with own peer + MSP identity
- [ ] SoftHSM + PKCS#11 integration in Go backend (key gen, sign-only calls)
- [ ] Chaincode: record submission (hash + signature + metadata), endorsement policy requiring multi-org agreement
- [ ] Document store integration (PDF storage, hash computed at upload)
- [ ] Self-check verification function (signature vs. currently stored payload)
- [ ] Cross-peer reconciliation job (query A/B/C, compare values + block hashes)
- [ ] `IntegrityViolationDetected` notification pipeline (email/in-app to B, C, authority)
- [ ] Scheduling (cron/worker) for periodic reconciliation
- [ ] On-demand lookup/verification path for jury members
- [ ] Audit log of reconciliation runs (even when no violation found)