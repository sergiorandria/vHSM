#ifndef VHSM_DOMAIN_SIGNING_SIGNATURE_RECORD_H
#define VHSM_DOMAIN_SIGNING_SIGNATURE_RECORD_H

#include "../core/kernel_types.h"
#include <cstdint>
#include <optional>
#include <string>

// SignatureRecord — aggregate root for the signing bounded context.
// Ledger fields are modeled as a separate value object would be in a
// fuller DDD split (LedgerAnchor), but kept inline here for minimal churn.
// Future: extract LedgerAnchor {tx_id, block_num, status} as its own VO.

struct SignatureRecord {
  std::string record_id; // UUID v4, primary key
  int64_t created_at;    // epoch milliseconds
  int slot_id;
  std::string token_label;
  std::string key_id;
  std::string key_fingerprint;
  std::string mechanism;        // e.g., "CKM_ECDSA_SHA256"
  std::string digest_algorithm; // e.g., "SHA-256"
  std::string payload_digest;   // hex string
  std::string signature_b64;    // base64url signature
  int payload_size;
  std::string session_handle;
  std::optional<std::string> user_label;
  std::optional<std::string> app_context;
  // Ledger anchor (filled later by LedgerWorker)
  std::optional<std::string> ledger_tx_id;
  std::optional<int64_t> ledger_block_num;
  std::string ledger_status; // PENDING|COMMITTED|FAILED|DISABLED

  // Post-quantum / hybrid companion signature. When a PQC key is paired with
  // the classical signing key, every sign also produces a Dilithium/SPHINCS+
  // signature over the same digest; both are anchored to the ledger so the
  // record remains verifiable against a quantum adversary. Empty when PQC is
  // unavailable or no PQC key is paired.
  std::string pqc_algo;                              // e.g. "DILITHIUM3"
  std::optional<std::string> signature_pqc_b64;      // base64url PQC signature
  std::optional<std::string> key_fingerprint_pqc;    // PQC public key (base64)

  // Domain invariants helpers (lightweight, no DB).
  bool is_pending() const noexcept { return ledger_status == "PENDING"; }
  void mark_committed(const std::string &tx_id, int64_t block_num) {
    ledger_tx_id = tx_id;
    ledger_block_num = block_num;
    ledger_status = "COMMITTED";
  }
  void mark_failed() noexcept { ledger_status = "FAILED"; }
};

#endif // VHSM_DOMAIN_SIGNING_SIGNATURE_RECORD_H
