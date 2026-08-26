#ifndef VHSM_AUDIT_LOG_H
#define VHSM_AUDIT_LOG_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vhsm::audit {
class AuditLog {
public:
  // WHY virtual dtor: derived P11AuditLog is held via unique_ptr<AuditLog>
  // (g_auditLog); deleting through the base without a virtual dtor is UB.
  virtual ~AuditLog() = default;

  // Log an audit event with the given details.
  // The details can include fields like: event type, timestamp, source, actor,
  // summary, and any relevant metadata.
  virtual void append(const std::string &event_id,
                      const std::string &event_type);
};

/**
 * Tamper-evident append-only audit log (hash chain).
 *
 * Each record is HMAC-chained to its predecessor:
 *
 *   record_bytes = SEQ | ISO8601_TS | EVENT_ID | EVENT_TYPE | PREV_HASH
 *   entry_hmac   = HMAC-SHA256(chain_key, record_bytes)
 *   PREV_HASH'   = entry_hmac
 *
 * Properties:
 *  - Any field modification breaks the HMAC of that record.
 *  - Any record deletion breaks the chain at the successor's PREV_HASH.
 *  - The chain key is injected (derived from the vault KEK by the
 *    composition root) — an attacker with file access alone cannot forge.
 *
 * File format: one record per line,
 *   SEQ|TS|EVENT_ID|EVENT_TYPE|PREV_HEX|HMAC_HEX\n
 * Human-inspectable; machine-verifiable via verify_chain().
 *
 * Caveat: truncation of the tail is not detectable from the file alone
 * (classic hash-chain property). Anchor the latest HMAC externally
 * (e.g., publish it on the ledger) to close that gap — see LedgerWorker.
 */
class HashChainedAuditLog final : public AuditLog {
public:
  /// @param path       Append-only audit file (created if absent)
  /// @param chain_key  32-byte HMAC key; caller-owned lifetime is copied
  HashChainedAuditLog(std::string path, std::vector<uint8_t> chain_key);

  ~HashChainedAuditLog() override;

  void append(const std::string &event_id,
              const std::string &event_type) override;

  /// Recompute every HMAC and link. Returns nullopt when the chain is
  /// intact; otherwise the 1-based line number of the first bad record.
  std::optional<std::size_t> verify_chain() const;

  /// Latest HMAC (hex) — for external anchoring. Empty if no records.
  const std::string &tail_hash() const noexcept { return tail_hex_; }

private:
  void recover_tail();

  std::string path_;
  std::vector<uint8_t> chain_key_;
  uint64_t seq_ = 0;
  std::string tail_hex_; // hex of last entry HMAC ("0"*(64) when empty)
};

} // namespace vhsm::audit

#endif // VHSM_AUDIT_LOG_H
