#ifndef VHSM_LEDGER_LEDGER_WORKER_H
#define VHSM_LEDGER_LEDGER_WORKER_H

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

#include "../domain/core/kernel_types.h"
#include "../domain/crypto/crypto_types.h"
#include "../domain/signing/signature_record.h"
#include "../notification/notification_bus.h"
#include "../threadpool/capability_token.h"
#include "../threadpool/thread_pool.h"
#include "ledger_client.h"
#include "ledger_entry.h"

namespace vhsm::ledger {

// Retry policy for transient submission failures.  Defaults match
// production (1 s, 2 s, 4 s, ... capped at 60 s); tests inject tiny
// values so the exponential backoff completes quickly.
// Static constants are defaults for production; instance fields allow
// per-worker customization (used by tests).
struct RetryPolicy {
  static inline constexpr int MAX_RETRIES =
      5; // retries beyond the first attempt
  static inline constexpr int BASE_DELAY_MS =
      1000; // delay before the first retry
  static inline constexpr int MAX_DELAY_MS = 60000; // cap on each backoff step
  static inline constexpr int DELAY_MULTIPLIER = 2; // exponential growth factor

  int max_retries = MAX_RETRIES;
  int base_delay_ms = BASE_DELAY_MS;
  int max_delay_ms = MAX_DELAY_MS;
  int delay_multiplier = DELAY_MULTIPLIER;
};

// Anchors signature records to the ledger asynchronously.  Instead of spinning
// a dedicated worker thread, submitted records are enqueued as tasks on a
// threadpool so multiple records can be committed concurrently while a stalled
// (backing off) submission never blocks the rest of the queue.
class LedgerWorker {
public:
  // Called after a record is successfully committed to the ledger.  The
  // callback typically persists the returned LedgerEntry (tx id / block
  // number) to the signature database.  May be empty (no-op).
  using CommitCallback =
      std::function<void(const SignatureRecord &, const LedgerEntry &)>;

  // Optional callback invoked when a record enters the in-flight state, so the
  // store can mark the row PROCESSING.  This is part of the exactly-once
  // anchoring guard: a record_id that is already in flight is never anchored
  // twice (duplicate submissions are dropped in submit_record()).
  using ProcessingCallback = std::function<void(const std::string &record_id)>;

  // concurrent_workers: pool size used for anchoring.  0 selects an automatic
  // default derived from hardware concurrency.  `pool` optionally injects a
  // shared threadpool owned by the caller; when null the worker creates and
  // owns its own pool on start().  drain_and_stop() shuts down the attached
  // pool (joining its threads), so a caller sharing one pool must serialize
  // drains at the owner level.
  explicit LedgerWorker(LedgerClient &client,
                        notification::NotificationBus &bus,
                        CommitCallback on_committed = nullptr,
                        RetryPolicy retry = RetryPolicy(),
                        std::size_t concurrent_workers = 0,
                        std::shared_ptr<threadpool::ThreadPool> pool = nullptr);
  ~LedgerWorker();

  // Start accepting and processing submissions.
  void start();
  // Stop accepting submissions, drain pending work and release the pool.
  void drain_and_stop();

  // Submit a record for ledger anchoring (to be called by the signature
  // dispatcher).  Duplicate submissions for an in-flight record_id are dropped.
  void submit_record(const SignatureRecord &record);

  void set_processing_callback(ProcessingCallback cb) {
    processing_callback_ = std::move(cb);
  }

  // Total number of records successfully committed since start() (thread-safe
  // diagnostic counter, reported and reset via notification events).
  long committed_count() const { return committed_count_.load(); }
  long failed_count() const { return failed_count_.load(); }
  long pending_count() const { return pending_count_.load(); }

  struct Stats {
    long committed;
    long failed;
    long pending;
  };
  Stats stats() const {
    return {committed_count_.load(), failed_count_.load(),
            pending_count_.load()};
  }

private:
  // Runs on a pool worker: submits `record` with exponential backoff and
  // publishes the outcome (LEDGER_COMMITTED / LEDGER_COMMIT_FAILED).
  void process_record(const SignatureRecord &record);

  // Publish a LEDGER_COMMITTED notification for a successful submission.
  void publish_committed(const SignatureRecord &record,
                         const LedgerEntry &entry);
  // Publish a LEDGER_COMMIT_FAILED notification after retries are exhausted.
  void publish_failed(const SignatureRecord &record);

  LedgerClient &ledger_client_;
  notification::NotificationBus &notification_bus_;
  CommitCallback on_committed_;
  ProcessingCallback processing_callback_;
  RetryPolicy retry_policy_;
  std::size_t pool_size_;

  // Exactly-once anchoring guard: record_ids currently being anchored.
  std::mutex in_flight_mu_;
  std::unordered_set<std::string> in_flight_;

  std::shared_ptr<threadpool::ThreadPool>
      owned_pool_;                         // set when created by start()
  threadpool::ThreadPool *pool_ = nullptr; // owned_pool_ or injected
  threadpool::CapabilityToken token_;
  std::atomic<bool> running_{false};
  std::atomic<long> committed_count_{0};
  std::atomic<long> failed_count_{0};
  std::atomic<long> pending_count_{0};
};

} // namespace vhsm::ledger

#endif // VHSM_LEDGER_LEDGER_WORKER_H