#include "ledger_worker.h"
#include "../core/hsm_instance.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <thread>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace vhsm::ledger {

namespace {

_VHSMXX_BEGIN_NAMESPACE

#ifndef _VHSMXX_BUILD_MAX_CORE
#define _VHSMXX_BUILD_MAX_CORE 64
#endif // _VHSMXX_BUILD_MAX_CORE

// Small anchoring pool: ledger submission is network-bound (gRPC to the
// Fabric gateway), so more than a handful of concurrent commits rarely pays
// off while a backing-off task must not tie up a single serial worker.
std::size_t default_pool_size() {
#ifdef _WIN32
  // On Windows std::thread::hardware_concurrency() is not reliably implemented
  // across MinGW/MSVC versions, so we query the OS directly.
  auto win_hardware_concurrency = []() -> std::size_t {
    std::size_t concurrency = 0;
    DWORD length = 0;

    // First call with nullptr to get required buffer size; it must fail with
    // ERROR_INSUFFICIENT_BUFFER.
    if (GetLogicalProcessorInformationEx(RelationAll, nullptr, &length) !=
        FALSE) {
      // Unexpected success with nullptr — treat as no info.
      return concurrency;
    }
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      return concurrency;
    }

    // Allocate correctly: malloc takes 1 arg; use std::free as deleter.
    std::unique_ptr<std::uint8_t, void (*)(void *)> buffer(
        static_cast<std::uint8_t *>(std::malloc(length)), std::free);
    if (!buffer) {
      return concurrency;
    }

    if (GetLogicalProcessorInformationEx(
            RelationAll,
            reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                buffer.get()),
            &length) == FALSE) {
      return concurrency;
    }

    for (DWORD i = 0; i < length;) {
      auto *proc = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
          buffer.get() + i);
      if (proc->Relationship == RelationProcessorCore) {
        for (WORD group = 0; group < proc->Processor.GroupCount; ++group) {
          for (KAFFINITY mask = proc->Processor.GroupMask[group].Mask;
               mask != 0; mask >>= 1) {
            concurrency += (mask & 1);
          }
        }
      }
      i += proc->Size;
    }
    return concurrency;
  };

  std::size_t hw = win_hardware_concurrency();

  // Lower bound of the number of
  // CPU cores.
  hw = max(hw, 2);

  // Clamp to avoid oversubscription on many-core Windows hosts; ledger is
  // network-bound, so 4 workers saturate the gateway.
  std::size_t capped = (hw >= 16 ? 4 : hw);

  // Prevent underflow: hw is size_t, so hw-? underflows when hw small.
  // Use bounded max.
  return (std::max<std::size_t>)(2, capped);
#else
  std::size_t hw = std::thread::hardware_concurrency();
  return hw <= 2 ? 2 : (hw >= 4 ? 4 : hw);
#endif
}

// Sleep that ends early once the worker is being torn down, so a retry
// backoff interval never delays drain_and_stop() by more than one short
// quantum. stop_flag is running_ (true=running); we return early when it
// becomes false (draining).
void sleep_interruptible(std::chrono::milliseconds amount,
                         const std::atomic_bool &running_flag) {
  const auto deadline = std::chrono::steady_clock::now() + amount;
  while (std::chrono::steady_clock::now() < deadline) {
    if (!running_flag.load(std::memory_order_acquire))
      return;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

_VHSMXX_END_NAMESPACE
} // namespace

LedgerWorker::LedgerWorker(LedgerClient &client,
                           notification::NotificationBus &bus,
                           CommitCallback on_committed, RetryPolicy retry,
                           std::size_t concurrent_workers,
                           std::shared_ptr<threadpool::ThreadPool> pool)
    : ledger_client_(client), notification_bus_(bus),
      on_committed_(std::move(on_committed)), retry_policy_(retry),
      pool_size_(concurrent_workers != 0 ? concurrent_workers
                                         : default_pool_size()),
      owned_pool_(std::move(pool)) {
  pool_ = owned_pool_.get();
}

LedgerWorker::~LedgerWorker() { drain_and_stop(); }

void LedgerWorker::start() {
  if (running_.exchange(true)) {
    return;
  }
  try {
    if (pool_ == nullptr) {
      owned_pool_ = std::make_shared<threadpool::ThreadPool>(
          threadpool::PoolConfig{pool_size_});
      pool_ = owned_pool_.get();
    }
  } catch (...) {
    running_.store(false);
    throw;
  }
  token_ = threadpool::CapabilityToken::grant(threadpool::PrivilegeTier::High);
}

void LedgerWorker::publish_committed(const SignatureRecord &record,
                                     const LedgerEntry &entry) {
  vhsm::notification::NotificationEvent event;
  event.type =
      vhsm::notification::NotificationEvent::EventType::LEDGER_COMMITTED;
  event.severity = vhsm::notification::NotificationEvent::Severity::INFO;
  event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
  event.source = "LedgerWorker";
  event.actor = "system";
  event.summary = "Record anchored to ledger: " + record.record_id;
  event.detail_json = R"({"record_id":")" + record.record_id +
                      R"(","ledger_tx_id":")" + entry.tx_id +
                      R"(","ledger_block_num":)" +
                      std::to_string(entry.block_number) + R"(})";
  event.hsm_instance = vhsm::core::hsm_instance_id();
  notification_bus_.publish(event);
}

void LedgerWorker::publish_failed(const SignatureRecord &record) {
  vhsm::notification::NotificationEvent event;
  event.type =
      vhsm::notification::NotificationEvent::EventType::LEDGER_COMMIT_FAILED;
  event.severity = vhsm::notification::NotificationEvent::Severity::WARNING;
  event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
  event.source = "LedgerWorker";
  event.actor = "system";
  event.summary = "Failed to anchor record: " + record.record_id;
  event.detail_json = "{}";
  event.hsm_instance = vhsm::core::hsm_instance_id();
  notification_bus_.publish(event);
}

void LedgerWorker::drain_and_stop() {
  if (!running_.exchange(false)) {
    return;
  }
  if (pool_ != nullptr) {
    // Drains remaining tasks (workers run them one-shot because running_
    // is now false) and joins every worker; never detaches.  An injected
    // pool is shut down but remains owned by the caller.
    pool_->shutdown();
    pool_ = nullptr;
  }
  owned_pool_.reset();
}

void LedgerWorker::submit_record(const SignatureRecord &record) {
  if (!running_.load(std::memory_order_acquire) || pool_ == nullptr) {
    return;
  }
  try {
    const bool accepted =
        pool_->enqueue(token_, [this, record] { process_record(record); });
    if (!accepted) {
      // Queue at capacity: the record cannot be anchored now.
      publish_failed(record);
    }
  } catch (const std::exception &) {
    // Pool is shutting down between our running_ check and the enqueue;
    // the record is dropped (best-effort anchoring during teardown).
  }
}

void LedgerWorker::process_record(const SignatureRecord &record) {
  int retry_count = 0;
  while (true) {
    auto entry = ledger_client_.submit_record(record);
    if (entry) {
      ++committed_count_;
      publish_committed(record, *entry);
      if (on_committed_) {
        try {
          on_committed_(record, *entry);
        } catch (...) {
          // Best-effort: the DB update is asynchronous and must not
          // fail the ledger commit that already succeeded.
        }
      }
      return;
    }

    // The record could not be submitted: give up immediately while draining
    // on shutdown (running_ == false) or when the retry budget is exhausted.
    if (!running_.load(std::memory_order_acquire) ||
        retry_count >= retry_policy_.max_retries) {
      break;
    }

    ++retry_count;
    if (retry_count > retry_policy_.max_retries) {
      break;
    }

    int delay_ms = retry_policy_.base_delay_ms;
    for (int i = 1; i < retry_count; ++i) {
      delay_ms *= retry_policy_.delay_multiplier;
    }
    if (delay_ms > retry_policy_.max_delay_ms) {
      delay_ms = retry_policy_.max_delay_ms;
    }
    if (delay_ms > 0) {
      sleep_interruptible(std::chrono::milliseconds(delay_ms), running_);
    }
  }

  publish_failed(record);
}

} // namespace vhsm::ledger
