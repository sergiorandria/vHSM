#include "ledger_worker.h"
#include <chrono>
#include <iostream>
#include <thread>
#include <utility>

namespace vhsm::ledger {

namespace {

    // Small anchoring pool: ledger submission is network-bound (gRPC to the
    // Fabric gateway), so more than a handful of concurrent commits rarely pays
    // off while a backing-off task must not tie up a single serial worker.
    std::size_t default_pool_size()
    {
        std::size_t hw = std::thread::hardware_concurrency();
        return hw <= 2 ? 2 : (hw >= 4 ? 4 : hw);
    }

} // namespace

LedgerWorker::LedgerWorker(LedgerClient& client, notification::NotificationBus& bus,
                           CommitCallback on_committed, RetryPolicy retry,
                           std::size_t concurrent_workers)
    : ledger_client_(client), notification_bus_(bus),
      on_committed_(std::move(on_committed)), retry_policy_(retry),
      pool_size_(concurrent_workers != 0 ? concurrent_workers : default_pool_size()) {}

LedgerWorker::~LedgerWorker() {
    drain_and_stop();
}

void LedgerWorker::start() {
    if (running_.exchange(true)) {
        return;
    }
    try {
        pool_ = &threadpool::ThreadPool::instance(pool_size_);
    } catch (...) {
        running_.store(false);
        throw;
    }
    token_ = threadpool::CapabilityToken::grant(threadpool::PrivilegeTier::High);
}

void LedgerWorker::publish_committed(const SignatureRecord& record, const LedgerEntry& entry) {
    vhsm::notification::NotificationEvent event;
    event.type = vhsm::notification::NotificationEvent::EventType::LEDGER_COMMITTED;
    event.severity = vhsm::notification::NotificationEvent::Severity::INFO;
    event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    event.source = "LedgerWorker";
    event.actor = "system";
    event.summary = "Record anchored to ledger: " + record.record_id;
    event.detail_json = R"({"record_id":")" + record.record_id +
                        R"(","ledger_tx_id":")" + entry.tx_id +
                        R"(","ledger_block_num":)" + std::to_string(entry.block_number) + R"(})";
    event.hsm_instance = "";
    notification_bus_.publish(event);
}

void LedgerWorker::publish_failed(const SignatureRecord& record) {
    vhsm::notification::NotificationEvent event;
    event.type = vhsm::notification::NotificationEvent::EventType::LEDGER_COMMIT_FAILED;
    event.severity = vhsm::notification::NotificationEvent::Severity::WARNING;
    event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    event.source = "LedgerWorker";
    event.actor = "system";
    event.summary = "Failed to submit record after " +
                    std::to_string(retry_policy_.max_retries) +
                    " retries: " + record.record_id;
    event.detail_json = "{}";
    event.hsm_instance = "";
    notification_bus_.publish(event);
}

void LedgerWorker::drain_and_stop() {
    if (!running_.exchange(false)) {
        return;
    }
    if (pool_) {
        // The pool drains its own queues: remaining tasks are processed by the
        // workers (one-shot, since running_ is now false) and then joined.
        pool_->shutdown();
        threadpool::ThreadPool::reset();
        pool_ = nullptr;
    }
}

void LedgerWorker::submit_record(const SignatureRecord& record) {
    if (!running_.load(std::memory_order_acquire) || pool_ == nullptr) {
        return;
    }
    try {
        pool_->enqueue(token_, [this, record] { process_record(record); });
    } catch (const std::exception&) {
        // Pool is shutting down between our running_ check and the enqueue;
        // the record is dropped (best-effort anchoring during teardown).
    }
}

void LedgerWorker::process_record(const SignatureRecord& record) {
    const bool one_shot = !running_.load(std::memory_order_acquire);

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
        // on shutdown, otherwise retry with exponential backoff.
        if (one_shot || retry_count >= retry_policy_.max_retries) {
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
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }

    publish_failed(record);
}

} // namespace vhsm::ledger