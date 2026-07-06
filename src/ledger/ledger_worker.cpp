#include "ledger_worker.h"
#include <chrono>
#include <iostream>

namespace vhsm::ledger {

LedgerWorker::LedgerWorker(LedgerClient& client, notification::NotificationBus& bus)
    : ledger_client_(client), notification_bus_(bus) {}

LedgerWorker::~LedgerWorker() {
    if (worker_thread_.joinable()) {
        drain_and_stop();
    }
}

void LedgerWorker::start() {
    if (running_) {
        return;
    }
    running_ = true;
    worker_thread_ = std::thread(&LedgerWorker::worker_loop, this);
}

void LedgerWorker::drain_and_stop() {
    if (!running_) {
        return;
    }
    running_ = false;
    queue_cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    // Drain the queue and try to submit remaining records
    std::queue<SignatureRecord> local_queue;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        local_queue.swap(record_queue_);
    }
    while (!local_queue.empty()) {
        auto record = local_queue.front();
        local_queue.pop();
        // Try to submit the record without retry logic (or with limited retries) during shutdown?
        // For simplicity, we'll just try once and if it fails, we drop it and notify.
        auto entry = ledger_client_.submit_record(record);

        // So technically this is just bullshit, 
        // ledger entry should be immutable.

        if (!entry) {
            // Notify about the failure
            // We'll create a notification event for LEDGER_COMMIT_FAILED
            // We need to create a NotificationEvent and publish it.
            // We'll skip the details for now, but we can call:
            // notification_bus_.publish(notification::NotificationEvent{ ... });
            // Since we don't have the full notification event structure here, we'll leave a comment.
            // In a real implementation, we would create the event and publish it.
            std::cerr << "Failed to submit record during shutdown: " << record.record_id << std::endl;
        }
    }
}

void LedgerWorker::submit_record(const SignatureRecord& record) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        record_queue_.push(record);
    }
    queue_cv_.notify_one();
}

void LedgerWorker::worker_loop() {
    while (running_) {
        SignatureRecord record;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] { return !running_ || !record_queue_.empty(); });
            if (!running_ && record_queue_.empty()) {
                break;
            }
            record = record_queue_.front();
            record_queue_.pop();
        }

        // Try to submit the record with exponential backoff
        int retry_count = 0;
        bool submitted = false;
        while (retry_count <= MAX_RETRIES && running_) {
            auto entry = ledger_client_.submit_record(record);
            if (entry) {
                submitted = true;
                break;
            }
            // Submission failed, wait and retry
            retry_count++;
            if (retry_count > MAX_RETRIES) {
                break;
            }
            int delay_sec = BASE_DELAY_SEC * (1 << (retry_count - 1)); // 1, 2, 4, 8, ...
            if (delay_sec > MAX_DELAY_SEC) {
                delay_sec = MAX_DELAY_SEC;
            }
            std::this_thread::sleep_for(std::chrono::seconds(delay_sec));
        }

        if (!submitted) {
            // After max retries, notify about the failure
            // We'll create a notification event for LEDGER_COMMIT_FAILED
            // For now, we'll just log an error.
            std::cerr << "Failed to submit record after " << MAX_RETRIES << " retries: " << record.record_id << std::endl;
            // TODO: Publish a notification event for LEDGER_COMMIT_FAILED
        }
    }
}

} // namespace vhsm::ledger