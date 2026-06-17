#ifndef VHSM_LEDGER_LEDGER_WORKER_H
#define VHSM_LEDGER_LEDGER_WORKER_H

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>
#include "../core/types.h"
#include "ledger_client.h"
#include "../notification/notification_bus.h"

namespace vhsm::ledger {

class LedgerWorker {
public:
    explicit LedgerWorker(LedgerClient& client, notification::NotificationBus& bus);
    ~LedgerWorker();

    // Start the worker thread
    void start();
    // Stop the worker thread and drain the queue
    void drain_and_stop();

    // Submit a record for ledger anchoring (to be called by the signature dispatcher)
    void submit_record(const SignatureRecord& record);

private:
    void worker_loop();

    LedgerClient& ledger_client_;
    notification::NotificationBus& notification_bus_;
    std::thread worker_thread_;
    std::atomic<bool> running_{false};
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<SignatureRecord> record_queue_;

    // Exponential backoff parameters
    static constexpr int MAX_RETRIES = 5;
    static constexpr int BASE_DELAY_SEC = 1;
    static constexpr int MAX_DELAY_SEC = 60;
};

} // namespace vhsm::ledger

#endif // VHSM_LEDGER_LEDGER_WORKER_H