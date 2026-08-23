#ifndef VHSM_SIGSTORE_OUTBOX_POLLER_H
#define VHSM_SIGSTORE_OUTBOX_POLLER_H

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

#include "../notification/notification_bus.h"
#include "db_connection.h"

namespace vhsm::signature_store::db {

// WHY OutboxPoller: The dispatcher writes SIGN_CREATED into `event_outbox`
// inside the same DB transaction as `signature_records`. If the process
// crashes between DB commit and `NotificationBus::publish`, the event would be
// lost. The poller replays `PENDING` rows on a timer and on `C_Initialize`
// (via `LedgerRetryQueue` for ledger, here for notifications), making the
// bus publish atomic with the DB commit without needing a distributed
// transaction.

class OutboxPoller {
public:
  OutboxPoller(IDbConnection& db, vhsm::notification::NotificationBus& bus,
               std::chrono::milliseconds interval = std::chrono::milliseconds(500));
  ~OutboxPoller();

  void start();
  void stop() noexcept;

  OutboxPoller(const OutboxPoller&) = delete;
  OutboxPoller& operator=(const OutboxPoller&) = delete;

private:
  void loop();
  void poll_once();

  IDbConnection& db_;
  vhsm::notification::NotificationBus& bus_;
  std::chrono::milliseconds interval_;
  std::atomic<bool> running_{false};
  std::unique_ptr<std::thread> thread_;
};

} // namespace vhsm::signature_store::db

#endif // VHSM_SIGSTORE_OUTBOX_POLLER_H
