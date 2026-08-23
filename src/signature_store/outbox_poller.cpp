#include "outbox_poller.h"

#include "../core/hsm_instance.h"
#include "../core/utils.h"
#include <chrono>
#include <thread>

namespace vhsm::signature_store::db {

OutboxPoller::OutboxPoller(IDbConnection& db,
                           vhsm::notification::NotificationBus& bus,
                           std::chrono::milliseconds interval)
    : db_(db), bus_(bus), interval_(interval) {}

OutboxPoller::~OutboxPoller() { stop(); }

void OutboxPoller::start() {
  if (running_.exchange(true)) return;
  thread_ = std::make_unique<std::thread>([this] { loop(); });
}

void OutboxPoller::stop() noexcept {
  if (!running_.exchange(false)) return;
  if (thread_ && thread_->joinable()) thread_->join();
  thread_.reset();
}

void OutboxPoller::loop() {
  while (running_.load(std::memory_order_acquire)) {
    try {
      poll_once();
    } catch (...) {
    }
    std::this_thread::sleep_for(interval_);
  }
}

void OutboxPoller::poll_once() {
  // Fetch up to 32 PENDING outbox rows in one go to avoid holding the DB
  // lock while publishing to the bus (which may block on subscriber I/O).
  auto rs = db_.query(
      "SELECT id, event_type, aggregate_id, payload FROM event_outbox WHERE status='PENDING' ORDER BY created_at ASC LIMIT 32;");
  if (rs.empty()) return;

  for (auto& row : rs.rows_) {
    auto id_opt = rs.get<std::string>(row, 0);
    auto type_opt = rs.get<std::string>(row, 1);
    auto agg_opt = rs.get<std::string>(row, 2);
    auto payload_opt = rs.get<std::string>(row, 3);
    if (!id_opt || !type_opt) continue;

    std::string id = *id_opt;
    std::string type = *type_opt;
    std::string payload = payload_opt.value_or("{}");

    // Publish to the bus — the bus is bounded and never throws, but the
    // subscriber adapters may fail; we treat any publish as success and mark
    // DISPATCHED so the outbox does not grow unbounded. Failed deliveries
    // are still recorded in notification_log via the dispatcher.
    vhsm::notification::NotificationEvent ev;
    ev.type = vhsm::notification::NotificationEvent::EventType::SIGN_CREATED;
    if (type == "SIGN_CREATED") {
      ev.type = vhsm::notification::NotificationEvent::EventType::SIGN_CREATED;
    } else if (type == "DB_WRITE_FAILED") {
      ev.type = vhsm::notification::NotificationEvent::EventType::DB_WRITE_FAILED;
    }
    ev.severity = vhsm::notification::NotificationEvent::Severity::INFO;
    ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
    ev.source = "outbox:" + id;
    ev.actor = "system";
    ev.summary = "Outbox replay: " + type + " " + id;
    ev.detail_json = payload;
    ev.hsm_instance = vhsm::core::hsm_instance_id();
    bus_.publish(ev);

    // Mark dispatched — best-effort, ignore errors (will be retried next poll).
    try {
      db_.exec("UPDATE event_outbox SET status='DISPATCHED' WHERE id=?;", {id});
    } catch (...) {
    }
  }
}

} // namespace vhsm::signature_store::db
