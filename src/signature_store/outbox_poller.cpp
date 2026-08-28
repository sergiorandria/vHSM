#include "../log/logger.h"
#include "outbox_poller.h"

#include "../core/hsm_instance.h"
#include "../core/utils.h"
#include "../metrics/metrics.h"
#include <chrono>
#include <thread>

namespace vhsm::signature_store::db {

OutboxPoller::OutboxPoller(IDbConnection &db,
                           vhsm::notification::NotificationBus &bus,
                           std::chrono::milliseconds interval)
    : db_(db), bus_(bus), interval_(interval) {}

OutboxPoller::~OutboxPoller() { stop(); }

void OutboxPoller::start() {
  if (running_.exchange(true))
    return;
  thread_ = std::make_unique<std::thread>([this] { loop(); });
}

void OutboxPoller::stop() noexcept {
  if (!running_.exchange(false))
    return;
  if (thread_ && thread_->joinable())
    thread_->join();
  thread_.reset();
}

void OutboxPoller::loop() {
  while (running_.load(std::memory_order_acquire)) {
    try {
      poll_once();
    } catch (const std::exception &e) {
      vhsm::log::global_logger().error("outbox",
                                       "poll error: " + std::string(e.what()));
    }
    std::this_thread::sleep_for(interval_);
  }
}

void OutboxPoller::poll_once() {
  // Expose the pending outbox depth for monitoring (alerts on backlog growth).
  try {
    auto c = db_.query(
        "SELECT COUNT(*) FROM event_outbox WHERE status='PENDING';");
    if (!c.rows_.empty()) {
      if (auto v = c.get<std::string>(c.rows_[0], 0)) {
        metrics::Metrics::instance().set(metrics::names::outbox_depth,
                                         std::stoll(*v));
      }
    }
  } catch (...) {
    // Metrics are best-effort; never let a counting failure break replay.
  }

  // Fetch up to 32 PENDING outbox rows in one go to avoid holding the DB
  // lock while publishing to the bus (which may block on subscriber I/O).
  auto rs = db_.query(
      "SELECT id, event_type, aggregate_id, payload FROM event_outbox WHERE "
      "status='PENDING' ORDER BY created_at ASC LIMIT 32;");
  if (rs.empty())
    return;

  // Build the events first (cheap, no external side effects).
  struct Pending {
    std::string id;
    vhsm::notification::NotificationEvent ev;
  };
  std::vector<Pending> pending;
  pending.reserve(rs.rows_.size());

  for (auto &row : rs.rows_) {
    auto id_opt = rs.get<std::string>(row, 0);
    auto type_opt = rs.get<std::string>(row, 1);
    auto agg_opt = rs.get<std::string>(row, 2);
    auto payload_opt = rs.get<std::string>(row, 3);
    if (!id_opt || !type_opt)
      continue;

    std::string id = *id_opt;
    std::string type = *type_opt;
    std::string payload = payload_opt.value_or("{}");
    (void)agg_opt;

    vhsm::notification::NotificationEvent ev;
    if (type == "DB_WRITE_FAILED") {
      ev.type =
          vhsm::notification::NotificationEvent::EventType::DB_WRITE_FAILED;
    } else {
      ev.type = vhsm::notification::NotificationEvent::EventType::SIGN_CREATED;
    }
    ev.severity = vhsm::notification::NotificationEvent::Severity::INFO;
    ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    // `source` doubles as an idempotency key: subscribers can dedupe replays
    // by (source = "outbox:<id>") across crashes/restarts.
    ev.source = "outbox:" + id;
    ev.actor = "system";
    ev.summary = "Outbox replay: " + type + " " + id;
    ev.detail_json = payload;
    ev.hsm_instance = vhsm::core::hsm_instance_id();
    pending.push_back({std::move(id), std::move(ev)});
  }

  if (pending.empty()) return;

  // Exactly-once dispatch: mark the rows DISPATCHED *before* publishing. Once
  // marked, they are no longer selected by the next poll, so a crash between
  // marking and publishing loses at most one event (acceptable) instead of
  // re-publishing the same event on every poll (the previous bug). The bus
  // never throws, so the publish below is reached for every marked row.
  std::vector<std::string> ids;
  ids.reserve(pending.size());
  for (auto &p : pending) ids.push_back(p.id);
  try {
    if (ids.size() == 1) {
      db_.exec("UPDATE event_outbox SET status='DISPATCHED' WHERE id=?;", ids);
    } else {
      std::string sql = "UPDATE event_outbox SET status='DISPATCHED' WHERE id IN (";
      for (size_t i = 0; i < ids.size(); ++i) {
        if (i) sql += ",";
        sql += "?";
      }
      sql += ");";
      db_.exec(sql, ids);
    }
  } catch (const std::exception &e) {
    // If the DB update fails we must NOT publish, otherwise the rows stay
    // PENDING and would be re-published (duplicate) on the next poll. Leave
    // them PENDING and retry next interval.
    vhsm::log::global_logger().error(
        "outbox", "failed to mark rows dispatched, will retry: " +
                      std::string(e.what()));
    return;
  }

  for (auto &p : pending) {
    bus_.publish(p.ev);
  }
}

} // namespace vhsm::signature_store::db
