#ifndef VHSM_METRICS_H
#define VHSM_METRICS_H

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace vhsm::metrics {

enum class Kind { Counter, Gauge };

// Process-wide metrics registry rendered in Prometheus text exposition format.
// Counters monotonically increase; gauges can move up/down. All values are
// int64. The singleton is safe for concurrent inc/set from worker threads.
class Metrics {
public:
  static Metrics &instance();

  // Declare a metric up-front (help text + type). Redeclaring is a no-op.
  void declare(const std::string &name, Kind kind, const std::string &help);

  // Increment a counter (or create it as a counter). `by` may be negative.
  void inc(const std::string &name, int64_t by = 1);
  // Set a gauge (or create it as a gauge).
  void set(const std::string &name, int64_t value);
  int64_t get(const std::string &name) const;

  // Render the registry as Prometheus exposition text.
  std::string prometheus() const;

private:
  Metrics() = default;

  struct Metric {
    Kind kind = Kind::Counter;
    std::string help;
    int64_t value = 0;
  };

  mutable std::mutex mu_;
  std::unordered_map<std::string, Metric> metrics_;
};

// Well-known metric names (used across the codebase). The Prometheus name is
// `vhsm_<name>` (the prefix is added in prometheus()).
namespace names {
constexpr const char *ledger_committed = "ledger_committed_total";
constexpr const char *ledger_failed = "ledger_failed_total";
constexpr const char *ledger_pending = "ledger_pending";
constexpr const char *notification_delivered = "notification_delivered_total";
constexpr const char *notification_failed = "notification_failed_total";
constexpr const char *outbox_depth = "outbox_depth";
constexpr const char *audit_chain_length = "audit_chain_length";
constexpr const char *pqc_signatures = "pqc_signatures_total";
constexpr const char *fips_active = "fips_mode_active";
} // namespace names

} // namespace vhsm::metrics

#endif // VHSM_METRICS_H
