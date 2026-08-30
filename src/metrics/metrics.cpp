#include "metrics.h"

namespace vhsm::metrics {

Metrics &Metrics::instance() {
  static Metrics s;
  return s;
}

void Metrics::declare(const std::string &name, Kind kind,
                      const std::string &help) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = metrics_.find(name);
  if (it != metrics_.end()) {
    // Keep the first declaration (type + help) stable.
    return;
  }
  metrics_[name] = Metric{kind, help, 0};
}

void Metrics::inc(const std::string &name, int64_t by) {
  std::lock_guard<std::mutex> lk(mu_);
  auto &m = metrics_[name];
  m.kind = Kind::Counter;
  m.value += by;
}

void Metrics::set(const std::string &name, int64_t value) {
  std::lock_guard<std::mutex> lk(mu_);
  auto &m = metrics_[name];
  m.kind = Kind::Gauge;
  m.value = value;
}

int64_t Metrics::get(const std::string &name) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = metrics_.find(name);
  return it == metrics_.end() ? 0 : it->second.value;
}

std::string Metrics::prometheus() const {
  std::lock_guard<std::mutex> lk(mu_);
  std::string out;
  for (const auto &kv : metrics_) {
    const std::string &name = kv.first;
    const Metric &m = kv.second;
    const std::string type = m.kind == Kind::Counter ? "counter" : "gauge";
    out += "# HELP vhsm_" + name + " " + (m.help.empty() ? name : m.help) + "\n";
    out += "# TYPE vhsm_" + name + " " + type + "\n";
    out += "vhsm_" + name + " " + std::to_string(m.value) + "\n";
  }
  return out;
}

} // namespace vhsm::metrics
