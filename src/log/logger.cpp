#include "logger.h"

#include <atomic>
#include <mutex>
#include <sstream>

namespace vhsm::log {

Logger::Logger() = default;
Logger::~Logger() = default;

void Logger::add_sink(std::shared_ptr<LogSink> sink) {
  if (!sink)
    return;
  std::lock_guard<std::mutex> lk(mutex_);
  sinks_.push_back(std::move(sink));
}

void Logger::set_level(Severity level) {
  std::lock_guard<std::mutex> lk(mutex_);
  min_level_ = level;
}

Severity Logger::level() const noexcept { return min_level_; }

void Logger::log(Severity severity, const char *module,
                 const std::string &message) {
  if (severity > min_level_)
    return;

  // Snapshot sinks under lock, write outside — avoids holding the mutex
  // during I/O and prevents deadlock if a sink logs.
  std::vector<std::shared_ptr<LogSink>> snapshot;
  {
    std::lock_guard<std::mutex> lk(mutex_);
    snapshot = sinks_;
  }

  for (auto &sink : snapshot) {
    try {
      sink->write(severity, module, message);
    } catch (...) {
      // Logging must never throw — swallow to prevent cascading failures.
    }
  }
}

void Logger::critical(const char *module, const std::string &msg) {
  log(Severity::Critical, module, msg);
}
void Logger::error(const char *module, const std::string &msg) {
  log(Severity::Error, module, msg);
}
void Logger::warning(const char *module, const std::string &msg) {
  log(Severity::Warning, module, msg);
}
void Logger::info(const char *module, const std::string &msg) {
  log(Severity::Info, module, msg);
}

// ─── Process-wide fallback ────────────────────────────────────────────────
// Pointer-swap pattern: the fallback is a static stderr-only Logger; the
// composition root installs the container-owned instance at startup. After
// installation, records flow to every configured sink (stderr + syslog).
// set_global_logger must be called before worker threads start (composition
// root guarantees this).

namespace {
std::atomic<Logger *> g_installed{nullptr};
} // namespace

Logger &global_logger() {
  static Logger fallback;
  static std::once_flag flag;
  std::call_once(flag,
                 [] { fallback.add_sink(std::make_shared<StderrSink>()); });
  Logger *p = g_installed.load(std::memory_order_acquire);
  return p ? *p : fallback;
}

void set_global_logger(Logger *logger) {
  g_installed.store(logger, std::memory_order_release);
}

} // namespace vhsm::log
