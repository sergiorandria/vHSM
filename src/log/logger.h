#ifndef VHSM_LOG_LOGGER_H
#define VHSM_LOG_LOGGER_H

#include "severity.h"
#include "sink.h"
#include "sinks.h"

#include "../core/macros.h"

#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace vhsm::log {

/**
 * Logger — the single entry point for all vHSM log output.
 *
 * Injectable (NOT a singleton): owned by AppContainer; tests create isolated
 * instances. A backward-compat process-wide accessor is provided for legacy
 * call sites during DI migration.
 *
 * Thread-safe: all methods may be called from any thread concurrently.
 *
 * Compile-time filtering: messages below min_level_ are compiled out via
 * the VHSM_LOG_* macros — zero runtime cost for disabled levels.
 */
class Logger {
public:
  Logger();
  ~Logger();

  // Non-copyable, non-movable (holds mutex + sink list).
  Logger(const Logger &) = delete;
  Logger &operator=(const Logger &) = delete;

  // ─── Configuration ────────────────────────────────────────────────────

  /// Add a sink. All registered sinks receive every message above min_level.
  void add_sink(std::shared_ptr<LogSink> sink);

  /// Set minimum severity. Messages below this level are dropped at runtime.
  void set_level(Severity level);

  _VHSMXX_NODISCARD Severity level() const noexcept;

  // ─── Logging ──────────────────────────────────────────────────────────

  /// Core logging method. Formats and writes to all sinks.
  void log(Severity severity, const char *module, const std::string &message);

  // ─── Convenience methods ──────────────────────────────────────────────

  void critical(const char *module, const std::string &msg);
  void error(const char *module, const std::string &msg);
  void warning(const char *module, const std::string &msg);
  void info(const char *module, const std::string &msg);

#ifdef VHSM_LOG_DEBUG
  void debug(const char *module, const std::string &msg);
#else
  void debug(const char *, const std::string &) {}
#endif

private:
  mutable std::mutex mutex_;
  std::vector<std::shared_ptr<LogSink>> sinks_;
  Severity min_level_ = Severity::Info;
};

// ─── Process-wide fallback ────────────────────────────────────────────────
// For modules that cannot easily receive DI (e.g., header-only ThreadPool
// used from third-party paths). Defaults to a Logger with StderrSink so
// behavior matches the legacy fprintf(stderr) call sites. The composition
// root installs the container-owned logger at startup; log records then
// flow to syslog/journald as well.

Logger &global_logger();
void set_global_logger(Logger *logger);

// ─── Macros ───────────────────────────────────────────────────────────────
// Usage: VHSM_LOG_INFO("pkcs11", "session opened: " << handle);
//
// The stream expression is only evaluated if the level is enabled.

#define VHSM_LOG_CRITICAL(logger, module, expr)                                \
  do {                                                                         \
    std::ostringstream vhsm_log_ss;                                            \
    vhsm_log_ss << expr;                                                       \
    (logger).critical(module, vhsm_log_ss.str());                                \
  } while (0)

#define VHSM_LOG_ERROR(logger, module, expr)                                   \
  do {                                                                         \
    std::ostringstream vhsm_log_ss;                                            \
    vhsm_log_ss << expr;                                                       \
    (logger).error(module, vhsm_log_ss.str());                                   \
  } while (0)

#define VHSM_LOG_WARNING(logger, module, expr)                                 \
  do {                                                                         \
    std::ostringstream vhsm_log_ss;                                            \
    vhsm_log_ss << expr;                                                       \
    (logger).warning(module, vhsm_log_ss.str());                                 \
  } while (0)

#define VHSM_LOG_INFO(logger, module, expr)                                    \
  do {                                                                         \
    std::ostringstream vhsm_log_ss;                                            \
    vhsm_log_ss << expr;                                                       \
    (logger).info(module, vhsm_log_ss.str());                                    \
  } while (0)

} // namespace vhsm::log

#endif // VHSM_LOG_LOGGER_H
