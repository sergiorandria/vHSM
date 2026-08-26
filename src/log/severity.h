#ifndef VHSM_LOG_SEVERITY_H
#define VHSM_LOG_SEVERITY_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace vhsm::log {

// ─── Severity levels (maps to syslog priority) ────────────────────────────
// Ordered from most to least severe. Compile-time filtering: messages below
// the configured minimum are compiled out entirely (zero runtime cost).

enum class Severity : uint8_t {
  Critical = 0, // service-threatening; always logged
  Error    = 1, // operation failed
  Warning  = 2, // degraded or suspicious
  Info     = 3, // normal lifecycle events
  Debug    = 4, // developer diagnostics
  Trace    = 5, // per-call tracing; compiled out in release builds
};

/// Syslog priority mapping — for integration with syslog(3) / journald.
constexpr int to_syslog_priority(Severity s) noexcept {
  switch (s) {
  case Severity::Critical: return 2; // LOG_CRIT
  case Severity::Error:    return 3; // LOG_ERR
  case Severity::Warning:  return 4; // LOG_WARNING
  case Severity::Info:     return 6; // LOG_INFO
  case Severity::Debug:    return 7; // LOG_DEBUG
  case Severity::Trace:    return 7; // LOG_DEBUG
  }
  return 6;
}

constexpr const char *to_string(Severity s) noexcept {
  switch (s) {
  case Severity::Critical: return "CRIT";
  case Severity::Error:    return "ERROR";
  case Severity::Warning:  return "WARN";
  case Severity::Info:     return "INFO";
  case Severity::Debug:    return "DEBUG";
  case Severity::Trace:    return "TRACE";
  }
  return "???";
}

} // namespace vhsm::log

#endif // VHSM_LOG_SEVERITY_H
