#ifndef VHSM_LOG_SINK_H
#define VHSM_LOG_SINK_H

#include "severity.h"

#include <string>

namespace vhsm::log {

/**
 * Sink interface — where log records go.
 *
 * Implementations: StderrSink, SyslogSink. Future: FileSink with rotation,
 * NetworkSink for remote collectors (Fluentd, Loki, etc.).
 *
 * Thread-safe: implementations MUST be safe to call from multiple threads
 * concurrently. write() may be called from any thread at any time.
 */
class LogSink {
public:
  virtual ~LogSink() = default;

  /**
   * Write a single log record.
   *
   * @param severity  Severity level of the message
   * @param module    Module/component name (e.g., "pkcs11", "ledger", "vault")
   * @param message   Formatted log message (no trailing newline)
   */
  virtual void write(Severity severity, const char *module,
                     const std::string &message) = 0;

  /**
   * Flush buffered output. Called on shutdown or when durability is needed.
   * Default: no-op (stderr/syslog are unbuffered by default).
   */
  virtual void flush() {}
};

} // namespace vhsm::log

#endif // VHSM_LOG_SINK_H
