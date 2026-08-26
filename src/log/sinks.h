#ifndef VHSM_LOG_SINKS_H
#define VHSM_LOG_SINKS_H

#include "severity.h"
#include "sink.h"

#include <cstdio>

#ifdef __linux__
#include <syslog.h>
#endif

namespace vhsm::log {

// ─── StderrSink ───────────────────────────────────────────────────────────
// Writes to stderr with structured prefix: [TIMESTAMP] [SEVERITY] [module] msg
// Compatible with Docker log capture, systemd service output redirection,
// and any stderr collector.

class StderrSink final : public LogSink {
public:
  void write(Severity severity, const char *module,
             const std::string &message) override {
    // Single fprintf call — thread-safe on POSIX (stderr is unbuffered).
    std::fprintf(stderr, "[%-5s] [%s] %s\n", to_string(severity), module,
                 message.c_str());
  }

  void flush() override { std::fflush(stderr); }
};

// ─── SyslogSink ───────────────────────────────────────────────────────────
// Sends to syslog(3) — integrates with journald (systemd), rsyslog,
// syslog-ng, and any RFC 5424 collector. Messages are forwarded to
// /var/log/syslog, /var/log/daemon.log, or the journal depending on config.
//
// On non-Linux platforms this sink is a no-op (use StderrSink instead).

class SyslogSink final : public LogSink {
public:
  SyslogSink(const std::string &ident = "vhsmd") {
#ifdef __linux__
    openlog(ident.c_str(), LOG_PID | LOG_NDELAY, LOG_DAEMON);
#else
    (void)ident;
#endif
  }

  ~SyslogSink() override {
#ifdef __linux__
    closelog();
#endif
  }

  void write(Severity severity, const char *module,
             const std::string &message) override {
#ifdef __linux__
    ::syslog(to_syslog_priority(severity), "[%s] %s", module, message.c_str());
#else
    (void)severity;
    (void)module;
    (void)message;
#endif
  }
};

} // namespace vhsm::log

#endif // VHSM_LOG_SINKS_H
