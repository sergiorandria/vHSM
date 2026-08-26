#ifndef VHSM_SESSION_LOGIN_THROTTLE_H
#define VHSM_SESSION_LOGIN_THROTTLE_H

#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

namespace vhsm::session {

/**
 * Progressive login throttling (rate limiting) applied BEFORE the token's
 * hard PIN lockout kicks in.
 *
 * Layering with Token PIN lockout:
 *  - failures < soft_threshold : no delay, CKR_PIN_INCORRECT
 *  - failures >= soft_threshold: exponential delay before verification —
 *    slows brute force while keeping the UX recoverable
 *  - hard lockout stays in keystore::Token (CKR_PIN_LOCKED after
 *    max_pin_attempts); the throttle complements it and never locks.
 *
 * Keys are caller-defined (composition root uses "slot:userType").
 * Thread-safe: all state guarded by an internal mutex.
 */
class LoginThrottle {
public:
  struct Policy {
    unsigned soft_threshold = 3;   // consecutive failures before delays
    unsigned base_delay_ms = 250;  // delay at soft_threshold
    unsigned max_delay_ms = 8000;  // cap for exponential growth
  };


  LoginThrottle() : policy_() {}
  explicit LoginThrottle(const Policy &policy) : policy_(policy) {}

  /// Milliseconds the caller must sleep BEFORE attempting verification for
  /// `key` given its failure history. Returns 0 when not throttled.
  unsigned delay_before_attempt(const std::string &key);

  void record_success(const std::string &key);
  void record_failure(const std::string &key);

  /// Test hook / introspection: current consecutive failure count.
  unsigned failures(const std::string &key) const;

private:
  struct AttemptState {
    unsigned consecutive_failures = 0;
  };

  Policy policy_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, AttemptState> attempts_;
};

} // namespace vhsm::session

#endif // VHSM_SESSION_LOGIN_THROTTLE_H
