#include "login_throttle.h"

#include <algorithm>

namespace vhsm::session {

unsigned LoginThrottle::delay_before_attempt(const std::string &key) {
  std::lock_guard<std::mutex> lk(mutex_);
  auto it = attempts_.find(key);
  if (it == attempts_.end() ||
      it->second.consecutive_failures < policy_.soft_threshold)
    return 0;

  // Exponential: base * 2^(failures - soft_threshold), capped.
  const unsigned exp = it->second.consecutive_failures -
                       policy_.soft_threshold;
  const unsigned delay = policy_.base_delay_ms << std::min<unsigned>(exp, 16);
  return std::min(delay, policy_.max_delay_ms);
}

void LoginThrottle::record_success(const std::string &key) {
  std::lock_guard<std::mutex> lk(mutex_);
  attempts_.erase(key);
}

void LoginThrottle::record_failure(const std::string &key) {
  std::lock_guard<std::mutex> lk(mutex_);
  ++attempts_[key].consecutive_failures;
}

unsigned LoginThrottle::failures(const std::string &key) const {
  std::lock_guard<std::mutex> lk(mutex_);
  auto it = attempts_.find(key);
  return it == attempts_.end() ? 0 : it->second.consecutive_failures;
}

} // namespace vhsm::session
