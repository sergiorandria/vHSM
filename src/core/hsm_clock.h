#ifndef VHSM_CORE_HSM_CLOCK
#define VHSM_CORE_HSM_CLOCK

#include <chrono>
#include <cstdint>
#include <ctime>
#include <string>

namespace vhsm {

// WHY HsmTimePoint uses millisecond precision: Blockchain transactions often
// require microsecond ordering, but wall-clock synchronization across
// distributed systems is unreliable below milliseconds (NTP is typically
// ±100ms). Millisecond precision is enough for reasonable timestamping and
// avoids false ordering guarantees that might tempt developers to rely on
// sub-millisecond resolution.
using HsmTimePoint = std::chrono::time_point<std::chrono::system_clock,
                                             std::chrono::milliseconds>;

// WHY IHsmClock is an interface, not a concrete class: Dependency injection via
// IHsmClock allows tests to inject FrozenHsmClock (always returns the same
// time) for deterministic testing. Production code uses SystemHsmClock (wraps
// std::chrono::system_clock). This separation is essential for testing
// time-dependent logic (session timeouts, anchor timestamps).
class IHsmClock {
public:
  virtual ~IHsmClock() = default;

  // WHY [[nodiscard]]: Forgetting to use now() is almost always a bug.
  // Return the current UTC wall-clock time, truncated to milliseconds.
  [[nodiscard]] virtual HsmTimePoint now() const noexcept = 0;
};
} // namespace vhsm

#endif // VHSM_CORE_HSM_CLOCK