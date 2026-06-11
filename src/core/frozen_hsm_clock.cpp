#include "frozen_hsm_clock.h"

namespace vhsm {

FrozenHsmClock::FrozenHsmClock(HsmTimePoint t) noexcept : t_(t) {}

[[nodiscard]] HsmTimePoint FrozenHsmClock::now() const noexcept { return t_; }

void FrozenHsmClock::advance(std::chrono::milliseconds delta) noexcept { t_ += delta; }

void FrozenHsmClock::set(HsmTimePoint t) noexcept { t_ = t; }
} // namespace vhsm