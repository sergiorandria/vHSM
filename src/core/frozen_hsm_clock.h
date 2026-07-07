#ifndef VHSM_CORE_FROZEN_HSM_CLOCK 
#define VHSM_CORE_FROZEN_HSM_CLOCK

#include "hsm_clock.h"

namespace vhsm {
class FrozenHsmClock final : public IHsmClock {
public:
    explicit FrozenHsmClock(HsmTimePoint t) noexcept;

    [[nodiscard]] HsmTimePoint now() const noexcept override;

    /// Move the frozen clock forward by `delta`.
    void advance(std::chrono::milliseconds delta) noexcept;

    /// Snap to a specific time (useful between test cases).
    void set(HsmTimePoint t) noexcept;

private:
    HsmTimePoint t_;
};
} // namespace vhsm 

#endif // VHSM_CORE_FROZEN_HSM_CLOCK