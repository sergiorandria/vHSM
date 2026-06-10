#ifndef VHSM_CORE_SYSTEM_HSM_CLOCK
#define VHSM_CORE_SYSTEM_HSM_CLOCK

#include "hsm_clock.h" 

namespace vhsm {
class SystemHsmClock final : public IHsmClock {
public:
    [[nodiscard]] HsmTimePoint now() const noexcept override;
};
} // namespace vhsm

#endif // VHSM_CORE_SYSTEM_HSM_CLOCK