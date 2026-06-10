#ifndef VHSM_CORE_HSM_CLOCK 
#define VHSM_CORE_HSM_CLOCK 

#include <chrono>
#include <cstdint>
#include <ctime>
#include <string>

namespace vhsm {

using HsmTimePoint = std::chrono::time_point<std::chrono::system_clock,
                                            std::chrono::milliseconds>;

class IHsmClock {
public:
    virtual ~IHsmClock() = default;

    // Return the current UTC wall-clock time, truncated to milliseconds.
    [[nodiscard]] virtual HsmTimePoint now() const noexcept = 0;
};
} // namespace vhsm

#endif // VHSM_CORE_HSM_CLOCK