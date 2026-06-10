#include "system_hsm_clock.h"

namespace vhsm { 
    [[nodiscard]] HsmTimePoint SystemHsmClock::now() const noexcept {
        // system_clock::now() may return a finer duration (nanoseconds on
        // Linux); floor<> truncates cleanly to milliseconds.
        return std::chrono::floor<std::chrono::milliseconds>(
            std::chrono::system_clock::now());
    }
}