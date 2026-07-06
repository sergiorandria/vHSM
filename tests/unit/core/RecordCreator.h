#ifndef VHSM_TESTS_RECORD_CREATOR_H 
#define VHSM_TESTS_RECORD_CREATOR_H

#include "../../../src/core/clock.h"

namespace vhsm::test {
    
// Simulates a component that takes IHsmClock by const-ref.
struct RecordCreator {
    const IHsmClock& clock;

    struct Record { int64_t created_at_ms; };

    Record create() const {
        return { ClockUtils::to_epoch_ms(clock.now()) };
    }
};
} // namespace vhsm::test

#endif // VHSM_TESTS_RECORD_CREATOR_H