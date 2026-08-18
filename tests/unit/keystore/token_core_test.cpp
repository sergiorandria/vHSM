#include <gtest/gtest.h>

#include "../../../src/keystore/internal/token_core.h"
#include "../../../src/core/frozen_hsm_clock.h"
#include "../../../src/core/ClockUtils.h"

#include <string>

using namespace vhsm;
using namespace vhsm::keystore::internal;

namespace {
// Fixed epoch used across the test: 2023-11-14T22:13:20.000Z.
constexpr std::int64_t kFixedMs = 1'700'000'000'000LL;
} // namespace

// The internal core must use the injected clock, not std::chrono directly,
// so its behaviour is deterministic under test (FrozenHsmClock).
TEST(v_TokenCore_M1, UsesInjectedClockForPinTimestamps) {
    FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
    v_TokenCore_M1 core("label", "id", clock);

    // Construction stamps the last PIN op time with the injected clock.
    EXPECT_EQ(ClockUtils::to_epoch_ms(core.v_last_pin_op_at()), kFixedMs);

    // A PIN operation while the clock is frozen keeps the same timestamp.
    ASSERT_EQ(core.v_initialize_user_pin(reinterpret_cast<const CK_CHAR*>("1234"), 4), CKR_OK);
    EXPECT_EQ(ClockUtils::to_epoch_ms(core.v_last_pin_op_at()), kFixedMs);

    // Advancing the frozen clock then doing another op moves the timestamp.
    clock.advance(std::chrono::milliseconds(1500));
    ASSERT_EQ(core.v_verify_user_pin(reinterpret_cast<const CK_CHAR*>("1234"), 4), CKR_OK);
    EXPECT_EQ(ClockUtils::to_epoch_ms(core.v_last_pin_op_at()), kFixedMs + 1500);
}

TEST(v_TokenCore_M1, PinLifecycle) {
    FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
    v_TokenCore_M1 core("label", "id", clock);

    // Verify before init must fail.
    EXPECT_EQ(core.v_verify_user_pin(reinterpret_cast<const CK_CHAR*>("1234"), 4),
              CKR_USER_PIN_NOT_INITIALIZED);

    ASSERT_EQ(core.v_initialize_user_pin(reinterpret_cast<const CK_CHAR*>("1234"), 4), CKR_OK);
    EXPECT_EQ(core.v_is_user_pin_set(), CK_TRUE);

    // Wrong PIN rejected.
    EXPECT_EQ(core.v_verify_user_pin(reinterpret_cast<const CK_CHAR*>("0000"), 4),
              CKR_PIN_INCORRECT);

    // Correct PIN accepted.
    EXPECT_EQ(core.v_verify_user_pin(reinterpret_cast<const CK_CHAR*>("1234"), 4), CKR_OK);

    // Change PIN.
    ASSERT_EQ(core.v_change_user_pin(reinterpret_cast<const CK_CHAR*>("1234"), 4,
                                     reinterpret_cast<const CK_CHAR*>("abcd"), 4),
              CKR_OK);
    EXPECT_EQ(core.v_verify_user_pin(reinterpret_cast<const CK_CHAR*>("abcd"), 4), CKR_OK);
    EXPECT_EQ(core.v_verify_user_pin(reinterpret_cast<const CK_CHAR*>("1234"), 4),
              CKR_PIN_INCORRECT);
}

TEST(v_TokenCore_M1, KeKAbsentByDefault) {
    FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
    v_TokenCore_M1 core("label", "id", clock);
    EXPECT_TRUE(core.v_get_kek().empty());
}
