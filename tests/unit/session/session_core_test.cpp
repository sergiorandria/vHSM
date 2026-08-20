#include <gtest/gtest.h>

#include "../../../src/core/ClockUtils.h"
#include "../../../src/core/frozen_hsm_clock.h"
#include "../../../src/session/internal/session_manager_core.h"
#include "../../../src/session/internal/slot_manager_core.h"

#include <string>

using namespace vhsm;
using namespace vhsm::session::internal;

namespace {
constexpr std::int64_t kFixedMs = 1'700'000'000'000LL;
} // namespace

// The internal session core must use the injected clock, not std::chrono.
TEST(v_SessionManagerCore_M1, UsesInjectedClockForLastOp) {
  FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
  v_SessionManagerCore_M1 core(clock);

  EXPECT_EQ(ClockUtils::to_epoch_ms(core.v_last_op_at()), kFixedMs);

  CK_SESSION_HANDLE h = 0;
  ASSERT_EQ(core.v_open_session(0, CKF_RW_SESSION, nullptr, nullptr, &h),
            CKR_OK);
  EXPECT_NE(h, 0);
  // Frozen clock does not advance on its own.
  EXPECT_EQ(ClockUtils::to_epoch_ms(core.v_last_op_at()), kFixedMs);

  clock.advance(std::chrono::milliseconds(2000));
  ASSERT_EQ(core.v_close_session(h), CKR_OK);
  EXPECT_EQ(ClockUtils::to_epoch_ms(core.v_last_op_at()), kFixedMs + 2000);

  // After close, the handle is gone.
  EXPECT_EQ(core.v_get_session(h), nullptr);
}

TEST(v_SlotManagerCore_M1, UsesInjectedClockForRegistration) {
  FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
  v_SlotManagerCore_M1 core(clock);

  EXPECT_TRUE(core.v_register_slot(1));
  EXPECT_EQ(ClockUtils::to_epoch_ms(core.v_last_registration_at()), kFixedMs);

  // Duplicate registration is rejected.
  EXPECT_FALSE(core.v_register_slot(1));
  EXPECT_NE(core.v_get_slot(1), nullptr);
  EXPECT_EQ(core.v_get_slot(99), nullptr);

  core.v_reset();
  EXPECT_EQ(core.v_get_slot(1), nullptr);
}
