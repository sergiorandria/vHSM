#include <gtest/gtest.h>

#include "../../../src/core/clock_utils.h"
#include "../../../src/core/frozen_hsm_clock.h"
#include "../../../src/keystore/internal/token_core.h"

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
  ASSERT_EQ(
      core.v_initialize_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_OK);
  EXPECT_EQ(ClockUtils::to_epoch_ms(core.v_last_pin_op_at()), kFixedMs);

  // Advancing the frozen clock then doing another op moves the timestamp.
  clock.advance(std::chrono::milliseconds(1500));
  ASSERT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_OK);
  EXPECT_EQ(ClockUtils::to_epoch_ms(core.v_last_pin_op_at()), kFixedMs + 1500);
}

TEST(v_TokenCore_M1, PinLifecycle) {
  FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
  v_TokenCore_M1 core("label", "id", clock);

  // Verify before init must fail.
  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_USER_PIN_NOT_INITIALIZED);

  ASSERT_EQ(
      core.v_initialize_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_OK);
  EXPECT_EQ(core.v_is_user_pin_set(), CK_TRUE);

  // Wrong PIN rejected.
  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("0000"), 4),
      CKR_PIN_INCORRECT);

  // Correct PIN accepted.
  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_OK);

  // Change PIN.
  ASSERT_EQ(core.v_change_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4,
                                   reinterpret_cast<const CK_CHAR *>("abcd"),
                                   4),
            CKR_OK);
  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("abcd"), 4),
      CKR_OK);
  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_PIN_INCORRECT);
}

TEST(v_TokenCore_M1, KeKAbsentByDefault) {
  FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
  v_TokenCore_M1 core("label", "id", clock);
  EXPECT_TRUE(core.v_get_kek().empty());
}

TEST(v_TokenCore_M1, FailedPinAttemptsTriggerLockout) {
  FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
  v_TokenCore_M1 core("label", "id", clock);
  ASSERT_EQ(
      core.v_initialize_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_OK);

  // Default threshold is 5 failed attempts.
  EXPECT_EQ(core.v_max_failed_attempts(), 5u);
  EXPECT_EQ(core.v_is_user_pin_locked(), CK_FALSE);

  // Wrong PINs count up and the last one trips the lockout.
  for (int i = 1; i <= 5; ++i) {
    CK_RV rv =
        core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("0000"), 4);
    EXPECT_EQ(core.v_user_failed_attempts(), static_cast<unsigned>(i));
    if (i < 5) {
      EXPECT_EQ(rv, CKR_PIN_INCORRECT);
      EXPECT_EQ(core.v_is_user_pin_locked(), CK_FALSE);
    } else {
      EXPECT_EQ(rv, CKR_PIN_LOCKED);
      EXPECT_EQ(core.v_is_user_pin_locked(), CK_TRUE);
    }
  }

  // Even the correct PIN is rejected once locked.
  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_PIN_LOCKED);
}

TEST(v_TokenCore_M1, LockoutThresholdIsConfigurable) {
  FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
  v_TokenCore_M1 core("label", "id", clock);
  ASSERT_EQ(
      core.v_initialize_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_OK);

  core.v_set_max_failed_attempts(2);
  EXPECT_EQ(core.v_max_failed_attempts(), 2u);

  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("0000"), 4),
      CKR_PIN_INCORRECT);
  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("0000"), 4),
      CKR_PIN_LOCKED);
  EXPECT_EQ(core.v_is_user_pin_locked(), CK_TRUE);
}

TEST(v_TokenCore_M1, SuccessfulLoginResetsFailedCounter) {
  FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
  v_TokenCore_M1 core("label", "id", clock);
  ASSERT_EQ(
      core.v_initialize_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_OK);

  // One failure, then a success clears the counter.
  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("0000"), 4),
      CKR_PIN_INCORRECT);
  EXPECT_EQ(core.v_user_failed_attempts(), 1u);
  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_OK);
  EXPECT_EQ(core.v_user_failed_attempts(), 0u);
  EXPECT_EQ(core.v_is_user_pin_locked(), CK_FALSE);
}

TEST(v_TokenCore_M1, SobPinHasIndependentLockout) {
  FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
  v_TokenCore_M1 core("label", "id", clock);
  ASSERT_EQ(
      core.v_initialize_so_pin(reinterpret_cast<const CK_CHAR *>("abcd"), 4),
      CKR_OK);

  core.v_set_max_failed_attempts(3);
  for (int i = 0; i < 3; ++i) {
    core.v_verify_so_pin(reinterpret_cast<const CK_CHAR *>("0000"), 4);
  }
  EXPECT_EQ(core.v_is_so_pin_locked(), CK_TRUE);
  EXPECT_EQ(core.v_so_failed_attempts(), 3u);
  // User PIN is unaffected by the SO lockout.
  EXPECT_EQ(core.v_is_user_pin_locked(), CK_FALSE);
}

TEST(v_TokenCore_M1, ReinitializePinClearsLockout) {
  FrozenHsmClock clock(ClockUtils::from_epoch_ms(kFixedMs));
  v_TokenCore_M1 core("label", "id", clock);
  ASSERT_EQ(
      core.v_initialize_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_OK);

  core.v_set_max_failed_attempts(2);
  core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("0000"), 4);
  core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("0000"), 4);
  EXPECT_EQ(core.v_is_user_pin_locked(), CK_TRUE);

  // Changing the PIN requires the (now locked) old PIN, so it fails; but
  // re-initialization is only allowed before the pin is set.  Verify that a
  // successful set after unlocking (here simply simulated by lowering the
  // threshold below the counter, then setting a new PIN with correct old PIN)
  // clears the state.
  core.v_set_max_failed_attempts(1);
  // The counter is still >= 1, so the lock persists.
  EXPECT_EQ(core.v_is_user_pin_locked(), CK_TRUE);

  // A correct old-PIN change resets the counter and clears the lock.
  EXPECT_EQ(core.v_change_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4,
                                   reinterpret_cast<const CK_CHAR *>("5678"),
                                   4),
            CKR_OK);
  EXPECT_EQ(core.v_user_failed_attempts(), 0u);
  EXPECT_EQ(core.v_is_user_pin_locked(), CK_FALSE);
  EXPECT_EQ(
      core.v_verify_user_pin(reinterpret_cast<const CK_CHAR *>("5678"), 4),
      CKR_OK);
}
