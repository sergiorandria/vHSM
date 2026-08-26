#include "../../../src/session/login_throttle.h"

#include <gtest/gtest.h>

using vhsm::session::LoginThrottle;

TEST(LoginThrottle, NoDelayBeforeSoftThreshold) {
  LoginThrottle t;
  for (int i = 0; i < 2; ++i)
    t.record_failure("slot:1");
  EXPECT_EQ(t.delay_before_attempt("slot:1"), 0u);
}

TEST(LoginThrottle, ExponentialDelayProgression) {
  LoginThrottle t({.soft_threshold = 3,
                   .base_delay_ms = 250,
                   .max_delay_ms = 8000});
  t.record_failure("k");
  t.record_failure("k");
  EXPECT_EQ(t.delay_before_attempt("k"), 0u); // 2 < 3

  t.record_failure("k");
  EXPECT_EQ(t.delay_before_attempt("k"), 250u); // base

  t.record_failure("k");
  EXPECT_EQ(t.delay_before_attempt("k"), 500u);

  t.record_failure("k");
  EXPECT_EQ(t.delay_before_attempt("k"), 1000u);
}

TEST(LoginThrottle, DelayCapped) {
  LoginThrottle t({.soft_threshold = 1,
                   .base_delay_ms = 250,
                   .max_delay_ms = 8000});
  for (int i = 0; i < 20; ++i)
    t.record_failure("k");
  EXPECT_EQ(t.delay_before_attempt("k"), 8000u);
}

TEST(LoginThrottle, SuccessResets) {
  LoginThrottle t;
  for (int i = 0; i < 5; ++i)
    t.record_failure("k");
  EXPECT_GT(t.delay_before_attempt("k"), 0u);
  t.record_success("k");
  EXPECT_EQ(t.failures("k"), 0u);
  EXPECT_EQ(t.delay_before_attempt("k"), 0u);
}

TEST(LoginThrottle, IndependentKeys) {
  LoginThrottle t;
  for (int i = 0; i < 4; ++i)
    t.record_failure("a");
  t.record_failure("b");
  EXPECT_GT(t.delay_before_attempt("a"), 0u);
  EXPECT_EQ(t.delay_before_attempt("b"), 0u);
}
