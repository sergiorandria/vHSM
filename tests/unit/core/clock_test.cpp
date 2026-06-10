// ---------------------------------------------------------------------------
// tests/core/test_clock.cpp
// ---------------------------------------------------------------------------
#include "../../../src/core/clock.h"
#include <gtest/gtest.h>
#include <chrono>
#include <optional>
#include <thread>

using namespace vhsm;
using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// SystemHsmClock
// ---------------------------------------------------------------------------

TEST(SystemHsmClock, ReturnsNonZeroTime) {
    SystemHsmClock clock;
    auto t = clock.now();
    // Must be well past the Unix epoch (year 2000 = 946684800000 ms)
    EXPECT_GT(ClockUtils::to_epoch_ms(t), 946'684'800'000LL);
}

TEST(SystemHsmClock, MonotonicallyIncreases) {
    SystemHsmClock clock;
    auto t1 = clock.now();
    std::this_thread::sleep_for(5ms);
    auto t2 = clock.now();
    EXPECT_GE(t2, t1);
}

TEST(SystemHsmClock, TruncatedToMilliseconds) {
    // HsmTimePoint has millisecond resolution by construction; calling now()
    // twice in rapid succession should give a value whose sub-millisecond
    // part is always zero (i.e. the duration count IS epoch-ms, not epoch-ns).
    SystemHsmClock clock;
    auto tp = clock.now();
    auto ms = ClockUtils::to_epoch_ms(tp);
    // Reconstruct and compare — round-trip must be exact.
    EXPECT_EQ(ClockUtils::from_epoch_ms(ms), tp);
}

// ---------------------------------------------------------------------------
// FrozenHsmClock
// ---------------------------------------------------------------------------

TEST(FrozenHsmClock, ReturnsSameValueRepeatedly) {
    const auto fixed = ClockUtils::from_epoch_ms(1'700'000'000'000LL);
    FrozenHsmClock clock(fixed);

    EXPECT_EQ(clock.now(), fixed);
    EXPECT_EQ(clock.now(), fixed);
    EXPECT_EQ(clock.now(), fixed);
}

TEST(FrozenHsmClock, AdvanceMovesTimeForward) {
    const auto start = ClockUtils::from_epoch_ms(1'000'000'000'000LL);
    FrozenHsmClock clock(start);

    clock.advance(1000ms);
    EXPECT_EQ(ClockUtils::to_epoch_ms(clock.now()), 1'000'001'000LL);

    clock.advance(500ms);
    EXPECT_EQ(ClockUtils::to_epoch_ms(clock.now()), 1'000'001'500LL);
}

TEST(FrozenHsmClock, SetSnapsToGivenTime) {
    FrozenHsmClock clock(ClockUtils::from_epoch_ms(0));
    clock.set(ClockUtils::from_epoch_ms(999'999LL));
    EXPECT_EQ(ClockUtils::to_epoch_ms(clock.now()), 999'999LL);
}

TEST(FrozenHsmClock, CanBeUsedViaInterface) {
    // Ensure IHsmClock* polymorphism works — the primary reason for the
    // pure-virtual design.
    const auto fixed = ClockUtils::from_epoch_ms(42'000LL);
    FrozenHsmClock fake(fixed);
    const IHsmClock& ref = fake;
    EXPECT_EQ(ClockUtils::to_epoch_ms(ref.now()), 42'000LL);
}

// ---------------------------------------------------------------------------
// ClockUtils::to_epoch_ms / from_epoch_ms round-trip
// ---------------------------------------------------------------------------

TEST(ClockUtils, EpochMsRoundTrip) {
    for (int64_t ms : {0LL, 1LL, 999LL, 1'000LL,
                       1'700'000'000'000LL,    // ~ Nov 2023
                       9'999'999'999'999LL}) {  // ~ year 2286
        EXPECT_EQ(ClockUtils::to_epoch_ms(ClockUtils::from_epoch_ms(ms)), ms)
            << "failed for ms=" << ms;
    }
}

TEST(ClockUtils, NegativeEpochMsBeforeUnixEpoch) {
    // Timestamps before 1970 are valid (e.g. for token "created" fields that
    // might be backfilled, or for test fixtures).
    const int64_t ms = -1'000LL;  // one second before epoch
    EXPECT_EQ(ClockUtils::to_epoch_ms(ClockUtils::from_epoch_ms(ms)), ms);
}

// ---------------------------------------------------------------------------
// ClockUtils::to_iso8601
// ---------------------------------------------------------------------------

TEST(ClockUtils, ToIso8601UnixEpoch) {
    auto tp = ClockUtils::from_epoch_ms(0);
    EXPECT_EQ(ClockUtils::to_iso8601(tp), "1970-01-01T00:00:00.000Z");
}

TEST(ClockUtils, ToIso8601KnownTimestamp) {
    // 1700000000000 ms = 2023-11-14T22:13:20.000Z  (verified externally)
    auto tp = ClockUtils::from_epoch_ms(1'700'000'000'000LL);
    EXPECT_EQ(ClockUtils::to_iso8601(tp), "2023-11-14T22:13:20.000Z");
}

TEST(ClockUtils, ToIso8601MillisecondPrecision) {
    // epoch 0 + 123 ms
    auto tp = ClockUtils::from_epoch_ms(123LL);
    EXPECT_EQ(ClockUtils::to_iso8601(tp), "1970-01-01T00:00:00.123Z");
}

TEST(ClockUtils, ToIso8601AlwaysEndsWithZ) {
    SystemHsmClock clock;
    auto s = ClockUtils::to_iso8601(clock.now());
    EXPECT_EQ(s.back(), 'Z');
}

// ---------------------------------------------------------------------------
// ClockUtils::from_iso8601
// ---------------------------------------------------------------------------

TEST(ClockUtils, FromIso8601RoundTrip) {
    for (int64_t ms : {0LL, 1'000LL, 1'700'000'000'000LL}) {
        auto tp  = ClockUtils::from_epoch_ms(ms);
        auto iso = ClockUtils::to_iso8601(tp);
        auto back = ClockUtils::from_iso8601(iso);
        ASSERT_TRUE(back.has_value()) << "parse failed for: " << iso;
        EXPECT_EQ(ClockUtils::to_epoch_ms(*back), ms);
    }
}

TEST(ClockUtils, FromIso8601WithoutMilliseconds) {
    // "Z" suffix without ".mmm" — should parse to ms = 0 within that second.
    auto result = ClockUtils::from_iso8601("1970-01-01T00:00:00Z");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(ClockUtils::to_epoch_ms(*result), 0LL);
}

TEST(ClockUtils, FromIso8601RejectsLocalOffset) {
    EXPECT_FALSE(ClockUtils::from_iso8601("2025-01-01T00:00:00+02:00").has_value());
}

TEST(ClockUtils, FromIso8601RejectsMalformed) {
    EXPECT_FALSE(ClockUtils::from_iso8601("").has_value());
    EXPECT_FALSE(ClockUtils::from_iso8601("not-a-date").has_value());
    EXPECT_FALSE(ClockUtils::from_iso8601("2025-13-01T00:00:00Z").has_value());
}

// ---------------------------------------------------------------------------
// Injection pattern — the reason for the pure-virtual interface
// ---------------------------------------------------------------------------

// Simulates a component that takes IHsmClock by const-ref.
struct RecordCreator {
    const IHsmClock& clock;

    struct Record { int64_t created_at_ms; };

    Record create() const {
        return { ClockUtils::to_epoch_ms(clock.now()) };
    }
};

TEST(ClockInjection, ComponentUsesInjectedClock) {
    FrozenHsmClock fake(ClockUtils::from_epoch_ms(5'000LL));
    RecordCreator  creator{fake};

    auto r1 = creator.create();
    EXPECT_EQ(r1.created_at_ms, 5'000LL);

    fake.advance(1000ms);
    auto r2 = creator.create();
    EXPECT_EQ(r2.created_at_ms, 6'000LL);
}