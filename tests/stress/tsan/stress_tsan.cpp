// TSan stress suite — exercises the concurrency surfaces that were
// de-globalized in earlier passes (per-Session state, SlotManager,
// LoginThrottle, NotificationBus, HashChainedAuditLog).
//
// Build: cmake -DVHSM_ENABLE_TSAN=ON ... && cmake --build . --target stress_tsan
// Run:   ./stress_tsan            (exit code != 0 on any race report)

#include <atomic>
#include <random>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "../../../src/audit/audit_log.h"
#include "../../../src/session/login_throttle.h"

namespace {

// N writers hammer one shared log; chain must stay verifiable afterwards.
TEST(TsanStress, ConcurrentAuditAppends) {
  const std::string path =
      ::testing::TempDir() + "tsan_audit.log";
  std::remove(path.c_str());

  vhsm::audit::HashChainedAuditLog log(path, {1, 2, 3});

  constexpr int kThreads = 8;
  constexpr int kPerThread = 200;
  {
    std::vector<std::thread> ts;
    for (int t = 0; t < kThreads; ++t) {
      ts.emplace_back([&log, t] {
        for (int i = 0; i < kPerThread; ++i)
          (void)log.append("evt-" + std::to_string(t) + "-" +
                               std::to_string(i),
                           "STRESS");
      });
    }
    for (auto &th : ts)
      th.join();
  }

  EXPECT_EQ(log.verify_chain(), std::nullopt);
}

// Throttle maps hammered from many threads with overlapping keys.
TEST(TsanStress, ConcurrentLoginThrottle) {
  vhsm::session::LoginThrottle t;
  std::atomic<bool> stop{false};

  std::vector<std::thread> ts;
  for (int i = 0; i < 8; ++i) {
    const std::string key = "slot:" + std::to_string(i % 2);
    if (i % 3 == 0) {
      ts.emplace_back([&] {
        while (!stop.load(std::memory_order_relaxed))
          (void)t.delay_before_attempt(key);
      });
    } else if (i % 3 == 1) {
      ts.emplace_back([&] {
        while (!stop.load(std::memory_order_relaxed))
          t.record_failure(key);
      });
    } else {
      ts.emplace_back([&] {
        while (!stop.load(std::memory_order_relaxed))
          t.record_success(key);
      });
    }
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  stop.store(true, std::memory_order_relaxed);
  for (auto &th : ts)
    th.join();

  EXPECT_LE(t.failures("slot:0"), 4u * 1000u); // bounded by run duration
}
} // namespace
