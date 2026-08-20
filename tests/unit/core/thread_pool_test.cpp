// thread_pool_test.cpp — Unit tests for the vhsm::threadpool::ThreadPool.
//
// Pools are plain injectable objects (no process-wide singleton), so every
// test constructs one directly and lets shutdown() join its threads.

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include "../../../src/threadpool/capability_token.h"
#include "../../../src/threadpool/task_worker.h"
#include "../../../src/threadpool/thread_pool.h"

using vhsm::threadpool::CapabilityToken;
using vhsm::threadpool::PoolConfig;
using vhsm::threadpool::PrivilegeTier;
using vhsm::threadpool::ThreadPool;

namespace {

const auto kHigh = CapabilityToken::grant(PrivilegeTier::High);
const auto kLow = CapabilityToken::grant(PrivilegeTier::Low);

TEST(ThreadPoolTest, SubmitReturnsResultFromWorker) {
  ThreadPool pool(PoolConfig{4});

  auto f = pool.submit(kHigh, [](int a, int b) { return a + b; }, 20, 22);
  EXPECT_EQ(f.get(), 42);

  auto g = pool.submit(kLow, [] { return std::string("done"); });
  EXPECT_EQ(g.get(), "done");

  pool.shutdown();
}

TEST(ThreadPoolTest, SubmitPropagatesExceptionThroughFuture) {
  ThreadPool pool(PoolConfig{4});

  auto f =
      pool.submit(kHigh, []() -> int { throw std::runtime_error("boom"); });
  EXPECT_THROW(f.get(), std::runtime_error);

  pool.shutdown();
}

TEST(ThreadPoolTest, EnqueueRunsEveryTaskExactlyOnce) {
  ThreadPool pool(PoolConfig{4});

  constexpr int kTasks = 1000;
  std::atomic<int> ran{0};
  for (int i = 0; i < kTasks; ++i)
    pool.enqueue(kHigh,
                 [&ran] { ran.fetch_add(1, std::memory_order_relaxed); });

  // shutdown() drains the queues: nothing is lost when stopping with work.
  pool.shutdown();
  EXPECT_EQ(ran.load(), kTasks);
  EXPECT_EQ(pool.queued_count(), 0u);
  EXPECT_EQ(pool.running_count(), 0u);
  EXPECT_EQ(pool.enqueued_count(), static_cast<std::size_t>(kTasks));
  EXPECT_EQ(pool.dropped_count(), 0u);
}

TEST(ThreadPoolTest, ShutdownDrainsWorkSubmittedJustBeforeStop) {
  ThreadPool pool(PoolConfig{2});

  std::atomic<int> ran{0};
  for (int i = 0; i < 50; ++i)
    pool.enqueue(kLow, [&ran] { ran.fetch_add(1, std::memory_order_relaxed); });

  pool.shutdown(std::chrono::milliseconds(5000));
  EXPECT_EQ(ran.load(), 50);

  // Repeated shutdown is idempotent and must not block for the grace timeout.
  pool.shutdown();
}

TEST(ThreadPoolTest, ConcurrentProducersLoseNoTasksWhenBacklogFits) {
  ThreadPool pool(PoolConfig{4, 8192}); // 8192 slots per worker queue

  constexpr int kProducers = 4;
  constexpr int kPerProducer = 2000;
  std::atomic<int> ran{0};

  std::vector<std::thread> producers;
  for (int p = 0; p < kProducers; ++p) {
    producers.emplace_back([&pool, &ran] {
      for (int i = 0; i < kPerProducer; ++i)
        pool.enqueue(kHigh,
                     [&ran] { ran.fetch_add(1, std::memory_order_relaxed); });
    });
  }
  for (auto &t : producers)
    t.join();

  pool.shutdown();
  EXPECT_EQ(ran.load(), kProducers * kPerProducer);
  EXPECT_EQ(pool.enqueued_count(),
            static_cast<std::size_t>(kProducers * kPerProducer));
  EXPECT_EQ(pool.executed_count(),
            static_cast<std::size_t>(kProducers * kPerProducer));
  EXPECT_EQ(pool.dropped_count(), 0u);
  EXPECT_EQ(pool.queued_count(), 0u);
  EXPECT_EQ(pool.running_count(), 0u);
}

TEST(ThreadPoolTest, SingleCorePoolRunsHighAndLowTier) {
  // nCores == 1 has no low tier; Low-privilege tasks must fall back onto the
  // high-tier queue instead of dividing by zero.
  ThreadPool pool(PoolConfig{1});

  std::atomic<int> high{0};
  std::atomic<int> low{0};
  for (int i = 0; i < 20; ++i) {
    pool.enqueue(kHigh,
                 [&high] { high.fetch_add(1, std::memory_order_relaxed); });
    pool.enqueue(kLow, [&low] { low.fetch_add(1, std::memory_order_relaxed); });
  }

  pool.shutdown();
  EXPECT_EQ(high.load(), 20);
  EXPECT_EQ(low.load(), 20);
}

TEST(ThreadPoolTest, InvalidTokenIsRejected) {
  ThreadPool pool(PoolConfig{2});

  CapabilityToken forged; // default-constructed => invalid
  EXPECT_THROW(pool.enqueue(forged, [] {}), std::runtime_error);

  pool.shutdown();
}

TEST(ThreadPoolTest, SubmitAfterShutdownIsRejected) {
  ThreadPool pool(PoolConfig{2});
  pool.shutdown();

  EXPECT_THROW(pool.submit(kHigh, [] { return 1; }), std::runtime_error);
  EXPECT_THROW(pool.enqueue(kHigh, [] {}), std::runtime_error);
}

TEST(ThreadPoolTest, PoolsAreIndependent) {
  ThreadPool first(PoolConfig{2});
  ThreadPool second(PoolConfig{2});

  auto a = first.submit(kHigh, [] { return 7; });
  auto b = second.submit(kHigh, [] { return 9; });
  EXPECT_EQ(a.get(), 7);
  EXPECT_EQ(b.get(), 9);

  first.shutdown();
  second.shutdown();
}

TEST(ThreadPoolTest, EnqueueBatchRunsEveryTask) {
  ThreadPool pool(PoolConfig{4});

  constexpr int kTasks = 64;
  std::atomic<int> ran{0};
  std::vector<std::function<void()>> tasks;
  for (int i = 0; i < kTasks; ++i)
    tasks.emplace_back([&ran] { ran.fetch_add(1, std::memory_order_relaxed); });

  EXPECT_EQ(pool.enqueue_batch(kHigh, tasks.begin(), tasks.end()),
            static_cast<std::size_t>(kTasks));
  EXPECT_EQ(pool.dropped_count(), 0u);
  pool.shutdown();
  EXPECT_EQ(ran.load(), kTasks);
}

TEST(ThreadPoolTest, BoundedQueuesDropWhenFull) {
  using namespace std::chrono_literals;
  ThreadPool pool(PoolConfig{1, 2}); // one worker, two-slot queue

  // Occupies the sole worker so subsequent tasks pile up in the queue.
  std::promise<void> release;
  auto gate = release.get_future();
  ASSERT_TRUE(pool.enqueue(kHigh, [&gate] { gate.wait(); }));

  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (pool.running_count() != 1u &&
         std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);
  ASSERT_EQ(pool.running_count(), 1u);

  EXPECT_TRUE(pool.enqueue(kHigh, [] {}));
  EXPECT_TRUE(pool.enqueue(kHigh, [] {}));
  EXPECT_FALSE(pool.enqueue(kHigh, [] {})); // queue full: dropped

  release.set_value();
  pool.shutdown();
  EXPECT_EQ(pool.dropped_count(), 1u);
  EXPECT_EQ(pool.enqueued_count(), 3u);
  EXPECT_EQ(pool.executed_count(), 3u);
}

TEST(ThreadPoolTest, TaskWorkerIsMoveOnlyAndRelocates) {
  using vhsm::threadpool::TaskWorker;
  static_assert(!std::is_copy_constructible_v<TaskWorker>);
  static_assert(!std::is_copy_assignable_v<TaskWorker>);
  static_assert(std::is_move_constructible_v<TaskWorker>);
  static_assert(std::is_move_assignable_v<TaskWorker>);

  int inline_hits = 0;
  int heap_hits = 0;
  {
    // Each task carries a distinct uid; moving preserves it.
    TaskWorker small([&inline_hits] { ++inline_hits; });
    ASSERT_TRUE(static_cast<bool>(small));
    const auto small_uid = small.uid();

    // Callable larger than the inline buffer: heap fallback.
    std::array<unsigned char, 4096> payload{};
    payload[0] = 0xAA;
    TaskWorker big([payload, &heap_hits]() {
      if (payload[0] == 0xAA)
        ++heap_hits;
    });
    ASSERT_TRUE(static_cast<bool>(big));
    const auto big_uid = big.uid();
    EXPECT_NE(small_uid, big_uid);

    // Moving relocates the payload and leaves the source empty.
    TaskWorker moved(std::move(small));
    ASSERT_FALSE(static_cast<bool>(small));
    TaskWorker moved2(std::move(big));
    ASSERT_FALSE(static_cast<bool>(big));

    EXPECT_EQ(moved.uid(), small_uid);
    EXPECT_EQ(moved2.uid(), big_uid);

    moved();
    moved2();
  }
  EXPECT_EQ(inline_hits, 1);
  EXPECT_EQ(heap_hits, 1);
}

} // namespace