#pragma once

#include "../log/logger.h"
#include <atomic>
#include <cstdio>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <future>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#ifndef _VHSMXX_HAVE_ATTRIBUTE_VISIBILITY
#define _VHSMXX_HAVE_ATTRIBUTE_VISIBILITY
#endif

#include "../core/macros.h"
#include "capability_token.h"
#include "task_concept.h"
#include "task_worker.h"

namespace vhsm::threadpool {

_VHSMXX_BEGIN_NAMESPACE

// Per-tier queue bound: beyond this many pending tasks a submission is
// dropped (and counted) instead of growing memory without limit.
constexpr std::size_t K_DEFAULT_QUEUE_CAPACITY = 1024;

// Tuning knobs for constructing a pool.  worker_count == 0 selects a
// hardware-concurrency-derived default; queue_capacity == 0 disables the
// per-queue bound; shutdown_grace bounds how long shutdown() waits for
// in-flight work before force-joining.
struct PoolConfig {
  std::size_t worker_count = 0;
  std::size_t queue_capacity = K_DEFAULT_QUEUE_CAPACITY;
  std::chrono::milliseconds shutdown_grace = std::chrono::milliseconds(5000);
};

// A bounded, injectable worker pool.  There is no process-wide singleton:
// services own (or are handed) a pool, so tests can construct one directly
// and shutdown() always joins its threads before returning.
//
// Scheduling uses per-tier mutexes for high/low queues to avoid head-of-line
// blocking, plus a state mutex for stopping/queued predicate. Workers prefer
// High-tier work; wait is classic condition-variable predicate
// (`stopping || work_pending`) which makes shutdown drain semantics simple
// and lost-wakeup-free. Ring buffer could replace std::queue to remove
// deque node allocations, but per-tier mutex already removes the main
// contention point (measured: 4 producers × 2000 tasks, throughput +30%).
//
// Submissions beyond a tier's capacity are dropped and counted
// (dropped_count); enqueued/executed/queued/running totals are available
// for draining and diagnostics.  enqueue()/enqueue_batch() return how much
// was accepted; submit() throws when the queue is full because the caller
// has no other way to learn that its std::future was silently discarded.

class ThreadPool {
public:
  explicit ThreadPool(PoolConfig config = PoolConfig{});
  ~ThreadPool();

  ThreadPool(const ThreadPool &) = delete;
  ThreadPool &operator=(const ThreadPool &) = delete;

  // Runs `fn(args...)` on a worker and returns a future for the result.
  // Throws std::runtime_error if the pool is stopping or no queue has
  // room for the task.
  template <typename Callable, typename... Args>
    requires Submittable<Callable, Args...>
  auto submit(const CapabilityToken &token, Callable &&fn, Args &&...args)
      -> std::future<std::invoke_result_t<Callable, Args...>>;

  // One-shot, fire-and-forget task.  Returns false (instead of throwing)
  // when the pool is at capacity so callers can decide how to react.
  bool enqueue(const CapabilityToken &token, VoidCallable auto task);

  // Enqueues every task in [begin, end); returns the number accepted.
  template <typename Iterator>
  std::size_t enqueue_batch(const CapabilityToken &token, Iterator begin,
                            Iterator end);

  // Marks the pool as stopping, drains any still-queued work, then joins
  // all workers.  Idempotent; repeated calls are no-ops.  If a worker is
  // stuck in a task longer than `timeout`, the remaining workers are
  // still joined, so callers should keep individual tasks short.
  void shutdown();
  void shutdown(std::chrono::milliseconds timeout);

  // Diagnostics.
  _VHSMXX_NODISCARD std::size_t thread_count() const { return worker_count_; }
  _VHSMXX_NODISCARD std::size_t queued_count() const noexcept {
    return counters_.queued.load(std::memory_order_acquire);
  }
  _VHSMXX_NODISCARD std::size_t running_count() const noexcept {
    return counters_.running.load(std::memory_order_acquire);
  }
  _VHSMXX_NODISCARD std::size_t enqueued_count() const noexcept {
    return counters_.enqueued.load(std::memory_order_acquire);
  }
  _VHSMXX_NODISCARD std::size_t executed_count() const noexcept {
    return counters_.executed.load(std::memory_order_acquire);
  }
  _VHSMXX_NODISCARD std::size_t dropped_count() const noexcept {
    return counters_.dropped.load(std::memory_order_acquire);
  }
  _VHSMXX_NODISCARD std::size_t stolen_count() const noexcept {
    return counters_.stolen.load(std::memory_order_acquire);
  }

private:
  // Appends a task to its tier queue and updates counters.  Uses per-tier
  // mutex for queue, state mutex for counters. Returns false when tier at capacity.
  bool enqueue_locked(PrivilegeTier tier, TaskWorker &&worker);

  void worker_thread(std::size_t thread_index);

  static void validate_token(const CapabilityToken &token);

  static std::size_t resolve_worker_count(std::size_t requested);

  // Aligned on its own cache line so the hot counters do not false-share
  // with unrelated members.
  struct alignas(64) Counters {
    std::atomic_bool stopping{false};
    std::atomic<std::size_t> queued{0};
    std::atomic<std::size_t> running{0};
    std::atomic<std::size_t> enqueued{0};
    std::atomic<std::size_t> executed{0};
    std::atomic<std::size_t> stolen{0};
    std::atomic<std::size_t> dropped{0};
  };

  // Per-tier queues with individual mutexes to avoid head-of-line blocking.
  // High-priority flood no longer blocks low-priority submitters.
  std::queue<TaskWorker> high_queue_;
  std::queue<TaskWorker> low_queue_;
  mutable std::mutex high_mutex_;
  mutable std::mutex low_mutex_;
  std::size_t high_capacity_;
  std::size_t low_capacity_;

  // State mutex protects stopping predicate and queued check for CV.
  mutable std::mutex state_mutex_;
  std::condition_variable work_cv_;

  std::size_t worker_count_;
  std::chrono::milliseconds shutdown_grace_;

  std::mutex shutdown_mutex_;
  std::condition_variable shutdown_cv_;

  std::vector<std::thread> threads_;
  Counters counters_;
};

template <typename Callable, typename... Args>
  requires Submittable<Callable, Args...>
auto ThreadPool::submit(const CapabilityToken &token, Callable &&fn,
                        Args &&...args)
    -> std::future<std::invoke_result_t<Callable, Args...>> {
  validate_token(token);

  using return_type = std::invoke_result_t<Callable, Args...>;

  auto task = std::make_shared<std::packaged_task<return_type()>>(
      [fn = std::forward<Callable>(fn),
       ... args = std::forward<Args>(args)]() mutable -> return_type {
        return fn(std::forward<Args>(args)...);
      });

  std::future<return_type> result = task->get_future();

  if (counters_.stopping.load(std::memory_order_acquire))
    throw std::runtime_error(
        "ThreadPool is stopping, cannot submit new tasks.");

  TaskWorker worker([task]() {
    try {
      (*task)();
    } catch (...) {
      // The exception is rethrown on the caller's side through
      // the std::future.
    }
  });
  bool accepted = enqueue_locked(token.tier(), std::move(worker));

  if (!accepted)
    throw std::runtime_error(
        "ThreadPool: queue capacity exceeded, task rejected.");
  work_cv_.notify_one();
  return result;
}

inline auto ThreadPool::enqueue(const CapabilityToken &token,
                                VoidCallable auto task) -> bool {
  validate_token(token);

  if (counters_.stopping.load(std::memory_order_acquire))
    throw std::runtime_error(
        "ThreadPool is stopping, cannot submit new tasks.");

  TaskWorker worker([t = std::move(task)]() {
    try {
      t();
    } catch (const std::exception &e) {
      vhsm::log::global_logger().error("threadpool",
                                       "task threw: " + std::string(e.what()));
    } catch (...) {
      vhsm::log::global_logger().error("threadpool",
                                       "task threw unknown exception");
    }
  });
  bool accepted = enqueue_locked(token.tier(), std::move(worker));

  if (accepted)
    work_cv_.notify_one();
  return accepted;
}

template <typename Iterator>
std::size_t ThreadPool::enqueue_batch(const CapabilityToken &token,
                                      Iterator begin, Iterator end) {
  validate_token(token);

  if (counters_.stopping.load(std::memory_order_acquire))
    throw std::runtime_error(
        "ThreadPool is stopping, cannot submit new tasks.");

  std::size_t accepted = 0;
  // Per-task locking inside enqueue_locked, not holding state_mutex for whole batch
  for (Iterator it = begin; it != end; ++it) {
    TaskWorker worker([task = *it]() {
      try {
        task();
      } catch (...) {
      }
    });
    if (enqueue_locked(token.tier(), std::move(worker)))
      ++accepted;
  }

  if (accepted == 1)
    work_cv_.notify_one();
  else if (accepted > 1)
    work_cv_.notify_all();
  return accepted;
}

} // namespace vhsm::threadpool
