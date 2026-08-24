#include "thread_pool.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <thread>
#include <utility>

namespace vhsm::threadpool {

ThreadPool::ThreadPool(PoolConfig config)
    : high_capacity_(config.queue_capacity),
      low_capacity_(config.queue_capacity),
      worker_count_(resolve_worker_count(config.worker_count)),
      shutdown_grace_(config.shutdown_grace) {
  threads_.reserve(worker_count_);
  for (std::size_t i = 0; i < worker_count_; ++i)
    threads_.emplace_back(&ThreadPool::worker_thread, this, i);
}

std::size_t ThreadPool::resolve_worker_count(std::size_t requested) {
  if (requested != 0)
    return requested;

  std::size_t hw = std::thread::hardware_concurrency();
  return hw == 0 ? 1 : hw;
}

ThreadPool::~ThreadPool() { shutdown(); }

void ThreadPool::shutdown() { shutdown(shutdown_grace_); }

void ThreadPool::shutdown(std::chrono::milliseconds timeout) {
  {
    std::lock_guard<std::mutex> lock(state_mutex_);
    counters_.stopping.store(true, std::memory_order_release);
  }
  work_cv_.notify_all();

  // Wait (bounded) for the pool to actually drain before joining so that
  // still-queued work runs instead of being abandoned.
  {
    std::unique_lock<std::mutex> lock(shutdown_mutex_);
    shutdown_cv_.wait_for(lock, timeout, [this] {
      return counters_.running.load(std::memory_order_acquire) == 0 &&
             counters_.queued.load(std::memory_order_acquire) == 0;
    });
  }

  for (auto &thread : threads_) {
    if (thread.joinable())
      thread.join();
  }
}

bool ThreadPool::enqueue_locked(PrivilegeTier tier, TaskWorker &&worker) {
  if (tier == PrivilegeTier::High) {
    std::lock_guard<std::mutex> lock(high_mutex_);
    if (high_capacity_ > 0 && high_queue_.size() >= high_capacity_) {
      counters_.dropped.fetch_add(1, std::memory_order_release);
      return false;
    }
    high_queue_.emplace(std::move(worker));
  } else {
    std::lock_guard<std::mutex> lock(low_mutex_);
    if (low_capacity_ > 0 && low_queue_.size() >= low_capacity_) {
      counters_.dropped.fetch_add(1, std::memory_order_release);
      return false;
    }
    low_queue_.emplace(std::move(worker));
  }
  counters_.queued.fetch_add(1, std::memory_order_release);
  counters_.enqueued.fetch_add(1, std::memory_order_release);
  return true;
}

void ThreadPool::worker_thread(std::size_t thread_index) {
  (void)thread_index;
  while (true) {
    TaskWorker task;
    {
      std::unique_lock<std::mutex> lock(state_mutex_);
      work_cv_.wait(lock, [this] {
        return counters_.stopping.load(std::memory_order_acquire) ||
               counters_.queued.load(std::memory_order_acquire) > 0;
      });

      if (counters_.stopping.load(std::memory_order_acquire) &&
          counters_.queued.load(std::memory_order_acquire) == 0) {
        return;
      }
      // Release state lock before acquiring tier locks to avoid inversion
      lock.unlock();

      bool got = false;
      {
        std::lock_guard<std::mutex> hlock(high_mutex_);
        if (!high_queue_.empty()) {
          task = std::move(high_queue_.front());
          high_queue_.pop();
          got = true;
        }
      }
      if (!got) {
        std::lock_guard<std::mutex> llock(low_mutex_);
        if (!low_queue_.empty()) {
          task = std::move(low_queue_.front());
          low_queue_.pop();
          got = true;
        }
      }
      if (!got) {
        // Spurious wakeup or race: another worker stole the work, go back to wait
        continue;
      }
      counters_.queued.fetch_sub(1, std::memory_order_release);
    }

    counters_.running.fetch_add(1, std::memory_order_acquire);
    try {
      task();
    } catch (...) {
      // Individual tasks must not take the pool down; submit()
      // surfaces exceptions through its future instead.
    }
    counters_.running.fetch_sub(1, std::memory_order_release);
    counters_.executed.fetch_add(1, std::memory_order_release);
    shutdown_cv_.notify_all();
  }
}

void ThreadPool::validate_token(const CapabilityToken &token) {
  if (!token.is_valid())
    throw std::runtime_error(
        "ThreadPool: invalid task token, submission refused.");
}

} // namespace vhsm::threadpool
