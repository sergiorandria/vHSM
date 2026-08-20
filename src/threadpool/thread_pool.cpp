#include "thread_pool.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <utility>

namespace vhsm::threadpool {

    ThreadPool::ThreadPool(std::size_t ncpus) : cpu_cores_(ncpus)
    {
        if (ncpus == 0)
            throw std::runtime_error("ThreadPool: required at least one worker core");

        high_tier_cores_ = std::max<std::size_t>(1, ncpus / 2);
        // ncpus == 1 yields low_tier_cores_ == 0; Low-privilege submissions are
        // routed onto the high-tier queue by queue_index_for_tier() in that case.
        low_tier_cores_ = ncpus - high_tier_cores_;

        task_queues_.resize(ncpus);
        threads_.reserve(ncpus);
        for (std::size_t i = 0; i < ncpus; ++i)
            threads_.emplace_back(&ThreadPool::worker_thread, this, i);
    }

    ThreadPool::~ThreadPool()
    {
        shutdown();
    }

    void ThreadPool::shutdown(std::chrono::milliseconds timeout)
    {
        {
            std::lock_guard<std::mutex> lock(submit_mutex_);
            stopping_.store(true, std::memory_order_release);
        }
        work_cv_.notify_all();

        // Grace period: wait until every task has been drained and no worker is
        // still executing one.  Workers notify shutdown_cv_ every time they
        // finish a task.  If `timeout` elapses first (e.g. a task is slow), we
        // do NOT detach: join() below still waits for the workers to run the
        // remaining queue and exit, which is the only choice that guarantees
        // the pool is never destroyed underneath a live worker.
        {
            std::unique_lock<std::mutex> lock(shutdown_mutex_);
            shutdown_cv_.wait_for(lock, timeout, [this] {
                return running_tasks_.load(std::memory_order_acquire) == 0
                    && queued_tasks_.load(std::memory_order_acquire) == 0;
            });
        }

        for (auto& thread : threads_)
        {
            if (thread.joinable())
                thread.join();
        }
    }

    bool ThreadPool::try_take_task(std::size_t thread_index, std::size_t tier_begin,
                                   std::size_t tier_end, TaskWorker& out)
    {
        // Own queue first: cheap, cache-friendly, preserves submission order
        // for a single consumer.
        {
            std::unique_lock<std::mutex> lock(task_queues_[thread_index].queue_mutex_);
            if (!task_queues_[thread_index].task_queue_.empty())
            {
                out = std::move(task_queues_[thread_index].task_queue_.front());
                task_queues_[thread_index].task_queue_.pop();
                queued_tasks_.fetch_sub(1, std::memory_order_release);
                return true;
            }
        }

        // Steal from tier-legal neighbours.  try_to_lock avoids two workers
        // fighting over the same foreign queue (one of them steals, the other
        // simply finds it locked and moves on).
        for (std::size_t i = tier_begin; i < tier_end; ++i)
        {
            if (i == thread_index)
                continue;

            std::unique_lock<std::mutex> lock(task_queues_[i].queue_mutex_, std::try_to_lock);
            if (lock.owns_lock() && !task_queues_[i].task_queue_.empty())
            {
                out = std::move(task_queues_[i].task_queue_.front());
                task_queues_[i].task_queue_.pop();
                queued_tasks_.fetch_sub(1, std::memory_order_release);
                return true;
            }
        }

        return false;
    }

    void ThreadPool::worker_thread(std::size_t thread_index)
    {
        // Stealing boundaries.  High-tier workers may steal across the full
        // range [0, cpu_cores_); low-tier workers steal only within their tier.
        const std::size_t tier_begin = is_high_tier_worker(thread_index) ? 0 : high_tier_cores_;
        const std::size_t tier_end   = is_high_tier_worker(thread_index) ? cpu_cores_ : cpu_cores_;

        while (true)
        {
            TaskWorker task;
            if (try_take_task(thread_index, tier_begin, tier_end, task))
            {
                running_tasks_.fetch_add(1, std::memory_order_acquire);
                try {
                    task();
                } catch (...) {
                    // Defensive: task wrappers already swallow exceptions, but a
                    // stray throw must never escape and terminate the worker.
                }
                running_tasks_.fetch_sub(1, std::memory_order_release);
                shutdown_cv_.notify_all();
                continue;
            }

            // Nothing to do: block until work appears or the pool is stopping.
            // The predicate is keyed on *queued* work only, so workers that
            // missed a race for the last task sleep immediately instead of
            // spinning while the winning worker finishes its task.
            std::unique_lock<std::mutex> lock(submit_mutex_);
            work_cv_.wait(lock, [this] {
                return stopping_.load(std::memory_order_acquire)
                    || queued_tasks_.load(std::memory_order_acquire) > 0;
            });

            // Stopping with nothing left queued: every worker exits and
            // shutdown() joins them.  A worker still executing its last task
            // finishes it here first (running_tasks_ is only for diagnostics).
            if (stopping_.load(std::memory_order_acquire)
                && queued_tasks_.load(std::memory_order_acquire) == 0)
                return;
        }
    }

} // namespace vhsm::threadpool