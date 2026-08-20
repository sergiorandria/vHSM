#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <future>
#include <iterator>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "singleton.h"
#include "aligned_task_queue.h"
#include "capability_token.h"
#include "task_concept.h"
#include "task_worker.h"

namespace vhsm::threadpool {

    // Process-wide pool of worker threads organised into two privilege tiers.
    //
    // Work is pushed into per-worker queues; a worker always drains its own
    // queue first and then steals from tier-legal neighbours (high-tier workers
    // may steal anywhere, low-tier workers only within their own tier) so a
    // burst of low-priority work cannot starve high-priority anchoring jobs.
    //
    // The pool is a singleton: only ISingleton<ThreadPool> may construct it.
    //
    // Hardening notes:
    //  - `queued_tasks_` vs `running_tasks_` are tracked separately.  Workers
    //    only wake when there is queued work to pop/steal, so a notification
    //    storm while a task is executing never causes a busy-spin.
    //  - shutdown() always joins the workers after signalling stop (it never
    //    detaches), so the pool object can never be destroyed underneath a
    //    worker that is still touching its state.
    class ThreadPool : public ISingleton<ThreadPool> {
        friend class ISingleton<ThreadPool>;
    public:
        ThreadPool(const ThreadPool&) = delete;
        ThreadPool& operator=(const ThreadPool&) = delete;

        ~ThreadPool();

        // Submit a callable (with optional arguments) that produces a result;
        // returns a future for it.  The task always runs exactly once, even if
        // the callable throws (the exception is rethrown by get()).
        template <typename Callable, typename... Args>
            requires Submittable<Callable, Args...>
        auto submit(const CapabilityToken& token, Callable&& fn, Args&&... args)
            -> std::future<std::invoke_result_t<Callable, Args...>>;

        // Fire-and-forget enqueue of a void callable.
        auto enqueue(const CapabilityToken& token, VoidCallable auto task) -> void;

        // Enqueue a homogeneous range of callables.
        template <typename Iterator>
        void enqueue_batch(const CapabilityToken& token, Iterator begin, Iterator end);

        // Stop accepting work and drain the queues.  Waits up to `timeout` for
        // every queued and running task to complete (grace period); when the
        // period elapses first it still blocks until the workers exit, because
        // a detached worker would touch freed pool state.
        void shutdown(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

        // Reserved: pins a worker's stack/uid for future affinity use.
        template <typename... Args, std::size_t StealProcStackSz = 256>
        void steal_pool_uid(Args... args);

        // Diagnostics (all thread-safe):
        std::size_t thread_count() const { return cpu_cores_; }
        std::size_t queued_count() const noexcept { return queued_tasks_.load(std::memory_order_acquire); }
        std::size_t running_count() const noexcept { return running_tasks_.load(std::memory_order_acquire); }

    private:
        void worker_thread(std::size_t thread_index);

        // Pop from own queue, then steal from tier-legal neighbours.  Returns
        // true and fills `out` when work was claimed, decrementing queued_tasks_.
        bool try_take_task(std::size_t thread_index, std::size_t tier_begin,
                           std::size_t tier_end, TaskWorker& out);

        static void validate_token(const CapabilityToken& token)
        {
            if (!token.is_valid())
                throw std::runtime_error("Invalid or revoked capability token.");
        }

        // Round-robins submissions across the queues of the given tier so no
        // single worker's queue becomes a hot spot.  A single-core pool has no
        // low tier, so Low-privilege work falls back onto the high-tier queue.
        std::size_t queue_index_for_tier(PrivilegeTier tier)
        {
            if (tier == PrivilegeTier::High || low_tier_cores_ == 0)
                return next_high_queue_index_.fetch_add(1, std::memory_order_relaxed) % high_tier_cores_;
            else
                return high_tier_cores_ + (next_low_queue_index_.fetch_add(1, std::memory_order_relaxed) % low_tier_cores_);
        }

        bool is_high_tier_worker(std::size_t thread_index) const
        {
            return thread_index < high_tier_cores_;
        }

        explicit ThreadPool(std::size_t ncpus);

        std::mutex              submit_mutex_;
        std::size_t             cpu_cores_;
        std::size_t             high_tier_cores_;
        std::size_t             low_tier_cores_;
        std::condition_variable work_cv_;

        // Guards the graceful-shutdown quiescence wait (see shutdown()).
        std::mutex              shutdown_mutex_;
        std::condition_variable shutdown_cv_;

        std::vector<std::thread>          threads_;
        std::vector<AlignedTaskQueue>     task_queues_;

        std::atomic_bool         stopping_ = false;
        std::atomic<std::size_t> next_high_queue_index_ = 0;
        std::atomic<std::size_t> next_low_queue_index_ = 0;
        std::atomic<std::size_t> queued_tasks_ = 0;  // sitting in queues (work available)
        std::atomic<std::size_t> running_tasks_ = 0; // claimed by a worker, not yet finished
    };

    template <typename Callable, typename... Args>
        requires Submittable<Callable, Args...>
    auto ThreadPool::submit(const CapabilityToken& token, Callable&& fn, Args&&... args)
        -> std::future<std::invoke_result_t<Callable, Args...>>
    {
        validate_token(token);

        using return_type = std::invoke_result_t<Callable, Args...>;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            [fn = std::forward<Callable>(fn), ...args = std::forward<Args>(args)]()
            mutable -> return_type {
                return fn(std::forward<Args>(args)...);
            });

        std::future<return_type> result = task->get_future();
        {
            std::lock_guard<std::mutex> lock(submit_mutex_);

            if (stopping_.load(std::memory_order_acquire))
                throw std::runtime_error("ThreadPool is stopping, cannot submit new tasks.");

            std::size_t queue_index = queue_index_for_tier(token.tier());
            {
                std::unique_lock<std::mutex> queue_lock(task_queues_[queue_index].queue_mutex_);
                task_queues_[queue_index].task_queue_.emplace(
                    [task]() {
                        try { (*task)(); }
                        catch (...) {}
                    });
                queued_tasks_.fetch_add(1, std::memory_order_release);
            }
        }
        work_cv_.notify_one();

        return result;
    }

    inline auto ThreadPool::enqueue(const CapabilityToken& token, VoidCallable auto task) -> void
    {
        validate_token(token);

        std::lock_guard<std::mutex> lock(submit_mutex_);

        if (stopping_.load(std::memory_order_acquire))
            throw std::runtime_error("ThreadPool is stopping, cannot submit new tasks.");

        std::size_t queue_index = queue_index_for_tier(token.tier());
        {
            std::unique_lock<std::mutex> queue_lock(task_queues_[queue_index].queue_mutex_);
            task_queues_[queue_index].task_queue_.emplace(
                [t = std::move(task)]() -> void {
                    try { t(); }
                    catch (...) {}
                });
            queued_tasks_.fetch_add(1, std::memory_order_release);
        }
        work_cv_.notify_one();
    }

    template <typename Iterator>
    void ThreadPool::enqueue_batch(const CapabilityToken& token, Iterator begin, Iterator end)
    {
        validate_token(token);

        std::size_t count = 0;
        {
            std::lock_guard<std::mutex> submit_lock(submit_mutex_);

            if (stopping_.load(std::memory_order_acquire))
                throw std::runtime_error("ThreadPool is stopping, cannot acquire new task");

            for (Iterator it = begin; it != end; ++it)
            {
                std::size_t queue_index = queue_index_for_tier(token.tier());
                {
                    std::unique_lock<std::mutex> queue_lock(task_queues_[queue_index].queue_mutex_);
                    task_queues_[queue_index].task_queue_.emplace(
                        [task = *it]() -> void {
                            try { task(); }
                            catch (...) {}
                        });
                    ++count;
                }
            }
            queued_tasks_.fetch_add(count, std::memory_order_release);
        }

        if (count == 0)
            return;
        else if (count == 1)
            work_cv_.notify_one();
        else
            work_cv_.notify_all();
    }

    template <typename... Args, std::size_t StealProcStackSz>
    inline void ThreadPool::steal_pool_uid(Args... args) {}

} // namespace vhsm::threadpool