#pragma once

#include <cstddef>
#include <mutex>
#include <queue>

#include "task_worker.h"

namespace vhsm::threadpool {

    // One work queue per worker thread.  The whole struct is cache-line aligned
    // so distinct workers operating on distinct queues never false-share the
    // same cache line.
    //
    // std::mutex is non-movable, so to keep this type usable inside a
    // std::vector that is resized during construction, the move operations move
    // only the task queue and simply default-construct the mutex (a moved-from
    // mutex is never observed because all mutation happens after the vector has
    // reached its final size and the pool threads have started).
    struct alignas(64) AlignedTaskQueue {
        AlignedTaskQueue() = default;

        AlignedTaskQueue(const AlignedTaskQueue&) = delete;
        AlignedTaskQueue& operator=(const AlignedTaskQueue&) = delete;

        AlignedTaskQueue(AlignedTaskQueue&& other) noexcept
            : task_queue_(std::move(other.task_queue_)) {}

        AlignedTaskQueue& operator=(AlignedTaskQueue&& other) noexcept
        {
            if (this != &other)
                task_queue_ = std::move(other.task_queue_);
            return *this;
        }

        std::mutex        queue_mutex_;
        std::queue<TaskWorker> task_queue_;
    };

} // namespace vhsm::threadpool