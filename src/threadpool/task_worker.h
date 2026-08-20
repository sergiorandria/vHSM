#pragma once

#include <atomic>
#include <cstddef>
#include <new>
#include <type_traits>
#include <utility>

#include "task_concept.h"

namespace vhsm::threadpool {

// Maximum payload stored inline, without a heap allocation, per task.
constexpr std::size_t k_task_worker_capacity = 256;

// Move-only, type-erased holder for a nullary callable.
//
// Inspired by the fast-wc task worker: the callable lives in a fixed-size
// inline buffer and is relocated (never copied) via type-erased function
// pointers, so enqueuing/running a task performs no heap allocation in the
// common case.  Callables larger than k_task_worker_capacity fall back to a
// single heap allocation so large payloads (e.g. a captured SignatureRecord)
// keep working; the excess cost is invisible to the worker (invoke, move and
// cleanup are one indirection either way).
//
// Invariants:
//  - Empty when constructed (operator bool == false).
//  - Never copied, only moved; a moved-from task worker is empty.
//  - A task is invocable at most once (call operator() while non-empty).
class TaskWorker {
public:
  TaskWorker() noexcept = default;
  ~TaskWorker() noexcept { reset(); }

  TaskWorker(const TaskWorker &) = delete;
  TaskWorker &operator=(const TaskWorker &) = delete;

  TaskWorker(TaskWorker &&other) noexcept;
  TaskWorker &operator=(TaskWorker &&other) noexcept;

  // Takes an rvalue callable so a task can never alias a caller's lvalue.
  // The callable is invoked with no arguments.
  template <typename Callable> explicit TaskWorker(Callable &&task);

  void operator()();

  explicit operator bool() const noexcept { return data_ != nullptr; }

  // Diagnostics: monotonically increasing identity for this task.
  std::size_t uid() const noexcept { return uid_; }

private:
  void reset() noexcept;
  void transfer(TaskWorker &&other) noexcept;
  void make_empty() noexcept;

  static std::atomic<std::size_t> next_uid_;

  // How the callable is stored:
  //   data_ == buffer_                 inline (on the stack)
  //   data_ != nullptr && heap_        caller-allocated block
  //   data_ == nullptr                 empty
  void *data_ = nullptr;
  alignas(std::max_align_t) std::byte buffer_[k_task_worker_capacity];
  bool heap_allocated_ = false;

  std::size_t uid_ = 0;

  // Type-erased operations over the callable object at `data_`.
  void (*invoke_)(void *) = nullptr;
  void (*move_)(void *dst, void *src) = nullptr;
  void (*cleanup_)(void *) = nullptr;
};

inline std::atomic<std::size_t> TaskWorker::next_uid_{0};

template <typename Callable> TaskWorker::TaskWorker(Callable &&task) {
  static_assert(std::is_same_v<Callable, std::decay_t<Callable>>,
                "TaskWorker requires an rvalue callable (wrap in std::move)");
  static_assert(std::is_invocable_v<Callable>,
                "TaskWorker callable must be invocable without arguments");
  using callable_type = std::decay_t<Callable>;
  static_assert(alignof(callable_type) <= alignof(std::max_align_t),
                "TaskWorker callable alignment exceeds the inline capacity");
  if constexpr (sizeof(callable_type) <= k_task_worker_capacity) {
    data_ = buffer_;
  } else {
    data_ = ::operator new(sizeof(callable_type));
    heap_allocated_ = true;
  }
  new (data_) callable_type(std::move(task));
  uid_ = next_uid_.fetch_add(1, std::memory_order_relaxed);
  invoke_ = [](void *data) { (*static_cast<callable_type *>(data))(); };
  move_ = [](void *dst, void *src) {
    new (dst) callable_type(std::move(*static_cast<callable_type *>(src)));
    static_cast<callable_type *>(src)->~callable_type();
  };
  cleanup_ = [](void *data) {
    static_cast<callable_type *>(data)->~callable_type();
  };
}

inline TaskWorker::TaskWorker(TaskWorker &&other) noexcept {
  if (other)
    transfer(std::move(other));
}

inline TaskWorker &TaskWorker::operator=(TaskWorker &&other) noexcept {
  if (this != &other) {
    reset();
    if (other)
      transfer(std::move(other));
  }
  return *this;
}

inline void TaskWorker::transfer(TaskWorker &&other) noexcept {
  uid_ = other.uid_;
  invoke_ = other.invoke_;
  move_ = other.move_;
  cleanup_ = other.cleanup_;
  if (other.heap_allocated_) {
    // Steal the heap block; no relocation required.
    data_ = other.data_;
    heap_allocated_ = true;
  } else {
    // Relocate the inline callable into our own buffer.
    data_ = buffer_;
    move_(data_, other.data_);
  }
  other.make_empty();
}

inline void TaskWorker::reset() noexcept {
  if (data_ != nullptr) {
    cleanup_(data_);
    if (heap_allocated_)
      ::operator delete(data_);
  }
  make_empty();
}

inline void TaskWorker::make_empty() noexcept {
  data_ = nullptr;
  heap_allocated_ = false;
  uid_ = 0;
  invoke_ = nullptr;
  move_ = nullptr;
  cleanup_ = nullptr;
}

inline void TaskWorker::operator()() {
  if (data_ != nullptr)
    invoke_(data_);
}

} // namespace vhsm::threadpool