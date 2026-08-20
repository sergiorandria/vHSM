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
// common case.  A callable is only stored inline if BOTH it fits in
// k_task_worker_capacity AND its move constructor is noexcept; otherwise
// it falls back to a single heap allocation.  This matters because
// heap-stored payloads are relocated by stealing a pointer (never throws),
// while inline payloads are relocated by invoking the move constructor
// from a noexcept context -- so a throwing move ctor is never called from
// that context, it just costs an allocation instead.
//
// Invariants:
//  - Empty when constructed (operator bool == false).
//  - Never copied, only moved; a moved-from task worker is empty.
//  - A task is invocable at most once (call operator() while non-empty).
//  - The stored callable's destructor must not throw: cleanup_ always
//    runs from a noexcept context (~TaskWorker, reset(), move-assignment)
//    regardless of storage, so this is enforced with a static_assert
//    rather than left as a runtime std::terminate() surprise.
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
  //
  // move_ and cleanup_ are noexcept-qualified as part of their *type*,
  // not just documentation. Assigning a non-noexcept callable to either
  // is a compile error (C++17 makes noexcept part of a function
  // pointer's type), so a future change that breaks the no-throw
  // contract fails to build instead of terminating at runtime.
  void (*invoke_)(void *) = nullptr;
  void (*move_)(void *dst, void *src) noexcept = nullptr;
  void (*cleanup_)(void *) noexcept = nullptr;
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
  static_assert(std::is_nothrow_destructible_v<callable_type>,
                "TaskWorker requires a non-throwing destructor: cleanup_ "
                "always runs from a noexcept context");

  // Only relocate a callable inline if that can never throw. Anything
  // else (too big, or a throwing move ctor) goes on the heap, where
  // "relocation" is a pointer steal in transfer() -- always noexcept.
  constexpr bool fits_inline =
      sizeof(callable_type) <= k_task_worker_capacity &&
      std::is_nothrow_move_constructible_v<callable_type>;

  if constexpr (fits_inline) {
    data_ = buffer_;
  } else {
    data_ = ::operator new(sizeof(callable_type));
    heap_allocated_ = true;
  }
  new (data_) callable_type(std::move(task));

  uid_ = next_uid_.fetch_add(1, std::memory_order_relaxed);

  invoke_ = [](void *data) { (*static_cast<callable_type *>(data))(); };

  if constexpr (fits_inline) {
    move_ = [](void *dst, void *src) noexcept {
      new (dst) callable_type(std::move(*static_cast<callable_type *>(src)));
      static_cast<callable_type *>(src)->~callable_type();
    };
  }
  // else: move_ keeps its default-member-initializer value (nullptr)
  // and is never called -- transfer() only invokes move_ for inline
  // storage; heap storage is relocated by stealing `data_` instead.

  cleanup_ = [](void *data) noexcept {
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
    // Relocate the inline callable into our own buffer. Only
    // reachable when the original was inline, which by construction
    // means move_ is non-null and noexcept.
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