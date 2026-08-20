#pragma once

#include <concepts>
#include <type_traits>

namespace vhsm::threadpool {

    // A callable that may be submitted to the pool for asynchronous execution.
    template <typename Callable, typename... Args>
    concept Submittable = std::invocable<Callable, Args...>;

    // A callable that executes fire-and-forget (no return value is produced).
    template <typename Callable>
    concept VoidCallable = std::is_invocable_v<Callable>;

} // namespace vhsm::threadpool