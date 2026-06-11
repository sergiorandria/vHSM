#ifndef VHSM_CORE_ERROR_H
#define VHSM_CORE_ERROR_H

#include <stdexcept>
#include <string>

/// Macro to check a condition and throw std::runtime_error if false.
/// Includes the condition expression, file, and line number in the error message.
#define VHSM_CHECK(condition) \
    do { \
        if (!(condition)) { \
            throw std::runtime_error(std::string("Check failed: ") + #condition \
                + std::string(" at ") + __FILE__ + std::string(":") + std::to_string(__LINE__)); \
        } \
    } while (0)

/// Macro to check a condition and throw std::runtime_error with a custom message if false.
/// Includes the custom message, file, and line number in the error message.
#define VHSM_CHECK_MSG(condition, msg) \
    do { \
        if (!(condition)) { \
            throw std::runtime_error(std::string(msg) \
                + std::string(" at ") + __FILE__ + std::string(":") + std::to_string(__LINE__)); \
        } \
    } while (0)

#define VHSM_CHECK_PTR_MSG(condition, msg) \
    do { \
        if (!(condition)) { \
            throw std::runtime_error(std::string(msg) \
                + std::string(" at ") + __FILE__ + std::string(":") + std::to_string(__LINE__)); \
        } \
    } while (0)

#endif // VHSM_CORE_ERROR_H