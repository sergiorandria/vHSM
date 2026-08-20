#ifndef VHSM_MACROS_H
#define VHSM_MACROS_H

#define VHSM_CORE_VERSION 0.1L

#ifdef __GNUC__
#define VHSM_NODISCARD [[nodiscard]]
#elif defined(_MSVC)
#define VHSM_NODISCARD __nodiscard
#endif

#endif // VHSM_MACROS_H