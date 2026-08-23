#ifndef VHSM_MACROS_H
#define VHSM_MACROS_H

// Unused — kept for backward compat with _VHSMXX_BEGIN_NAMESPACE blocks
#define _VHSMXX_BEGIN_NAMESPACE
#define _VHSMXX_END_NAMESPACE

#if defined(__GNUC__) || defined(__clang__)
#define _VHSMXX_NODISCARD [[nodiscard]]
#elif defined(_MSC_VER)
#define _VHSMXX_NODISCARD [[nodiscard]]
#else
#define _VHSMXX_NODISCARD
#endif

// Visibility: hidden by default on ELF (GCC/Clang), empty on MSVC/Windows
#if defined(__GNUC__) || defined(__clang__)
#define _VHSMXX_VISIBILITY(V) __attribute__((visibility(#V)))
#define _VHSMXX_VISIBILITY_VALUE
#define _VHSM_VISIBILITY_VALUE_HIDDEN ("hidden")
#define _VHSM_VISIBILITY_VALUE_DEFAULT ("default")
#else
#define _VHSMXX_VISIBILITY(V)
#define _VHSMXX_VISIBILITY_VALUE
#define _VHSM_VISIBILITY_VALUE_HIDDEN ("hidden")
#define _VHSM_VISIBILITY_VALUE_DEFAULT ("default")
#endif

// Core version — used for optional version-gated APIs (e.g. hsm_instance)
#ifndef _VHSMXX_CORE_VERSION
#define _VHSMXX_CORE_VERSION 1ULL
#endif

#ifdef __GNUC__

#ifndef _VHSMXX_DEFAULT_ABI_TAG
#define _VHSMXX_DEFAULT_ABI_TAG __attribute((__abi_tag__("1.0.0")))
#else
#define _VHSMXX_DEFAULT_ABI_TAG
#endif // _VHSMXX_DEFAULT_ABI_TAG

#define _VHSMXX_USE_ABI1 _VHSMXX_DEFAULT_ABI_TAG

#endif // __GNUC__
#endif // VHSM_MACROS_H