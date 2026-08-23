#ifndef VHSM_DOMAIN_CORE_KERNEL_TYPES_H
#define VHSM_DOMAIN_CORE_KERNEL_TYPES_H

#include <atomic>
#include <cstdint>

// Domain kernel — fixed-width aliases (DDD shared kernel, no infra deps).
typedef std::uint8_t u8;
typedef std::uint16_t u16;
typedef std::uint32_t u32;
typedef std::uint64_t u64;

typedef std::atomic_int8_t ts8;
typedef std::atomic_int16_t ts16;
typedef std::atomic_int32_t ts32;
typedef std::atomic_int64_t ts64;

typedef std::int8_t i8;
typedef std::int16_t i16;
typedef std::int32_t i32;
typedef std::int64_t i64;

// Small version value object used by C_GetInfo mapping.
struct version {
  u8 major_version;
  u8 minor_version;
};

#endif // VHSM_DOMAIN_CORE_KERNEL_TYPES_H
