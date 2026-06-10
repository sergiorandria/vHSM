#ifndef VHSM_CORE_SECURE_BUFFER_H
#define VHSM_CORE_SECURE_BUFFER_H

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <sys/mman.h>
#include <stdexcept>
#include <cstring>
#include <new>

namespace vhsm {

// Allocates memory using std::malloc and locks it with mlock().
// Memory is unlocked and zeroed before freeing, making it unswapable.
// 
// For this first version, not using a template parameter the right 
// choice, because metaprogramming will break the directory file extensions 
// naming and project philosophy.
//template <typename BufferElementType>
class SecureBuffer {
// Maybe in future update, it will be analyzed 
// carefully if the use of metaprogramming is necessary, or not.
//    using T = BufferElementType;

// This should be inside core/types.h, 
// std::uint8_t is not thread safe.
    using u8 = std::uint8_t;
public:
    explicit SecureBuffer(std::size_t element_count = 1);

    ~SecureBuffer();

    // Non-copyable
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Movable
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    // Pointer to the locked memory
    u8* data() noexcept;

    // Const pointer to the locked memory
    const u8* data() const noexcept;

    // Size of the buffer in elements
    std::size_t size() const noexcept;

    // Size of the buffer in bytes
    std::size_t byte_size() const noexcept;

    // Zeroize the buffer contents
    void wipe() noexcept;
    
private:
    u8* data_;                  // Pointer to the usable memory region
    std::size_t size_;          // Usable bytes requested by caller 
    void* alloc_base_;          // Address base of the full mmap allocation
    std::size_t alloc_size_;    // Total allocation size
};

} // namespace vhsm

#endif // VHSM_CORE_SECURE_BUFFER_H