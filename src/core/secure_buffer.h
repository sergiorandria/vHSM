#ifndef VHSM_CORE_SECURE_BUFFER_H
#define VHSM_CORE_SECURE_BUFFER_H

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <sys/mman.h>
#include <stdexcept>
#include <cstring>
#include <new>

#include "types.h"

namespace vhsm {

// Allocates memory using std::malloc and locks it with mlock().
// Memory is unlocked and zeroed before freeing, making it unswapable.
// 
// For this first version, not using a template parameter the right 
// choice, because metaprogramming will break the directory file extensions 
// naming and project philosophy.
//template <typename BufferElementType>
class SecureBuffer {
public:
    explicit SecureBuffer(std::size_t element_count = 1);

    ~SecureBuffer() noexcept;

    // Non-copyable
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Movable
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    // Pointer to the locked memory
    [[nodiscard]]
    u8* data() noexcept;

    // Const pointer to the locked memory
    [[nodiscard]]
    const u8* data() const noexcept;

    // Size of the buffer in elements
    [[nodiscard]]
    std::size_t size() const noexcept;

    // Size of the buffer in bytes
    [[nodiscard]]
    std::size_t byte_size() const noexcept;

    // Write `len` bytes from `src` into the buffer at `offset`.
    // Throws std::out_of_range if offset+len > size().
    void write(std::size_t offset, const u8* src, std::size_t len);
    
    // Read `len` bytes starting at `offset` into `dst`.
    // Throws std::out_of_range if offset+len > size().
    void read(std::size_t offset, u8* dst, std::size_t len) const;

    [[nodiscard]] 
    bool equals(const SecureBuffer& other) const noexcept;

    bool operator==(const SecureBuffer& other) const noexcept; 
    bool operator!=(const SecureBuffer& other) const noexcept;

    // Zeroize the buffer contents
    void wipe() noexcept;
    
private:
    // Round `n` up to the next multiple of the system page size.
    static std::size_t round_up_to_page(std::size_t n) noexcept;

    // Returns the system page size (cached after first call).
    static std::size_t page_size() noexcept;

    // This symbol isn't exported from the shared
    // object, so it can't be interposed via LD_PRELOAD by an attacker
    // with code-execution-adjacent access to the process
    __attribute__((nonnull(1)))
    __attribute__((warn_unused_result))
    __attribute__((noinline))
    __attribute__((visibility("hidden")))
    static bool lock_pages(void* addr, std::size_t len);

    // Platform-specific: unlock pages (best-effort; called in destructor).
    static void unlock_pages(void* addr, std::size_t len) noexcept;

    // Platform-specific: zero memory without compiler elision.
    static void secure_zero(void* addr, std::size_t len) noexcept;

    // Free the full mmap/VirtualAlloc region and reset all members to null.
    void release() noexcept;


    u8* data_;                  // Pointer to the usable memory region
    std::size_t size_;          // Usable bytes requested by caller 
    void* alloc_base_;          // Address base of the full mmap allocation
    std::size_t alloc_size_;    // Total allocation size
};

} // namespace vhsm

namespace vhsm {
// Template variant of SecureBuffer for arbitrary element types. 
// This is a separate class to avoid template bloat in the main SecureBuffer class.
template <typename T = u8>
class SecureBufferT {
public: 
    SecureBufferT(std::size_t element_count = 1)
        : buffer_(element_count * sizeof(T)) {}

    ~SecureBufferT() noexcept = default;

private: 
    SecureBuffer buffer_;
};
} // namespace vhsm
#endif // VHSM_CORE_SECURE_BUFFER_H