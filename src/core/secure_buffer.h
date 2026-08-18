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
#include "macros.h"

namespace vhsm {

// WHY SecureBuffer locks memory with mlock(): Sensitive data (keys, credentials, PINs)
// must never be paged to disk. mlock() prevents the OS from evicting locked pages to swap.
// If the HSM is compromised and the attacker reads /swapfile, secrets won't be found there.
// This is defense-in-depth: even a privileged process (with code-execution-adjacent access)
// can't recover keys from disk if we lock them in RAM.
//
// WHY memory is zeroed before freeing: mlock() only prevents swapping; it doesn't prevent
// memory dumps or physical attacks. Zeroing (using secure_zero, not memset) overwrites
// the bytes with zeros using methods the compiler can't optimize away (volatile writes).
// After free(), the allocator might reuse the memory for non-sensitive data; we don't
// want garbage collecting to reveal old key bytes.
//
// WHY template parameter explicitly rejected: Templating SecureBuffer would generate
// separate code for SecureBuffer<u8>, SecureBuffer<u16>, etc. This bloats the binary and
// complicates auditing (code paths multiply). The byte-oriented design (u8-only) keeps
// it simple, auditable, and focused on the security contract.
class SecureBuffer {
public:
    // WHY explicit constructor with default size=1: explicit prevents accidental implicit
    // conversions (size_t → SecureBuffer). Default size=1 allows (SecureBuffer sb;) without
    // forcing size specification. The size is in elements (bytes for u8), not bytes directly.
    explicit SecureBuffer(std::size_t element_count = 1);

    ~SecureBuffer() noexcept;

    // WHY non-copyable: Copying would create a second buffer with the same sensitive data.
    // Doubling the attack surface is unacceptable. Callers must move (transfer ownership)
    // or use references. This constraint enforces single ownership of sensitive data.
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // WHY moves are noexcept: Containers (std::vector, std::unique_ptr) require move to be
    // noexcept for exception safety. If move threw, the vector would be in an invalid state.
    // noexcept guarantees atomicity: either the move succeeds, or the source is unchanged.
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    // WHY VHSM_NODISCARD on all getters: Forgetting to use the returned pointer is a bug.
    // [[nodiscard]] makes the compiler warn if you call data() and ignore the result.
    // This catches mistakes like: buffer.data(); buffer.write(...) — the pointer is
    // generated but unused, suggesting a logic error.
    // Pointer to the locked memory
    VHSM_NODISCARD u8* data() noexcept;

    // Const pointer to the locked memory
    VHSM_NODISCARD const u8* data() const noexcept;

    // WHY size() is in elements, byte_size() is in bytes: size() matches container semantics
    // (std::vector::size() returns element count). byte_size() is explicit for those who need
    // byte accuracy. Having both avoids off-by-one errors from manual multiplication.
    // Size of the buffer in elements
    VHSM_NODISCARD std::size_t size() const noexcept;

    // Size of the buffer in bytes
    VHSM_NODISCARD std::size_t byte_size() const noexcept;

    // WHY write/read take offset + length: Allows precise byte-level manipulation without
    // requiring callers to do pointer arithmetic. The methods validate bounds (throw if
    // offset+len > size), preventing buffer overruns. Both methods throw std::out_of_range
    // on bounds violation (fail-closed).
    // Write `len` bytes from `src` into the buffer at `offset`.
    // Throws std::out_of_range if len > size() - offset.
    void write(std::size_t offset, const u8* src, std::size_t len);
    
    // Read `len` bytes starting at `offset` into `dst`.
    // Throws std::out_of_range if len > size() - offset.
    void read(std::size_t offset, u8* dst, std::size_t len) const;

    // WHY equals() instead of operator==: Two SecureBuffers are equal if their contents match.
    // But operator== is usually used for identity (this buffer == another object). Using a
    // named method (equals()) makes it explicit that we're comparing contents, not identity.
    // This avoids the pitfall of accidental pointer comparison.
    VHSM_NODISCARD 
    bool equals(const SecureBuffer& other) const noexcept;

    // WHY provide operator== and operator!=: Some contexts require these (e.g., std::map).
    // They delegate to equals() for semantic clarity.
    bool operator==(const SecureBuffer& other) const noexcept; 
    bool operator!=(const SecureBuffer& other) const noexcept;

    // WHY separate wipe() method: Explicit zeroing is sometimes needed before destroying
    // the buffer (e.g., logging reveals we're about to destruct a key). The wipe() method
    // lets callers zero the contents without deallocating. The destructor calls wipe()
    // automatically, so double-wipe is harmless but unnecessary.
    void wipe() noexcept;
    
private:
    // Round `n` up to the next multiple of the system page size.
    static std::size_t v_sb_round_up_to_page(std::size_t n) noexcept;

    // Returns the system page size (cached after first call).
    static std::size_t v_sb_page_size() noexcept;

    // This symbol isn't exported from the shared
    // object, so it can't be interposed via LD_PRELOAD by an attacker
    // with code-execution-adjacent access to the process
    __attribute__((nonnull(1)))
    __attribute__((warn_unused_result))
    __attribute__((noinline))
    __attribute__((visibility("hidden")))
    static bool v_sb_lock_pages(void* addr, std::size_t len);

    // Platform-specific: unlock pages.
    // All major platform have different way to handle pages. 
    static void v_sb_unlock_pages(void* addr, std::size_t len) noexcept;

    // Platform-specific: zero memory without compiler elision.
    static void v_sb_secure_zero(void* addr, std::size_t len) noexcept;

    // Internal, already-validated copies. Marked noinline + hidden so the
    // secret-copy cannot be interposed via LD_PRELOAD by an attacker with
    // code-execution-adjacent access to the process (mirrors v_sb_lock_pages).
    // The public read()/write() perform all bounds/null validation before
    // calling these; they must never be invoked with unvalidated arguments.
    __attribute__((visibility("hidden")))
    __attribute__((noinline))
    void __v_sb_write(std::size_t offset, const u8* src, std::size_t len);

    __attribute__((visibility("hidden")))
    __attribute__((noinline))
    void __v_sb_read(std::size_t offset, u8* dst, std::size_t len) const;

    // Free the full mmap/VirtualAlloc region and reset all members to null.
    void v_sb_release() noexcept;


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