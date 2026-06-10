#include "secure_buffer.h"

#include <cassert>
#include <cstring> 
#include <stdexcept> 

#ifdef _WIN32 
#include <windows.h> 
#else 
// For POSIX system
#include <sys/mman.h> 
#include <unistd.h>
#endif 

namespace vhsm {
// Should use std::atomic_uint8_t for 
// thread safe application, but can 
// complicate SecureBuffer implementation 
// a little bit. Current implementation uses std::uint8_t. 

std::size_t SecureBuffer::page_size() noexcept {
#ifdef _WIN32
    static const std::size_t ps = []() -> std::size_t {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        return static_cast<std::size_t>(si.dwPageSize);
    }();
#else
// sysconf(_SC_PAGESIZE) the system memory page size in bytes, 
// which is the fundamental unit of virtual memory allocation. 
// Modern alternative of getpagesize(). 
    static const std::size_t ps =
        static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
#endif
    return ps;
}

std::size_t SecureBuffer::round_up_to_page(std::size_t n) noexcept {
    const std::size_t ps = page_size();
    return ((n + ps - 1) / ps) * ps;
}

void SecureBuffer::lock_pages(void* addr, std::size_t len) {
#ifdef _WIN32
    if (!VirtualLock(addr, len)) {
        throw std::runtime_error(
            "SecureBuffer: VirtualLock failed (err=" +
            std::to_string(GetLastError()) + "). "
            "Consider raising the working set limit.");
    }
#else
    if (::mlock(addr, len) != 0) {
        throw std::runtime_error(
            "SecureBuffer: mlock(2) failed. "
            "Check RLIMIT_MEMLOCK (see 'ulimit -l'). "
            "On Linux you can raise it in /etc/security/limits.conf.");
    }
#endif
}

void SecureBuffer::unlock_pages(void* addr, std::size_t len) noexcept {
#ifdef _WIN32
    VirtualUnlock(addr, len);   
#else
    ::munlock(addr, len);       
#endif
}

void SecureBuffer::secure_zero(void* addr, std::size_t len) noexcept {
    if (addr == nullptr || len == 0) return;
#ifdef _WIN32
    SecureZeroMemory(addr, len);
#elif defined(__GLIBC__) && \
      (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    // explicit_bzero is in POSIX.1-2008 and glibc ≥ 2.25; guaranteed not
    // to be optimised away.
    ::explicit_bzero(addr, len);
#else
    // Fallback: volatile pointer write.  Still technically UB-adjacent but
    // the volatile qualifier prevents most optimiser elision.
    volatile uint8_t* p = static_cast<volatile uint8_t*>(addr);
    for (std::size_t i = 0; i < len; ++i) p[i] = 0;
#endif
}

SecureBuffer::SecureBuffer(std::size_t size) {
    if (size == 0) {
        throw std::runtime_error("SecureBuffer: size must be > 0");
    }

    const std::size_t ps = page_size();
    const std::size_t data_pages = round_up_to_page(size);
    
    // Total layout: guard | data pages | guard
    alloc_size_ = ps + data_pages + ps;
 
#ifdef _WIN32
    // VirtualAlloc reserves and commits in one call; MEM_COMMIT | MEM_RESERVE.
    alloc_base_ = ::VirtualAlloc(nullptr, alloc_size_,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc_base_) {
        throw std::runtime_error("SecureBuffer: VirtualAlloc failed");
    }

#else
    // MAP_ANONYMOUS | MAP_PRIVATE gives a zero-initialised private mapping.
    alloc_base_ = ::mmap(nullptr, alloc_size_,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (alloc_base_ == MAP_FAILED) {
        throw std::runtime_error("SecureBuffer: mmap failed");
    }
#endif
    // Front guard: first page of the allocation.
    // Rear  guard: last page of the allocation.
    // Any access to either triggers a hardware fault (SIGSEGV / AV).
    uint8_t* base = static_cast<uint8_t*>(alloc_base_);
 
#ifdef _WIN32
    DWORD old_protect;
    if (!VirtualProtect(base, ps, PAGE_NOACCESS, &old_protect)) {
        VirtualFree(alloc_base_, 0, MEM_RELEASE);
        throw std::runtime_error("SecureBuffer: VirtualProtect (front guard) failed");
    }
    if (!VirtualProtect(base + ps + data_pages, ps, PAGE_NOACCESS, &old_protect)) {
        VirtualFree(alloc_base_, 0, MEM_RELEASE);
        throw std::runtime_error("SecureBuffer: VirtualProtect (rear guard) failed");
    }
#else
    if (::mprotect(base, ps, PROT_NONE) != 0) {
        ::munmap(alloc_base_, alloc_size_);
        throw std::runtime_error("SecureBuffer: mprotect (front guard) failed");
    }
    if (::mprotect(base + ps + data_pages, ps, PROT_NONE) != 0) {
        ::munmap(alloc_base_, alloc_size_);
        throw std::runtime_error("SecureBuffer: mprotect (rear guard) failed");
    }
#endif
 
    // Lock the data pages into RAM
    data_ = base + ps;
    size_ = size;
 
    try {
        lock_pages(data_, data_pages);
    } catch (...) {
        // Restore protections so munmap/VirtualFree can access all pages.
#ifdef _WIN32
        VirtualProtect(base,                  ps, PAGE_READWRITE, &old_protect);
        VirtualProtect(base + ps + data_pages, ps, PAGE_READWRITE, &old_protect);
        VirtualFree(alloc_base_, 0, MEM_RELEASE);
#else
        ::mprotect(base,                   ps, PROT_READ | PROT_WRITE);
        ::mprotect(base + ps + data_pages, ps, PROT_READ | PROT_WRITE);
        ::munmap(alloc_base_, alloc_size_);
#endif
        alloc_base_ = nullptr;
        data_       = nullptr;
        size_       = 0;
        alloc_size_ = 0;
        throw;
    }

    // mmap already zero-fills MAP_ANONYMOUS; explicit zero for Windows.
#ifdef _WIN32
    ::memset(data_, 0, data_pages);
#endif
}

SecureBuffer::~SecureBuffer() noexcept {
    release();
}

void SecureBuffer::release() noexcept {
    if (alloc_base_ == nullptr) {
        return;
    }

    const std::size_t ps = page_size();
    const std::size_t data_pages = alloc_size_ - 2 * ps;
    u8* base = static_cast<u8*>(alloc_base_);

    // Wipe the data region first, while it's still mapped with RW.
    if (data_ != nullptr) {
        secure_zero(data_, data_pages);
    }

    // Unlock pages (best-effort).
    unlock_pages(data_, data_pages);

    // Restore guard page permissions so the OS can reclaim them cleanly.
#ifdef _WIN32
    DWORD old;
    VirtualProtect(base, ps, PAGE_READWRITE, &old);
    VirtualProtect(base + ps + data_pages, ps, PAGE_READWRITE, &old);
    VirtualFree(alloc_base_, 0, MEM_RELEASE);
#else
    ::mprotect(base, ps, PROT_READ | PROT_WRITE);
    ::mprotect(base + ps + data_pages, ps, PROT_READ | PROT_WRITE);
    ::munmap(alloc_base_, alloc_size_);
#endif

    alloc_base_ = nullptr;
    data_       = nullptr;
    size_       = 0;
    alloc_size_ = 0;
}

// SecureBuffer should be movable, 
// like any memory data structure.
SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_      (other.data_)
    , size_      (other.size_)
    , alloc_base_(other.alloc_base_)
    , alloc_size_(other.alloc_size_)
{
    other.data_       = nullptr;
    other.size_       = 0;
    other.alloc_base_ = nullptr;
    other.alloc_size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        release();                       
        data_       = other.data_;
        size_       = other.size_;
        alloc_base_ = other.alloc_base_;
        alloc_size_ = other.alloc_size_;
        other.data_       = nullptr;
        other.size_       = 0;
        other.alloc_base_ = nullptr;
        other.alloc_size_ = 0;
    }
    return *this;
}

void SecureBuffer::read(std::size_t offset,
                        u8* dst,
                        std::size_t len) const
{
    if (offset + len > size_) {
        throw std::out_of_range(
            "SecureBuffer::read: offset=" + std::to_string(offset) +
            " len="    + std::to_string(len) +
            " size="   + std::to_string(size_));
    }

    ::memcpy(dst, data_ + offset, len);
}
 
void SecureBuffer::write(std::size_t    offset,
                         const u8* src,
                         std::size_t    len)
{
    if (offset + len > size_) {
        throw std::out_of_range(
            "SecureBuffer::write: offset=" + std::to_string(offset) +
            " len="    + std::to_string(len) +
            " size="   + std::to_string(size_));
    }

    ::memcpy(data_ + offset, src, len);
}

bool SecureBuffer::equals(const SecureBuffer& other) const noexcept {
    if (size_ != other.size_) {
        return false;
    }

    if (data_ == nullptr && other.data_ == nullptr) {
        return true;
    }

    if (data_ == nullptr || other.data_ == nullptr) {
        return false;
    }

    // XOR every byte and OR the results, no early exit.
    volatile u8 acc = 0;
    const u8* a = data_;
    const u8* b = other.data_;
    
    for (std::size_t i = 0; i < size_; ++i) {
        acc |= (a[i] ^ b[i]);
    }
    
    return acc == 0;
}

// Pointer to the locked memory
u8* SecureBuffer::data() noexcept { return data_; }

// Const pointer to the locked memory
const u8* SecureBuffer::data() const noexcept { return data_; }

// Size of the buffer in elements
std::size_t SecureBuffer::size() const noexcept { return size_; }

// Size of the buffer in bytes
std::size_t SecureBuffer::byte_size() const noexcept { return size_ * sizeof(u8); }

bool SecureBuffer::operator==(const SecureBuffer& other) const noexcept {
    return this->equals(other);
} 
    
bool SecureBuffer::operator!=(const SecureBuffer& other) const noexcept {
    return !this->equals(other);
}

// Zeroize the buffer contents
void SecureBuffer::wipe() noexcept {
    if (data_ != nullptr)
        secure_zero(data_, size_);
}
}