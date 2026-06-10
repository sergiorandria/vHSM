#include "secure_buffer.h"

#include <cassert>
#include <cstdint>
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
// complicate SecureBuffer a little bit.
// Should be inside core/types.h
using u8 = std::uint8_t; 

SecureBuffer::SecureBuffer(std::size_t element_count)
        : size_(element_count),
          data_(element_count > 0 ? static_cast<u8*>(std::malloc(element_count * sizeof(u8))) : nullptr) {
    if (element_count > 0 && !data_) {
        throw std::bad_alloc();
    }
    if (element_count > 0 && mlock(data_, element_count * sizeof(u8)) != 0) {
        std::free(data_);
        data_ = nullptr;
        throw std::runtime_error("mlock failed");
    }
}

SecureBuffer::~SecureBuffer() {
    if (data_) {
        // Zeroize memory before unlocking and freeing, 
        // but an open question arise, will be this destructor 
        // called everytime a SecureBuffer is destroyed ?
        // This destructor should be called manually to wipe 
        // this->data_; 
        std::memset(data_, 0, size_ * sizeof(u8));
        munlock(data_, size_ * sizeof(u8));
        std::free(data_);
    }
}

// Movable
SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : size_(other.size_), data_(other.data_) {
    other.size_ = 0;
    other.data_ = nullptr;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        wipe();
        size_ = other.size_;
        data_ = other.data_;
        other.size_ = 0;
        other.data_ = nullptr;
    }

    return *this;
}

// Pointer to the locked memory
u8* SecureBuffer::data() noexcept { return data_; }

// Const pointer to the locked memory
const u8* SecureBuffer::data() const noexcept { return data_; }

// Size of the buffer in elements
std::size_t SecureBuffer::size() const noexcept { return size_; }

// Size of the buffer in bytes
std::size_t SecureBuffer::byte_size() const noexcept { return size_ * sizeof(u8); }

// Zeroize the buffer contents
void SecureBuffer::wipe() noexcept {
    if (data_) {
        std::memset(data_, 0, size_ * sizeof(u8));
    }
}
}