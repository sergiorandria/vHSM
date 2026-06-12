#include "slot.h"
#include "token.h"

// Flags PKCS#11 standard
constexpr uint64_t CKF_TOKEN_PRESENT    = 0x00000001;
constexpr uint64_t CKF_REMOVABLE_DEVICE = 0x00000002;
constexpr uint64_t CKF_HW_SLOT          = 0x00000004;

namespace vhsm {

Slot::Slot(uint64_t slot_id)
    : slot_id_(slot_id),
      token_(nullptr),
      description_("Virtual HSM Slot " + std::to_string(slot_id)),
      manufacturer_id_("vHSM Team Corp") {}

bool Slot::is_token_present() const {
    std::lock_guard<std::mutex> lock(slot_mutex_);
    return token_ != nullptr;
}

void Slot::insert_token(std::shared_ptr<token> token) {
    std::lock_guard<std::mutex> lock(slot_mutex_);
    token_ = std::move(token);
}

void Slot::remove_token() {
    std::lock_guard<std::mutex> lock(slot_mutex_);
    token_.reset();
}

std::shared_ptr<token> Slot::get_token() const {
    std::lock_guard<std::mutex> lock(slot_mutex_);
    return token_;
}

uint64_t Slot::get_flags() const {
    uint64_t flags = 0;
    flags |= CKF_REMOVABLE_DEVICE;
    flags |= CKF_HW_SLOT;

    if (is_token_present()) {
        flags |= CKF_TOKEN_PRESENT;
    }

    return flags;
}

} // namespace vhsm