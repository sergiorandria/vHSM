#include "slot.h"
#include "token.h"

// Flags PKCS#11 standard


namespace vhsm::keystore {

Slot::Slot(u64 slot_id)
    : slot_id_(slot_id),
      token_(nullptr),
      description_("Virtual HSM Slot " + std::to_string(slot_id)),
      manufacturer_id_("vHSM Team Corp"), 
      hardware_version_({1, 0}), 
      firmware_version_({1,0}) {}

bool Slot::is_token_present() const {
    std::lock_guard<std::mutex> lock(slot_mutex_);
    return token_ != nullptr;
}

void Slot::insert_token(std::shared_ptr<Token> token) {
    std::lock_guard<std::mutex> lock(slot_mutex_);
    token_ = std::move(token);
}

void Slot::remove_token() {
    std::lock_guard<std::mutex> lock(slot_mutex_);
    token_.reset();
}

std::shared_ptr<Token> Slot::get_token() const {
    std::lock_guard<std::mutex> lock(slot_mutex_);
    return token_;
}

u64 Slot::get_flags() const {
    u64 flags = 0;
    flags |= CKF_REMOVABLE_DEVICE;
    flags |= CKF_HW_SLOT;

    if (is_token_present()) {
        flags |= CKF_TOKEN_PRESENT;
    }

    return flags;
}

void Slot::define_firmware_version(const struct version& firmware_version)
{
    auto major_version = firmware_version.major_version;
    auto minor_version = firmware_version.minor_version;

    if (major_version <= firmware_version_.major_version 
            && ((major_version != firmware_version_.major_version) || minor_version <= firmware_version_.minor_version)) 
    {
        throw VersionException("Incoherent version affectation");
    }

    firmware_version_ = firmware_version;
}

} // namespace vhsm::keystore