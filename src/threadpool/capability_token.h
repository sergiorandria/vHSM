#pragma once

#include <cstdint>

namespace vhsm::threadpool {

    // Work tier a capability token grants.  High-tier tasks land in the
    // dedicated high-tier queues; low-tier tasks are confined to their own
    // (stealing) tier.  This prevents a flood of best-effort work from starving
    // latency-sensitive anchoring.
    enum class PrivilegeTier : std::uint8_t {
        Low,
        High
    };

    // Opaque handle that authorises work submission to the pool.  Tokens are
    // only minted by CapabilityToken::grant(); any other object is rejected by
    // the pool's token validation.
    class CapabilityToken {
    public:
        CapabilityToken() = default;

        static CapabilityToken grant(PrivilegeTier tier)
        {
            return CapabilityToken(tier, true);
        }

        PrivilegeTier tier() const noexcept { return tier_; }
        bool is_valid() const noexcept { return valid_; }

    private:
        explicit CapabilityToken(PrivilegeTier tier, bool valid) noexcept
            : tier_(tier), valid_(valid) {}

        PrivilegeTier tier_ = PrivilegeTier::Low;
        bool          valid_ = false;
    };

} // namespace vhsm::threadpool