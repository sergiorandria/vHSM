#ifndef VHSM_REKOR_CLIENT_H
#define VHSM_REKOR_CLIENT_H

#include <string>
#include <optional>
#include <vector>

namespace vhsm::rekor {

struct RekorEntry {
    std::string entry_uuid;      // 64-char hex UUID from Rekor
    int64_t log_index;           // monotonic log index
    std::string integrated_time; // RFC3339 timestamp from Rekor SET
    std::string inclusion_proof; // JSON-serialized InclusionProof
    std::string set_b64;         // Signed Entry Timestamp (base64)
};

struct HashedRekordPayload {
    struct {
        struct {
            std::string algorithm;
            std::string value;
        } hash;
    } data;
    struct {
        std::string content;
    } signature;
    struct {
        std::string content;
    } publicKey;
};

class RekorClient {
public:
    virtual ~RekorClient() = default;
    virtual std::optional<RekorEntry> create_entry(const HashedRekordPayload& payload) = 0;
};

} // namespace vhsm::rekor

#endif // VHSM_REKOR_CLIENT_H