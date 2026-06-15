#include "db_hmac_key.h"

#include "../core/utils.h"
#include "db_connection.h"
#include "db_schema.h"

#include <vector>

namespace vhsm::signature_store {
namespace db {

DbHmacKey::DbHmacKey(IDbConnection& conn) : conn_(conn) {}

std::vector<std::uint8_t> DbHmacKey::get_key() const {
    // For simplicity, we return a fixed 32-byte key.
    // In a real implementation, this would be derived from the KEK.
    static const std::vector<std::uint8_t> fixed_key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    return fixed_key;
}

void DbHmacKey::store_key_wrapped(const std::vector<std::uint8_t>& key) const {
    // Wrap the key with a simple XOR for demonstration? Not secure.
    // In production, use AES-Wrap with the KEK.
    // For now, we store the base64-encoded raw key.
    std::string wrapped = vhsm::utils::base64_encode(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(key.data()), key.size()));
    conn_.exec(
        "INSERT INTO db_meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value;",
        { std::string(meta_key::kHmacKeyWrapped), wrapped });
}

}  // namespace db
}  // namespace vhsm::signature_store