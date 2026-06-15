#include "db_hmac_key.h"

#include "../core/utils.h"
#include "db_connection.h"
#include "db_schema.h"

#include "../keystore/key_wrap.h"

#include <vector>
#include <string>
#include <optional>

namespace vhsm::signature_store {
namespace db {

DbHmacKey::DbHmacKey(IDbConnection& conn, vhsm::keystore::Token& token)
    : conn_(conn)
    , token_(token) {}

std::vector<std::uint8_t> DbHmacKey::get_key() const {
    // Retrieve the wrapped key from db_meta
    std::string sql = "SELECT value FROM db_meta WHERE key = ?";
    std::vector<std::string> params{std::string(meta_key::kHmacKeyWrapped)};
    DbResultSet rs = conn_.query(sql, params);
    if (rs.rows_count() == 0) {
        // No wrapped key stored yet
        return {};
    }
    // Get first row
    const DbRow& row = rs.rows_[0];
    // Get the value as string (column 0)
    std::optional<std::string> wrapped_b64 = row.get_string(0);
    if (!wrapped_b64 || wrapped_b64->empty()) {
        return {};
    }
    // Decode base64
    auto decoded = vhsm::utils::base64_decode(*wrapped_b64);
    if (!decoded) {
        return {};
    }
    std::vector<std::uint8_t> wrapped_key;
    wrapped_key.reserve(decoded->size());
    for (auto b : *decoded) {
        wrapped_key.push_back(static_cast<std::uint8_t>(b));
    }
    // Get KEK from token
    std::vector<std::uint8_t> kek = token_.get_kek();
    if (kek.empty()) {
        return {};
    }
    // Unwrap using KeyWrap
    try {
        vhsm::keystore::KeyWrap key_wrap(kek);
        return key_wrap.unwrap(wrapped_key);
    } catch (const std::exception&) {
        // Unwrap failed (e.g., integrity check failed)
        return {};
    }
}

void DbHmacKey::store_key_wrapped(const std::vector<std::uint8_t>& key) const {
    // Get KEK from token
    std::vector<std::uint8_t> kek = token_.get_kek();
    if (kek.empty()) {
        // No KEK available; cannot store wrapped key
        return;
    }
    // Wrap the key
    try {
        vhsm::keystore::KeyWrap key_wrap(kek);
        std::vector<std::uint8_t> wrapped_key = key_wrap.wrap(key);
        // Encode to base64
        std::string wrapped_b64 = vhsm::utils::base64_encode(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(wrapped_key.data()),
                wrapped_key.size()));
        // Upsert into db_meta
        std::string sql = "INSERT INTO db_meta(key, value) VALUES(?, ?) "
                          "ON CONFLICT(key) DO UPDATE SET value=excluded.value;";
        std::vector<std::string> params{
            std::string(meta_key::kHmacKeyWrapped),
            wrapped_b64
        };
        conn_.exec(sql, params);
    } catch (const std::exception&) {
        // Wrap failed; silently ignore
    }
}

}  // namespace db
}  // namespace vhsm::signature_store