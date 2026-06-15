#include "row_integrity.h"

#include "../core/error.h"
#include "../core/utils.h"
#include "db_connection.h"
#include "db_hmac_key.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>

namespace vhsm::signature_store {
namespace db {

RowIntegrity::RowIntegrity(IDbConnection& conn) : conn_(conn) {}

std::string RowIntegrity::compute_hmac(const std::vector<std::optional<std::string>>& column_values) const {
    // Get the HMAC key
    DbHmacKey hmac_key(conn_);
    std::vector<std::uint8_t> key = hmac_key.get_key();
    if (key.empty()) {
        // If we cannot get the key, return empty HMAC (or throw?)
        return "";
    }

    // Concatenate column values with a delimiter that does not appear in the data.
    // We'll use a null byte as delimiter, assuming the data does not contain null bytes.
    std::string concatenated;
    for (size_t i = 0; i < column_values.size(); ++i) {
        if (i > 0) {
            concatenated.push_back('\0'); // delimiter
        }
        if (column_values[i]) {
            concatenated += *column_values[i];
        }
        // If nullopt, we append nothing (empty string)
    }

    // Compute HMAC-SHA256
    unsigned int hmac_len = 0;
    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(),
         key.data(), key.size(),
         reinterpret_cast<const unsigned char*>(concatenated.data()),
         concatenated.size(),
         hmac_result, &hmac_len);

    // Convert to hex string
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hmac_len; ++i) {
        ss << std::setw(2) << static_cast<int>(hmac_result[i]);
    }
    return ss.str();
}

bool RowIntegrity::verify_hmac(const std::vector<std::optional<std::string>>& column_values,
                               const std::optional<std::string>& stored_hmac) const {
    if (!stored_hmac) {
        // No stored HMAC, consider it invalid
        return false;
    }
    std::string computed = compute_hmac(column_values);
    return computed == *stored_hmac;
}

}  // namespace db
}  // namespace vhsm::signature_store