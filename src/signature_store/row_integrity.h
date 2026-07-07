#ifndef VHSM_SIGSTORE_ROW_INTEGRITY_H
#define VHSM_SIGSTORE_ROW_INTEGRITY_H

#include <string>
#include <vector>
#include <optional>

#include "../core/types.h"
#include "db_connection.h"
#include "../keystore/token.h"

namespace vhsm::signature_store {
namespace db {

// Computes and verifies HMAC for a database row.
// The HMAC covers all columns of the row except the integrity_hmac column itself.
// The column order must match the order in the CREATE TABLE statement for signature_records.
class RowIntegrity {
public:
    RowIntegrity(IDbConnection& conn, vhsm::keystore::Token& token);

    // Computes the HMAC for the given column values.
    // The values must be in the same order as the columns in the table.
    // The integrity_hmac column value is ignored (should be empty).
    std::string compute_hmac(const std::vector<std::optional<std::string>>& column_values) const;

    // Verifies that the given HMAC matches the computed HMAC for the column values.
    bool verify_hmac(const std::vector<std::optional<std::string>>& column_values,
                     const std::optional<std::string>& stored_hmac) const;

private:
    IDbConnection& conn_;
    vhsm::keystore::Token& token_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_ROW_INTEGRITY_H