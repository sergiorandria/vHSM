#ifndef VHSM_SIGSTORE_DB_ROW_H
#define VHSM_SIGSTORE_DB_ROW_H

#include <charconv>
#include <string>
#include <vector>
#include <optional>

#include "../core/types.h"

namespace vhsm::signature_store {
namespace db {

// Represents a single row in a result set
class DbRow {
public:
    // Construct from column values as strings (raw database output)
    explicit DbRow(std::vector<std::string> column_values);

    // Get number of columns in this row
    size_t column_count() const;

    // Try to get value as string
    std::optional<std::string> get_string(size_t column_index) const; 
    
    // Try to get value as 64-bit integer
    std::optional<i64> get_i64(size_t column_index) const;

    // Try to get value as double
    std::optional<double> get_double(size_t column_index) const;

    // Try to get value as bool
    // Accepts "0"/"1", "false"/"true" (case-insensitive)
    std::optional<bool> get_bool(size_t column_index) const;

private:
    std::vector<std::string> values_;
};
}
} // namespace vhsm::signature_store
#endif // VHSM_SIGSTORE_DB_ROW_H