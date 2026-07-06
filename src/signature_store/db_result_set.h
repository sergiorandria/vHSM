#ifndef VHSM_SIGNATURE_STORE_DB_RESULT_SET_H
#define VHSM_SIGNATURE_STORE_DB_RESULT_SET_H

#include "db_row.h"
#include <vector>
#include <optional>

namespace vhsm::signature_store {
namespace db {
// Represents a set of rows returned by a query
class DbResultSet {
public:
    DbResultSet() = default;
    explicit DbResultSet(std::vector<DbRow> rows) : rows_(std::move(rows)) {}

    // Get number of rows in the result set
    size_t rows_count() const { return rows_.size(); }

    // Check if result set is empty
    bool empty() const { return rows_.empty(); }

    // Access the rows directly (public member variable)
    // This allows:
    //   rs.rows.empty() - check if no rows
    //   rs.rows[0] - get first row
    //   rs.get<T>(rs.rows[0], 0) - get value from first row
    std::vector<DbRow> rows_;

    // Get a value from a specific row and column
    // Delegates to the DbRow's get method
    template<typename T>
    std::optional<T> get(const DbRow& row, size_t column_index) const {
        if constexpr (std::is_same_v<T, std::string>) {
            return row.get_string(column_index);
        } else if constexpr (std::is_same_v<T, i64>) {
            return row.get_i64(column_index);
        } else if constexpr (std::is_same_v<T, double>) {
            return row.get_double(column_index);
        } else if constexpr (std::is_same_v<T, bool>) {
            return row.get_bool(column_index);
        } else {
            static_assert(always_false_v<T>, "Unsupported type for DbResultSet::get");
            return std::nullopt;
        }
    }

private:
    // Helper for static_assert in template
    template<typename T>
    static constexpr bool always_false_v = false;
};
}  // namespace db
} // namespace vhsm::signature_store
#endif // VHSM_SIGNATURE_STORE_DB_RESULT_SET_H