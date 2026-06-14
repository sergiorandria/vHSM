#ifndef VHSM_SIGSTORE_DB_CONNECTION_H
#define VHSM_SIGSTORE_DB_CONNECTION_H

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <stdexcept>
#include <optional>
#include <cstddef>
#include <type_traits>
#include <charconv>

#include "db_row.h"

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

// Interface for database transactions
class IDbTransaction {
public:
    virtual ~IDbTransaction() = default;

    // Execute a query within the transaction
    virtual DbResultSet query(
        const std::string& sql,
        const std::vector<std::string>& params = {}) = 0;

    // Execute a statement within the transaction
    virtual i64 exec(
        const std::string& sql,
        const std::vector<std::string>& params = {}) = 0;
};

// Interface for database connections
class IDbConnection {
public:
    virtual ~IDbConnection() = default;

    // Execute a query and return result set
    // Parameters:
    //   sql - SQL query string with ? placeholders for parameters
    //   params - vector of parameter values to bind to the placeholders
    // Returns: DbResultSet containing the query results
    virtual DbResultSet query(
        const std::string& sql,
        const std::vector<std::string>& params = {}) = 0;

    // Execute a statement (INSERT, UPDATE, DELETE, etc.)
    // Parameters:
    //   sql - SQL statement string with ? placeholders for parameters
    //   params - vector of parameter values to bind to the placeholders
    // Returns: number of rows affected
    virtual i64 exec(
        const std::string& sql,
        const std::vector<std::string>& params = {}) = 0;

    // Execute a function within a database transaction
    // Parameters:
    //   func - lambda/function that takes a DbTransaction reference and returns void
    // The function will be executed within a transaction that is automatically
    // committed if the function succeeds, or rolled back if it throws an exception
    virtual void with_transaction(
        const std::function<void(IDbTransaction&)>& func) = 0;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_DB_CONNECTION_H