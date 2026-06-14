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
#include "db_result_set.h"
#include "db_transaction.h"

namespace vhsm::signature_store {
namespace db {

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