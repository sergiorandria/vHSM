#ifndef VHSM_SIGNATURE_STORE_DB_TRANSACTION_H
#define VHSM_SIGNATURE_STORE_DB_TRANSACTION_H

#include "db_result_set.h"

namespace vhsm::signature_store {
    namespace db {

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
    } // namespace db
} // namespace vhsm::signature_store

#endif // VHSM_SIGNATURE_STORE_DB_TRANSACTION_H