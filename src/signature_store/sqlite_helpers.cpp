// sqlite_helpers.cpp
#include "sqlite_helpers.h"
#include "../core/error.h" // For DbError

// Internal helpers
namespace vhsm::signature_store::db::internal {
    
    // Throw a DbError whose message is prefixed with context and suffixed with the
    // SQLite error string for the given db handle.
    [[noreturn]] void throw_sqlite_error(sqlite3* db, int rc, const char* context) {
        std::string msg = context;
        msg += ": ";
        if (db) {
            msg += sqlite3_errmsg(db);
        } else {
            msg += sqlite3_errstr(rc);
        }
    
        throw DbError(DbError::Kind::IoError, std::move(msg));
    }

    // Bind a vector of string parameters to a prepared statement.
    // SQLite uses 1-based indices.
    void bind_params(sqlite3* db, sqlite3_stmt* stmt, const std::vector<std::string>& params) {
        for (int i = 0; i < static_cast<int>(params.size()); ++i) {
            // SQLITE_TRANSIENT tells SQLite to make its own copy of the string.
            int rc = sqlite3_bind_text(stmt, i + 1, params[i].c_str(), static_cast<int>(params[i].size()), SQLITE_TRANSIENT);
            if (rc != SQLITE_OK) {
                throw_sqlite_error(db, rc, "sqlite3_bind_text");
            }
        }
    }

    // Step a prepared statement to completion and collect all result rows.
    DbResultSet collect_rows(sqlite3* db, sqlite3_stmt* stmt) {
        std::vector<DbRow> rows;
    
        int rc;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            int ncols = sqlite3_column_count(stmt);
            std::vector<std::string> values;
            values.reserve(ncols);
        
            for (int c = 0; c < ncols; ++c) {
                // sqlite3_column_text returns NULL for SQL NULL values.
                // We represent SQL NULL as the empty string here; callers that
                // need to distinguish NULL from "" should add a sentinel or use
                // a separate optional<string> layer in a future refactor.
                const unsigned char* text = sqlite3_column_text(stmt, c);
                values.emplace_back(text ? reinterpret_cast<const char*>(text) : "");
            }
        
            rows.emplace_back(std::move(values));
        }
    
        if (rc != SQLITE_DONE) {
            throw_sqlite_error(db, rc, "sqlite3_step");
        }
    
        return DbResultSet(std::move(rows));
    }

} // namespace
