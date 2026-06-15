#ifndef VHSM_SIGSTORE_DB_CONFIG_H
#define VHSM_SIGSTORE_DB_CONFIG_H

#include <string>

namespace vhsm::signature_store {
namespace config {

// Database backend options
enum class DbBackend {
    Sqlite,
    PostgreSQL,
    MySQL
};

// Database configuration structure
struct DbConfig {
    DbBackend backend = DbBackend::Sqlite;
    bool async_db = false;              // Use async write queue for DB
    bool require_db = true;             // Fail C_Sign if DB write fails
    std::string connection_string;      // Database connection string

    // SQLite specific
    bool sqlite_wal_mode = true;        // Use WAL mode for SQLite
    int sqlite_busy_timeout = 5000;     // SQLite busy timeout in ms

    // PostgreSQL/MySQL specific
#ifdef VHSM_ENABLE_POSTGRESQL
    std::string pg_host = "localhost";
    int pg_port = 5432;
    std::string pg_database = "vhsm";
    std::string pg_username = "vhsm";
    std::string pg_password = "";
#endif

#ifdef VHSM_ENABLE_MYSQL
    std::string mysql_host = "localhost";
    int mysql_port = 3306;
    std::string mysql_database = "vhsm";
    std::string mysql_username = "vhsm";
    std::string mysql_password = "";
#endif
};

// Global configuration instance
extern DbConfig g_db_config;

// Initialize configuration from environment or defaults
void init_db_config();

// Helper functions
inline std::string backend_to_string(DbBackend backend) {
    switch (backend) {
        case DbBackend::Sqlite: return "sqlite";
        case DbBackend::PostgreSQL: return "postgres";
        case DbBackend::MySQL: return "mysql";
        default: return "unknown";
    }
}

inline DbBackend string_to_backend(const std::string& str) {
    if (str == "sqlite") return DbBackend::Sqlite;
    if (str == "postgres") return DbBackend::PostgreSQL;
    if (str == "mysql") return DbBackend::MySQL;
    return DbBackend::Sqlite; // default
}

}  // namespace config
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_DB_CONFIG_H