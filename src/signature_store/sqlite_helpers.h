// sqlite_helpers.h
#ifndef vHSM_SIGNATURE_STORE_SQLITE_HELPERS_H
#define vHSM_SIGNATURE_STORE_SQLITE_HELPERS_H

#include <sqlite3.h>
#include <string>
#include <vector>
#include "db_result_set.h" // Ajustez selon votre structure (où est défini DbResultSet)

namespace vhsm::signature_store::db::internal {

    // Déclaration de la fonction d'erreur
    [[noreturn]] void throw_sqlite_error(sqlite3* db, int rc, const char* context);

    // Déclaration du liage de paramètres
    void bind_params(sqlite3* db, sqlite3_stmt* stmt, const std::vector<std::string>& params);

    // Déclaration de la collecte de lignes
    DbResultSet collect_rows(sqlite3* db, sqlite3_stmt* stmt);

} // namespace vhsm::signature_store::db::internal

#endif