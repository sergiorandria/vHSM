#ifndef VHSM_SIGNATURE_STORE_STMT_GUARD_H
#define VHSM_SIGNATURE_STORE_STMT_GUARD_H

#include <sqlite3.h>

// RAII wrapper around sqlite3_stmt.
class StmtGuard {
public:
    explicit StmtGuard(sqlite3_stmt* stmt) : stmt_(stmt) {}
    ~StmtGuard() { if (stmt_) sqlite3_finalize(stmt_); }

    StmtGuard(const StmtGuard&)            = delete;
    StmtGuard& operator=(const StmtGuard&) = delete;

    sqlite3_stmt* get() const { return stmt_; }

private:
    sqlite3_stmt* stmt_;
};
#endif // VHSM_SIGNATURE_STORE_STMT_GUARD_H