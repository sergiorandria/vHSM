#ifndef VHSM_SIGNATURE_STORE_POSTGRES_CONNECTION_H
#define VHSM_SIGNATURE_STORE_POSTGRES_CONNECTION_H

#include <mutex>
#include <string>
#include <vector>

#include "db_connection.h"
#include "db_result_set.h"
#include "db_transaction.h"

struct pg_conn;
typedef struct pg_conn PGconn;

namespace vhsm::signature_store {
namespace db {

class PostgresConnection : public IDbConnection {
public:
  explicit PostgresConnection(const std::string &connection_string);
  ~PostgresConnection() override;

  PostgresConnection(const PostgresConnection &) = delete;
  PostgresConnection &operator=(const PostgresConnection &) = delete;

  DbResultSet query(const std::string &sql,
                    const std::vector<std::string> &params = {}) override;
  i64 exec(const std::string &sql,
           const std::vector<std::string> &params = {}) override;
  void with_transaction(const std::function<void(IDbTransaction &)> &func) override;

private:
  PGconn *conn_ = nullptr;
  std::mutex mutex_;

  std::string translate_placeholders(const std::string &sql);
  DbResultSet exec_params(const std::string &sql,
                          const std::vector<std::string> &params,
                          bool is_query);
};

class PostgresTransaction : public IDbTransaction {
public:
  PostgresTransaction(PGconn *conn, std::mutex &mu);
  DbResultSet query(const std::string &sql,
                    const std::vector<std::string> &params = {}) override;
  i64 exec(const std::string &sql,
           const std::vector<std::string> &params = {}) override;
private:
  PGconn *conn_;
  std::mutex &mu_;
};

} // namespace db
} // namespace vhsm::signature_store

#endif // VHSM_SIGNATURE_STORE_POSTGRES_CONNECTION_H
