#ifndef VHSM_SIGNATURE_STORE_MYSQL_CONNECTION_H
#define VHSM_SIGNATURE_STORE_MYSQL_CONNECTION_H

#include <mutex>
#include <string>
#include <vector>

#include "db_connection.h"
#include "db_result_set.h"
#include "db_transaction.h"

struct st_mysql;
typedef struct st_mysql MYSQL;

namespace vhsm::signature_store {
namespace db {

class MySqlConnection : public IDbConnection {
public:
  explicit MySqlConnection(const std::string &connection_string);
  ~MySqlConnection() override;

  MySqlConnection(const MySqlConnection &) = delete;
  MySqlConnection &operator=(const MySqlConnection &) = delete;

  DbResultSet query(const std::string &sql,
                    const std::vector<std::string> &params = {}) override;
  i64 exec(const std::string &sql,
           const std::vector<std::string> &params = {}) override;
  void with_transaction(const std::function<void(IDbTransaction &)> &func) override;

private:
  MYSQL *conn_ = nullptr;
  std::mutex mutex_;

  std::string build_sql(const std::string &sql,
                        const std::vector<std::string> &params);
};

class MySqlTransaction : public IDbTransaction {
public:
  MySqlTransaction(MYSQL *conn, std::mutex &mu);
  DbResultSet query(const std::string &sql,
                    const std::vector<std::string> &params = {}) override;
  i64 exec(const std::string &sql,
           const std::vector<std::string> &params = {}) override;
private:
  MYSQL *conn_;
  std::mutex &mu_;
};

} // namespace db
} // namespace vhsm::signature_store

#endif // VHSM_SIGNATURE_STORE_MYSQL_CONNECTION_H
