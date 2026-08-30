#include "mysql_connection.h"

#include <mysql.h>
#include <mysqld_error.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "../core/error.h"

namespace vhsm::signature_store
{
namespace db
{

namespace
{
std::string mysql_escape(MYSQL* conn, const std::string& s)
{
  std::string out;
  out.resize(s.size() * 2 + 1);
  unsigned long len = mysql_real_escape_string(conn, out.data(), s.c_str(), s.size());
  out.resize(len);
  return out;
}

std::string mysql_build(MYSQL* conn, const std::string& sql, const std::vector<std::string>& params)
{
  std::string out;
  out.reserve(sql.size() + params.size() * 16);
  size_t pidx = 0;
  for (char c : sql)
  {
    if (c == '?' && pidx < params.size())
    {
      out += "'";
      out += mysql_escape(conn, params[pidx++]);
      out += "'";
    }
    else
    {
      out += c;
    }
  }
  return out;
}
}  // namespace

MySqlConnection::MySqlConnection(const std::string& conn_str)
{
  conn_ = mysql_init(nullptr);
  if (!conn_)
    throw DbError(DbError::Kind::ConnectionError, "mysql_init failed");
  // conn_str is expected as mysql:// or key=value; try as URI first, then fallback
  // For simplicity, treat conn_str as host/db/user/pass via parsing or as single host
  // Use mysql_real_connect with parsed components if needed.
  // If conn_str contains '=', use as option string via mysql_options.
  // Simplest: if it contains '://', parse, else treat as host.
  std::string host = "127.0.0.1";
  std::string user = "root";
  std::string pass = "";
  std::string db = "vhsm";
  unsigned int port = 3306;

  // Very small parser for mysql://user:pass@host:port/db
  if (conn_str.rfind("mysql://", 0) == 0)
  {
    std::string uri = conn_str.substr(8);
    auto at = uri.find('@');
    std::string hostpart;
    if (at != std::string::npos)
    {
      std::string userinfo = uri.substr(0, at);
      hostpart = uri.substr(at + 1);
      auto colon = userinfo.find(':');
      if (colon != std::string::npos)
      {
        user = userinfo.substr(0, colon);
        pass = userinfo.substr(colon + 1);
      }
      else
      {
        user = userinfo;
      }
    }
    else
    {
      hostpart = uri;
    }
    auto slash = hostpart.find('/');
    std::string hostport = (slash == std::string::npos) ? hostpart : hostpart.substr(0, slash);
    if (slash != std::string::npos)
      db = hostpart.substr(slash + 1);
    auto colon2 = hostport.find(':');
    if (colon2 != std::string::npos)
    {
      host = hostport.substr(0, colon2);
      try
      {
        port = std::stoi(hostport.substr(colon2 + 1));
      }
      catch (...)
      {}
    }
    else if (!hostport.empty())
    {
      host = hostport;
    }
  }
  else if (!conn_str.empty() && conn_str.find('=') == std::string::npos)
  {
    host = conn_str;
  }
  else if (!conn_str.empty())
  {
    // key=value string, let mysql handle via options is complex; fallback to host
    // Try to extract host=, user=, password=, dbname=
    auto get_val = [&](const std::string& key) -> std::string {
      auto pos = conn_str.find(key + "=");
      if (pos == std::string::npos)
        return "";
      pos += key.size() + 1;
      auto end = conn_str.find(' ', pos);
      if (end == std::string::npos)
        end = conn_str.find(';', pos);
      std::string v = conn_str.substr(pos,
                                      end == std::string::npos ? std::string::npos : end - pos);
      // trim quotes
      if (!v.empty() && (v.front() == '\'' || v.front() == '"'))
        v = v.substr(1, v.size() - 2);
      return v;
    };
    std::string h = get_val("host");
    std::string u = get_val("user");
    std::string p = get_val("password");
    std::string d = get_val("dbname");
    std::string po = get_val("port");
    if (!h.empty())
      host = h;
    if (!u.empty())
      user = u;
    if (!p.empty())
      pass = p;
    if (!d.empty())
      db = d;
    if (!po.empty())
      try
      {
        port = std::stoi(po);
      }
      catch (...)
      {}
  }

  if (!mysql_real_connect(
          conn_, host.c_str(), user.c_str(), pass.c_str(), db.c_str(), port, nullptr, 0))
  {
    std::string msg = "mysql_real_connect failed: ";
    msg += mysql_error(conn_);
    mysql_close(conn_);
    conn_ = nullptr;
    throw DbError(DbError::Kind::ConnectionError, msg);
  }
  // Ensure autocommit is on (default) - with_transaction will use START TRANSACTION
}

MySqlConnection::~MySqlConnection()
{
  if (conn_)
  {
    mysql_close(conn_);
    conn_ = nullptr;
  }
}

std::string MySqlConnection::build_sql(const std::string& sql,
                                       const std::vector<std::string>& params)
{
  return mysql_build(conn_, sql, params);
}

DbResultSet MySqlConnection::query(const std::string& sql, const std::vector<std::string>& params)
{
  std::lock_guard<std::mutex> lk(mutex_);
  std::string q = build_sql(sql, params);
  if (mysql_real_query(conn_, q.c_str(), q.size()))
  {
    std::string msg = "mysql query failed: ";
    msg += mysql_error(conn_);
    throw DbError(DbError::Kind::IoError, msg);
  }
  MYSQL_RES* res = mysql_store_result(conn_);
  if (!res)
  {
    if (mysql_field_count(conn_) == 0)
      return DbResultSet();
    std::string msg = "mysql_store_result failed: ";
    msg += mysql_error(conn_);
    throw DbError(DbError::Kind::IoError, msg);
  }
  int ncols = mysql_num_fields(res);
  std::vector<DbRow> rows;
  MYSQL_ROW row;
  while ((row = mysql_fetch_row(res)))
  {
    std::vector<std::string> vals;
    vals.reserve(ncols);
    unsigned long* lengths = mysql_fetch_lengths(res);
    for (int i = 0; i < ncols; ++i)
    {
      if (row[i] == nullptr)
        vals.emplace_back("");
      else
        vals.emplace_back(row[i], lengths[i]);
    }
    rows.emplace_back(std::move(vals));
  }
  mysql_free_result(res);
  return DbResultSet(std::move(rows));
}

i64 MySqlConnection::exec(const std::string& sql, const std::vector<std::string>& params)
{
  std::lock_guard<std::mutex> lk(mutex_);
  std::string q = build_sql(sql, params);
  if (mysql_real_query(conn_, q.c_str(), q.size()))
  {
    std::string msg = "mysql exec failed: ";
    msg += mysql_error(conn_);
    unsigned int err = mysql_errno(conn_);
    if (err == ER_DUP_ENTRY)
      throw DbError(DbError::Kind::ConstraintError, msg);
    throw DbError(DbError::Kind::IoError, msg);
  }
  // For SELECT executed via exec, discard result
  MYSQL_RES* res = mysql_store_result(conn_);
  if (res)
    mysql_free_result(res);
  return static_cast<i64>(mysql_affected_rows(conn_));
}

void MySqlConnection::with_transaction(const std::function<void(IDbTransaction&)>& func)
{
  std::unique_lock<std::mutex> lk(mutex_);
  if (mysql_real_query(conn_, "START TRANSACTION", 17))
  {
    throw DbError(DbError::Kind::TransactionError, mysql_error(conn_));
  }
  try
  {
    MySqlTransaction tx(conn_, mutex_);
    func(tx);
    if (mysql_real_query(conn_, "COMMIT", 6))
    {
      throw DbError(DbError::Kind::TransactionError, mysql_error(conn_));
    }
  }
  catch (...)
  {
    mysql_real_query(conn_, "ROLLBACK", 8);
    throw;
  }
}

MySqlTransaction::MySqlTransaction(MYSQL* conn, std::mutex& mu) : conn_(conn), mu_(mu) {}

DbResultSet MySqlTransaction::query(const std::string& sql, const std::vector<std::string>& params)
{
  std::string q = mysql_build(conn_, sql, params);
  if (mysql_real_query(conn_, q.c_str(), q.size()))
  {
    throw DbError(DbError::Kind::IoError, mysql_error(conn_));
  }
  MYSQL_RES* res = mysql_store_result(conn_);
  if (!res)
  {
    if (mysql_field_count(conn_) == 0)
      return DbResultSet();
    throw DbError(DbError::Kind::IoError, mysql_error(conn_));
  }
  int ncols = mysql_num_fields(res);
  std::vector<DbRow> rows;
  MYSQL_ROW row;
  while ((row = mysql_fetch_row(res)))
  {
    std::vector<std::string> vals;
    unsigned long* lengths = mysql_fetch_lengths(res);
    for (int i = 0; i < ncols; ++i)
      vals.emplace_back(row[i] ? std::string(row[i], lengths[i]) : "");
    rows.emplace_back(std::move(vals));
  }
  mysql_free_result(res);
  return DbResultSet(std::move(rows));
}

i64 MySqlTransaction::exec(const std::string& sql, const std::vector<std::string>& params)
{
  std::string q = mysql_build(conn_, sql, params);
  if (mysql_real_query(conn_, q.c_str(), q.size()))
  {
    unsigned int err = mysql_errno(conn_);
    std::string msg = mysql_error(conn_);
    if (err == ER_DUP_ENTRY)
      throw DbError(DbError::Kind::ConstraintError, msg);
    throw DbError(DbError::Kind::IoError, msg);
  }
  MYSQL_RES* res = mysql_store_result(conn_);
  if (res)
    mysql_free_result(res);
  return static_cast<i64>(mysql_affected_rows(conn_));
}

}  // namespace db
}  // namespace vhsm::signature_store
