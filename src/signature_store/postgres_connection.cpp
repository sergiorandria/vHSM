#include "postgres_connection.h"

#include <libpq-fe.h>

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
std::string pg_translate(const std::string& sql)
{
  std::string out;
  out.reserve(sql.size() + 8);
  int idx = 1;
  for (char c : sql)
  {
    if (c == '?')
    {
      out += "$" + std::to_string(idx++);
    }
    else
    {
      out += c;
    }
  }
  return out;
}
}  // namespace

PostgresConnection::PostgresConnection(const std::string& conn_str)
{
  conn_ = PQconnectdb(conn_str.c_str());
  if (!conn_ || PQstatus(conn_) != CONNECTION_OK)
  {
    std::string msg = "PQconnectdb failed: ";
    msg += conn_ ? PQerrorMessage(conn_) : "null conn";
    if (conn_)
      PQfinish(conn_);
    conn_ = nullptr;
    throw DbError(DbError::Kind::ConnectionError, msg);
  }
}

PostgresConnection::~PostgresConnection()
{
  if (conn_)
  {
    PQfinish(conn_);
    conn_ = nullptr;
  }
}

std::string PostgresConnection::translate_placeholders(const std::string& sql)
{
  return pg_translate(sql);
}

DbResultSet PostgresConnection::exec_params(const std::string& sql,
                                            const std::vector<std::string>& params,
                                            bool is_query)
{
  std::string pg_sql = translate_placeholders(sql);
  std::vector<const char*> c_params;
  c_params.reserve(params.size());
  for (auto& p : params)
    c_params.push_back(p.c_str());

  PGresult* res = PQexecParams(conn_,
                               pg_sql.c_str(),
                               static_cast<int>(params.size()),
                               nullptr,
                               c_params.empty() ? nullptr : c_params.data(),
                               nullptr,
                               nullptr,
                               0);
  if (!res)
  {
    throw DbError(DbError::Kind::IoError,
                  std::string("PQexecParams null: ") + PQerrorMessage(conn_));
  }
  ExecStatusType st = PQresultStatus(res);
  if (is_query)
  {
    if (st != PGRES_TUPLES_OK)
    {
      std::string msg = "query failed: ";
      msg += PQresultErrorMessage(res);
      PQclear(res);
      throw DbError(DbError::Kind::IoError, msg);
    }
    int nrows = PQntuples(res);
    int ncols = PQnfields(res);
    std::vector<DbRow> rows;
    rows.reserve(nrows);
    for (int r = 0; r < nrows; ++r)
    {
      std::vector<std::string> vals;
      vals.reserve(ncols);
      for (int c = 0; c < ncols; ++c)
      {
        if (PQgetisnull(res, r, c))
          vals.emplace_back("");
        else
          vals.emplace_back(PQgetvalue(res, r, c));
      }
      rows.emplace_back(std::move(vals));
    }
    PQclear(res);
    return DbResultSet(std::move(rows));
  }
  else
  {
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK)
    {
      std::string msg = "exec failed: ";
      msg += PQresultErrorMessage(res);
      PQclear(res);
      // Map constraint errors
      if (msg.find("duplicate") != std::string::npos || msg.find("unique") != std::string::npos)
        throw DbError(DbError::Kind::ConstraintError, msg);
      throw DbError(DbError::Kind::IoError, msg);
    }
    (void)PQcmdTuples(res);
    PQclear(res);
    return DbResultSet();
  }
}

DbResultSet PostgresConnection::query(const std::string& sql,
                                      const std::vector<std::string>& params)
{
  std::lock_guard<std::mutex> lk(mutex_);
  return exec_params(sql, params, true);
}

i64 PostgresConnection::exec(const std::string& sql, const std::vector<std::string>& params)
{
  std::lock_guard<std::mutex> lk(mutex_);
  std::string pg_sql = translate_placeholders(sql);
  std::vector<const char*> c_params;
  c_params.reserve(params.size());
  for (auto& p : params)
    c_params.push_back(p.c_str());
  PGresult* res = PQexecParams(conn_,
                               pg_sql.c_str(),
                               static_cast<int>(params.size()),
                               nullptr,
                               c_params.empty() ? nullptr : c_params.data(),
                               nullptr,
                               nullptr,
                               0);
  if (!res)
  {
    throw DbError(DbError::Kind::IoError,
                  std::string("PQexecParams null: ") + PQerrorMessage(conn_));
  }
  ExecStatusType st = PQresultStatus(res);
  if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK)
  {
    std::string msg = "exec failed: ";
    msg += PQresultErrorMessage(res);
    PQclear(res);
    if (msg.find("duplicate") != std::string::npos || msg.find("unique") != std::string::npos)
      throw DbError(DbError::Kind::ConstraintError, msg);
    throw DbError(DbError::Kind::IoError, msg);
  }
  char* tuples = PQcmdTuples(res);
  i64 affected = 0;
  if (tuples && *tuples)
  {
    try
    {
      affected = std::stoll(tuples);
    }
    catch (...)
    {}
  }
  PQclear(res);
  return affected;
}

void PostgresConnection::with_transaction(const std::function<void(IDbTransaction&)>& func)
{
  std::unique_lock<std::mutex> lk(mutex_);
  PGresult* res = PQexec(conn_, "BEGIN");
  if (PQresultStatus(res) != PGRES_COMMAND_OK)
  {
    std::string msg = "BEGIN failed: ";
    msg += PQresultErrorMessage(res);
    PQclear(res);
    throw DbError(DbError::Kind::TransactionError, msg);
  }
  PQclear(res);
  try
  {
    PostgresTransaction tx(conn_, mutex_);
    func(tx);
    res = PQexec(conn_, "COMMIT");
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
    {
      std::string msg = "COMMIT failed: ";
      msg += PQresultErrorMessage(res);
      PQclear(res);
      throw DbError(DbError::Kind::TransactionError, msg);
    }
    PQclear(res);
  }
  catch (...)
  {
    PGresult* r2 = PQexec(conn_, "ROLLBACK");
    if (r2)
      PQclear(r2);
    throw;
  }
}

// Simpler correct with_transaction implementation - redefine to avoid deadlock
// We will provide a clean implementation that does not deadlock by not re-locking in tx
// PostgresTransaction in transaction context should directly use conn_ without locking

PostgresTransaction::PostgresTransaction(PGconn* conn, std::mutex& mu) : conn_(conn), mu_(mu) {}

DbResultSet PostgresTransaction::query(const std::string& sql,
                                       const std::vector<std::string>& params)
{
  // Assumes outer with_transaction holds lock - do not lock again
  std::string pg_sql = pg_translate(sql);
  std::vector<const char*> c_params;
  for (auto& p : params)
    c_params.push_back(p.c_str());
  PGresult* res = PQexecParams(conn_,
                               pg_sql.c_str(),
                               static_cast<int>(params.size()),
                               nullptr,
                               c_params.empty() ? nullptr : c_params.data(),
                               nullptr,
                               nullptr,
                               0);
  if (!res)
    throw DbError(DbError::Kind::IoError, "PQexecParams null");
  if (PQresultStatus(res) != PGRES_TUPLES_OK)
  {
    std::string msg = PQresultErrorMessage(res);
    PQclear(res);
    throw DbError(DbError::Kind::IoError, msg);
  }
  int nrows = PQntuples(res);
  int ncols = PQnfields(res);
  std::vector<DbRow> rows;
  for (int r = 0; r < nrows; ++r)
  {
    std::vector<std::string> vals;
    for (int c = 0; c < ncols; ++c)
    {
      vals.emplace_back(PQgetisnull(res, r, c) ? "" : PQgetvalue(res, r, c));
    }
    rows.emplace_back(std::move(vals));
  }
  PQclear(res);
  return DbResultSet(std::move(rows));
}

i64 PostgresTransaction::exec(const std::string& sql, const std::vector<std::string>& params)
{
  std::string pg_sql = pg_translate(sql);
  std::vector<const char*> c_params;
  for (auto& p : params)
    c_params.push_back(p.c_str());
  PGresult* res = PQexecParams(conn_,
                               pg_sql.c_str(),
                               static_cast<int>(params.size()),
                               nullptr,
                               c_params.empty() ? nullptr : c_params.data(),
                               nullptr,
                               nullptr,
                               0);
  if (!res)
    throw DbError(DbError::Kind::IoError, "PQexecParams null");
  if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK)
  {
    std::string msg = PQresultErrorMessage(res);
    PQclear(res);
    throw DbError(DbError::Kind::IoError, msg);
  }
  char* tuples = PQcmdTuples(res);
  i64 affected = 0;
  if (tuples && *tuples)
    try
    {
      affected = std::stoll(tuples);
    }
    catch (...)
    {}
  PQclear(res);
  return affected;
}

}  // namespace db
}  // namespace vhsm::signature_store
