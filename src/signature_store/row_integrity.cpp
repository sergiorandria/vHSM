#include "row_integrity.h"

#include "db_connection.h"
#include "db_hmac_key.h"
#include "vhsm/scrypto/constant_time.h"

#include <iomanip>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <vector>

namespace vhsm::signature_store {
namespace db {

RowIntegrity::RowIntegrity(IDbConnection &conn, vhsm::keystore::Token &token)
    : conn_(conn), token_(token) {}

std::string RowIntegrity::compute_hmac(
    const std::vector<std::optional<std::string>> &column_values) const {
  // Get the HMAC key — if unavailable, fail closed (throw) rather than
  // returning a sentinel "" that could be compared as "" == "" and verify.
  DbHmacKey hmac_key(conn_, token_);
  std::vector<std::uint8_t> key = hmac_key.get_key();
  if (key.empty()) {
    throw std::runtime_error(
        "RowIntegrity::compute_hmac: HMAC key unavailable — fail closed");
  }

  // Length-prefix each field (4-byte big-endian) instead of \0 delimiter,
  // so the scheme is correct even if a column contains null bytes.
  // Format: [len32_be][bytes] per column, with len=0 for nullopt.
  std::string concatenated;
  // Reserve roughly: 4*fields + sum(lengths) to avoid realloc
  size_t total = column_values.size() * 4;
  for (auto &v : column_values) if (v) total += v->size();
  concatenated.reserve(total);
  for (auto &opt : column_values) {
    uint32_t len = opt ? static_cast<uint32_t>(opt->size()) : 0;
    concatenated.push_back(static_cast<char>((len >> 24) & 0xFF));
    concatenated.push_back(static_cast<char>((len >> 16) & 0xFF));
    concatenated.push_back(static_cast<char>((len >> 8) & 0xFF));
    concatenated.push_back(static_cast<char>(len & 0xFF));
    if (opt) concatenated.append(*opt);
  }

  // Compute HMAC-SHA256
  unsigned int hmac_len = 0;
  unsigned char hmac_result[SHA256_DIGEST_LENGTH];
  HMAC(EVP_sha256(), key.data(), key.size(),
       reinterpret_cast<const unsigned char *>(concatenated.data()),
       concatenated.size(), hmac_result, &hmac_len);

  // Convert to hex string
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < hmac_len; ++i) {
    ss << std::setw(2) << static_cast<int>(hmac_result[i]);
  }
  return ss.str();
}

bool RowIntegrity::verify_hmac(
    const std::vector<std::optional<std::string>> &column_values,
    const std::optional<std::string> &stored_hmac) const {
  if (!stored_hmac || stored_hmac->empty()) {
    // No stored HMAC, or empty sentinel — always invalid
    return false;
  }
  std::string computed;
  try {
    computed = compute_hmac(column_values);
  } catch (...) {
    // Key unavailable or HMAC failure — fail closed, never report verified
    return false;
  }
  if (computed.empty()) return false;
  // Constant-time compare over raw hex bytes (no early exit). Also require
  // equal length to avoid length-leak; scrypto::constant_time_eq already
  // does length check, but we make it explicit.
  if (computed.size() != stored_hmac->size()) return false;
  return vhsm::scrypto::constant_time_eq(
      reinterpret_cast<const uint8_t *>(computed.data()),
      reinterpret_cast<const uint8_t *>(stored_hmac->data()),
      computed.size());
}

} // namespace db
} // namespace vhsm::signature_store