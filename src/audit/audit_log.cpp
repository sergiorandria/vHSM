#include "audit_log.h"

#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <mutex>

#include <vhsm/scrypto/hmac.h>
#include <vhsm/scrypto/mem.h>

namespace vhsm::audit {

namespace {

constexpr size_t kHexDigestLen = 64; // SHA-256 hex

void to_hex(const uint8_t *in, size_t len, char *out) {
  static const char kDigits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[2 * i] = kDigits[in[i] >> 4];
    out[2 * i + 1] = kDigits[in[i] & 0xF];
  }
}

// ISO-8601 UTC timestamp with millisecond precision.
std::string iso8601_now() {
  using namespace std::chrono;
  const auto now = system_clock::now();
  const auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
  const std::time_t t = system_clock::to_time_t(now);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                tm.tm_min, tm.tm_sec, static_cast<int>(ms.count()));
  return buf;
}

std::array<uint8_t, 32> chain_hmac(const std::vector<uint8_t> &key,
                                   const std::string &record_bytes) {
  const std::vector<uint8_t> data(record_bytes.begin(), record_bytes.end());
  return vhsm::scrypto::hmac_sha256(key, data);
}

} // namespace

HashChainedAuditLog::HashChainedAuditLog(std::string path,
                                         std::vector<uint8_t> chain_key)
    : path_(std::move(path)), chain_key_(std::move(chain_key)) {
  tail_hex_.assign(kHexDigestLen, '0');
  recover_tail();
}

HashChainedAuditLog::~HashChainedAuditLog() {
  vhsm::scrypto::cleanse_vec(chain_key_);
}

void HashChainedAuditLog::recover_tail() {
  FILE *f = std::fopen(path_.c_str(), "rb");
  if (!f)
    return; // fresh file
  char line[1024];
  while (std::fgets(line, sizeof(line), f)) {
    // Last well-formed line wins: SEQ|TS|ID|TYPE|PREV|HMAC
    std::string s(line);
    if (!s.empty() && s.back() == '\n')
      s.pop_back();
    const auto p5 = s.rfind('|');
    if (p5 == std::string::npos)
      continue;
    tail_hex_ = s.substr(p5 + 1);
    const auto p0 = s.find('|');
    if (p0 != std::string::npos)
      seq_ = std::strtoull(s.substr(0, p0).c_str(), nullptr, 10);
  }
  std::fclose(f);
}

void HashChainedAuditLog::append(const std::string &event_id,
                                 const std::string &event_type) {
  static std::mutex m; // single process-wide audit sink — serialize appends
  std::lock_guard<std::mutex> lk(m);

  ++seq_;
  const std::string ts = iso8601_now();

  std::string record_bytes = std::to_string(seq_) + "|" + ts + "|" + event_id +
                             "|" + event_type + "|" + tail_hex_;
  const auto mac = chain_hmac(chain_key_, record_bytes);

  char hex[kHexDigestLen];
  to_hex(mac.data(), mac.size(), hex);
  const std::string line = record_bytes + "|" + std::string(hex, kHexDigestLen) +
                           "\n";

  FILE *f = std::fopen(path_.c_str(), "ab");
  if (!f)
    throw std::runtime_error("audit: cannot open " + path_);
  const bool ok =
      std::fwrite(line.data(), 1, line.size(), f) == line.size() &&
      std::fflush(f) == 0 && ::fsync(::fileno(f)) == 0;
  std::fclose(f);
  if (!ok)
    throw std::runtime_error("audit: append failed for " + path_);

  tail_hex_.assign(hex, kHexDigestLen);
}

std::optional<std::size_t> HashChainedAuditLog::verify_chain() const {
  FILE *f = std::fopen(path_.c_str(), "rb");
  if (!f)
    return std::nullopt; // nothing logged yet — intact

  std::string prev(kHexDigestLen, '0');
  std::string line_buf;
  std::size_t lineno = 0;
  char raw[2048];

  while (std::fgets(raw, sizeof(raw), f)) {
    ++lineno;
    std::string s(raw);
    if (!s.empty() && s.back() == '\n')
      s.pop_back();

    // Split into exactly 6 fields.
    std::vector<std::string> parts;
    size_t start = 0;
    for (int i = 0; i < 6; ++i) {
      const size_t p = s.find('|', start);
      if (p == std::string::npos && i < 5)
        break;
      parts.push_back(i < 5 ? s.substr(start, p - start) : s.substr(start));
      if (p != std::string::npos)
        start = p + 1;
    }
    if (parts.size() != 6 || parts[5].size() != kHexDigestLen ||
        parts[4] != prev)
      return lineno;

    std::string record_bytes = parts[0] + "|" + parts[1] + "|" + parts[2] +
                               "|" + parts[3] + "|" + parts[4];
    const auto mac = chain_hmac(chain_key_, record_bytes);
    char hex[kHexDigestLen];
    to_hex(mac.data(), mac.size(), hex);
    if (std::string(hex, kHexDigestLen) != parts[5])
      return lineno;

    prev = parts[5];
  }
  std::fclose(f);
  return std::nullopt;
}

// Base-class no-op retained for other sinks.
void AuditLog::append(const std::string &, const std::string &) {}

} // namespace vhsm::audit
