#include "key_policy.h"

#include <stdexcept>

#include <nlohmann/json.hpp>

namespace vhsm::domain::signing {

KeyPolicy KeyPolicy::from_json(const std::string &text) {
  KeyPolicy p;
  if (text.empty()) {
    return p;
  }
  nlohmann::json doc;
  try {
    doc = nlohmann::json::parse(text);
  } catch (const std::exception &e) {
    throw std::runtime_error(std::string("invalid KeyPolicy JSON: ") + e.what());
  }
  if (!doc.is_object()) {
    throw std::runtime_error("KeyPolicy JSON must be an object");
  }
  if (doc.contains("allowed_mechanisms") && !doc["allowed_mechanisms"].is_null()) {
    for (const auto &m : doc["allowed_mechanisms"]) {
      if (m.is_string())
        p.allowed_mechanisms.push_back(m.get<std::string>());
    }
  }
  if (doc.contains("not_before_ms") && !doc["not_before_ms"].is_null()) {
    p.not_before_ms = doc["not_before_ms"].get<int64_t>();
  }
  if (doc.contains("not_after_ms") && !doc["not_after_ms"].is_null()) {
    p.not_after_ms = doc["not_after_ms"].get<int64_t>();
  }
  if (doc.contains("allowed_signers") && !doc["allowed_signers"].is_null()) {
    for (const auto &s : doc["allowed_signers"]) {
      if (s.is_string())
        p.allowed_signers.push_back(s.get<std::string>());
    }
  }
  if (doc.contains("min_attestations") && !doc["min_attestations"].is_null()) {
    p.min_attestations = doc["min_attestations"].get<int>();
  }
  return p;
}

std::string KeyPolicy::to_json() const {
  nlohmann::json doc;
  doc["allowed_mechanisms"] = allowed_mechanisms;
  doc["not_before_ms"] = not_before_ms;
  doc["not_after_ms"] = not_after_ms;
  doc["allowed_signers"] = allowed_signers;
  doc["min_attestations"] = min_attestations;
  return doc.dump();
}

PolicyEvaluation KeyPolicy::evaluate(const std::string &actor,
                                     const std::string &mechanism,
                                     int64_t now_ms,
                                     size_t attestation_count) const {
  PolicyEvaluation r;
  if (not_before_ms != 0 && now_ms < not_before_ms) {
    r.reason = "key policy: signing not yet active (not_before in the future)";
    return r;
  }
  if (not_after_ms != 0 && now_ms > not_after_ms) {
    r.reason = "key policy: signing window has expired (not_after passed)";
    return r;
  }
  if (!allowed_mechanisms.empty()) {
    bool found = false;
    for (const auto &m : allowed_mechanisms) {
      if (m == mechanism) {
        found = true;
        break;
      }
    }
    if (!found) {
      r.reason = "key policy: mechanism " + mechanism + " not permitted";
      return r;
    }
  }
  if (!allowed_signers.empty()) {
    bool found = false;
    for (const auto &s : allowed_signers) {
      if (s == actor) {
        found = true;
        break;
      }
    }
    if (!found) {
      r.reason = "key policy: actor " + actor + " not authorized to sign";
      return r;
    }
  }
  if (static_cast<int>(attestation_count) < min_attestations) {
    r.reason = "key policy: insufficient attestations (" +
               std::to_string(attestation_count) + " < " +
               std::to_string(min_attestations) + " required)";
    return r;
  }
  r.ok = true;
  r.reason = "ok";
  return r;
}

} // namespace vhsm::domain::signing
