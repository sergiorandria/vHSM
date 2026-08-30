#ifndef VHSM_DOMAIN_SIGNING_KEY_POLICY_H
#define VHSM_DOMAIN_SIGNING_KEY_POLICY_H

#include <cstdint>
#include <string>
#include <vector>

namespace vhsm::domain::signing {

// Result of evaluating a KeyPolicy at sign time.
struct PolicyEvaluation {
  bool ok = false;
  std::string reason;
};

// KeyPolicy describes the conditions under which a key may be used to sign.
// It is serialized as JSON and attached to a key object via the vendor
// attribute CKA_VHSM_POLICY (see pkcs11_internal.h). The fields are all
// optional/permissive by default so that an empty policy is equivalent to
// "no policy".
struct KeyPolicy {
  // Empty = any mechanism allowed. Otherwise the signing mechanism (e.g.
  // "CKM_ECDSA_SHA256") must be listed here.
  std::vector<std::string> allowed_mechanisms;
  // Time window (epoch milliseconds). 0 = unbounded on that side.
  int64_t not_before_ms = 0;
  int64_t not_after_ms = 0;
  // Allowed signer identities (matched against the PKCS#11 session user
  // label, e.g. "user-1"). Empty = any signer allowed.
  std::vector<std::string> allowed_signers;
  // Minimum number of attestations that must be present before signing is
  // permitted (quorum). 0 = no attestations required. The canonical
  // attestation registry lives on the ledger (chaincode); the C++ side uses
  // this count to fail closed when the chaincode is unreachable.
  int min_attestations = 0;

  // Parse from a JSON document; throws std::runtime_error on malformed input.
  static KeyPolicy from_json(const std::string &json);
  std::string to_json() const;

  // Evaluate whether `actor` may sign with `mechanism` at time `now_ms`
  // given `attestation_count` collected attestations.
  PolicyEvaluation evaluate(const std::string &actor,
                            const std::string &mechanism, int64_t now_ms,
                            size_t attestation_count) const;
};

} // namespace vhsm::domain::signing

#endif // VHSM_DOMAIN_SIGNING_KEY_POLICY_H
