#ifndef VHSM_DOMAIN_CRYPTO_TYPES_H
#define VHSM_DOMAIN_CRYPTO_TYPES_H

#include "../core/kernel_types.h"
#include <string>
#include <vector>

namespace vhsm::crypto {

// SignResult — domain value object returned by CryptoEngine::sign().
struct SignResult {
  std::vector<u8> signature;  // raw DER bytes
  std::string mechanism_str;  // e.g., "CKM_ECDSA_SHA256"
  std::string digest_alg;     // e.g., "SHA-256"
  std::string payload_digest; // hex SHA-256 of input
  size_t payload_size;
};

enum class HashAlgorithm { SHA256, SHA384, SHA512 };

} // namespace vhsm::crypto

#endif // VHSM_DOMAIN_CRYPTO_TYPES_H
