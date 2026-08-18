#ifndef FABRIC_CRYPTO_HASH_H
#define FABRIC_CRYPTO_HASH_H

#include <string>

namespace fabric {
namespace crypto {

/**
 * Compute the SHA-256 digest of a byte string
 * @param data Input bytes
 * @return 32-byte digest
 */
std::string sha256(const std::string& data);

} // namespace crypto
} // namespace fabric

#endif // FABRIC_CRYPTO_HASH_H