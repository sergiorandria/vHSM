/*
 * aes_gcm.cpp — OpenSSL-free via vhsm::scrypto
 */
#include "aes_gcm.h"
#include "../core/error.h"
#include "../core/types.h"
#include "vhsm/scrypto/aes_gcm.h"
#include "vhsm/scrypto/mem.h"
#include <stdexcept>

namespace vhsm::crypto {

AESGCMResult AESGCM::encrypt(const std::vector<u8> &key,
                             const std::vector<u8> &plaintext) {
  VHSM_CHECK_MSG(key.size() == 32, "AESGCM::encrypt: key must be 32 bytes");
  auto r = vhsm::scrypto::aes256_gcm_encrypt(key, plaintext);
  AESGCMResult out;
  out.ciphertext = std::move(r.ciphertext);
  out.nonce = std::move(r.nonce);
  out.tag = std::move(r.tag);
  return out;
}

std::vector<u8> AESGCM::decrypt(const std::vector<u8> &key,
                                const AESGCMResult &data) {
  VHSM_CHECK_MSG(key.size() == 32, "AESGCM::decrypt: key must be 32 bytes");
  VHSM_CHECK_MSG(data.nonce.size() == 12, "AESGCM::decrypt: nonce must be 12 bytes");
  VHSM_CHECK_MSG(data.tag.size() == 16, "AESGCM::decrypt: tag must be 16 bytes");
  vhsm::scrypto::GcmResult r;
  r.ciphertext = data.ciphertext;
  r.nonce = data.nonce;
  r.tag = data.tag;
  try {
    return vhsm::scrypto::aes256_gcm_decrypt(key, r);
  } catch (const std::exception &e) {
    throw std::runtime_error(std::string("authentication failed: ") + e.what());
  }
}

} // namespace vhsm::crypto
