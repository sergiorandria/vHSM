#include "aes_ecb.h"
#include "vhsm/scrypto/aes.h"
#include <stdexcept>

namespace vhsm::crypto {

void AESECB::encrypt_block(const uint8_t *key, const uint8_t *input,
                           uint8_t *output) {
  vhsm::scrypto::aes256_ecb_encrypt_block(key, input, output);
}

void AESECB::decrypt_block(const uint8_t *key, const uint8_t *input,
                           uint8_t *output) {
  vhsm::scrypto::aes256_ecb_decrypt_block(key, input, output);
}

} // namespace vhsm::crypto
