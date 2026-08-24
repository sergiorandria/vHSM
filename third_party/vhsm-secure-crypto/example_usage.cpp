// Example: using vhsm-secure-crypto for all vHSM primitives
#include "vhsm/scrypto/aes_gcm.h"
#include "vhsm/scrypto/constant_time.h"
#include "vhsm/scrypto/hash.h"
#include "vhsm/scrypto/hmac.h"
#include "vhsm/scrypto/kdf.h"
#include "vhsm/scrypto/rng.h"
#include "vhsm/scrypto/scrypto.h"
#include <iostream>

int main() {
  using namespace vhsm::scrypto;
  selftest(true);
  std::cout << version() << "\n";

  // hash
  auto h = sha256((const uint8_t *)"hello", 5);
  std::cout << "sha256 hello: " << sha256_hex((const uint8_t *)"hello", 5)
            << "\n";

  // hmac
  std::vector<uint8_t> key = {1, 2, 3}, data = {'a', 'b', 'c'};
  auto mac = hmac_sha256(key, data);

  // pbkdf2 / hkdf
  auto kek =
      pbkdf2_hmac_sha256("password", std::vector<uint8_t>(16, 0x42), 1000, 32);
  auto dbkey = derive_db_hmac_key(kek);

  // aes-gcm roundtrip
  std::vector<uint8_t> aeskey(32, 0x01), pt = {'s', 'e', 'c', 'r', 'e', 't'};
  auto enc = aes256_gcm_encrypt(aeskey, pt);
  auto dec = aes256_gcm_decrypt(aeskey, enc);
  std::cout << "gcm ok: " << (dec == pt ? "yes" : "no")
            << " tag constant-time: " << constant_time_eq(enc.tag, enc.tag)
            << "\n";

  // rng
  SecureRng rng;
  uint8_t rnd[16];
  rng.bytes(rnd, 16);

  // constant-time compare for RowIntegrity
  std::string a = "abcd", b = "abcd";
  std::cout << "ct_eq: " << constant_time_eq_str(a, b) << "\n";

  cleanse(kek.data(), kek.size());
  return 0;
}
