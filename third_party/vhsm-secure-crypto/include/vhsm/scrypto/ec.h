#pragma once
#include <cstdint>
#include <vector>

namespace vhsm::scrypto {

enum class Curve { P256, P384, P521 };

struct EcKeyPair {
  void *handle = nullptr;
  Curve curve = Curve::P256;
};
void ec_free(EcKeyPair kp) noexcept;

EcKeyPair ec_generate(Curve c);
std::vector<uint8_t> ec_sign(const EcKeyPair &key,
                             const std::vector<uint8_t> &data);
bool ec_verify(const EcKeyPair &key, const std::vector<uint8_t> &data,
               const std::vector<uint8_t> &sig);
std::vector<uint8_t> ecdh_derive(const EcKeyPair &priv,
                                 const EcKeyPair &peer_pub);

// EVP interop
void *ec_handle_from_evp(void *evp) noexcept;

} // namespace vhsm::scrypto
