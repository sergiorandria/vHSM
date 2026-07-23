#ifndef VHSM_KEYSTORE_KEY_FINGERPRINT 
#define VHSM_KEYSTORE_KEY_FINGERPRINT

#include "../crypto/ecc.h"
#include "../crypto/rsa.h"

#include <array>

namespace vhsm::keystore {

class KeyFingerprint
{
public:   
    using Fingerprint = std::array<uint8_t, 32>;
    
    static Fingerprint from_SPKI(const std::vector<uint8_t>& spki);
    static Fingerprint from_public_key(const vhsm::crypto::ECCKeyPair& key);
    static Fingerprint from_public_key(const vhsm::crypto::RSAKeyPair& key);
};
} // namespace vhsm::keystore 
#endif // VHSM_KEYSTORE_KEY_FINGERPRINT