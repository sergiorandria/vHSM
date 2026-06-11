#pragma once
#include "../crypto/ecc.h"
#include "../crypto/rsa.h"


class Key_fingerprint
{
    public:
        using Fingerprint = std::array<uint8_t, 32>;
        Fingerprint from_SPKI(const std::vector<uint8_t>& spki);
        Fingerprint from_public_key(const vhsm::crypto::ECKeyPair& key);
        Fingerprint from_public_key(const vhsm::crypto::RSAKeyPair& key);

};