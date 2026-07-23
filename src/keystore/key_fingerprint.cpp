#include "key_fingerprint.h"
#include "../crypto/MdCtxGuard.h"
#include "../core/error.h"

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>

namespace vhsm::keystore {
// Utilities to compute a SHA-256 fingerprint for a public key.
// Fingerprints are computed over a serialized public-key representation
// (DER SubjectPublicKeyInfo / SPKI). Uses OpenSSL EVP for digest
// operations and BIO/i2d_* helpers to obtain DER encoding from an EVP_PKEY.

// Compute SHA-256 over a provided SPKI/DER representation.
// - `spki`: DER bytes of SubjectPublicKeyInfo (SPKI)
// Returns a `Fingerprint` (32-byte SHA-256). On error a zeroed fingerprint is returned.
KeyFingerprint::Fingerprint KeyFingerprint::from_SPKI(const std::vector<uint8_t>& spki)
{
    // Initialized with zero
    Fingerprint fingerprint{};

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    VHSM_CHECK(ctx != nullptr);

    const crypto::MdCtxGuard guard(ctx);

    VHSM_CHECK_MSG(EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr), "EVP_DigestInit_ex() failed");
    VHSM_CHECK(EVP_DigestUpdate(ctx, spki.data(), spki.size()));
    VHSM_CHECK(EVP_DigestFinal_ex(ctx, fingerprint.data(), nullptr));

    return fingerprint;
}

// Serialize an EC `ECKeyPair` to DER/SPKI via a memory BIO and delegate
// to `from_SPKI` for the SHA-256 calculation.
// CORRIGÉ : vhsm::crypto:: ajouté devant ECKeyPair
KeyFingerprint::Fingerprint KeyFingerprint::from_public_key(const vhsm::crypto::ECCKeyPair& key)
{
    KeyFingerprint::Fingerprint fingerprint{};
    BIO* bio = BIO_new(BIO_s_mem());

    if (bio && i2d_PUBKEY_bio(bio, key.key) == 1) {
        BUF_MEM* mem_ptr;
        BIO_get_mem_ptr(bio, &mem_ptr);
        
        std::vector<uint8_t> spki(
            reinterpret_cast<uint8_t*>(mem_ptr->data), 
            reinterpret_cast<uint8_t*>(mem_ptr->data) + mem_ptr->length
        );

        BIO_free(bio);
        return from_SPKI(spki);
    }

    if(bio) {
        BIO_free(bio);
    }

    return fingerprint;
}

// Serialize an RSA `RSAKeyPair` to DER/SPKI via a memory BIO and delegate
// to `from_SPKI` for the SHA-256 calculation.
KeyFingerprint::Fingerprint KeyFingerprint::from_public_key(const vhsm::crypto::RSAKeyPair& key)
{
    KeyFingerprint::Fingerprint fingerprint{};
    BIO* bio = BIO_new(BIO_s_mem());
    
    if (bio && i2d_PUBKEY_bio(bio, key.key) == 1) {
        BUF_MEM* mem_ptr;
        BIO_get_mem_ptr(bio, &mem_ptr);
        
        std::vector<uint8_t> spki(
            reinterpret_cast<uint8_t*>(mem_ptr->data),
            reinterpret_cast<uint8_t*>(mem_ptr->data) + mem_ptr->length
        );

        BIO_free(bio);
        return from_SPKI(spki);
    }

    if(bio) {
        BIO_free(bio);
    }

    return fingerprint;
}
} // namespace vhsm::keystore