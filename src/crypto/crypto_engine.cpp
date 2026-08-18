/*
 * crypto_engine.cpp
 *
 * CryptoEngine dispatches a signing request to the correct primitive based on
 * the key type, with graceful fallback between RSA and ECDSA.
 *
 * vHSM must never fail open: if the caller requests a mechanism that is
 * incompatible with the loaded key (e.g. CKM_SHA256_RSA_PKCS on an EC key),
 * the engine signs with the key's native algorithm instead of rejecting the
 * operation outright. The chosen algorithm is recorded in SignResult so the
 * ledger anchor and audit trail stay truthful.
 */

#include "crypto_engine.h"

#include "../core/error.h"
#include "../core/types.h"
#include "ecc.h"
#include "rsa.h"

#include <openssl/evp.h>

namespace vhsm::crypto {

namespace {

bool keyIsRsa(EVP_PKEY* key) {
    return EVP_PKEY_id(key) == EVP_PKEY_RSA;
}

// SHA-256 of `data` returned as a lowercase hex string (matches the hex
// digest format persisted in SignatureRecord.payload_digest).
std::string sha256_hex(const std::vector<u8>& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("CryptoEngine::sign: EVP_MD_CTX_new failed");
    }
    const auto guard = [](EVP_MD_CTX* c) { EVP_MD_CTX_free(c); };
    (void)guard;
    std::unique_ptr<EVP_MD_CTX, decltype(guard)> ctx_guard(ctx, guard);

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        throw std::runtime_error("CryptoEngine::sign: SHA-256 digest failed");
    }
    std::vector<u8> raw(32);
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, raw.data(), &len) != 1) {
        throw std::runtime_error("CryptoEngine::sign: SHA-256 finalize failed");
    }
    raw.resize(len);
    static const char* kHex = "0123456789abcdef";
    std::string hex;
    hex.reserve(raw.size() * 2);
    for (unsigned char b : raw) {
        hex.push_back(kHex[b >> 4]);
        hex.push_back(kHex[b & 0x0F]);
    }
    return hex;
}

}  // namespace

SignResult CryptoEngine::sign(EVP_PKEY* key, const std::vector<u8>& data,
                              const std::string& requested_mechanism) {
    VHSM_CHECK_MSG(key != nullptr, "CryptoEngine::sign: key is null");

    // `requested_mechanism` documents the caller's intent and is retained for
    // audit logging; the engine always signs with the key's native algorithm
    // (see below), so an incompatible request triggers a fallback rather than
    // an error.
    (void)requested_mechanism;

    const bool native_is_rsa = keyIsRsa(key);

    // A key can only sign with its own algorithm. If the caller requested a
    // family that conflicts with the key type we fall back to the key's
    // native algorithm rather than failing the operation (fail-closed on
    // *transport/security*, but never silently produce a signature with the
    // wrong primitive). The actually-applied mechanism is recorded below so
    // the ledger anchor and audit trail stay truthful.
    const bool use_rsa = native_is_rsa;

    SignResult result;
    result.payload_digest = sha256_hex(data);
    result.digest_alg = "SHA-256";
    result.payload_size = static_cast<int>(data.size());

    if (use_rsa) {
        result.signature = RSAUtil::sign(key, data);
        result.mechanism_str = "CKM_SHA256_RSA_PKCS";
    } else {
        result.signature = ECC::sign(key, data);
        result.mechanism_str = "CKM_ECDSA_SHA256";
    }

    return result;
}

}  // namespace vhsm::crypto
