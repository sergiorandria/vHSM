#include "pkcs11_internal.h"
#include "pkcs11.h"
#include "pkcs11_types.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <vector>
#include <string>
#include <cstring>
#include <unordered_map>

// PKCS#11 OAEP parameter struct / constants are not in our minimal types header;
// define a local mirror of the standard layout so we can parse C_EncryptInit params.
#ifndef CKG_MGF1_SHA1
#define CKG_MGF1_SHA1   0x00000001UL
#define CKG_MGF1_SHA256 0x00000002UL
#define CKG_MGF1_SHA384 0x00000003UL
#define CKG_MGF1_SHA512 0x00000004UL
#endif
#ifndef CKZ_DATA_SPECIFIED
#define CKZ_DATA_SPECIFIED 0x00000001UL
#endif
struct CK_RSA_PKCS_OAEP_PARAMS {
    CK_MECHANISM_TYPE hashAlg;
    CK_MECHANISM_TYPE mgf;
    CK_MECHANISM_TYPE source;
    CK_ULONG          ulSourceDataLen;
    CK_BYTE_PTR       pSourceData;
};

extern "C" {
namespace vhsm::pkcs11 {

namespace {

// OAEP/MGF1 mechanism -> OpenSSL digest name.
const char* oaep_md_name(CK_MECHANISM_TYPE m) {
    switch (m) {
        case CKM_SHA_1:   return "SHA-1";
        case CKM_SHA_256: return "SHA-256";
        case CKM_SHA_384: return "SHA-384";
        case CKM_SHA_512: return "SHA-512";
        default:          return "SHA-256";
    }
}
const char* mgf_name(CK_MECHANISM_TYPE m) {
    switch (m) {
        case CKG_MGF1_SHA1:   return "SHA-1";
        case CKG_MGF1_SHA256: return "SHA-256";
        case CKG_MGF1_SHA384: return "SHA-384";
        case CKG_MGF1_SHA512: return "SHA-512";
        default:              return "SHA-256";
    }
}

bool is_digest_mech(CK_MECHANISM_TYPE m) {
    return m == CKM_SHA_256 || m == CKM_SHA_384 || m == CKM_SHA_512;
}

std::vector<u8> load_secret_key(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE k) {
    std::vector<u8> out;
    HsmObject* o = p11_get_object(h, k);
    if (!o) return out;
    const std::vector<u8>* v = o->findAttribute(CKA_VALUE);
    if (v) out = *v;
    return out;
}

EVP_PKEY* load_asym_key(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE k) {
    HsmObject* o = p11_get_object(h, k);
    if (!o) return nullptr;
    return p11_evp_from_object(o);
}

CK_RV finish_output(std::vector<u8>& out, CK_BYTE_PTR pOut, CK_ULONG_PTR pOutLen) {
    if (!pOutLen) return CKR_ARGUMENTS_BAD;
    if (pOut == nullptr) {
        *pOutLen = static_cast<CK_ULONG>(out.size());
        return CKR_OK;
    }
    if (*pOutLen < out.size()) {
        *pOutLen = static_cast<CK_ULONG>(out.size());
        return CKR_BUFFER_TOO_SMALL;
    }
    if (!out.empty()) std::memcpy(pOut, out.data(), out.size());
    *pOutLen = static_cast<CK_ULONG>(out.size());
    return CKR_OK;
}

// Begin a single-key crypto operation: remember mechanism + key, clear buffers.
CK_RV op_begin(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k, bool needKey) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!m) return CKR_ARGUMENTS_BAD;
    if (needKey && k == CK_INVALID_HANDLE) return CKR_KEY_HANDLE_INVALID;
    g_activeMech[h] = m->mechanism;
    g_signKey[h]     = k;
    g_opBuf[h].clear();
    return CKR_OK;
}
CK_RV op_check(CK_SESSION_HANDLE h) {
    return (g_activeMech.find(h) == g_activeMech.end())
               ? CKR_OPERATION_NOT_INITIALIZED
               : CKR_OK;
}
void op_end(CK_SESSION_HANDLE h) { p11_reset_op(h); }

// ----- Encrypt / Decrypt -----
CK_RV do_encrypt(CK_SESSION_HANDLE h, const std::vector<u8>& in, std::vector<u8>& out) {
    CK_MECHANISM_TYPE mech = g_activeMech[h];
    CK_OBJECT_HANDLE  k    = g_signKey[h];

    if (mech == CKM_AES_GCM) {
        std::vector<u8> key = load_secret_key(h, k);
        if (key.empty()) return CKR_KEY_HANDLE_INVALID;
        std::vector<u8> ct, tag;
        CK_RV rv = p11_aes_gcm_encrypt(key, g_gcmIv[h], g_gcmAad[h], in, ct, tag);
        if (rv == CKR_OK) { out = ct; out.insert(out.end(), tag.begin(), tag.end()); }
        return rv;
    }

    EVP_PKEY* pk = load_asym_key(h, k);
    if (!pk) return CKR_KEY_HANDLE_INVALID;
    int padding = RSA_PKCS1_PADDING;
    std::string md;
    if (mech == CKM_RSA_X_509)       padding = RSA_NO_PADDING;
    else if (mech == CKM_RSA_PKCS_OAEP) { padding = RSA_PKCS1_OAEP_PADDING; md = g_oaepMgf1[h]; }
    const std::vector<u8>* labelPtr = (mech == CKM_RSA_PKCS_OAEP && g_oaepLabel.count(h) && !g_oaepLabel[h].empty())
                                          ? &g_oaepLabel[h] : nullptr;
    CK_RV rv = p11_rsa_encrypt(pk, in, out, padding, labelPtr, md);
    EVP_PKEY_free(pk);
    return rv;
}

CK_RV do_decrypt(CK_SESSION_HANDLE h, const std::vector<u8>& in, std::vector<u8>& out) {
    CK_MECHANISM_TYPE mech = g_activeMech[h];
    CK_OBJECT_HANDLE  k    = g_signKey[h];

    if (mech == CKM_AES_GCM) {
        std::vector<u8> key = load_secret_key(h, k);
        if (key.empty()) return CKR_KEY_HANDLE_INVALID;
        const size_t tagLen = 16;
        if (in.size() < tagLen) return CKR_ENCRYPTED_DATA_LEN_RANGE;
        std::vector<u8> ct(in.begin(), in.end() - tagLen);
        std::vector<u8> tag(in.end() - tagLen, in.end());
        return p11_aes_gcm_decrypt(key, g_gcmIv[h], g_gcmAad[h], ct, tag, out);
    }

    EVP_PKEY* pk = load_asym_key(h, k);
    if (!pk) return CKR_KEY_HANDLE_INVALID;
    int padding = RSA_PKCS1_PADDING;
    std::string md;
    if (mech == CKM_RSA_X_509)       padding = RSA_NO_PADDING;
    else if (mech == CKM_RSA_PKCS_OAEP) { padding = RSA_PKCS1_OAEP_PADDING; md = g_oaepMgf1[h]; }
    const std::vector<u8>* labelPtr = (mech == CKM_RSA_PKCS_OAEP && g_oaepLabel.count(h) && !g_oaepLabel[h].empty())
                                          ? &g_oaepLabel[h] : nullptr;
    CK_RV rv = p11_rsa_decrypt(pk, in, out, padding, labelPtr, md);
    EVP_PKEY_free(pk);
    return rv;
}

// ----- Sign / Verify -----
CK_RV do_sign(CK_SESSION_HANDLE h, const std::vector<u8>& data, std::vector<u8>& sig) {
    CK_MECHANISM_TYPE mech = g_activeMech[h];
    CK_OBJECT_HANDLE  k    = g_signKey[h];
    EVP_PKEY* pk = load_asym_key(h, k);
    if (!pk) return CKR_KEY_HANDLE_INVALID;

    CK_RV rv = CKR_MECHANISM_INVALID;
    if (is_rsa_mech(mech)) {
        int padding = RSA_PKCS1_PADDING;
        std::string mdName, mgf1;
        std::vector<u8> tosign;
        if (mech == CKM_RSA_PKCS)               { padding = RSA_PKCS1_PADDING; mdName.clear(); tosign = data; }
        else if (mech == CKM_RSA_X_509)         { padding = RSA_NO_PADDING;     mdName.clear(); tosign = data; }
        else if (mech == CKM_RSA_PKCS_PSS)      { padding = RSA_PKCS1_PSS_PADDING; mdName = "SHA256"; mgf1 = "SHA256"; tosign = p11_hash(vhsm::crypto::HashAlgorithm::SHA256, data); }
        else if (mech == CKM_RSA_PKCS_OAEP)     { rv = CKR_MECHANISM_INVALID; }
        else {
            vhsm::crypto::HashAlgorithm ha = mech_to_hash(mech);
            bool pss = (mech == CKM_SHA256_RSA_PKCS_PSS || mech == CKM_SHA384_RSA_PKCS_PSS ||
                        mech == CKM_SHA512_RSA_PKCS_PSS);
            padding = pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;
            mdName  = digest_name(ha);
            mgf1    = pss ? mdName : std::string();
            tosign  = p11_hash(ha, data);
        }
        if (rv == CKR_MECHANISM_INVALID) { EVP_PKEY_free(pk); return rv; }
        rv = p11_rsa_sign(pk, tosign, sig, padding, mdName, mgf1);
    } else if (is_ec_mech(mech)) {
        std::vector<u8> tosign;
        if (mech == CKM_ECDSA) tosign = data;
        else tosign = p11_hash(mech_to_hash(mech), data);
        rv = p11_ecdsa_sign(pk, tosign, sig);
    }
    EVP_PKEY_free(pk);
    return rv;
}

CK_RV do_verify(CK_SESSION_HANDLE h, const std::vector<u8>& data, const std::vector<u8>& sig) {
    CK_MECHANISM_TYPE mech = g_activeMech[h];
    CK_OBJECT_HANDLE  k    = g_signKey[h];
    EVP_PKEY* pk = load_asym_key(h, k);
    if (!pk) return CKR_KEY_HANDLE_INVALID;

    CK_RV rv = CKR_MECHANISM_INVALID;
    if (is_rsa_mech(mech)) {
        int padding = RSA_PKCS1_PADDING;
        std::string mdName, mgf1;
        std::vector<u8> tosign;
        if (mech == CKM_RSA_PKCS)               { padding = RSA_PKCS1_PADDING; mdName.clear(); tosign = data; }
        else if (mech == CKM_RSA_X_509)         { padding = RSA_NO_PADDING;     mdName.clear(); tosign = data; }
        else if (mech == CKM_RSA_PKCS_PSS)      { padding = RSA_PKCS1_PSS_PADDING; mdName = "SHA256"; mgf1 = "SHA256"; tosign = p11_hash(vhsm::crypto::HashAlgorithm::SHA256, data); }
        else if (mech == CKM_RSA_PKCS_OAEP)     { rv = CKR_MECHANISM_INVALID; }
        else {
            vhsm::crypto::HashAlgorithm ha = mech_to_hash(mech);
            bool pss = (mech == CKM_SHA256_RSA_PKCS_PSS || mech == CKM_SHA384_RSA_PKCS_PSS ||
                        mech == CKM_SHA512_RSA_PKCS_PSS);
            padding = pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;
            mdName  = digest_name(ha);
            mgf1    = pss ? mdName : std::string();
            tosign  = p11_hash(ha, data);
        }
        if (rv == CKR_MECHANISM_INVALID) { EVP_PKEY_free(pk); return rv; }
        rv = p11_rsa_verify(pk, tosign, sig, padding, mdName, mgf1);
    } else if (is_ec_mech(mech)) {
        std::vector<u8> tosign;
        if (mech == CKM_ECDSA) tosign = data;
        else tosign = p11_hash(mech_to_hash(mech), data);
        rv = p11_ecdsa_verify(pk, tosign, sig);
    }
    EVP_PKEY_free(pk);
    return rv;
}

} // namespace

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------
CK_RV C_EncryptInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE hKey) {
    if (!m) return CKR_ARGUMENTS_BAD;
    if (m->mechanism != CKM_RSA_PKCS && m->mechanism != CKM_RSA_X_509 &&
        m->mechanism != CKM_RSA_PKCS_OAEP && m->mechanism != CKM_AES_GCM)
        return CKR_MECHANISM_INVALID;

    CK_RV rv = op_begin(h, m, hKey, true);
    if (rv != CKR_OK) return rv;

    if (m->mechanism == CKM_AES_GCM) {
        if (!m->pParameter || m->ulParameterLen < sizeof(CK_GCM_PARAMS))
            return CKR_MECHANISM_PARAM_INVALID;
        auto* g = static_cast<CK_GCM_PARAMS_PTR>(m->pParameter);
        if (!g->pIv || g->ulIvLen == 0) return CKR_MECHANISM_PARAM_INVALID;
        g_gcmIv[h].assign(g->pIv, g->pIv + g->ulIvLen);
        if (g->pAAD && g->ulAADLen)
            g_gcmAad[h].assign(g->pAAD, g->pAAD + g->ulAADLen);
        else
            g_gcmAad[h].clear();
    } else if (m->mechanism == CKM_RSA_PKCS_OAEP) {
        if (m->pParameter && m->ulParameterLen >= sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
            auto* o = static_cast<CK_RSA_PKCS_OAEP_PARAMS*>(m->pParameter);
            g_oaepMgf1[h] = oaep_md_name(o->hashAlg);
            if (o->source == CKZ_DATA_SPECIFIED && o->pSourceData && o->ulSourceDataLen)
                g_oaepLabel[h].assign(o->pSourceData, o->pSourceData + o->ulSourceDataLen);
        } else {
            g_oaepMgf1[h] = "SHA-256";
        }
    }
    return CKR_OK;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    std::vector<u8> in(pData, pData + ulDataLen);
    std::vector<u8> out;
    CK_RV rv = do_encrypt(h, in, out);
    if (rv == CKR_OK) rv = finish_output(out, pEncryptedData, pulEncryptedDataLen);
    op_end(h);
    return rv;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                      CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    g_opBuf[h].insert(g_opBuf[h].end(), pPart, pPart + ulPartLen);
    if (pEncryptedPart == nullptr) { if (pulEncryptedPartLen) *pulEncryptedPartLen = 0; return CKR_OK; }
    if (pulEncryptedPartLen) *pulEncryptedPartLen = 0;
    return CKR_OK;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    std::vector<u8> out;
    CK_RV rv = do_encrypt(h, g_opBuf[h], out);
    if (rv == CKR_OK) rv = finish_output(out, pLastEncryptedPart, pulLastEncryptedPartLen);
    op_end(h);
    return rv;
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------
CK_RV C_DecryptInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE hKey) {
    if (!m) return CKR_ARGUMENTS_BAD;
    if (m->mechanism != CKM_RSA_PKCS && m->mechanism != CKM_RSA_X_509 &&
        m->mechanism != CKM_RSA_PKCS_OAEP && m->mechanism != CKM_AES_GCM)
        return CKR_MECHANISM_INVALID;

    CK_RV rv = op_begin(h, m, hKey, true);
    if (rv != CKR_OK) return rv;

    if (m->mechanism == CKM_AES_GCM) {
        if (!m->pParameter || m->ulParameterLen < sizeof(CK_GCM_PARAMS))
            return CKR_MECHANISM_PARAM_INVALID;
        auto* g = static_cast<CK_GCM_PARAMS_PTR>(m->pParameter);
        if (!g->pIv || g->ulIvLen == 0) return CKR_MECHANISM_PARAM_INVALID;
        g_gcmIv[h].assign(g->pIv, g->pIv + g->ulIvLen);
        if (g->pAAD && g->ulAADLen)
            g_gcmAad[h].assign(g->pAAD, g->pAAD + g->ulAADLen);
        else
            g_gcmAad[h].clear();
    } else if (m->mechanism == CKM_RSA_PKCS_OAEP) {
        if (m->pParameter && m->ulParameterLen >= sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
            auto* o = static_cast<CK_RSA_PKCS_OAEP_PARAMS*>(m->pParameter);
            g_oaepMgf1[h] = oaep_md_name(o->hashAlg);
            if (o->source == CKZ_DATA_SPECIFIED && o->pSourceData && o->ulSourceDataLen)
                g_oaepLabel[h].assign(o->pSourceData, o->pSourceData + o->ulSourceDataLen);
        } else {
            g_oaepMgf1[h] = "SHA-256";
        }
    }
    return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    std::vector<u8> in(pEncryptedData, pEncryptedData + ulEncryptedDataLen);
    std::vector<u8> out;
    CK_RV rv = do_decrypt(h, in, out);
    if (rv == CKR_OK) rv = finish_output(out, pData, pulDataLen);
    op_end(h);
    return rv;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    g_opBuf[h].insert(g_opBuf[h].end(), pEncryptedPart, pEncryptedPart + ulEncryptedPartLen);
    if (pPart == nullptr) { if (pulPartLen) *pulPartLen = 0; return CKR_OK; }
    if (pulPartLen) *pulPartLen = 0;
    return CKR_OK;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    std::vector<u8> out;
    CK_RV rv = do_decrypt(h, g_opBuf[h], out);
    if (rv == CKR_OK) rv = finish_output(out, pLastPart, pulLastPartLen);
    op_end(h);
    return rv;
}

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------
CK_RV C_DigestInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m) {
    if (!m) return CKR_ARGUMENTS_BAD;
    if (!is_digest_mech(m->mechanism)) return CKR_MECHANISM_INVALID;
    return op_begin(h, m, CK_INVALID_HANDLE, false);
}

CK_RV C_Digest(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    std::vector<u8> out = p11_hash(mech_to_hash(g_activeMech[h]),
                                   std::vector<u8>(pData, pData + ulDataLen));
    CK_RV rv = finish_output(out, pDigest, pulDigestLen);
    op_end(h);
    return rv;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    g_opBuf[h].insert(g_opBuf[h].end(), pPart, pPart + ulPartLen);
    return CKR_OK;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE hKey) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    std::vector<u8> key = load_secret_key(h, hKey);
    if (key.empty()) return CKR_KEY_INDIGESTIBLE;
    g_opBuf[h].insert(g_opBuf[h].end(), key.begin(), key.end());
    return CKR_OK;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    std::vector<u8> out = p11_hash(mech_to_hash(g_activeMech[h]), g_opBuf[h]);
    CK_RV rv = finish_output(out, pDigest, pulDigestLen);
    op_end(h);
    return rv;
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------
CK_RV C_SignInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE hKey) {
    if (!m) return CKR_ARGUMENTS_BAD;
    if (!is_rsa_mech(m->mechanism) && !is_ec_mech(m->mechanism))
        return CKR_MECHANISM_INVALID;
    return op_begin(h, m, hKey, true);
}

CK_RV C_Sign(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    std::vector<u8> sig;
    CK_RV rv = do_sign(h, std::vector<u8>(pData, pData + ulDataLen), sig);
    if (rv == CKR_OK) rv = finish_output(sig, pSignature, pulSignatureLen);
    op_end(h);
    return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    g_opBuf[h].insert(g_opBuf[h].end(), pPart, pPart + ulPartLen);
    return CKR_OK;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    std::vector<u8> sig;
    CK_RV rv = do_sign(h, g_opBuf[h], sig);
    if (rv == CKR_OK) rv = finish_output(sig, pSignature, pulSignatureLen);
    op_end(h);
    return rv;
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------
CK_RV C_VerifyInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE hKey) {
    if (!m) return CKR_ARGUMENTS_BAD;
    if (!is_rsa_mech(m->mechanism) && !is_ec_mech(m->mechanism))
        return CKR_MECHANISM_INVALID;
    return op_begin(h, m, hKey, true);
}

CK_RV C_Verify(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    CK_RV rv = do_verify(h, std::vector<u8>(pData, pData + ulDataLen),
                         std::vector<u8>(pSignature, pSignature + ulSignatureLen));
    op_end(h);
    return rv;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    g_opBuf[h].insert(g_opBuf[h].end(), pPart, pPart + ulPartLen);
    return CKR_OK;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    if (op_check(h) != CKR_OK) return CKR_OPERATION_NOT_INITIALIZED;
    CK_RV rv = do_verify(h, g_opBuf[h],
                         std::vector<u8>(pSignature, pSignature + ulSignatureLen));
    op_end(h);
    return rv;
}

// ---------------------------------------------------------------------------
// Combined / recover operations (not supported)
// ---------------------------------------------------------------------------
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)h; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    (void)h; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                           CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)h; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    (void)h; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE hKey) {
    (void)h; (void)m; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SignRecover(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    (void)h; (void)pData; (void)ulDataLen; (void)pSignature; (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE hKey) {
    (void)h; (void)m; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_VerifyRecover(CK_SESSION_HANDLE h, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
                      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    (void)h; (void)pSignature; (void)ulSignatureLen; (void)pData; (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

} // namespace vhsm::pkcs11
} // extern "C"
