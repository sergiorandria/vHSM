#include "pkcs11.h"
#include "pkcs11_internal.h"
#include "pkcs11_types.h"

#include "../crypto/ecc.h"
#include "../keystore/key_wrap.h"
#include "../notification/notification_event.h"

#include <cstring>
#include <openssl/rsa.h>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
namespace vhsm::pkcs11 {

namespace {

struct CK_ECDH1_DERIVE_PARAMS {
  CK_ULONG kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
};

std::string mech_label(CK_MECHANISM_TYPE m) {
  switch (m) {
  case CKM_AES_KEY_WRAP:
    return "CKM_AES_KEY_WRAP";
  case CKM_RSA_PKCS:
    return "CKM_RSA_PKCS";
  case CKM_RSA_PKCS_OAEP:
    return "CKM_RSA_PKCS_OAEP";
  case CKM_ECDH1_DERIVE:
    return "CKM_ECDH1_DERIVE";
  default:
    return "CKM_VENDOR_DEFINED";
  }
}

bool raw_key_bytes(HsmObject *o, std::vector<u8> &out) {
  const auto *v = o->findAttribute(CKA_VALUE);
  if (v && !v->empty()) {
    out = *v;
    return true;
  }
  const auto *rp = o->findAttribute(CKA_VHSM_RSA_PRIV);
  if (rp && !rp->empty()) {
    out = *rp;
    return true;
  }
  const auto *ep = o->findAttribute(CKA_VHSM_EC_PRIV);
  if (ep && !ep->empty()) {
    out = *ep;
    return true;
  }
  const auto *ru = o->findAttribute(CKA_VHSM_RSA_PUB);
  if (ru && !ru->empty()) {
    out = *ru;
    return true;
  }
  const auto *eu = o->findAttribute(CKA_VHSM_EC_PUB);
  if (eu && !eu->empty()) {
    out = *eu;
    return true;
  }
  return false;
}

CK_RV create_from_raw(CK_SESSION_HANDLE hSession, const std::vector<u8> &raw,
                      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                      CK_OBJECT_HANDLE_PTR phKey) {
  auto s = p11_sessions().getSession(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  auto &store = s->getObjectStore();

  HsmObject probe(ObjectType::PRIVATE_KEY, true, true, false, true);
  probe.setAttribute(CKA_VALUE, raw.data(), raw.size());
  EVP_PKEY *pk = p11_build_key_from_attrs(&probe, true, 0);
  if (pk) {
    auto [h, ptr] = store.v_create_object<HsmObject>(ObjectType::PRIVATE_KEY,
                                                     true, true, false, true);
    CK_RV rv = p11_apply_template(*ptr, pTemplate, ulCount);
    if (rv == CKR_OK)
      p11_store_key(*ptr, pk, true,
                    EVP_PKEY_get_base_id(pk) == EVP_PKEY_RSA ? CKK_RSA
                                                             : CKK_EC);
    EVP_PKEY_free(pk);
    if (rv != CKR_OK) {
      store.v_destroy_object(h);
      return rv;
    }
    *phKey = h;
    return CKR_OK;
  }
  if (raw.size() == 16 || raw.size() == 24 || raw.size() == 32) {
    auto [h, ptr] = store.v_create_object<HsmObject>(ObjectType::SECRET_KEY,
                                                     false, true, false, false);
    CK_RV rv = p11_apply_template(*ptr, pTemplate, ulCount);
    if (rv == CKR_OK)
      p11_store_secret(*ptr, raw);
    if (rv != CKR_OK) {
      store.v_destroy_object(h);
      return rv;
    }
    *phKey = h;
    return CKR_OK;
  }
  return CKR_WRAPPED_KEY_INVALID;
}

} // namespace

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!pMechanism || !pulWrappedKeyLen)
    return CKR_ARGUMENTS_BAD;
  auto s = p11_sessions().getSession(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;

  auto wkey = p11_get_object(hSession, hWrappingKey);
  auto tkey = p11_get_object(hSession, hKey);
  if (!wkey || !tkey)
    return CKR_KEY_HANDLE_INVALID;

  // PKCS#11: non-extractable keys may not be wrapped.
  if (!tkey->isExtractable())
    return CKR_KEY_UNEXTRACTABLE;

  std::vector<u8> raw;
  if (!raw_key_bytes(tkey.get(), raw))
    return CKR_KEY_HANDLE_INVALID;

  std::vector<u8> out;
  CK_RV rv = CKR_OK;

  if (pMechanism->mechanism == CKM_AES_KEY_WRAP) {
    const auto *kekAttr = wkey->findAttribute(CKA_VALUE);
    if (!kekAttr || kekAttr->size() != 32)
      return CKR_KEY_SIZE_RANGE;
    try {
      KeyWrap kw(*kekAttr);
      out = kw.wrap(raw);
    } catch (...) {
      return CKR_WRAPPED_KEY_INVALID;
    }
  } else if (pMechanism->mechanism == CKM_RSA_PKCS ||
             pMechanism->mechanism == CKM_RSA_PKCS_OAEP) {
    EVP_PKEY *wk = p11_evp_from_object(wkey.get());
    if (!wk)
      return CKR_WRAPPING_KEY_HANDLE_INVALID;
    int padding = (pMechanism->mechanism == CKM_RSA_PKCS_OAEP)
                      ? RSA_PKCS1_OAEP_PADDING
                      : RSA_PKCS1_PADDING;
    std::string md =
        (pMechanism->mechanism == CKM_RSA_PKCS_OAEP) ? "SHA-256" : "";
    rv = p11_rsa_encrypt(wk, raw, out, padding, nullptr, md);
    EVP_PKEY_free(wk);
  } else {
    return CKR_MECHANISM_INVALID;
  }

  if (rv == CKR_OK) {
    if (pWrappedKey == nullptr) {
      *pulWrappedKeyLen = static_cast<CK_ULONG>(out.size());
      return CKR_OK;
    }
    if (*pulWrappedKeyLen < out.size()) {
      *pulWrappedKeyLen = static_cast<CK_ULONG>(out.size());
      return CKR_BUFFER_TOO_SMALL;
    }
    if (!out.empty())
      std::memcpy(pWrappedKey, out.data(), out.size());
    *pulWrappedKeyLen = static_cast<CK_ULONG>(out.size());

    // Audit: key wrap completed
    auto *token = p11_get_token_for_session(hSession);
    auto session = p11_get_session(hSession);
    int slot_id = session ? static_cast<int>(session->getSlotID()) : 0;
    std::string token_label = token ? token->get_label() : "unknown";
    std::string wkey_label =
        wkey->findAttribute(CKA_LABEL)
            ? std::string(reinterpret_cast<const char *>(
                              wkey->findAttribute(CKA_LABEL)->data()),
                          wkey->findAttribute(CKA_LABEL)->size())
            : std::string();
    std::string key_info =
        wkey_label.empty() ? std::to_string(hWrappingKey) : wkey_label;

    std::stringstream detail_ss;
    detail_ss << R"({"mechanism":")" << mech_label(pMechanism->mechanism)
              << R"(",)"
              << R"("wrapped_key_len":)" << out.size() << R"(})";
    p11_publish_event(
        vhsm::notification::NotificationEvent::EventType::WRAP_KEY_COMPLETED,
        vhsm::notification::NotificationEvent::Severity::INFO, slot_id,
        token_label, key_info, "C_WrapKey completed using key " + key_info,
        detail_ss.str(), std::nullopt, "C_WrapKey");
  }
  return rv;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                  CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!pMechanism || !pWrappedKey || !phKey)
    return CKR_ARGUMENTS_BAD;
  auto s = p11_sessions().getSession(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;

  auto ukey = p11_get_object(hSession, hUnwrappingKey);
  if (!ukey)
    return CKR_UNWRAPPING_KEY_HANDLE_INVALID;

  std::vector<u8> raw;
  CK_RV rv = CKR_OK;

  if (pMechanism->mechanism == CKM_AES_KEY_WRAP) {
    const auto *kekAttr = ukey->findAttribute(CKA_VALUE);
    if (!kekAttr || kekAttr->size() != 32)
      return CKR_KEY_SIZE_RANGE;
    try {
      KeyWrap kw(*kekAttr);
      raw = kw.unwrap(
          std::vector<u8>(pWrappedKey, pWrappedKey + ulWrappedKeyLen));
    } catch (...) {
      return CKR_WRAPPED_KEY_INVALID;
    }
  } else if (pMechanism->mechanism == CKM_RSA_PKCS ||
             pMechanism->mechanism == CKM_RSA_PKCS_OAEP) {
    EVP_PKEY *uk = p11_evp_from_object(ukey.get());
    if (!uk)
      return CKR_UNWRAPPING_KEY_HANDLE_INVALID;
    int padding = (pMechanism->mechanism == CKM_RSA_PKCS_OAEP)
                      ? RSA_PKCS1_OAEP_PADDING
                      : RSA_PKCS1_PADDING;
    std::string md =
        (pMechanism->mechanism == CKM_RSA_PKCS_OAEP) ? "SHA-256" : "";
    std::vector<u8> in(pWrappedKey, pWrappedKey + ulWrappedKeyLen);
    rv = p11_rsa_decrypt(uk, in, raw, padding, nullptr, md);
    EVP_PKEY_free(uk);
  } else {
    return CKR_MECHANISM_INVALID;
  }

  if (rv != CKR_OK)
    return rv;
  CK_RV crv =
      create_from_raw(hSession, raw, pTemplate, ulAttributeCount, phKey);
  if (crv == CKR_OK) {
    // Audit: key unwrap completed
    auto *token = p11_get_token_for_session(hSession);
    auto session = p11_get_session(hSession);
    int slot_id = session ? static_cast<int>(session->getSlotID()) : 0;
    std::string token_label = token ? token->get_label() : "unknown";
    std::string ukey_label =
        ukey->findAttribute(CKA_LABEL)
            ? std::string(reinterpret_cast<const char *>(
                              ukey->findAttribute(CKA_LABEL)->data()),
                          ukey->findAttribute(CKA_LABEL)->size())
            : std::string();
    std::string key_info =
        ukey_label.empty() ? std::to_string(hUnwrappingKey) : ukey_label;

    std::stringstream detail_ss;
    detail_ss << R"({"mechanism":")" << mech_label(pMechanism->mechanism)
              << R"(",)"
              << R"("new_key_handle":)" << *phKey << R"(})";
    p11_publish_event(
        vhsm::notification::NotificationEvent::EventType::UNWRAP_KEY_COMPLETED,
        vhsm::notification::NotificationEvent::Severity::INFO, slot_id,
        token_label, key_info, "C_UnwrapKey completed using key " + key_info,
        detail_ss.str(), std::nullopt, "C_UnwrapKey");
  }
  return crv;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!pMechanism || !phKey)
    return CKR_ARGUMENTS_BAD;
  if (pMechanism->mechanism != CKM_ECDH1_DERIVE)
    return CKR_MECHANISM_INVALID;

  auto s = p11_sessions().getSession(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;

  auto bkey = p11_get_object(hSession, hBaseKey);
  if (!bkey)
    return CKR_KEY_HANDLE_INVALID;
  EVP_PKEY *priv = p11_evp_from_object(bkey.get());
  if (!priv)
    return CKR_KEY_HANDLE_INVALID;
  // RAII: early returns below (mechanism param checks) previously leaked priv
  struct PrivGuard {
    EVP_PKEY *p;
    ~PrivGuard() { EVP_PKEY_free(p); }
  } priv_guard{priv};

  if (!pMechanism->pParameter ||
      pMechanism->ulParameterLen < sizeof(CK_ECDH1_DERIVE_PARAMS)) {
    return CKR_MECHANISM_PARAM_INVALID;
  }
  auto *params = static_cast<CK_ECDH1_DERIVE_PARAMS *>(pMechanism->pParameter);
  if (!params->pPublicData || params->ulPublicDataLen == 0) {
    return CKR_MECHANISM_PARAM_INVALID;
  }
  const u8 *p = params->pPublicData;
  EVP_PKEY *peer =
      d2i_PUBKEY(nullptr, &p, static_cast<long>(params->ulPublicDataLen));
  if (!peer) {
    return CKR_MECHANISM_PARAM_INVALID;
  }

  std::vector<u8> secret = p11_ecdh_derive(priv, peer);
  EVP_PKEY_free(peer);
  if (secret.empty())
    return CKR_GENERAL_ERROR;

  auto &store = s->getObjectStore();
  auto [h, ptr] = store.v_create_object<HsmObject>(ObjectType::SECRET_KEY,
                                                   false, true, false, false);
  CK_RV rv = p11_apply_template(*ptr, pTemplate, ulAttributeCount);
  if (rv == CKR_OK)
    p11_store_secret(*ptr, secret);
  if (rv != CKR_OK) {
    store.v_destroy_object(h);
    return rv;
  }
  *phKey = h;

  // Audit: ECDH key derivation completed
  auto *token = p11_get_token_for_session(hSession);
  int slot_id = static_cast<int>(s->getSlotID());
  std::string token_label = token ? token->get_label() : "unknown";
  std::stringstream detail_ss;
  detail_ss << R"({"mechanism":")" << "CKM_ECDH1_DERIVE" << R"(",)"
            << R"("new_key_handle":)" << h << R"(})";
  p11_publish_event(
      vhsm::notification::NotificationEvent::EventType::KEY_ROTATED,
      vhsm::notification::NotificationEvent::Severity::INFO, slot_id,
      token_label, std::to_string(hBaseKey),
      "C_DeriveKey (ECDH1) completed from base key " + std::to_string(hBaseKey),
      detail_ss.str(), std::nullopt, "C_DeriveKey");
  return CKR_OK;
}

} // namespace vhsm::pkcs11
} // extern "C"
