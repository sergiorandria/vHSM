#include <cstdio>
#include "pkcs11.h"
#include "pkcs11_internal.h"
#include "pkcs11_types.h"

#include "../crypto/ecc.h"
#include "../crypto/rsa.h"

#include <cstring>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
namespace vhsm::pkcs11 {

namespace {

// Extract the CKA_LABEL from a creation template (empty string if absent).
std::string label_from_template(CK_ATTRIBUTE_PTR t, CK_ULONG n) {
  for (CK_ULONG i = 0; i < n; ++i) {
    if (t[i].type == CKA_LABEL && t[i].pValue && t[i].ulValueLen > 0) {
      return std::string(static_cast<const char *>(t[i].pValue),
                         t[i].ulValueLen);
    }
  }
  return {};
}

// WHY rotation detection here: the plan defines KEY_ROTATED as "signing key
// replaced via admin RPC" (WARN severity).  No admin RPC exists yet, so the
// PKCS#11-native equivalent is regenerating a key that reuses an existing
// CKA_LABEL (the identifer applications key on).  When a prior object with the
// same identity is found, we emit KEY_ROTATED with the old handle so
// subscribers can correlate the replacement.
void publish_rotation_event(Session &s, const std::string &label,
                            const std::vector<CK_OBJECT_HANDLE> &newHandles) {
  if (label.empty())
    return;
  auto &store = s.getObjectStore();
  CK_OBJECT_HANDLE oldHandle = CK_INVALID_HANDLE;
  auto [oh, oo] = store.v_find_object_if([&](HsmObject *o) {
    if (o->getType() == ObjectType::DATA)
      return false;
    const auto *v = o->findAttribute(CKA_LABEL);
    return v && !v->empty() &&
           std::string(reinterpret_cast<const char *>(v->data()), v->size()) ==
               label;
  });
  if (!oo)
    return;
  oldHandle = oh;
  for (CK_OBJECT_HANDLE h : newHandles) {
    if (oldHandle == h)
      return;
  }

  auto *token = p11_get_token_for_session(s.getHandle());
  int slot_id = static_cast<int>(s.getSlotID());
  std::string token_label = token ? token->get_label() : "unknown";
  std::stringstream detail_ss;
  detail_ss << R"({"old_handle":)" << oldHandle << R"(,"new_handle":)"
            << newHandles.back() << R"(,"label":")" << label << R"("})";
  p11_publish_event(
      vhsm::notification::NotificationEvent::EventType::KEY_ROTATED,
      vhsm::notification::NotificationEvent::Severity::WARNING, slot_id,
      token_label, label,
      "Key rotation: label '" + label + "' replaced handle " +
          std::to_string(oldHandle),
      detail_ss.str(), std::nullopt, "C_GenerateKeyPair/C_GenerateKey");
}

vhsm::crypto::Curve curve_from_params(const HsmObject *pub,
                                      const HsmObject *priv) {
  const HsmObject *src = pub ? pub : priv;
  if (!src)
    return vhsm::crypto::Curve::EccCurveType_P256;
  const auto *v = src->findAttribute(CKA_EC_PARAMS);
  if (!v || v->empty())
    return vhsm::crypto::Curve::EccCurveType_P256;
  std::string name(v->begin(), v->end());
  if (name.find("P-384") != std::string::npos ||
      name.find("secp384r1") != std::string::npos)
    return vhsm::crypto::Curve::EccCurveType_P384;
  if (name.find("P-521") != std::string::npos ||
      name.find("secp521r1") != std::string::npos)
    return vhsm::crypto::Curve::EccCurveType_P521;
  return vhsm::crypto::Curve::EccCurveType_P256;
}

int rsa_bits_from_template(const HsmObject *priv) {
  if (!priv)
    return 2048;
  const auto *v = priv->findAttribute(CKA_MODULUS_BITS);
  if (v && v->size() == sizeof(CK_ULONG)) {
    CK_ULONG bits = 0;
    std::memcpy(&bits, v->data(), sizeof(CK_ULONG));
    if (bits >= 2048)
      return static_cast<int>(bits);
  }
  return 2048;
}

} // namespace

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phKey) {
  VHSM_C_TRY
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!pMechanism || !phKey)
    return CKR_ARGUMENTS_BAD;
  if (pMechanism->mechanism != CKM_AES_KEY_GEN)
    return CKR_MECHANISM_INVALID;

  auto s = p11_sessions().getSession(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  auto &store = s->getObjectStore();

  CK_ULONG keyLen = 32;
  for (CK_ULONG i = 0; i < ulCount; ++i) {
    if (pTemplate[i].type == CKA_VALUE_LEN &&
        pTemplate[i].ulValueLen == sizeof(CK_ULONG))
      std::memcpy(&keyLen, pTemplate[i].pValue, sizeof(CK_ULONG));
  }
  if (keyLen != 16 && keyLen != 24 && keyLen != 32)
    return CKR_KEY_SIZE_RANGE;

  std::vector<u8> raw(keyLen);
  CK_RV rv = p11_random_bytes(raw.data(), keyLen);
  if (rv != CKR_OK)
    return rv;

  auto [handle, ptr] = store.v_create_object<HsmObject>(
      ObjectType::SECRET_KEY, true, true, false, false);
  rv = p11_apply_template(*ptr, pTemplate, ulCount);
  if (rv != CKR_OK) {
    store.v_destroy_object(handle);
    return rv;
  }
  p11_store_secret(*ptr, raw);
  *phKey = handle;
  publish_rotation_event(*s, label_from_template(pTemplate, ulCount), {handle});
  return CKR_OK;
VHSM_C_CATCH
}

// Core keypair generation + storage, shared by C_GenerateKeyPair and
// p11_rotate_keypair. When `hOldPrivate` names an existing private key, the new
// key is generated Active (the default) and the old key is transitioned to
// Rotating (it can still VERIFY/DECRYPT but can no longer SIGN — plan §3.2).
CK_RV p11_generate_and_store_keypair(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey,
    CK_OBJECT_HANDLE hOldPrivate) {
  if (!pMechanism || !phPublicKey || !phPrivateKey)
    return CKR_ARGUMENTS_BAD;

  auto s = p11_sessions().getSession(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  auto &store = s->getObjectStore();

  bool isRsa = false;
  vhsm::crypto::RSAKeyPair rsaKp{};
  vhsm::crypto::ECCKeyPair ecKp{};
  if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN ||
      pMechanism->mechanism == CKM_RSA_X_509) {
    isRsa = true;
    int bits = 2048;
    if (pPrivateKeyTemplate) {
      HsmObject tmpPriv(ObjectType::PRIVATE_KEY, true, true, false, true);
      p11_apply_template(tmpPriv, pPrivateKeyTemplate,
                         ulPrivateKeyAttributeCount);
      bits = rsa_bits_from_template(&tmpPriv);
    }
    rsaKp = vhsm::crypto::RSAUtil::generate_key(bits);
  } else if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN ||
             pMechanism->mechanism == CKM_ECDSA_KEY_PAIR_GEN) {
    HsmObject tmpPub(ObjectType::PUBLIC_KEY, false, true, false, false);
    HsmObject tmpPriv(ObjectType::PRIVATE_KEY, true, true, false, true);
    if (pPublicKeyTemplate)
      p11_apply_template(tmpPub, pPublicKeyTemplate, ulPublicKeyAttributeCount);
    if (pPrivateKeyTemplate)
      p11_apply_template(tmpPriv, pPrivateKeyTemplate,
                         ulPrivateKeyAttributeCount);
    auto curve = curve_from_params(&tmpPub, &tmpPriv);
    ecKp = vhsm::crypto::ECC::generate_key(curve);
  } else {
    return CKR_MECHANISM_INVALID;
  }

  if (!rsaKp.key && !ecKp.key)
    return CKR_GENERAL_ERROR;

  auto [hPub, ptrPub] = store.v_create_object<HsmObject>(
      ObjectType::PUBLIC_KEY, false, true, false, false);
  CK_RV rv = p11_apply_template(*ptrPub, pPublicKeyTemplate,
                                ulPublicKeyAttributeCount);
  if (rv == CKR_OK) {
    if (isRsa) {
      rv = p11_store_key(*ptrPub, rsaKp, false, CKK_RSA);
    } else {
      rv = p11_store_key_ec(*ptrPub, ecKp, false);
    }
  }

  auto [hPriv, ptrPriv] = store.v_create_object<HsmObject>(
      ObjectType::PRIVATE_KEY, true, true, false, true);
  if (rv == CKR_OK)
    rv = p11_apply_template(*ptrPriv, pPrivateKeyTemplate,
                            ulPrivateKeyAttributeCount);
  if (rv == CKR_OK) {
    if (isRsa) {
      rv = p11_store_key(*ptrPriv, rsaKp, true, CKK_RSA);
    } else {
      rv = p11_store_key_ec(*ptrPriv, ecKp, true);
    }
  }

  if (isRsa) {
    vhsm::crypto::rsa_free_key(rsaKp);
  } else {
    vhsm::crypto::ecc_free_key(ecKp);
  }

  if (rv != CKR_OK) {
    store.v_destroy_object(hPub);
    store.v_destroy_object(hPriv);
    return rv;
  }
  *phPublicKey = hPub;
  *phPrivateKey = hPriv;

  // Lifecycle transition: a rotated key is superseded. Mark the previous
  // private key Rotating so it remains usable for verify/decrypt but cannot
  // sign new data (plan §3.2 / §6).
  if (hOldPrivate != CK_INVALID_HANDLE) {
    if (auto old = store.v_get_object(hOldPrivate)) {
      old->setKeyState(vhsm::keystore::KeyState::Rotating);
    }
  }

  std::string rotationLabel =
      label_from_template(pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
  if (rotationLabel.empty()) {
    rotationLabel =
        label_from_template(pPublicKeyTemplate, ulPublicKeyAttributeCount);
  }
  publish_rotation_event(*s, rotationLabel, {hPub, hPriv});
  return CKR_OK;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey,
                        CK_OBJECT_HANDLE_PTR phPrivateKey) {
  VHSM_C_TRY
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!pMechanism || !phPublicKey || !phPrivateKey)
    return CKR_ARGUMENTS_BAD;

  return p11_generate_and_store_keypair(
      hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount,
      pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey,
      phPrivateKey, CK_INVALID_HANDLE);
VHSM_C_CATCH
}

// p11_rotate_keypair: generate a fresh replacement for `hOldPrivate`, matching
// its algorithm family and parameters, inherit its CKA_LABEL/CKA_ID (so
// label-based lookups transparently resolve the new Active key), and transition
// the old key to Rotating. Returns the new public/private handles.
CK_RV p11_rotate_keypair(CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE hOldPrivate,
                         CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                         CK_ULONG ulPublicKeyAttributeCount,
                         CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                         CK_ULONG ulPrivateKeyAttributeCount,
                         CK_OBJECT_HANDLE_PTR phPublicKey,
                         CK_OBJECT_HANDLE_PTR phPrivateKey) {
  VHSM_C_TRY
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!phPublicKey || !phPrivateKey)
    return CKR_ARGUMENTS_BAD;

  auto s = p11_sessions().getSession(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  auto old = p11_get_object(hSession, hOldPrivate);
  if (!old)
    return CKR_OBJECT_HANDLE_INVALID;
  if (old->getType() != ObjectType::PRIVATE_KEY)
    return CKR_KEY_HANDLE_INVALID;

  // Determine the algorithm family from the existing key.
  CK_MECHANISM mech{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  const auto *kt = old->findAttribute(CKA_KEY_TYPE);
  if (kt && kt->size() == sizeof(CK_ULONG)) {
    CK_ULONG ktype = 0;
    std::memcpy(&ktype, kt->data(), sizeof(CK_ULONG));
    if (ktype == CKK_RSA) {
      mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    }
  }

  // Inherit identity + parameters from the old key so the replacement is a
  // drop-in for applications that look the key up by label/id or algorithm.
  std::vector<CK_ATTRIBUTE> pubTmpl, privTmpl;
  auto copy_tmpl = [](std::vector<CK_ATTRIBUTE> &dst, CK_ATTRIBUTE_PTR src,
                      CK_ULONG n) {
    if (!src)
      return;
    for (CK_ULONG i = 0; i < n; ++i)
      dst.push_back(src[i]);
  };
  copy_tmpl(pubTmpl, pPublicKeyTemplate, ulPublicKeyAttributeCount);
  copy_tmpl(privTmpl, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);

  auto ensure_attr = [&](std::vector<CK_ATTRIBUTE> &dst, CK_ATTRIBUTE_TYPE t) {
    for (const auto &a : dst)
      if (a.type == t)
        return;
    const auto *v = old->findAttribute(t);
    if (v && !v->empty())
      dst.push_back({t, const_cast<u8 *>(v->data()),
                     static_cast<CK_ULONG>(v->size())});
  };
  ensure_attr(pubTmpl, CKA_LABEL);
  ensure_attr(pubTmpl, CKA_ID);
  ensure_attr(pubTmpl, CKA_EC_PARAMS);
  ensure_attr(privTmpl, CKA_LABEL);
  ensure_attr(privTmpl, CKA_ID);
  ensure_attr(privTmpl, CKA_MODULUS_BITS);

  return p11_generate_and_store_keypair(
      hSession, &mech, pubTmpl.data(),
      static_cast<CK_ULONG>(pubTmpl.size()), privTmpl.data(),
      static_cast<CK_ULONG>(privTmpl.size()), phPublicKey, phPrivateKey,
      hOldPrivate);
VHSM_C_CATCH
}

} // namespace vhsm::pkcs11
} // extern "C"
