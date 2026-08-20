#include "pkcs11.h"
#include "pkcs11_internal.h"
#include "pkcs11_types.h"

#include "../crypto/SecureRNG.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/ecc.h"
#include "../crypto/rsa.h"

#include "../keystore/attribute_store.h"
#include "../keystore/hsm_object.h"
#include "../keystore/object_store.h"
#include "../keystore/slot.h"
#include "../keystore/token.h"

#include "../session/session.h"
#include "../session/session_manager.h"
#include "../session/slot_manager.h"

#include "../persistence/vault.h"

#include "../audit/audit_log.h"
#include "../ledger/ledger_worker.h"
#include "../notification/bounded_notification_bus.h"
#include "../notification/notification_bus.h"
#include "../notification/notification_event.h"
#include "../signature_store/db_connection.h"
#include "../signature_store/signature_dispatcher.h"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace vhsm::pkcs11 {
using keystore::HsmObject;
using keystore::ObjectType;
using session::Session;
using session::SessionManager;

// WHY g_cka_public_key / g_cka_private_key: Stored as raw bytes to set
// CKA_CLASS via HsmObject::setAttribute. The attribute interface takes a byte
// pointer + length, so we need a stable CK_OBJECT_CLASS value to point at.
static const CK_OBJECT_CLASS g_cka_public_key = CKO_PUBLIC_KEY;
static const CK_OBJECT_CLASS g_cka_private_key = CKO_PRIVATE_KEY;

// SignatureDispatcher instance (initialized in C_Initialize)
std::unique_ptr<vhsm::signature_store::db::SignatureDispatcher>
    g_signatureDispatcher;
std::unique_ptr<vhsm::notification::NotificationBus> g_notificationBus;
std::unique_ptr<vhsm::audit::AuditLog> g_auditLog;
std::unique_ptr<vhsm::signature_store::db::IDbConnection> g_dbConnection;

// Notification delivery pipeline (bus → dispatcher → subscribers)
std::unique_ptr<vhsm::signature_store::db::NotificationDispatcher>
    g_notificationDispatcher;
std::unique_ptr<vhsm::signature_store::db::NotificationRepository>
    g_notificationRepo;
std::unique_ptr<vhsm::notification::BoundedNotificationBus> g_boundedBus;

// Ledger anchoring globals (optional; only populated when a Fabric gateway is
// configured)
std::unique_ptr<vhsm::ledger::LedgerClient> g_ledgerClient;
std::unique_ptr<vhsm::ledger::LedgerWorker> g_ledgerWorker;

// Optional encrypted vault backing the default token (PLAN.md Phase 7).
std::unique_ptr<vhsm::persistence::Vault> g_vault;

// ---------------------------------------------------------------------------
// Library / session state
// ---------------------------------------------------------------------------
bool g_initialized = false;
SessionManager g_sessionManager;

// Per-session registry of object handles we have created (used for FindObjects
// enumeration, since the underlying ObjectStore does not expose iteration).
std::unordered_map<CK_SESSION_HANDLE, std::vector<CK_OBJECT_HANDLE>>
    g_objectRegistry;

// Active operation state per session.
std::unordered_map<CK_SESSION_HANDLE, CK_MECHANISM_TYPE> g_activeMech;
std::unordered_map<CK_SESSION_HANDLE, std::vector<u8>> g_opBuf;
std::unordered_map<CK_SESSION_HANDLE, CK_OBJECT_HANDLE> g_signKey;
std::unordered_map<CK_SESSION_HANDLE, std::vector<u8>> g_gcmIv;
std::unordered_map<CK_SESSION_HANDLE, std::vector<u8>> g_gcmAad;
std::unordered_map<CK_SESSION_HANDLE, std::vector<u8>> g_oaepLabel;
std::unordered_map<CK_SESSION_HANDLE, std::string> g_oaepMgf1;
std::unordered_map<CK_SESSION_HANDLE, std::vector<CK_OBJECT_HANDLE>>
    g_findResults;

// Login state per session (userType, or CKU_INVALID if not logged in).
std::unordered_map<CK_SESSION_HANDLE, CK_USER_TYPE> g_loginState;

// Single mutex guarding all g_* per-session maps (see pkcs11_internal.h
// rationale).
std::mutex g_stateMutex;

bool p11_is_initialized() { return g_initialized; }

SessionManager &p11_sessions() { return g_sessionManager; }

// ---------------------------------------------------------------------------
// SignatureDispatcher access
// ---------------------------------------------------------------------------
vhsm::signature_store::db::SignatureDispatcher *p11_signature_dispatcher() {
  return g_signatureDispatcher.get();
}

vhsm::signature_store::db::IDbConnection *p11_db_connection() {
  return g_dbConnection.get();
}

vhsm::notification::NotificationBus *p11_notification_bus() {
  return g_notificationBus.get();
}

vhsm::audit::AuditLog *p11_audit_log() { return g_auditLog.get(); }

void p11_publish_event(vhsm::notification::NotificationEvent::EventType type,
                       vhsm::notification::NotificationEvent::Severity severity,
                       int slot_id, const std::string &token_label,
                       const std::string &key_id, const std::string &summary,
                       const std::string &detail_json,
                       const std::optional<std::string> &user_label,
                       const std::string &audit_event_type) {
  auto *notification_bus = g_notificationBus.get();
  auto *audit_log = g_auditLog.get();
  if (!notification_bus || !audit_log)
    return;

  try {
    int64_t created_at =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();

    vhsm::notification::NotificationEvent event;
    event.type = type;
    event.severity = severity;
    event.timestamp = created_at;
    event.source = "slot:" + std::to_string(slot_id) + "/token:" + token_label +
                   "/key:" + key_id;
    event.actor = user_label.value_or("UNKNOWN");
    event.summary = summary;
    event.detail_json = detail_json;
    event.hsm_instance = ""; // TODO: fetch from db_meta
    notification_bus->publish(event);

    audit_log->append(audit_event_type + "-" + std::to_string(created_at),
                      audit_event_type);
  } catch (const std::exception &) {
    // Notification/audit must never raise across the C API boundary.
  }
}

// ---------------------------------------------------------------------------
// Slot / token lookup
// ---------------------------------------------------------------------------
keystore::Slot *p11_get_slot(CK_SLOT_ID id) {
  auto sp =
      vhsm::session::SlotManager::get_instance().get_slot(static_cast<u64>(id));
  return sp.get();
}

keystore::Token *p11_get_token(CK_SLOT_ID id) {
  auto sp =
      vhsm::session::SlotManager::get_instance().get_slot(static_cast<u64>(id));
  if (!sp)
    return nullptr;
  auto tp = sp->get_token();
  return tp.get();
}

// ---------------------------------------------------------------------------
// Session lookup
// ---------------------------------------------------------------------------
keystore::Token *p11_get_token_for_session(CK_SESSION_HANDLE hSession) {
  auto s = g_sessionManager.getSession(hSession);
  if (!s)
    return nullptr;
  return p11_get_token(s->getSlotID());
}

std::shared_ptr<Session> p11_get_session(CK_SESSION_HANDLE h) {
  return g_sessionManager.getSession(h);
}

std::shared_ptr<HsmObject> p11_get_object(CK_SESSION_HANDLE hSession,
                                          CK_OBJECT_HANDLE hObject) {
  auto s = g_sessionManager.getSession(hSession);
  if (!s)
    return nullptr;
  return s->getObjectStore().v_get_object(hObject);
}

void p11_register_object(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE h) {
  std::lock_guard<std::mutex> lock(g_stateMutex);
  g_objectRegistry[hSession].push_back(h);
}

void p11_unregister_object(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE h) {
  std::lock_guard<std::mutex> lock(g_stateMutex);
  auto it = g_objectRegistry.find(hSession);
  if (it != g_objectRegistry.end()) {
    auto &v = it->second;
    v.erase(std::remove(v.begin(), v.end(), h), v.end());
  }
}

void p11_clear_session_objects(CK_SESSION_HANDLE hSession) {
  p11_reset_op(hSession);
  std::lock_guard<std::mutex> lock(g_stateMutex);
  g_objectRegistry.erase(hSession);
  g_findResults.erase(hSession);
  g_loginState.erase(hSession);
}

void p11_reset_op(CK_SESSION_HANDLE h) {
  std::lock_guard<std::mutex> lock(g_stateMutex);
  g_activeMech.erase(h);
  g_opBuf.erase(h);
  g_signKey.erase(h);
  g_gcmIv.erase(h);
  g_gcmAad.erase(h);
  g_oaepLabel.erase(h);
  g_oaepMgf1.erase(h);
}

// ---------------------------------------------------------------------------
// Mechanism / class conversions
// ---------------------------------------------------------------------------
CK_MECHANISM_TYPE class_to_mech(ObjectType t) {
  switch (t) {
  case ObjectType::PUBLIC_KEY:
    return CKM_RSA_PKCS;
  case ObjectType::PRIVATE_KEY:
    return CKM_RSA_PKCS;
  case ObjectType::SECRET_KEY:
    return CKM_AES_ECB;
  default:
    return CKM_VENDOR_DEFINED;
  }
}

vhsm::crypto::HashAlgorithm mech_to_hash(CK_MECHANISM_TYPE m) {
  switch (m) {
  case CKM_SHA256:
  case CKM_SHA256_RSA_PKCS:
  case CKM_ECDSA_SHA256:
  case CKM_SHA256_HMAC:
    return vhsm::crypto::HashAlgorithm::SHA256;
  case CKM_SHA384:
  case CKM_SHA384_RSA_PKCS:
  case CKM_ECDSA_SHA384:
  case CKM_SHA384_HMAC:
    return vhsm::crypto::HashAlgorithm::SHA384;
  case CKM_SHA512:
  case CKM_SHA512_RSA_PKCS:
  case CKM_ECDSA_SHA512:
  case CKM_SHA512_HMAC:
    return vhsm::crypto::HashAlgorithm::SHA512;
  default:
    return vhsm::crypto::HashAlgorithm::SHA256;
  }
}

bool is_rsa_mech(CK_MECHANISM_TYPE m) {
  return m == CKM_RSA_PKCS || m == CKM_RSA_X_509 || m == CKM_SHA256_RSA_PKCS ||
         m == CKM_SHA384_RSA_PKCS || m == CKM_SHA512_RSA_PKCS ||
         m == CKM_RSA_PKCS_OAEP || m == CKM_RSA_PKCS_PSS ||
         m == CKM_SHA256_RSA_PKCS_PSS || m == CKM_SHA384_RSA_PKCS_PSS ||
         m == CKM_SHA512_RSA_PKCS_PSS;
}
bool is_ec_mech(CK_MECHANISM_TYPE m) {
  return m == CKM_ECDSA || m == CKM_ECDSA_SHA256 || m == CKM_ECDSA_SHA384 ||
         m == CKM_ECDSA_SHA512;
}

// ---------------------------------------------------------------------------
// Attribute helpers (via v_AttributeStore_M1 for correct PKCS#11 semantics)
// ---------------------------------------------------------------------------
CK_RV p11_apply_template(HsmObject &obj, CK_ATTRIBUTE_PTR pTemplate,
                         CK_ULONG ulCount) {
  for (CK_ULONG i = 0; i < ulCount; ++i) {
    CK_ATTRIBUTE_PTR a = &pTemplate[i];
    if (a->type & CKF_ARRAY_ATTRIBUTE)
      continue;
    if (a->pValue == nullptr && a->ulValueLen != 0)
      return CKR_ARGUMENTS_BAD;
    if (a->pValue == nullptr) {
      // deletion not directly supported on HsmObject; skip
      continue;
    }
    obj.setAttribute(a->type, static_cast<const u8 *>(a->pValue),
                     a->ulValueLen);
  }
  return CKR_OK;
}

CK_RV p11_get_attr(const HsmObject &obj, CK_ATTRIBUTE_PTR a) {
  vhsm::keystore::internal::v_AttributeStore_M1 store(
      const_cast<HsmObject &>(obj));
  CK_ULONG len = a->ulValueLen;
  CK_RV rv = store.v_get_attribute(a->type, a->pValue, &len);
  a->ulValueLen = len;
  return rv;
}

std::vector<u8> p11_get_attr_bytes(const HsmObject &obj, CK_ATTRIBUTE_TYPE t) {
  const std::vector<u8> *v = obj.findAttribute(t);
  if (!v)
    return {};
  return *v;
}

CK_RV p11_store_secret(HsmObject &obj, const std::vector<u8> &raw) {
  obj.setAttribute(CKA_VALUE, raw.data(), raw.size());
  return CKR_OK;
}

// ---------------------------------------------------------------------------
// EVP_PKEY <-> HsmObject
// ---------------------------------------------------------------------------
CK_RV p11_store_key(HsmObject &obj, EVP_PKEY *pkey, bool isPrivate,
                    int keyType) {
  int base = EVP_PKEY_get_base_id(pkey);
  std::vector<u8> der;
  if (base == EVP_PKEY_RSA) {
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa)
      return CKR_GENERAL_ERROR;
    if (isPrivate) {
      int len = i2d_RSAPrivateKey(rsa, nullptr);
      if (len <= 0) {
        RSA_free(rsa);
        return CKR_GENERAL_ERROR;
      }
      der.resize(static_cast<std::size_t>(len));
      u8 *p = der.data();
      i2d_RSAPrivateKey(rsa, &p);
      obj.setAttribute(CKA_VHSM_RSA_PRIV, der.data(), der.size());
    } else {
      int len = i2d_RSAPublicKey(rsa, nullptr);
      if (len <= 0) {
        RSA_free(rsa);
        return CKR_GENERAL_ERROR;
      }
      der.resize(static_cast<std::size_t>(len));
      u8 *p = der.data();
      i2d_RSAPublicKey(rsa, &p);
      obj.setAttribute(CKA_VHSM_RSA_PUB, der.data(), der.size());
    }
    RSA_free(rsa);
    obj.setAttribute(CKA_CLASS, reinterpret_cast<const u8 *>(&g_cka_public_key),
                     sizeof(CK_OBJECT_CLASS));
    (void)keyType;
  } else if (base == EVP_PKEY_EC) {
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec)
      return CKR_GENERAL_ERROR;
    if (isPrivate) {
      int len = i2d_ECPrivateKey(ec, nullptr);
      if (len <= 0) {
        EC_KEY_free(ec);
        return CKR_GENERAL_ERROR;
      }
      der.resize(static_cast<std::size_t>(len));
      u8 *p = der.data();
      i2d_ECPrivateKey(ec, &p);
      obj.setAttribute(CKA_VHSM_EC_PRIV, der.data(), der.size());
    } else {
      int len = i2o_ECPublicKey(ec, nullptr);
      if (len <= 0) {
        EC_KEY_free(ec);
        return CKR_GENERAL_ERROR;
      }
      der.resize(static_cast<std::size_t>(len));
      u8 *p = der.data();
      i2o_ECPublicKey(ec, &p);
      obj.setAttribute(CKA_VHSM_EC_PUB, der.data(), der.size());
    }
    const EC_GROUP *grp = EC_KEY_get0_group(ec);
    std::vector<u8> params;
    int plen = i2d_ECPKParameters(grp, nullptr);
    if (plen <= 0) {
      EC_KEY_free(ec);
      return CKR_GENERAL_ERROR;
    }
    params.resize(static_cast<std::size_t>(plen));
    u8 *pp = params.data();
    i2d_ECPKParameters(grp, &pp);
    obj.setAttribute(CKA_EC_PARAMS, params.data(), params.size());
    std::vector<u8> pt;
    int ptlen =
        EC_POINT_point2oct(grp, EC_KEY_get0_public_key(ec),
                           POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (ptlen <= 0) {
      EC_KEY_free(ec);
      return CKR_GENERAL_ERROR;
    }
    pt.resize(static_cast<std::size_t>(ptlen));
    EC_POINT_point2oct(grp, EC_KEY_get0_public_key(ec),
                       POINT_CONVERSION_UNCOMPRESSED, pt.data(), ptlen,
                       nullptr);
    obj.setAttribute(CKA_EC_POINT, pt.data(), ptlen);
    EC_KEY_free(ec);
    (void)keyType;
  } else {
    return CKR_GENERAL_ERROR;
  }
  if (isPrivate)
    obj.setAttribute(CKA_CLASS,
                     reinterpret_cast<const u8 *>(&g_cka_private_key),
                     sizeof(CK_OBJECT_CLASS));
  else
    obj.setAttribute(CKA_CLASS, reinterpret_cast<const u8 *>(&g_cka_public_key),
                     sizeof(CK_OBJECT_CLASS));
  CK_KEY_TYPE kt = (base == EVP_PKEY_RSA) ? CKK_RSA : CKK_EC;
  obj.setAttribute(CKA_KEY_TYPE, reinterpret_cast<const u8 *>(&kt),
                   sizeof(CK_KEY_TYPE));
  return CKR_OK;
}

EVP_PKEY *p11_evp_from_object(HsmObject *obj) {
  if (!obj)
    return nullptr;
  return p11_build_key_from_attrs(obj, obj->isPrivate(), 0);
}

const char *digest_name(vhsm::crypto::HashAlgorithm h) {
  switch (h) {
  case vhsm::crypto::HashAlgorithm::SHA256:
    return "SHA256";
  case vhsm::crypto::HashAlgorithm::SHA384:
    return "SHA384";
  case vhsm::crypto::HashAlgorithm::SHA512:
    return "SHA512";
  default:
    return "SHA256";
  }
}

std::vector<u8> p11_hash(vhsm::crypto::HashAlgorithm h,
                         const std::vector<u8> &data) {
  const EVP_MD *md = EVP_get_digestbyname(digest_name(h));
  std::vector<u8> out(EVP_MD_size(md));
  unsigned int sz = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, md, nullptr);
  EVP_DigestUpdate(ctx, data.data(), data.size());
  EVP_DigestFinal_ex(ctx, out.data(), &sz);
  EVP_MD_CTX_free(ctx);
  out.resize(sz);
  return out;
}

CK_RV p11_rsa_encrypt(EVP_PKEY *key, const std::vector<u8> &in,
                      std::vector<u8> &out, int padding,
                      const std::vector<u8> *label,
                      const std::string &mgf1_md) {
  ERR_clear_error();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx)
    return CKR_HOST_MEMORY;
  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  if (padding == RSA_PKCS1_OAEP_PADDING) {
    const EVP_MD *omd =
        mgf1_md.empty() ? EVP_sha256() : EVP_get_digestbyname(mgf1_md.c_str());
    if (!omd)
      omd = EVP_sha256();
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, omd);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, omd);
  }
  if (label && !label->empty()) {
    u8 *copy =
        static_cast<u8 *>(OPENSSL_malloc(label->size() ? label->size() : 1));
    std::memcpy(copy, label->data(), label->size());
    EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, copy, label->size());
  }
  size_t outlen = 0;
  if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, in.data(), in.size()) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  out.resize(outlen);
  if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, in.data(), in.size()) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  out.resize(outlen);
  EVP_PKEY_CTX_free(ctx);
  return CKR_OK;
}

CK_RV p11_rsa_decrypt(EVP_PKEY *key, const std::vector<u8> &in,
                      std::vector<u8> &out, int padding,
                      const std::vector<u8> *label,
                      const std::string &mgf1_md) {
  ERR_clear_error();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx)
    return CKR_HOST_MEMORY;
  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  if (padding == RSA_PKCS1_OAEP_PADDING) {
    const EVP_MD *omd =
        mgf1_md.empty() ? EVP_sha256() : EVP_get_digestbyname(mgf1_md.c_str());
    if (!omd)
      omd = EVP_sha256();
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, omd);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, omd);
  }
  if (label && !label->empty()) {
    u8 *copy =
        static_cast<u8 *>(OPENSSL_malloc(label->size() ? label->size() : 1));
    std::memcpy(copy, label->data(), label->size());
    EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, copy, label->size());
  }
  size_t outlen = 0;
  if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, in.data(), in.size()) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  out.resize(outlen);
  if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, in.data(), in.size()) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  out.resize(outlen);
  EVP_PKEY_CTX_free(ctx);
  return CKR_OK;
}

CK_RV p11_rsa_sign(EVP_PKEY *key, const std::vector<u8> &digest,
                   std::vector<u8> &sig, int padding, const std::string &mdName,
                   const std::string &mgf1_md) {
  ERR_clear_error();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx)
    return CKR_HOST_MEMORY;
  if (EVP_PKEY_sign_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  EVP_PKEY_CTX_set_rsa_padding(ctx, padding);
  const EVP_MD *md =
      mdName.empty() ? nullptr : EVP_get_digestbyname(mdName.c_str());
  if (padding == RSA_PKCS1_PSS_PADDING) {
    const EVP_MD *mgf = mgf1_md.empty() ? (md ? md : EVP_sha256())
                                        : EVP_get_digestbyname(mgf1_md.c_str());
    EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST);
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf);
    EVP_PKEY_CTX_set_signature_md(ctx, md ? md : mgf);
  } else if (md) {
    EVP_PKEY_CTX_set_signature_md(ctx, md);
  }
  size_t siglen = 0;
  if (EVP_PKEY_sign(ctx, nullptr, &siglen, digest.data(), digest.size()) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  sig.resize(siglen);
  if (EVP_PKEY_sign(ctx, sig.data(), &siglen, digest.data(), digest.size()) <=
      0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  sig.resize(siglen);
  EVP_PKEY_CTX_free(ctx);
  return CKR_OK;
}

CK_RV p11_rsa_verify(EVP_PKEY *key, const std::vector<u8> &digest,
                     const std::vector<u8> &sig, int padding,
                     const std::string &mdName, const std::string &mgf1_md) {
  ERR_clear_error();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx)
    return CKR_HOST_MEMORY;
  if (EVP_PKEY_verify_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  EVP_PKEY_CTX_set_rsa_padding(ctx, padding);
  const EVP_MD *md =
      mdName.empty() ? nullptr : EVP_get_digestbyname(mdName.c_str());
  if (padding == RSA_PKCS1_PSS_PADDING) {
    const EVP_MD *mgf = mgf1_md.empty() ? (md ? md : EVP_sha256())
                                        : EVP_get_digestbyname(mgf1_md.c_str());
    EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST);
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf);
    EVP_PKEY_CTX_set_signature_md(ctx, md ? md : mgf);
  } else if (md) {
    EVP_PKEY_CTX_set_signature_md(ctx, md);
  }
  int rc = EVP_PKEY_verify(ctx, sig.data(), sig.size(), digest.data(),
                           digest.size());
  EVP_PKEY_CTX_free(ctx);
  return rc == 1 ? CKR_OK : CKR_SIGNATURE_INVALID;
}

CK_RV p11_ecdsa_sign(EVP_PKEY *key, const std::vector<u8> &digest,
                     std::vector<u8> &sig) {
  ERR_clear_error();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx)
    return CKR_HOST_MEMORY;
  if (EVP_PKEY_sign_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  size_t siglen = 0;
  if (EVP_PKEY_sign(ctx, nullptr, &siglen, digest.data(), digest.size()) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  sig.resize(siglen);
  if (EVP_PKEY_sign(ctx, sig.data(), &siglen, digest.data(), digest.size()) <=
      0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  sig.resize(siglen);
  EVP_PKEY_CTX_free(ctx);
  return CKR_OK;
}

CK_RV p11_ecdsa_verify(EVP_PKEY *key, const std::vector<u8> &digest,
                       const std::vector<u8> &sig) {
  ERR_clear_error();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx)
    return CKR_HOST_MEMORY;
  if (EVP_PKEY_verify_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CKR_GENERAL_ERROR;
  }
  int rc = EVP_PKEY_verify(ctx, sig.data(), sig.size(), digest.data(),
                           digest.size());
  EVP_PKEY_CTX_free(ctx);
  return rc == 1 ? CKR_OK : CKR_SIGNATURE_INVALID;
}

std::vector<u8> p11_ecdh_derive(EVP_PKEY *priv, EVP_PKEY *peer) {
  ERR_clear_error();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, nullptr);
  std::vector<u8> secret;
  if (!ctx)
    return secret;
  if (EVP_PKEY_derive_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return secret;
  }
  if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return secret;
  }
  size_t len = 0;
  if (EVP_PKEY_derive(ctx, nullptr, &len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return secret;
  }
  secret.resize(len);
  if (EVP_PKEY_derive(ctx, secret.data(), &len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return {};
  }
  secret.resize(len);
  EVP_PKEY_CTX_free(ctx);
  return secret;
}

CK_RV p11_aes_gcm_encrypt(const std::vector<u8> &key, const std::vector<u8> &iv,
                          const std::vector<u8> &aad, const std::vector<u8> &pt,
                          std::vector<u8> &ct, std::vector<u8> &tag) {
  ERR_clear_error();
  const EVP_CIPHER *cipher = (key.size() == 32)   ? EVP_aes_256_gcm()
                             : (key.size() == 24) ? EVP_aes_192_gcm()
                                                  : EVP_aes_128_gcm();
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return CKR_HOST_MEMORY;
  int rc = CKR_OK;
  do {
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
      rc = CKR_GENERAL_ERROR;
      break;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), nullptr) != 1) {
      rc = CKR_GENERAL_ERROR;
      break;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
      rc = CKR_GENERAL_ERROR;
      break;
    }
    int len = 0;
    if (!aad.empty() && EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                                          static_cast<int>(aad.size())) != 1) {
      rc = CKR_GENERAL_ERROR;
      break;
    }
    ct.resize(pt.size());
    if (EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(),
                          static_cast<int>(pt.size())) != 1) {
      rc = CKR_GENERAL_ERROR;
      break;
    }
    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + len, &finalLen) != 1) {
      rc = CKR_GENERAL_ERROR;
      break;
    }
    ct.resize(static_cast<size_t>(len) + static_cast<size_t>(finalLen));
    tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
      rc = CKR_GENERAL_ERROR;
      break;
    }
  } while (0);
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}

CK_RV p11_aes_gcm_decrypt(const std::vector<u8> &key, const std::vector<u8> &iv,
                          const std::vector<u8> &aad, const std::vector<u8> &ct,
                          const std::vector<u8> &tag, std::vector<u8> &pt) {
  ERR_clear_error();
  if (tag.size() != 16)
    return CKR_ENCRYPTED_DATA_LEN_RANGE;
  const EVP_CIPHER *cipher = (key.size() == 32)   ? EVP_aes_256_gcm()
                             : (key.size() == 24) ? EVP_aes_192_gcm()
                                                  : EVP_aes_128_gcm();
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return CKR_HOST_MEMORY;
  int rc = CKR_GENERAL_ERROR;
  do {
    int len = 0;
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), nullptr) != 1)
      break;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
      break;
    if (!aad.empty() && EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(),
                                          static_cast<int>(aad.size())) != 1)
      break;
    pt.resize(ct.size());
    if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct.data(),
                          static_cast<int>(ct.size())) != 1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()),
                            const_cast<u8 *>(tag.data())) != 1)
      break;
    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, pt.data() + len, &finalLen) == 1) {
      pt.resize(static_cast<size_t>(len) + static_cast<size_t>(finalLen));
      rc = CKR_OK;
    }
  } while (0);
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}

CK_RV p11_random_bytes(u8 *out, size_t len) {
  static vhsm::crypto::SecureRNG rng;
  try {
    rng.bytes(out, len);
    return CKR_OK;
  } catch (...) {
    return CKR_GENERAL_ERROR;
  }
}

// ---------------------------------------------------------------------------
// EVP_PKEY construction from HsmObject attributes (RSA / EC)
// ---------------------------------------------------------------------------
EVP_PKEY *p11_build_key_from_attrs(HsmObject *obj, bool /*isPrivate*/,
                                   int /*keyType*/) {
  if (!obj)
    return nullptr;
  bool isPriv = obj->isPrivate();
  const std::vector<u8> *rsaPriv = obj->findAttribute(CKA_VHSM_RSA_PRIV);
  const std::vector<u8> *rsaPub = obj->findAttribute(CKA_VHSM_RSA_PUB);
  const std::vector<u8> *ecPriv = obj->findAttribute(CKA_VHSM_EC_PRIV);
  const std::vector<u8> *ecPub = obj->findAttribute(CKA_VHSM_EC_PUB);

  if ((rsaPriv && !rsaPriv->empty())) {
    const u8 *p = rsaPriv->data();
    RSA *rsa =
        d2i_RSAPrivateKey(nullptr, &p, static_cast<long>(rsaPriv->size()));
    if (!rsa)
      return nullptr;
    EVP_PKEY *pk = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pk, rsa);
    return pk;
  }
  if ((ecPriv && !ecPriv->empty())) {
    const u8 *p = ecPriv->data();
    EC_KEY *ec =
        d2i_ECPrivateKey(nullptr, &p, static_cast<long>(ecPriv->size()));
    if (!ec)
      return nullptr;
    EVP_PKEY *pk = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pk, ec);
    return pk;
  }
  if ((rsaPub && !rsaPub->empty())) {
    const u8 *p = rsaPub->data();
    RSA *rsa = d2i_RSAPublicKey(nullptr, &p, static_cast<long>(rsaPub->size()));
    if (!rsa)
      return nullptr;
    EVP_PKEY *pk = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pk, rsa);
    return pk;
  }
  if ((ecPub && !ecPub->empty())) {
    const std::vector<u8> *params = obj->findAttribute(CKA_EC_PARAMS);
    const std::vector<u8> *point = obj->findAttribute(CKA_EC_POINT);
    if (params && point && !params->empty() && !point->empty()) {
      const u8 *pp = params->data();
      EC_GROUP *grp =
          d2i_ECPKParameters(nullptr, &pp, static_cast<long>(params->size()));
      if (grp) {
        EC_KEY *ec = EC_KEY_new();
        EC_KEY_set_group(ec, grp);
        EC_POINT *pt = EC_POINT_new(grp);
        if (EC_POINT_oct2point(grp, pt, point->data(), point->size(),
                               nullptr) == 1) {
          EC_KEY_set_public_key(ec, pt);
          EVP_PKEY *pk = EVP_PKEY_new();
          EVP_PKEY_assign_EC_KEY(pk, ec);
          EC_POINT_free(pt);
          EC_GROUP_free(grp);
          return pk;
        }
        EC_POINT_free(pt);
        EC_GROUP_free(grp);
        EC_KEY_free(ec);
      }
    }
    const u8 *p = ecPub->data();
    EC_KEY *ec = d2i_EC_PUBKEY(nullptr, &p, static_cast<long>(ecPub->size()));
    if (ec) {
      EVP_PKEY *pk = EVP_PKEY_new();
      EVP_PKEY_assign_EC_KEY(pk, ec);
      return pk;
    }
    return nullptr;
  }
  (void)isPriv;
  return nullptr;
}

// ---------------------------------------------------------------------------
// Helper functions for SignatureDispatcher
// ---------------------------------------------------------------------------
std::string p11_key_fingerprint(EVP_PKEY *pkey) {
  if (!pkey)
    return "";

  int base = EVP_PKEY_get_base_id(pkey);
  std::vector<u8> der;
  std::string fingerprint;

  if (base == EVP_PKEY_RSA) {
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa) {
      int len = i2d_RSAPublicKey(rsa, nullptr);
      if (len > 0) {
        der.resize(len);
        u8 *p = der.data();
        i2d_RSAPublicKey(rsa, &p);
        // Compute SHA-256 of the DER
        const EVP_MD *md = EVP_sha256();
        std::vector<u8> hash(EVP_MD_size(md));
        unsigned int hash_len = 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, der.data(), der.size());
        EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
        EVP_MD_CTX_free(ctx);

        // Convert to hex
        std::ostringstream oss;
        for (unsigned int i = 0; i < hash_len; ++i) {
          oss << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(hash[i]);
        }
        fingerprint = oss.str();
      }
      RSA_free(rsa);
    }
  } else if (base == EVP_PKEY_EC) {
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (ec) {
      int len = i2o_ECPublicKey(ec, nullptr);
      if (len > 0) {
        der.resize(len);
        u8 *p = der.data();
        i2o_ECPublicKey(ec, &p);
        // Compute SHA-256 of the DER
        const EVP_MD *md = EVP_sha256();
        std::vector<u8> hash(EVP_MD_size(md));
        unsigned int hash_len = 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, der.data(), der.size());
        EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
        EVP_MD_CTX_free(ctx);

        // Convert to hex
        std::ostringstream oss;
        for (unsigned int i = 0; i < hash_len; ++i) {
          oss << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(hash[i]);
        }
        fingerprint = oss.str();
      }
      EC_KEY_free(ec);
    }
  }
  return fingerprint;
}

std::string p11_key_id(const HsmObject *obj) {
  if (!obj)
    return "";
  // Use CKA_ID if available, otherwise generate from object handle
  const std::vector<u8> *id = obj->findAttribute(CKA_ID);
  if (id && !id->empty()) {
    std::ostringstream oss;
    for (u8 b : *id) {
      oss << std::hex << std::setw(2) << std::setfill('0')
          << static_cast<int>(b);
    }
    return oss.str();
  }
  // Fallback: use a placeholder based on object type
  return "key-" + std::to_string(reinterpret_cast<uintptr_t>(obj));
}

} // namespace vhsm::pkcs11
