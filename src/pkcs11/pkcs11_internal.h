// WHY this header is internal (not part of C ABI): PKCS#11 applications don't
// include this. It declares C++ helper functions for the p11_*.cpp
// implementations. It's internal to vHSM.

#ifndef VHSM_PKCS11_INTERNAL_H
#define VHSM_PKCS11_INTERNAL_H

#include "../core/secure_buffer.h"
#include "../core/types.h"
#include "pkcs11_types.h"

#include "../keystore/attribute_store.h"
#include "../keystore/hsm_object.h"
#include "../keystore/key_wrap.h"
#include "../keystore/object_store.h"
#include "../keystore/slot.h"
#include "../keystore/token.h"

#include "../session/session.h"
#include "../session/session_manager.h"
#include "../session/slot_manager.h"

#include "../crypto/SecureRNG.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/crypto_engine.h"
#include "../crypto/ecc.h"
#include "../crypto/rsa.h"

#include "../audit/audit_log.h"
#ifdef VHSM_LEDGER
#include "../ledger/ledger_client.h"
#include "../ledger/ledger_entry.h"
#include "../ledger/ledger_worker.h"
#endif
#include "../notification/bounded_notification_bus.h"
#include "../notification/notification_bus.h"
#include "../notification/notification_event.h"
#include "../signature_store/db_connection.h"
#include "../signature_store/notification_dispatcher.h"
#include "../signature_store/notification_repository.h"
#include "../signature_store/signature_dispatcher.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Concrete implementations for NotificationBus and AuditLog (defined here for
// use in C_Initialize)
class P11NotificationBus : public vhsm::notification::NotificationBus {
public:
  void publish(const vhsm::notification::NotificationEvent &event) override {
    // In production, this would publish to a message queue, database, etc.
    // For now, log to stderr for debugging
    std::cerr << "[NOTIFICATION] type=" << static_cast<int>(event.type)
              << " severity=" << static_cast<int>(event.severity)
              << " source=" << event.source << " actor=" << event.actor
              << " summary=" << event.summary << " detail=" << event.detail_json
              << std::endl;
  }
};

class P11AuditLog : public vhsm::audit::AuditLog {
public:
  void append(const std::string &event_id,
              const std::string &event_type) override {
    // In production, this would write to an audit database/file
    // For now, log to stderr for debugging
    std::cerr << "[AUDIT] event_id=" << event_id << " event_type=" << event_type
              << std::endl;
  }
};

// Forward-declared at global scope so g_vault (a unique_ptr<..::Vault>) can be
// declared inside vhsm::pkcs11 without pulling in the whole persistence
// headers.
namespace vhsm::persistence {
class Vault;
}

namespace vhsm::pkcs11 {
using keystore::HsmObject;
using keystore::KeyWrap;
using keystore::ObjectType;
using session::Session;
using session::SessionManager;

// WHY extern g_initialized: Shared across translation units in the PKCS#11
// module. p11_init.cpp sets/clears it; p11_internal.cpp reads it via
// p11_is_initialized().
extern bool g_initialized;

// AppContainer forward (composition root owns all services)
struct AppContainer;
extern std::unique_ptr<AppContainer> g_appContainer;

// SignatureDispatcher and related globals (now views into g_appContainer when
// C_Initialize uses the composition root; still owning for backward compat)
extern std::unique_ptr<vhsm::signature_store::db::SignatureDispatcher>
    g_signatureDispatcher;
extern vhsm::notification::NotificationBus *g_notificationBus;
extern std::unique_ptr<vhsm::audit::AuditLog> g_auditLog;
extern std::unique_ptr<vhsm::signature_store::db::IDbConnection> g_dbConnection;

// Notification delivery pipeline (bus → dispatcher → subscribers)
extern std::unique_ptr<vhsm::signature_store::db::NotificationDispatcher>
    g_notificationDispatcher;
extern std::unique_ptr<vhsm::signature_store::db::NotificationRepository>
    g_notificationRepo;
extern std::unique_ptr<vhsm::notification::BoundedNotificationBus> g_boundedBus;

// Ledger anchoring globals (optional; only when VHSM_LEDGER is ON)
#ifdef VHSM_LEDGER
extern std::unique_ptr<vhsm::ledger::LedgerClient> g_ledgerClient;
extern std::unique_ptr<vhsm::ledger::LedgerWorker> g_ledgerWorker;
#endif

// Optional encrypted vault backing the default token (PLAN.md Phase 7).
// Owned by the PKCS#11 module; opened/created in C_Initialize from
// VHSM_VAULT_PATH + VHSM_VAULT_PASSWORD, closed in C_Finalize.
extern std::unique_ptr<vhsm::persistence::Vault> g_vault;

// WHY extern g_sessionManager: Same pattern as g_initialized. Defined in
// p11_internal.cpp, used by p11_session.cpp, p11_keygen.cpp, etc.
extern SessionManager g_sessionManager;

// WHY CKA_VHSM_* constants: Internal vendor-defined attributes for storing key
// material. These are not standard PKCS#11 attributes; they store DER-encoded
// key blobs so the PKCS#11 layer can reconstruct EVP_PKEY objects from HSM
// objects.
inline constexpr CK_ULONG CKA_VHSM_RSA_PRIV = 0x81000001UL;
inline constexpr CK_ULONG CKA_VHSM_RSA_PUB = 0x81000002UL;
inline constexpr CK_ULONG CKA_VHSM_EC_PRIV = 0x81000003UL;
inline constexpr CK_ULONG CKA_VHSM_EC_PUB = 0x81000004UL;

bool p11_is_initialized();
SessionManager &p11_sessions();

keystore::Slot *p11_get_slot(CK_SLOT_ID id);
keystore::Token *p11_get_token(CK_SLOT_ID id);
keystore::Token *p11_get_token_for_session(CK_SESSION_HANDLE hSession);
std::shared_ptr<session::Session> p11_get_session(CK_SESSION_HANDLE h);
std::shared_ptr<keystore::HsmObject> p11_get_object(CK_SESSION_HANDLE hSession,
                                                    CK_OBJECT_HANDLE hObject);

// SignatureDispatcher access
vhsm::signature_store::db::SignatureDispatcher *p11_signature_dispatcher();
vhsm::signature_store::db::IDbConnection *p11_db_connection();
vhsm::notification::NotificationBus *p11_notification_bus();
vhsm::audit::AuditLog *p11_audit_log();

// Publish a generic audit/notification event. Used by operations that do not
// carry per-session operation state (e.g., key wrap/unwrap).
void p11_publish_event(vhsm::notification::NotificationEvent::EventType type,
                       vhsm::notification::NotificationEvent::Severity severity,
                       int slot_id, const std::string &token_label,
                       const std::string &key_id, const std::string &summary,
                       const std::string &detail_json,
                       const std::optional<std::string> &user_label,
                       const std::string &audit_event_type);

void p11_register_object(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
void p11_unregister_object(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
void p11_clear_session_objects(CK_SESSION_HANDLE);

CK_MECHANISM_TYPE class_to_mech(ObjectType);
vhsm::crypto::HashAlgorithm mech_to_hash(CK_MECHANISM_TYPE);
bool is_rsa_mech(CK_MECHANISM_TYPE);
bool is_ec_mech(CK_MECHANISM_TYPE);

CK_RV p11_apply_template(HsmObject &obj, CK_ATTRIBUTE_PTR pTemplate,
                         CK_ULONG ulCount);
CK_RV p11_get_attr(const HsmObject &obj, CK_ATTRIBUTE_PTR a);
std::vector<u8> p11_get_attr_bytes(const HsmObject &obj, CK_ATTRIBUTE_TYPE t);
CK_RV p11_store_secret(HsmObject &obj, const std::vector<u8> &rawKey);
CK_RV p11_store_key(HsmObject &obj, EVP_PKEY *pkey, bool isPrivate,
                    int keyType);

EVP_PKEY *p11_evp_from_object(HsmObject *obj);
EVP_PKEY *p11_build_key_from_attrs(HsmObject *obj, bool isPrivate, int keyType);
const char *digest_name(vhsm::crypto::HashAlgorithm h);
std::vector<u8> p11_hash(vhsm::crypto::HashAlgorithm h,
                         const std::vector<u8> &data);

CK_RV p11_rsa_encrypt(EVP_PKEY *key, const std::vector<u8> &in,
                      std::vector<u8> &out, int padding,
                      const std::vector<u8> *label, const std::string &mgf1_md);
CK_RV p11_rsa_decrypt(EVP_PKEY *key, const std::vector<u8> &in,
                      std::vector<u8> &out, int padding,
                      const std::vector<u8> *label, const std::string &mgf1_md);
CK_RV p11_rsa_sign(EVP_PKEY *key, const std::vector<u8> &digest,
                   std::vector<u8> &sig, int padding, const std::string &mdName,
                   const std::string &mgf1_md);
CK_RV p11_rsa_verify(EVP_PKEY *key, const std::vector<u8> &digest,
                     const std::vector<u8> &sig, int padding,
                     const std::string &mdName, const std::string &mgf1_md);
CK_RV p11_ecdsa_sign(EVP_PKEY *key, const std::vector<u8> &digest,
                     std::vector<u8> &sig);
CK_RV p11_ecdsa_verify(EVP_PKEY *key, const std::vector<u8> &digest,
                       const std::vector<u8> &sig);
std::vector<u8> p11_ecdh_derive(EVP_PKEY *priv, EVP_PKEY *peerPub);
CK_RV p11_aes_gcm_encrypt(const std::vector<u8> &key, const std::vector<u8> &iv,
                          const std::vector<u8> &aad, const std::vector<u8> &pt,
                          std::vector<u8> &ct, std::vector<u8> &tag);
CK_RV p11_aes_gcm_decrypt(const std::vector<u8> &key, const std::vector<u8> &iv,
                          const std::vector<u8> &aad, const std::vector<u8> &ct,
                          const std::vector<u8> &tag, std::vector<u8> &pt);
CK_RV p11_random_bytes(u8 *out, std::size_t n);

// Helper for key fingerprint
std::string p11_key_fingerprint(EVP_PKEY *pkey);
std::string p11_key_id(const HsmObject *obj);

// Per-session operation state is now owned by Session (see session.h).
// The ten global maps and g_stateMutex have been removed. Each Session
// owns its own activeMech, opBuf, signKey, gcmIv/Aad, oaep* and find
// state, so cross-session contention is zero. See Session::opBegin etc.

// Reset all per-session crypto-operation state (now delegates to Session).
void p11_reset_op(CK_SESSION_HANDLE h);

// WHY extern "C": The PKCS#11 API functions (C_Initialize, C_GetSlotList, etc.)
// must have C linkage so they are not name-mangled.  The declarations below let
// each p11_*.cpp implementation file see C linkage when it defines the
// functions, ensuring the symbols exported from the .so match the extern "C"
// expectations in function_list.cpp.
extern "C" {
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
CK_RV C_Finalize(CK_VOID_PTR pReserved);
CK_RV C_GetInfo(CK_INFO_PTR pInfo);
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount);
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                         CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount);
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo);
CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                  CK_UTF8CHAR_PTR pLabel);
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                CK_ULONG ulPinLen);
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
               CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV C_Logout(CK_SESSION_HANDLE hSession);
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject);
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                      CK_ULONG_PTR pulSize);
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount);
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey);
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen);
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen);
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
                     CK_ULONG_PTR pulLastEncryptedPartLen);
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey);
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen);
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart,
                      CK_ULONG_PTR pulDecryptedPartLen);
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                     CK_ULONG_PTR pulLastPartLen);
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
               CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
               CK_ULONG_PTR pulDigestLen);
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen);
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                    CK_ULONG_PTR pulDigestLen);
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hKey);
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                   CK_ULONG ulPartLen);
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                  CK_ULONG_PTR pulSignatureLen);
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hKey);
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
               CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
               CK_ULONG ulSignatureLen);
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen);
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                    CK_ULONG ulSignatureLen);
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phKey);
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey,
                        CK_OBJECT_HANDLE_PTR phPrivateKey);
CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                  CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                   CK_ULONG ulSeedLen);
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData,
                       CK_ULONG ulRandomLen);
} // extern "C"

} // namespace vhsm::pkcs11

#endif // VHSM_PKCS11_INTERNAL_H
