// WHY this header is internal (not part of C ABI): PKCS#11 applications don't include this.
// It declares C++ helper functions for the p11_*.cpp implementations. It's internal to vHSM.

#ifndef VHSM_PKCS11_INTERNAL_H
#define VHSM_PKCS11_INTERNAL_H

#include "pkcs11_types.h"
#include "../core/types.h"
#include "../core/secure_buffer.h"

#include "../keystore/slot.h"
#include "../keystore/token.h"
#include "../keystore/hsm_object.h"
#include "../keystore/object_store.h"
#include "../keystore/attribute_store.h"
#include "../keystore/key_wrap.h"

#include "../session/session_manager.h"
#include "../session/slot_manager.h"
#include "../session/session.h"

#include "../crypto/crypto_engine.h"
#include "../crypto/rsa.h"
#include "../crypto/ecc.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/SecureRNG.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

#include <unordered_map>
#include <vector>
#include <string>
#include <cstring>

namespace vhsm::pkcs11 {

bool p11_is_initialized();
SessionManager& p11_sessions();

keystore::Slot*  p11_get_slot(CK_SLOT_ID id);
keystore::Token* p11_get_token(CK_SLOT_ID id);
keystore::Token* p11_get_token_for_session(CK_SESSION_HANDLE hSession);
Session* p11_get_session(CK_SESSION_HANDLE h);
HsmObject* p11_get_object(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

void p11_register_object(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
void p11_unregister_object(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
void p11_clear_session_objects(CK_SESSION_HANDLE);

CK_MECHANISM_TYPE            class_to_mech(ObjectType);
vhsm::crypto::HashAlgorithm mech_to_hash(CK_MECHANISM_TYPE);
bool is_rsa_mech(CK_MECHANISM_TYPE);
bool is_ec_mech(CK_MECHANISM_TYPE);

CK_RV p11_apply_template(HsmObject& obj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV p11_get_attr(const HsmObject& obj, CK_ATTRIBUTE_PTR a);
std::vector<u8> p11_get_attr_bytes(const HsmObject& obj, CK_ATTRIBUTE_TYPE t);
CK_RV p11_store_secret(HsmObject& obj, const std::vector<u8>& rawKey);
CK_RV p11_store_key(HsmObject& obj, EVP_PKEY* pkey, bool isPrivate, int keyType);

EVP_PKEY* p11_evp_from_object(HsmObject* obj);
EVP_PKEY* p11_build_key_from_attrs(HsmObject* obj, bool isPrivate, int keyType);
const char* digest_name(vhsm::crypto::HashAlgorithm h);
std::vector<u8> p11_hash(vhsm::crypto::HashAlgorithm h, const std::vector<u8>& data);

CK_RV p11_rsa_encrypt(EVP_PKEY* key, const std::vector<u8>& in, std::vector<u8>& out,
                      int padding, const std::vector<u8>* label, const std::string& mgf1_md);
CK_RV p11_rsa_decrypt(EVP_PKEY* key, const std::vector<u8>& in, std::vector<u8>& out,
                      int padding, const std::vector<u8>* label, const std::string& mgf1_md);
CK_RV p11_rsa_sign(EVP_PKEY* key, const std::vector<u8>& digest, std::vector<u8>& sig,
                   int padding, const std::string& mdName, const std::string& mgf1_md);
CK_RV p11_rsa_verify(EVP_PKEY* key, const std::vector<u8>& digest, const std::vector<u8>& sig,
                     int padding, const std::string& mdName, const std::string& mgf1_md);
CK_RV p11_ecdsa_sign(EVP_PKEY* key, const std::vector<u8>& digest, std::vector<u8>& sig);
CK_RV p11_ecdsa_verify(EVP_PKEY* key, const std::vector<u8>& digest, const std::vector<u8>& sig);
std::vector<u8> p11_ecdh_derive(EVP_PKEY* priv, EVP_PKEY* peerPub);
CK_RV p11_aes_gcm_encrypt(const std::vector<u8>& key, const std::vector<u8>& iv,
                          const std::vector<u8>& aad, const std::vector<u8>& pt,
                          std::vector<u8>& ct, std::vector<u8>& tag);
CK_RV p11_aes_gcm_decrypt(const std::vector<u8>& key, const std::vector<u8>& iv,
                          const std::vector<u8>& aad, const std::vector<u8>& ct,
                          const std::vector<u8>& tag, std::vector<u8>& pt);
CK_RV p11_random_bytes(u8* out, std::size_t n);

// Per-session operation state (defined in p11_internal.cpp).
extern std::unordered_map<CK_SESSION_HANDLE, CK_MECHANISM_TYPE>     g_activeMech;
extern std::unordered_map<CK_SESSION_HANDLE, std::vector<u8>>        g_opBuf;
extern std::unordered_map<CK_SESSION_HANDLE, CK_OBJECT_HANDLE>       g_signKey;
extern std::unordered_map<CK_SESSION_HANDLE, std::vector<u8>>        g_gcmIv;
extern std::unordered_map<CK_SESSION_HANDLE, std::vector<u8>>        g_gcmAad;
extern std::unordered_map<CK_SESSION_HANDLE, std::vector<u8>>        g_oaepLabel;
extern std::unordered_map<CK_SESSION_HANDLE, std::string>            g_oaepMgf1;
extern std::unordered_map<CK_SESSION_HANDLE, std::vector<CK_OBJECT_HANDLE>> g_findResults;
extern std::unordered_map<CK_SESSION_HANDLE, CK_USER_TYPE>           g_loginState;
extern std::unordered_map<CK_SESSION_HANDLE, std::vector<CK_OBJECT_HANDLE>> g_objectRegistry;

// Reset all per-session crypto-operation state.
void p11_reset_op(CK_SESSION_HANDLE h);

} // namespace vhsm::pkcs11

#endif // VHSM_PKCS11_INTERNAL_H
