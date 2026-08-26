#include "pkcs11.h"
#include "pkcs11_internal.h"
#include "pkcs11_types.h"

#include "../core/hsm_instance.h"
#include "../core/system_hsm_clock.h"
#include "../crypto/crypto_engine.h"
#include "../crypto/EvpPkeyGuard.h"
#include "../signature_store/signature_dispatcher.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <chrono>
#include <cstring>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// PKCS#11 OAEP parameter struct / constants are not in our minimal types
// header; define a local mirror of the standard layout so we can parse
// C_EncryptInit params.
#ifndef CKG_MGF1_SHA1
#define CKG_MGF1_SHA1 0x00000001UL
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
  CK_BYTE_PTR pSourceData;
  CK_ULONG ulSourceDataLen;
};

extern "C" {
namespace vhsm::pkcs11 {

namespace {

// OAEP/MGF1 mechanism -> OpenSSL digest name.
const char *oaep_md_name(CK_MECHANISM_TYPE m) {
  switch (m) {
  case CKM_SHA_1:
    return "SHA-1";
  case CKM_SHA_256:
    return "SHA-256";
  case CKM_SHA_384:
    return "SHA-384";
  case CKM_SHA_512:
    return "SHA-512";
  default:
    return "SHA-256";
  }
}
const char *mgf_name(CK_MECHANISM_TYPE m) {
  switch (m) {
  case CKG_MGF1_SHA1:
    return "SHA-1";
  case CKG_MGF1_SHA256:
    return "SHA-256";
  case CKG_MGF1_SHA384:
    return "SHA-384";
  case CKG_MGF1_SHA512:
    return "SHA-512";
  default:
    return "SHA-256";
  }
}

bool is_digest_mech(CK_MECHANISM_TYPE m) {
  return m == CKM_SHA_256 || m == CKM_SHA_384 || m == CKM_SHA_512;
}

std::vector<u8> load_secret_key(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE k) {
  std::vector<u8> out;
  auto o = p11_get_object(h, k);
  if (!o)
    return out;
  const std::vector<u8> *v = o->findAttribute(CKA_VALUE);
  if (v)
    out = *v;
  return out;
}

EVP_PKEY *load_asym_key(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE k) {
  auto o = p11_get_object(h, k);
  if (!o)
    return nullptr;
  return p11_evp_from_object(o.get());
}

CK_RV finish_output(std::vector<u8> &out, CK_BYTE_PTR pOut,
                    CK_ULONG_PTR pOutLen) {
  if (!pOutLen)
    return CKR_ARGUMENTS_BAD;
  if (pOut == nullptr) {
    *pOutLen = static_cast<CK_ULONG>(out.size());
    return CKR_OK;
  }
  if (*pOutLen < out.size()) {
    *pOutLen = static_cast<CK_ULONG>(out.size());
    return CKR_BUFFER_TOO_SMALL;
  }
  if (!out.empty())
    std::memcpy(pOut, out.data(), out.size());
  *pOutLen = static_cast<CK_ULONG>(out.size());
  return CKR_OK;
}

// Begin a single-key crypto operation: remember mechanism + key, clear buffers.
// State lives on the Session — zero cross-session contention.
CK_RV op_begin(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k,
               bool needKey) {
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!m)
    return CKR_ARGUMENTS_BAD;
  if (needKey && k == CK_INVALID_HANDLE)
    return CKR_KEY_HANDLE_INVALID;
  auto s = p11_get_session(h);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  return s->opBegin(m->mechanism, k);
}
CK_RV op_check(CK_SESSION_HANDLE h) {
  auto s = p11_get_session(h);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  return s->opCheck();
}
void op_end(CK_SESSION_HANDLE h) {
  if (auto s = p11_get_session(h))
    s->opEnd();
}
// Fetch session once; nullptr-safe helper for do_* functions.
static session::Session *op_session(CK_SESSION_HANDLE h) {
  auto sp = p11_get_session(h);
  return sp.get();
}

// ----- Encrypt / Decrypt -----
// Shared session state read for encrypt/decrypt. All references point into
// Session-owned storage (no copies).
struct EncDecParams {
  CK_MECHANISM_TYPE mech;
  CK_OBJECT_HANDLE key;
  const std::vector<u8> *gcm_iv;
  const std::vector<u8> *gcm_aad;
  const std::string *oaep_mgf1;
  const std::vector<u8> *oaep_label;
};

static EncDecParams read_encdec_params(session::Session *sess) {
  return {sess->opMech(),   sess->opKey(),        &sess->gcmIv(),
          &sess->gcmAad(),  &sess->oaepMgf1(),    &sess->oaepLabel()};
}

// Shared RSA encrypt/decrypt padding+label resolution.
struct RsaEncDecParams {
  int padding;
  std::string md;
  const std::vector<u8> *label_ptr; // points into oaep_label
};

static RsaEncDecParams resolve_rsa_encdec(CK_MECHANISM_TYPE mech,
                                           const std::string &oaep_mgf1,
                                           const std::vector<u8> &oaep_label) {
  RsaEncDecParams p;
  p.padding = RSA_PKCS1_PADDING;
  p.md.clear();
  p.label_ptr = nullptr;
  if (mech == CKM_RSA_X_509)
    p.padding = RSA_NO_PADDING;
  else if (mech == CKM_RSA_PKCS_OAEP) {
    p.padding = RSA_PKCS1_OAEP_PADDING;
    p.md = oaep_mgf1;
    if (!oaep_label.empty())
      p.label_ptr = &oaep_label;
  }
  return p;
}

CK_RV do_encrypt(CK_SESSION_HANDLE h, const std::vector<u8> &in,
                 std::vector<u8> &out) {
  auto *sess = op_session(h);
  if (!sess)
    return CKR_SESSION_HANDLE_INVALID;
  auto prm = read_encdec_params(sess);

  if (prm.mech == CKM_AES_GCM) {
    std::vector<u8> key = load_secret_key(h, prm.key);
    if (key.empty())
      return CKR_KEY_HANDLE_INVALID;
    std::vector<u8> ct, tag;
    CK_RV rv = p11_aes_gcm_encrypt(key, *prm.gcm_iv, *prm.gcm_aad, in, ct, tag);
    if (rv == CKR_OK) {
      out = ct;
      out.insert(out.end(), tag.begin(), tag.end());
    }
    return rv;
  }

  vhsm::crypto::EvpPkeyGuard pk_guard(load_asym_key(h, prm.key));
  auto *pk = pk_guard.get();
  if (!pk)
    return CKR_KEY_HANDLE_INVALID;
  auto rsa = resolve_rsa_encdec(prm.mech, *prm.oaep_mgf1, *prm.oaep_label);
  return p11_rsa_encrypt(pk, in, out, rsa.padding, rsa.label_ptr, rsa.md);
}

CK_RV do_decrypt(CK_SESSION_HANDLE h, const std::vector<u8> &in,
                 std::vector<u8> &out) {
  auto *sess = op_session(h);
  if (!sess)
    return CKR_SESSION_HANDLE_INVALID;
  auto prm = read_encdec_params(sess);

  if (prm.mech == CKM_AES_GCM) {
    std::vector<u8> key = load_secret_key(h, prm.key);
    if (key.empty())
      return CKR_KEY_HANDLE_INVALID;
    constexpr size_t kGcmTagLen = 16;
    if (in.size() < kGcmTagLen)
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
    std::vector<u8> ct(in.begin(), in.end() - kGcmTagLen);
    std::vector<u8> tag(in.end() - kGcmTagLen, in.end());
    return p11_aes_gcm_decrypt(key, *prm.gcm_iv, *prm.gcm_aad, ct, tag, out);
  }

  vhsm::crypto::EvpPkeyGuard pk_guard(load_asym_key(h, prm.key));
  auto *pk = pk_guard.get();
  if (!pk)
    return CKR_KEY_HANDLE_INVALID;
  auto rsa = resolve_rsa_encdec(prm.mech, *prm.oaep_mgf1, *prm.oaep_label);
  return p11_rsa_decrypt(pk, in, out, rsa.padding, rsa.label_ptr, rsa.md);
}

// ----- Sign / Verify -----
// Shared mechanism→(padding, hash) resolution for RSA sign/verify.
static bool resolve_rsa_mech(CK_MECHANISM_TYPE mech,
                              const std::vector<u8> &data, int &padding,
                              std::string &mdName, std::string &mgf1,
                              std::vector<u8> &tosign) {
  padding = RSA_PKCS1_PADDING;
  mdName.clear();
  mgf1.clear();
  tosign = data;
  if (mech == CKM_RSA_PKCS) {
  } else if (mech == CKM_RSA_X_509) {
    padding = RSA_NO_PADDING;
  } else if (mech == CKM_RSA_PKCS_PSS) {
    padding = RSA_PKCS1_PSS_PADDING;
    mdName = "SHA256";
    mgf1 = "SHA256";
    tosign = p11_hash(vhsm::crypto::HashAlgorithm::SHA256, data);
  } else if (mech == CKM_RSA_PKCS_OAEP) {
    return false;
  } else {
    auto ha = mech_to_hash(mech);
    bool pss = (mech == CKM_SHA256_RSA_PKCS_PSS ||
                mech == CKM_SHA384_RSA_PKCS_PSS ||
                mech == CKM_SHA512_RSA_PKCS_PSS);
    padding = pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;
    mdName = digest_name(ha);
    mgf1 = pss ? mdName : std::string();
    tosign = p11_hash(ha, data);
  }
  return true;
}

static std::vector<u8>
resolve_ec_mech(CK_MECHANISM_TYPE mech, const std::vector<u8> &data) {
  if (mech == CKM_ECDSA)
    return data;
  return p11_hash(mech_to_hash(mech), data);
}

CK_RV do_sign(CK_SESSION_HANDLE h, const std::vector<u8> &data,
              std::vector<u8> &sig) {
  auto *sess = op_session(h);
  if (!sess)
    return CKR_SESSION_HANDLE_INVALID;
  const CK_MECHANISM_TYPE mech = sess->opMech();
  const CK_OBJECT_HANDLE k = sess->opKey();
  vhsm::crypto::EvpPkeyGuard pk_guard(load_asym_key(h, k));
  auto *pk = pk_guard.get();
  if (!pk)
    return CKR_KEY_HANDLE_INVALID;
  {
    int base = EVP_PKEY_get_base_id(pk);
    if ((is_rsa_mech(mech) && base != EVP_PKEY_RSA) ||
        (is_ec_mech(mech) && base != EVP_PKEY_EC)) {
      return CKR_KEY_TYPE_INCONSISTENT;
    }
  }
  CK_RV rv;
  if (is_rsa_mech(mech)) {
    int padding; std::string mdName, mgf1; std::vector<u8> tosign;
    if (!resolve_rsa_mech(mech, data, padding, mdName, mgf1, tosign)) {
      return CKR_MECHANISM_INVALID;
    }
    rv = p11_rsa_sign(pk, tosign, sig, padding, mdName, mgf1);
  } else if (is_ec_mech(mech)) {
    rv = p11_ecdsa_sign(pk, resolve_ec_mech(mech, data), sig);
  } else
    rv = CKR_MECHANISM_INVALID;
  return rv;
}

CK_RV do_verify(CK_SESSION_HANDLE h, const std::vector<u8> &data,
                const std::vector<u8> &sig) {
  auto *sess = op_session(h);
  if (!sess)
    return CKR_SESSION_HANDLE_INVALID;
  const CK_MECHANISM_TYPE mech = sess->opMech();
  const CK_OBJECT_HANDLE k = sess->opKey();
  vhsm::crypto::EvpPkeyGuard pk_guard(load_asym_key(h, k));
  auto *pk = pk_guard.get();
  if (!pk)
    return CKR_KEY_HANDLE_INVALID;
  {
    int base = EVP_PKEY_get_base_id(pk);
    if ((is_rsa_mech(mech) && base != EVP_PKEY_RSA) ||
        (is_ec_mech(mech) && base != EVP_PKEY_EC)) {
      return CKR_KEY_TYPE_INCONSISTENT;
    }
  }
  CK_RV rv;
  if (is_rsa_mech(mech)) {
    int padding; std::string mdName, mgf1; std::vector<u8> tosign;
    if (!resolve_rsa_mech(mech, data, padding, mdName, mgf1, tosign)) {
      return CKR_MECHANISM_INVALID;
    }
    rv = p11_rsa_verify(pk, tosign, sig, padding, mdName, mgf1);
  } else if (is_ec_mech(mech)) {
    rv = p11_ecdsa_verify(pk, resolve_ec_mech(mech, data), sig);
  } else
    rv = CKR_MECHANISM_INVALID;
  return rv;
}

// Mechanism constant -> human-readable string. Static map: O(1) lookup,
// single source of truth, adding a new mechanism = one line.
std::string mech_to_str(CK_MECHANISM_TYPE mech) {
  static const std::unordered_map<CK_MECHANISM_TYPE, std::string> kMechNames = {
      {CKM_RSA_PKCS, "CKM_RSA_PKCS"},
      {CKM_RSA_X_509, "CKM_RSA_X_509"},
      {CKM_RSA_PKCS_PSS, "CKM_RSA_PKCS_PSS"},
      {CKM_RSA_PKCS_OAEP, "CKM_RSA_PKCS_OAEP"},
      {CKM_SHA256_RSA_PKCS, "CKM_SHA256_RSA_PKCS"},
      {CKM_SHA384_RSA_PKCS, "CKM_SHA384_RSA_PKCS"},
      {CKM_SHA512_RSA_PKCS, "CKM_SHA512_RSA_PKCS"},
      {CKM_SHA256_RSA_PKCS_PSS, "CKM_SHA256_RSA_PKCS_PSS"},
      {CKM_SHA384_RSA_PKCS_PSS, "CKM_SHA384_RSA_PKCS_PSS"},
      {CKM_SHA512_RSA_PKCS_PSS, "CKM_SHA512_RSA_PKCS_PSS"},
      {CKM_ECDSA, "CKM_ECDSA"},
      {CKM_ECDSA_SHA256, "CKM_ECDSA_SHA256"},
      {CKM_ECDSA_SHA384, "CKM_ECDSA_SHA384"},
      {CKM_ECDSA_SHA512, "CKM_ECDSA_SHA512"},
      {CKM_AES_GCM, "CKM_AES_GCM"},
      {CKM_AES_ECB, "CKM_AES_ECB"},
  };
  auto it = kMechNames.find(mech);
  return it != kMechNames.end() ? it->second : "CKM_VENDOR_DEFINED";
}

std::string digest_to_str(CK_MECHANISM_TYPE mech) {
  // Maps mechanism → digest algorithm name for audit metadata.
  static const std::unordered_map<CK_MECHANISM_TYPE, std::string> kDigestNames = {
      {CKM_SHA384, "SHA-384"},
      {CKM_SHA384_RSA_PKCS, "SHA-384"},
      {CKM_ECDSA_SHA384, "SHA-384"},
      {CKM_SHA384_HMAC, "SHA-384"},
      {CKM_SHA384_RSA_PKCS_PSS, "SHA-384"},
      {CKM_SHA512, "SHA-512"},
      {CKM_SHA512_RSA_PKCS, "SHA-512"},
      {CKM_ECDSA_SHA512, "SHA-512"},
      {CKM_SHA512_HMAC, "SHA-512"},
      {CKM_SHA512_RSA_PKCS_PSS, "SHA-512"},
  };
  auto it = kDigestNames.find(mech);
  return it != kDigestNames.end() ? it->second : "SHA-256";
}

// Build a structured NotificationEvent with the standard session/key context.
void publish_verify_event(CK_SESSION_HANDLE h, CK_RV rv,
                          const std::vector<u8> &data) {
  auto *notification_bus = p11_notification_bus();
  auto *audit_log = p11_audit_log();
  if (!notification_bus || !audit_log)
    return;

  // Get session/token info
  auto *token = p11_get_token_for_session(h);
  auto session = p11_get_session(h);
  int slot_id = session ? static_cast<int>(session->getSlotID()) : 0;
  std::string token_label = token ? token->get_label() : "unknown";

  // Get key info — one Session read replaces the global lock section.
  auto session_sp = p11_get_session(h);
  session::Session *sess = session_sp.get();
  CK_OBJECT_HANDLE k = sess ? sess->opKey() : CK_INVALID_HANDLE;
  CK_MECHANISM_TYPE active_mech = sess ? sess->opMech() : 0;
  std::optional<std::string> user_label;
  {
    CK_USER_TYPE ut = sess ? sess->getUserType() : CKU_INVALID;
    if (ut != CKU_INVALID)
      user_label = "user-" + std::to_string(static_cast<int>(ut));
  }
  auto obj = p11_get_object(h, k);
  std::string key_id = obj ? p11_key_id(obj.get()) : "unknown";

  EVP_PKEY *pk = load_asym_key(h, k);
  std::string key_fp = pk ? p11_key_fingerprint(pk) : "unknown";

  std::string mechanism_str = mech_to_str(active_mech);
  std::string digest_alg = digest_to_str(active_mech);

  // Compute payload digest
  auto payload_hash = p11_hash(vhsm::crypto::HashAlgorithm::SHA256, data);
  std::ostringstream oss;
  for (u8 b : payload_hash) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
  }
  std::string payload_digest = oss.str();

  int64_t created_at = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();

  vhsm::notification::NotificationEvent event;
  event.type =
      (rv == CKR_OK)
          ? vhsm::notification::NotificationEvent::EventType::VERIFY_COMPLETED
          : vhsm::notification::NotificationEvent::EventType::VERIFY_FAILED;
  event.severity =
      (rv == CKR_OK) ? vhsm::notification::NotificationEvent::Severity::INFO
                     : vhsm::notification::NotificationEvent::Severity::WARNING;
  event.timestamp = created_at;
  event.source = "slot:" + std::to_string(slot_id) + "/token:" + token_label;
  event.actor = user_label.value_or("UNKNOWN");
  event.summary = "Signature verification " +
                  std::string(rv == CKR_OK ? "succeeded" : "failed") +
                  " for key " + key_id + " using " + mechanism_str;

  std::stringstream detail_ss;
  detail_ss << R"({"mechanism":")" << mechanism_str << R"(",)"
            << R"("digest_algorithm":")" << digest_alg << R"(",)"
            << R"("key_fingerprint":")" << key_fp << R"(",)"
            << R"("payload_digest":")" << payload_digest << R"(",)"
            << R"("result":")" << (rv == CKR_OK ? "valid" : "invalid")
            << R"("})";
  event.detail_json = detail_ss.str();
  event.hsm_instance = vhsm::core::hsm_instance_id();

  try {
    notification_bus->publish(event);
    (void)audit_log->append("verify-" + std::to_string(created_at),
                            rv == CKR_OK ? "C_VERIFY_OK" : "C_VERIFY_FAILED");
  } catch (const std::exception &) {
    // Notification must never raise across the C API boundary.
  }
}

// Publish an audit event for encrypt/decrypt/wrap/unwrap operations.
void publish_crypto_op_event(
    CK_SESSION_HANDLE h, const std::string &op_name,
    vhsm::notification::NotificationEvent::EventType type,
    const std::vector<u8> &data) {
  auto *notification_bus = p11_notification_bus();
  auto *audit_log = p11_audit_log();
  if (!notification_bus || !audit_log)
    return;

  // Get session/token info
  auto *token = p11_get_token_for_session(h);
  auto session = p11_get_session(h);
  int slot_id = session ? static_cast<int>(session->getSlotID()) : 0;
  std::string token_label = token ? token->get_label() : "unknown";

  // Get key info — one Session read replaces the global lock section.
  auto session_sp = p11_get_session(h);
  session::Session *sess = session_sp.get();
  CK_OBJECT_HANDLE k = sess ? sess->opKey() : CK_INVALID_HANDLE;
  CK_MECHANISM_TYPE active_mech = sess ? sess->opMech() : 0;
  std::optional<std::string> user_label;
  {
    CK_USER_TYPE ut = sess ? sess->getUserType() : CKU_INVALID;
    if (ut != CKU_INVALID)
      user_label = "user-" + std::to_string(static_cast<int>(ut));
  }
  auto obj = p11_get_object(h, k);
  std::string key_id = obj ? p11_key_id(obj.get()) : "unknown";

  EVP_PKEY *pk = load_asym_key(h, k);
  std::string key_fp = pk ? p11_key_fingerprint(pk) : "unknown";

  std::string mechanism_str = mech_to_str(active_mech);

  // Compute payload digest
  auto payload_hash = p11_hash(vhsm::crypto::HashAlgorithm::SHA256, data);
  std::ostringstream oss;
  for (u8 b : payload_hash) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
  }
  std::string payload_digest = oss.str();

  int64_t created_at = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();

  vhsm::notification::NotificationEvent event;
  event.type = type;
  event.severity = vhsm::notification::NotificationEvent::Severity::INFO;
  event.timestamp = created_at;
  event.source = "slot:" + std::to_string(slot_id) + "/token:" + token_label;
  event.actor = user_label.value_or("UNKNOWN");
  event.summary =
      op_name + " completed for key " + key_id + " using " + mechanism_str;

  std::stringstream detail_ss;
  detail_ss << R"({"operation":")" << op_name << R"(",)"
            << R"("mechanism":")" << mechanism_str << R"(",)"
            << R"("key_fingerprint":")" << key_fp << R"(",)"
            << R"("payload_digest":")" << payload_digest << R"("})";
  event.detail_json = detail_ss.str();
  event.hsm_instance = vhsm::core::hsm_instance_id();

  try {
    notification_bus->publish(event);
    (void)audit_log->append(op_name + "-" + std::to_string(created_at), op_name);
  } catch (const std::exception &) {
    // Notification must never raise across the C API boundary.
  }
}

} // namespace

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

// Dispatch a completed signature to the SignatureDispatcher for persistence,
// audit, and notification. Shared by C_Sign and C_SignFinal — previously
// duplicated verbatim (~100 lines), one divergence away from mis-labeling
// multi-part signatures when the next mechanism is added to only one copy.
// Returns CKR_OK on success or CKR_DEVICE_ERROR if require_db_write fails.
static CK_RV dispatch_sign_result(
    CK_SESSION_HANDLE h, CK_MECHANISM_TYPE mech, const std::vector<u8> &data,
    const std::vector<u8> &sig) {
  auto *dispatcher = p11_signature_dispatcher();
  if (!dispatcher)
    return CKR_OK; // no dispatcher configured (tests) — skip silently

  auto session_sp = p11_get_session(h);
  session::Session *sess = session_sp.get();
  CK_OBJECT_HANDLE k = sess ? sess->opKey() : CK_INVALID_HANDLE;

  EVP_PKEY *pk = load_asym_key(h, k);
  if (!pk)
    return CKR_OK; // can't fingerprint without key — don't block signing

  vhsm::crypto::SignResult sign_result;
  sign_result.signature = sig;
  sign_result.mechanism_str = mech_to_str(mech);
  sign_result.digest_alg = digest_to_str(mech);

  // Compute payload digest (SHA-256 of data)
  auto payload_hash = p11_hash(vhsm::crypto::HashAlgorithm::SHA256, data);
  std::ostringstream oss;
  for (u8 b : payload_hash) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
  }
  sign_result.payload_digest = oss.str();
  sign_result.payload_size = static_cast<int>(data.size());

  // Get key metadata
  auto obj = p11_get_object(h, k);
  std::string key_id = obj ? p11_key_id(obj.get()) : "unknown";
  std::string key_fp = p11_key_fingerprint(pk);

  // Get session/token info
  auto *token = p11_get_token_for_session(h);
  int slot_id = sess ? static_cast<int>(sess->getSlotID()) : 0;
  std::string token_label = token ? token->get_label() : "unknown";

  // Get user label if logged in
  std::optional<std::string> user_label;
  {
    CK_USER_TYPE ut = sess ? sess->getUserType() : CKU_INVALID;
    if (ut != CKU_INVALID)
      user_label = "user-" + std::to_string(static_cast<int>(ut));
  }

  int64_t created_at = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();

  bool dispatch_ok = false;
  try {
    dispatch_ok =
        dispatcher->dispatch(sign_result, created_at, slot_id, token_label,
                             key_id, key_fp, sign_result.mechanism_str,
                             sign_result.digest_alg, std::to_string(h),
                             user_label, std::nullopt);
  } catch (const std::exception &) {
    dispatch_ok = false; // DB write failure must not escape the C ABI.
  }

  return dispatch_ok ? CKR_OK : CKR_DEVICE_ERROR;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                    CK_OBJECT_HANDLE hKey) {
  VHSM_C_TRY
  if (!m)
    return CKR_ARGUMENTS_BAD;
  if (m->mechanism != CKM_RSA_PKCS && m->mechanism != CKM_RSA_X_509 &&
      m->mechanism != CKM_RSA_PKCS_OAEP && m->mechanism != CKM_AES_GCM)
    return CKR_MECHANISM_INVALID;

  CK_RV rv = op_begin(h, m, hKey, true);
  if (rv != CKR_OK)
    return rv;

  auto sess_for_params_sp = p11_get_session(h);
  auto *sess_for_params = sess_for_params_sp.get();
  if (m->mechanism == CKM_AES_GCM) {
    if (!m->pParameter || m->ulParameterLen < sizeof(CK_GCM_PARAMS))
      return CKR_MECHANISM_PARAM_INVALID;
    auto *g = static_cast<CK_GCM_PARAMS_PTR>(m->pParameter);
    if (!g->pIv || g->ulIvLen == 0)
      return CKR_MECHANISM_PARAM_INVALID;
    std::vector<u8> iv(g->pIv, g->pIv + g->ulIvLen);
    std::vector<u8> aad;
    if (g->pAAD && g->ulAADLen)
      aad.assign(g->pAAD, g->pAAD + g->ulAADLen);
    sess_for_params->setGcmParams(iv, aad);
  } else if (m->mechanism == CKM_RSA_PKCS_OAEP) {
    if (m->pParameter && m->ulParameterLen >= sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
      auto *o = static_cast<CK_RSA_PKCS_OAEP_PARAMS *>(m->pParameter);
      std::vector<u8> lbl;
      if (o->source == CKZ_DATA_SPECIFIED && o->pSourceData &&
          o->ulSourceDataLen)
        lbl.assign(o->pSourceData, o->pSourceData + o->ulSourceDataLen);
      sess_for_params->setOaepParams(oaep_md_name(o->hashAlg), lbl);
    } else {
      sess_for_params->setOaepParams("SHA-256", {});
    }
  }
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_Encrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pData == nullptr && ulDataLen > 0)
    return CKR_ARGUMENTS_BAD;
  std::vector<u8> in(pData, pData + ulDataLen);
  std::vector<u8> out;
  CK_RV rv = do_encrypt(h, in, out);
  if (rv == CKR_OK) {
    rv = finish_output(out, pEncryptedData, pulEncryptedDataLen);
    if (rv == CKR_OK) {
      publish_crypto_op_event(
          h, "C_Encrypt",
          vhsm::notification::NotificationEvent::EventType::ENCRYPT_COMPLETED,
          in);
    }
  }
  op_end(h);
  return rv;
VHSM_C_CATCH
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pPart == nullptr && ulPartLen > 0)
    return CKR_ARGUMENTS_BAD;
  if (auto s = p11_get_session(h))
    s->opUpdate(pPart, ulPartLen);
  if (pEncryptedPart == nullptr) {
    if (pulEncryptedPartLen)
      *pulEncryptedPartLen = 0;
    return CKR_OK;
  }
  if (pulEncryptedPartLen)
    *pulEncryptedPartLen = 0;
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pLastEncryptedPart,
                     CK_ULONG_PTR pulLastEncryptedPartLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  auto s_final = p11_get_session(h);
  if (!s_final)
    return CKR_SESSION_HANDLE_INVALID;
  // Move the accumulated buffer out — zero copy vs old deep copy under lock.
  std::vector<u8> in = s_final->opTakeBuffer();
  s_final->opUpdate(in.data(), in.size());  // keep for publish event below
  std::vector<u8> out;
  CK_RV rv = do_encrypt(h, in, out);
  if (rv == CKR_OK) {
    rv = finish_output(out, pLastEncryptedPart, pulLastEncryptedPartLen);
    if (rv == CKR_OK) {
      publish_crypto_op_event(
          h, "C_EncryptFinal",
          vhsm::notification::NotificationEvent::EventType::ENCRYPT_COMPLETED,
          in);
    }
  }
  op_end(h);
  return rv;
VHSM_C_CATCH
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------
CK_RV C_DecryptInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                    CK_OBJECT_HANDLE hKey) {
  VHSM_C_TRY
  if (!m)
    return CKR_ARGUMENTS_BAD;
  if (m->mechanism != CKM_RSA_PKCS && m->mechanism != CKM_RSA_X_509 &&
      m->mechanism != CKM_RSA_PKCS_OAEP && m->mechanism != CKM_AES_GCM)
    return CKR_MECHANISM_INVALID;

  CK_RV rv = op_begin(h, m, hKey, true);
  if (rv != CKR_OK)
    return rv;

  auto sess_for_params_sp = p11_get_session(h);
  auto *sess_for_params = sess_for_params_sp.get();
  if (m->mechanism == CKM_AES_GCM) {
    if (!m->pParameter || m->ulParameterLen < sizeof(CK_GCM_PARAMS))
      return CKR_MECHANISM_PARAM_INVALID;
    auto *g = static_cast<CK_GCM_PARAMS_PTR>(m->pParameter);
    if (!g->pIv || g->ulIvLen == 0)
      return CKR_MECHANISM_PARAM_INVALID;
    std::vector<u8> iv(g->pIv, g->pIv + g->ulIvLen);
    std::vector<u8> aad;
    if (g->pAAD && g->ulAADLen)
      aad.assign(g->pAAD, g->pAAD + g->ulAADLen);
    sess_for_params->setGcmParams(iv, aad);
  } else if (m->mechanism == CKM_RSA_PKCS_OAEP) {
    if (m->pParameter && m->ulParameterLen >= sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
      auto *o = static_cast<CK_RSA_PKCS_OAEP_PARAMS *>(m->pParameter);
      std::vector<u8> lbl;
      if (o->source == CKZ_DATA_SPECIFIED && o->pSourceData &&
          o->ulSourceDataLen)
        lbl.assign(o->pSourceData, o->pSourceData + o->ulSourceDataLen);
      sess_for_params->setOaepParams(oaep_md_name(o->hashAlg), lbl);
    } else {
      sess_for_params->setOaepParams("SHA-256", {});
    }
  }
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_Decrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR pEncryptedData,
                CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pEncryptedData == nullptr && ulEncryptedDataLen > 0)
    return CKR_ARGUMENTS_BAD;
  std::vector<u8> in(pEncryptedData, pEncryptedData + ulEncryptedDataLen);
  std::vector<u8> out;
  CK_RV rv = do_decrypt(h, in, out);
  if (rv == CKR_OK) {
    rv = finish_output(out, pData, pulDataLen);
    if (rv == CKR_OK) {
      publish_crypto_op_event(
          h, "C_Decrypt",
          vhsm::notification::NotificationEvent::EventType::DECRYPT_COMPLETED,
          in);
    }
  }
  op_end(h);
  return rv;
VHSM_C_CATCH
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                      CK_ULONG_PTR pulPartLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pEncryptedPart == nullptr && ulEncryptedPartLen > 0)
    return CKR_ARGUMENTS_BAD;
  if (auto s = p11_get_session(h))
    s->opUpdate(pEncryptedPart, ulEncryptedPartLen);
  if (pPart == nullptr) {
    if (pulPartLen)
      *pulPartLen = 0;
    return CKR_OK;
  }
  if (pulPartLen)
    *pulPartLen = 0;
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pLastPart,
                     CK_ULONG_PTR pulLastPartLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  auto s_fin = p11_get_session(h);
  if (!s_fin)
    return CKR_SESSION_HANDLE_INVALID;
  std::vector<u8> in = s_fin->opTakeBuffer();
  s_fin->opUpdate(in.data(), in.size());
  std::vector<u8> out;
  CK_RV rv = do_decrypt(h, in, out);
  if (rv == CKR_OK) {
    rv = finish_output(out, pLastPart, pulLastPartLen);
    if (rv == CKR_OK) {
      publish_crypto_op_event(
          h, "C_DecryptFinal",
          vhsm::notification::NotificationEvent::EventType::DECRYPT_COMPLETED,
          in);
    }
  }
  op_end(h);
  return rv;
VHSM_C_CATCH
}

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------
CK_RV C_DigestInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m) {
  VHSM_C_TRY
  if (!m)
    return CKR_ARGUMENTS_BAD;
  if (!is_digest_mech(m->mechanism))
    return CKR_MECHANISM_INVALID;
  return op_begin(h, m, CK_INVALID_HANDLE, false);
VHSM_C_CATCH
}

CK_RV C_Digest(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pData == nullptr && ulDataLen > 0)
    return CKR_ARGUMENTS_BAD;
  auto s_d = p11_get_session(h);
  if (!s_d)
    return CKR_SESSION_HANDLE_INVALID;
  CK_MECHANISM_TYPE mech = s_d->opMech();
  std::vector<u8> out =
      p11_hash(mech_to_hash(mech), std::vector<u8>(pData, pData + ulDataLen));
  CK_RV rv = finish_output(out, pDigest, pulDigestLen);
  op_end(h);
  return rv;
VHSM_C_CATCH
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pPart == nullptr && ulPartLen > 0)
    return CKR_ARGUMENTS_BAD;
  if (auto s = p11_get_session(h))
    s->opUpdate(pPart, ulPartLen);
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_DigestKey(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE hKey) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  std::vector<u8> key = load_secret_key(h, hKey);
  if (key.empty())
    return CKR_KEY_INDIGESTIBLE;
  if (auto s = p11_get_session(h))
    s->opUpdate(key.data(), key.size());
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pDigest,
                    CK_ULONG_PTR pulDigestLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  auto s_dg = p11_get_session(h);
  if (!s_dg)
    return CKR_SESSION_HANDLE_INVALID;
  std::vector<u8> buf = s_dg->opTakeBuffer();
  CK_MECHANISM_TYPE mech = s_dg->opMech();
  std::vector<u8> out = p11_hash(mech_to_hash(mech), buf);
  CK_RV rv = finish_output(out, pDigest, pulDigestLen);
  op_end(h);
  return rv;
VHSM_C_CATCH
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------
CK_RV C_SignInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                 CK_OBJECT_HANDLE hKey) {
  VHSM_C_TRY
  if (!m)
    return CKR_ARGUMENTS_BAD;
  if (!is_rsa_mech(m->mechanism) && !is_ec_mech(m->mechanism))
    return CKR_MECHANISM_INVALID;
  return op_begin(h, m, hKey, true);
VHSM_C_CATCH
}

CK_RV C_Sign(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pData == nullptr && ulDataLen > 0)
    return CKR_ARGUMENTS_BAD;
  std::vector<u8> data(pData, pData + ulDataLen);
  std::vector<u8> sig;
  CK_RV rv = do_sign(h, data, sig);
  if (rv == CKR_OK) {
    rv = finish_output(sig, pSignature, pulSignatureLen);

    // Dispatch to SignatureDispatcher for persistence/audit/notification
    if (rv == CKR_OK) {
      auto sf_sess = p11_get_session(h);
      CK_MECHANISM_TYPE active_mech = sf_sess ? sf_sess->opMech() : 0;
      rv = dispatch_sign_result(h, active_mech, data, sig);
    }
  }
  op_end(h);
  return rv;
VHSM_C_CATCH
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pPart == nullptr && ulPartLen > 0)
    return CKR_ARGUMENTS_BAD;
  if (auto s = p11_get_session(h))
    s->opUpdate(pPart, ulPartLen);
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_SignFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pSignature,
                  CK_ULONG_PTR pulSignatureLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  auto s_sf = p11_get_session(h);
  if (!s_sf)
    return CKR_SESSION_HANDLE_INVALID;
  // Move out — zero-copy vs old deep copy under the global lock.
  std::vector<u8> data = s_sf->opTakeBuffer();
  s_sf->opUpdate(data.data(), data.size());  // retained for digest below
  std::vector<u8> sig;
  CK_RV rv = do_sign(h, data, sig);
  if (rv == CKR_OK) {
    rv = finish_output(sig, pSignature, pulSignatureLen);

    // Dispatch to SignatureDispatcher for persistence/audit/notification
    // Uses shared dispatch_sign_result() — same as C_Sign.
    if (rv == CKR_OK) {
      auto sf_sess = p11_get_session(h);
      CK_MECHANISM_TYPE active_mech = sf_sess ? sf_sess->opMech() : 0;
      rv = dispatch_sign_result(h, active_mech, data, sig);
    }
  }
  op_end(h);
  return rv;
VHSM_C_CATCH
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------
CK_RV C_VerifyInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                   CK_OBJECT_HANDLE hKey) {
  VHSM_C_TRY
  if (!m)
    return CKR_ARGUMENTS_BAD;
  if (!is_rsa_mech(m->mechanism) && !is_ec_mech(m->mechanism))
    return CKR_MECHANISM_INVALID;
  return op_begin(h, m, hKey, true);
VHSM_C_CATCH
}

CK_RV C_Verify(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pData == nullptr && ulDataLen > 0)
    return CKR_ARGUMENTS_BAD;
  if (pSignature == nullptr && ulSignatureLen > 0)
    return CKR_ARGUMENTS_BAD;
  std::vector<u8> data(pData, pData + ulDataLen);
  std::vector<u8> sig(pSignature, pSignature + ulSignatureLen);
  CK_RV rv = do_verify(h, data, sig);

  // Publish verification result for audit/notification
  if (rv == CKR_OK || rv == CKR_SIGNATURE_INVALID) {
    publish_verify_event(h, rv, data);
  }

  op_end(h);
  return rv;
VHSM_C_CATCH
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pPart == nullptr && ulPartLen > 0)
    return CKR_ARGUMENTS_BAD;
  if (auto s = p11_get_session(h))
    s->opUpdate(pPart, ulPartLen);
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR pSignature,
                    CK_ULONG ulSignatureLen) {
  VHSM_C_TRY
  if (op_check(h) != CKR_OK)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (pSignature == nullptr && ulSignatureLen > 0)
    return CKR_ARGUMENTS_BAD;
  auto s_vf = p11_get_session(h);
  if (!s_vf)
    return CKR_SESSION_HANDLE_INVALID;
  std::vector<u8> data = s_vf->opTakeBuffer();
  s_vf->opUpdate(data.data(), data.size());
  CK_RV rv = do_verify(
      h, data, std::vector<u8>(pSignature, pSignature + ulSignatureLen));

  // Publish verification result for audit/notification
  if (rv == CKR_OK || rv == CKR_SIGNATURE_INVALID) {
    publish_verify_event(h, rv, data);
  }

  op_end(h);
  return rv;
VHSM_C_CATCH
}

// ---------------------------------------------------------------------------
// Combined / recover operations (not supported)
// ---------------------------------------------------------------------------
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart,
                            CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG_PTR pulEncryptedPartLen) {
  VHSM_C_TRY
  (void)h;
  (void)pPart;
  (void)ulPartLen;
  (void)pEncryptedPart;
  (void)pulEncryptedPartLen;
  return CKR_FUNCTION_NOT_SUPPORTED;
VHSM_C_CATCH
}
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                            CK_ULONG_PTR pulPartLen) {
  VHSM_C_TRY
  (void)h;
  (void)pEncryptedPart;
  (void)ulEncryptedPartLen;
  (void)pPart;
  (void)pulPartLen;
  return CKR_FUNCTION_NOT_SUPPORTED;
VHSM_C_CATCH
}
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pPart,
                          CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                          CK_ULONG_PTR pulEncryptedPartLen) {
  VHSM_C_TRY
  (void)h;
  (void)pPart;
  (void)ulPartLen;
  (void)pEncryptedPart;
  (void)pulEncryptedPartLen;
  return CKR_FUNCTION_NOT_SUPPORTED;
VHSM_C_CATCH
}
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                            CK_ULONG_PTR pulPartLen) {
  VHSM_C_TRY
  (void)h;
  (void)pEncryptedPart;
  (void)ulEncryptedPartLen;
  (void)pPart;
  (void)pulPartLen;
  return CKR_FUNCTION_NOT_SUPPORTED;
VHSM_C_CATCH
}
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                        CK_OBJECT_HANDLE hKey) {
  VHSM_C_TRY
  (void)h;
  (void)m;
  (void)hKey;
  return CKR_FUNCTION_NOT_SUPPORTED;
VHSM_C_CATCH
}
CK_RV C_SignRecover(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  VHSM_C_TRY
  (void)h;
  (void)pData;
  (void)ulDataLen;
  (void)pSignature;
  (void)pulSignatureLen;
  return CKR_FUNCTION_NOT_SUPPORTED;
VHSM_C_CATCH
}
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                          CK_OBJECT_HANDLE hKey) {
  VHSM_C_TRY
  (void)h;
  (void)m;
  (void)hKey;
  return CKR_FUNCTION_NOT_SUPPORTED;
VHSM_C_CATCH
}
CK_RV C_VerifyRecover(CK_SESSION_HANDLE h, CK_BYTE_PTR pSignature,
                      CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                      CK_ULONG_PTR pulDataLen) {
  VHSM_C_TRY
  (void)h;
  (void)pSignature;
  (void)ulSignatureLen;
  (void)pData;
  (void)pulDataLen;
  return CKR_FUNCTION_NOT_SUPPORTED;
VHSM_C_CATCH
}

} // namespace vhsm::pkcs11
} // extern "C"
