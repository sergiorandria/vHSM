#include "pkcs11.h"
#include "pkcs11_internal.h"
#include "pkcs11_types.h"

#include "../keystore/slot.h"
#include "../keystore/token.h"

#include <cstring>
#include <string>
#include <vector>

namespace vhsm::pkcs11 {

namespace {

void copy_fixed(CK_UTF8CHAR_PTR dst, CK_ULONG dstLen, const char *src) {
  std::memset(dst, ' ', dstLen);
  std::size_t n = std::strlen(src);
  if (n > dstLen)
    n = dstLen;
  std::memcpy(dst, src, n);
}

const std::vector<CK_MECHANISM_TYPE> &supported_mechanisms() {
  static const std::vector<CK_MECHANISM_TYPE> m = {
      CKM_RSA_PKCS,
      CKM_RSA_X_509,
      CKM_RSA_PKCS_OAEP,
      CKM_RSA_PKCS_PSS,
      CKM_SHA256_RSA_PKCS,
      CKM_SHA384_RSA_PKCS,
      CKM_SHA512_RSA_PKCS,
      CKM_SHA256_RSA_PKCS_PSS,
      CKM_SHA384_RSA_PKCS_PSS,
      CKM_SHA512_RSA_PKCS_PSS,
      CKM_EC_KEY_PAIR_GEN,
      CKM_ECDSA,
      CKM_ECDSA_SHA256,
      CKM_ECDSA_SHA384,
      CKM_ECDSA_SHA512,
      CKM_SHA256,
      CKM_SHA384,
      CKM_SHA512,
      CKM_AES_ECB,
      CKM_AES_CBC,
      CKM_AES_GCM,
      CKM_AES_KEY_GEN,
      CKM_AES_KEY_WRAP,
      CKM_ECDH1_DERIVE,
  };
  return m;
}

void fill_mech_info(CK_MECHANISM_TYPE t, CK_MECHANISM_INFO_PTR info) {
  info->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY |
                CKF_WRAP | CKF_UNWRAP | CKF_DERIVE;
  if (t == CKM_SHA256 || t == CKM_SHA384 || t == CKM_SHA512 ||
      t == CKM_AES_KEY_GEN) {
    info->flags = CKF_HW | CKF_DIGEST | CKF_GENERATE;
  }
  if (t == CKM_RSA_PKCS || t == CKM_RSA_X_509 || t == CKM_RSA_PKCS_OAEP ||
      t == CKM_RSA_PKCS_PSS || t == CKM_SHA256_RSA_PKCS ||
      t == CKM_SHA384_RSA_PKCS || t == CKM_SHA512_RSA_PKCS ||
      t == CKM_SHA256_RSA_PKCS_PSS || t == CKM_SHA384_RSA_PKCS_PSS ||
      t == CKM_SHA512_RSA_PKCS_PSS) {
    info->ulMinKeySize = 2048;
    info->ulMaxKeySize = 4096;
  } else if (t == CKM_EC_KEY_PAIR_GEN || t == CKM_ECDSA ||
             t == CKM_ECDSA_SHA256 || t == CKM_ECDSA_SHA384 ||
             t == CKM_ECDSA_SHA512 || t == CKM_ECDH1_DERIVE) {
    info->ulMinKeySize = 256;
    info->ulMaxKeySize = 521;
  } else if (t == CKM_AES_ECB || t == CKM_AES_CBC || t == CKM_AES_GCM ||
             t == CKM_AES_KEY_GEN || t == CKM_AES_KEY_WRAP) {
    info->ulMinKeySize = 128;
    info->ulMaxKeySize = 256;
  } else {
    info->ulMinKeySize = 0;
    info->ulMaxKeySize = 0;
  }
}

} // namespace

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount) {
  if (!pulCount)
    return CKR_ARGUMENTS_BAD;
  auto ids = vhsm::session::SlotManager::get_instance().get_slot_id_list();
  if (tokenPresent) {
    std::vector<u64> filt;
    for (auto id : ids) {
      auto sp = vhsm::session::SlotManager::get_instance().get_slot(id);
      if (sp && sp->is_token_present())
        filt.push_back(id);
    }
    ids = filt;
  }
  if (!pSlotList) {
    *pulCount = static_cast<CK_ULONG>(ids.size());
    return CKR_OK;
  }
  if (*pulCount < ids.size()) {
    *pulCount = static_cast<CK_ULONG>(ids.size());
    return CKR_BUFFER_TOO_SMALL;
  }
  for (CK_ULONG i = 0; i < ids.size(); ++i)
    pSlotList[i] = static_cast<CK_SLOT_ID>(ids[i]);
  *pulCount = static_cast<CK_ULONG>(ids.size());
  return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  if (!pInfo)
    return CKR_ARGUMENTS_BAD;
  keystore::Slot *slot = p11_get_slot(slotID);
  if (!slot)
    return CKR_SLOT_ID_INVALID;
  std::memset(pInfo, 0, sizeof(CK_SLOT_INFO));
  copy_fixed(pInfo->slotDescription, sizeof(pInfo->slotDescription),
             slot->get_description().c_str());
  copy_fixed(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
             slot->get_manufacturer().c_str());
  pInfo->flags = slot->get_flags();
  pInfo->hardwareVersion.major = 1;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = 1;
  pInfo->firmwareVersion.minor = 0;
  return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  if (!pInfo)
    return CKR_ARGUMENTS_BAD;
  keystore::Token *tok = p11_get_token(slotID);
  if (!tok)
    return CKR_SLOT_ID_INVALID;
  std::memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
  copy_fixed(pInfo->label, sizeof(pInfo->label), tok->get_label().c_str());
  copy_fixed(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "vHSM");
  copy_fixed(pInfo->model, sizeof(pInfo->model), "vHSM-SW");
  copy_fixed(pInfo->serialNumber, sizeof(pInfo->serialNumber),
             tok->get_id().c_str());
  CK_FLAGS flags = CKF_RNG;
  if (tok->is_token_initialized())
    flags |= CKF_TOKEN_INITIALIZED;
  if (tok->is_user_login_required())
    flags |= CKF_LOGIN_REQUIRED;
  if (tok->is_user_pin_set())
    flags |= CKF_USER_PIN_INITIALIZED;
  if (tok->is_so_pin_set())
    flags |= CKF_SO_PIN_INITIALIZED;
  pInfo->flags = flags;
  pInfo->ulMaxSessionCount = tok->get_max_session_count();
  pInfo->ulSessionCount = tok->get_session_count();
  pInfo->ulMaxRwSessionCount = tok->get_max_rw_session_count();
  pInfo->ulRwSessionCount = tok->get_rw_session_count();
  pInfo->ulMaxPinLen = 256;
  pInfo->ulMinPinLen = 4;
  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->hardwareVersion.major = 1;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = 1;
  pInfo->firmwareVersion.minor = 0;
  return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                         CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount) {
  (void)slotID;
  if (!pulCount)
    return CKR_ARGUMENTS_BAD;
  const auto &m = supported_mechanisms();
  if (!pMechanismList) {
    *pulCount = static_cast<CK_ULONG>(m.size());
    return CKR_OK;
  }
  if (*pulCount < m.size()) {
    *pulCount = static_cast<CK_ULONG>(m.size());
    return CKR_BUFFER_TOO_SMALL;
  }
  for (CK_ULONG i = 0; i < m.size(); ++i)
    pMechanismList[i] = m[i];
  *pulCount = static_cast<CK_ULONG>(m.size());
  return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo) {
  (void)slotID;
  if (!pInfo)
    return CKR_ARGUMENTS_BAD;
  const auto &m = supported_mechanisms();
  if (std::find(m.begin(), m.end(), type) == m.end())
    return CKR_MECHANISM_INVALID;
  fill_mech_info(type, pInfo);
  return CKR_OK;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                  CK_UTF8CHAR_PTR pLabel) {
  keystore::Token *tok = p11_get_token(slotID);
  if (!tok)
    return CKR_SLOT_ID_INVALID;
  if (pPin && ulPinLen > 0) {
    CK_RV rv = tok->initialize_so_pin(reinterpret_cast<const CK_CHAR *>(pPin),
                                      ulPinLen);
    if (rv != CKR_OK)
      return rv;
  }
  (void)pLabel;
  return CKR_OK;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                CK_ULONG ulPinLen) {
  keystore::Token *tok = p11_get_token_for_session(hSession);
  if (!tok)
    return CKR_SESSION_HANDLE_INVALID;
  if (!pPin)
    return CKR_ARGUMENTS_BAD;
  return tok->initialize_user_pin(reinterpret_cast<const CK_CHAR *>(pPin),
                                  ulPinLen);
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
               CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
  keystore::Token *tok = p11_get_token_for_session(hSession);
  if (!tok)
    return CKR_SESSION_HANDLE_INVALID;
  if (!pNewPin)
    return CKR_ARGUMENTS_BAD;
  if (pOldPin && ulOldLen > 0)
    return tok->change_user_pin(
        reinterpret_cast<const CK_CHAR *>(pOldPin), ulOldLen,
        reinterpret_cast<const CK_CHAR *>(pNewPin), ulNewLen);
  return tok->set_user_pin(
      nullptr, 0, reinterpret_cast<const CK_CHAR *>(pNewPin), ulNewLen);
}

} // namespace vhsm::pkcs11
