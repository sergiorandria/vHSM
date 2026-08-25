#include "pkcs11.h"
#include "pkcs11_internal.h"
#include "pkcs11_types.h"

#include "../keystore/attribute_store.h"
#include "../keystore/hsm_object.h"

#include <cstring>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace vhsm::pkcs11 {

namespace {

ObjectType class_from_attr(CK_OBJECT_CLASS c) {
  switch (c) {
  case CKO_DATA:
    return ObjectType::DATA;
  case CKO_CERTIFICATE:
    return ObjectType::CERTIFICATE;
  case CKO_PUBLIC_KEY:
    return ObjectType::PUBLIC_KEY;
  case CKO_PRIVATE_KEY:
    return ObjectType::PRIVATE_KEY;
  case CKO_SECRET_KEY:
    return ObjectType::SECRET_KEY;
  default:
    return ObjectType::OTHER;
  }
}

// Determine the object class and flags from a creation template.
bool parse_class_and_flags(CK_ATTRIBUTE_PTR t, CK_ULONG n, ObjectType &outType,
                           bool &sensitive, bool &extractable, bool &token,
                           bool &priv) {
  outType = ObjectType::DATA;
  sensitive = false;
  extractable = true;
  token = false;
  priv = false;
  CK_OBJECT_CLASS cls = CKO_DATA;
  bool haveCls = false;
  for (CK_ULONG i = 0; i < n; ++i) {
    if (t[i].type == CKA_CLASS && t[i].pValue &&
        t[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
      std::memcpy(&cls, t[i].pValue, sizeof(CK_OBJECT_CLASS));
      haveCls = true;
    } else if (t[i].type == CKA_TOKEN && t[i].pValue &&
               t[i].ulValueLen == sizeof(CK_BBOOL)) {
      CK_BBOOL b;
      std::memcpy(&b, t[i].pValue, sizeof(CK_BBOOL));
      token = (b == CK_TRUE);
    } else if (t[i].type == CKA_PRIVATE && t[i].pValue &&
               t[i].ulValueLen == sizeof(CK_BBOOL)) {
      CK_BBOOL b;
      std::memcpy(&b, t[i].pValue, sizeof(CK_BBOOL));
      priv = (b == CK_TRUE);
    } else if (t[i].type == CKA_SENSITIVE && t[i].pValue &&
               t[i].ulValueLen == sizeof(CK_BBOOL)) {
      CK_BBOOL b;
      std::memcpy(&b, t[i].pValue, sizeof(CK_BBOOL));
      sensitive = (b == CK_TRUE);
    } else if (t[i].type == CKA_EXTRACTABLE && t[i].pValue &&
               t[i].ulValueLen == sizeof(CK_BBOOL)) {
      CK_BBOOL b;
      std::memcpy(&b, t[i].pValue, sizeof(CK_BBOOL));
      extractable = (b == CK_TRUE);
    }
  }
  if (!haveCls)
    return false;
  outType = class_from_attr(cls);
  return true;
}

// Copy key/secret material from src to dst (for C_CopyObject).
void copy_material(HsmObject &dst, const HsmObject &src) {
  static const CK_ATTRIBUTE_TYPE mat[] = {
      CKA_VALUE,       CKA_KEY_TYPE,     CKA_EC_PARAMS,
      CKA_EC_POINT,    CKA_VHSM_RSA_PUB, CKA_VHSM_RSA_PRIV,
      CKA_VHSM_EC_PUB, CKA_VHSM_EC_PRIV, CKA_LABEL,
      CKA_ID,          CKA_MODULUS_BITS, CKA_CLASS};
  for (CK_ATTRIBUTE_TYPE t : mat) {
    const std::vector<u8> *v = src.findAttribute(t);
    if (v && !v->empty())
      dst.setAttribute(t, v->data(), v->size());
  }
}

bool match_object(const HsmObject &obj, CK_ATTRIBUTE_PTR t, CK_ULONG n) {
  vhsm::keystore::internal::v_AttributeStore_M1 store(
      const_cast<HsmObject &>(obj));
  for (CK_ULONG i = 0; i < n; ++i) {
    CK_ATTRIBUTE_PTR a = &t[i];
    if (a->type & CKF_ARRAY_ATTRIBUTE)
      continue;
    if (a->pValue == nullptr) {
      // attribute must simply be present
      std::vector<u8> tmp(1);
      CK_ULONG len = 0;
      CK_RV rv = store.v_get_attribute(a->type, nullptr, &len);
      if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_OK)
        continue;
      return false;
    }
    std::vector<u8> buf(a->ulValueLen);
    CK_ULONG len = a->ulValueLen;
    CK_RV rv = store.v_get_attribute(a->type, buf.data(), &len);
    if (rv != CKR_OK)
      return false;
    if (len != a->ulValueLen)
      return false;
    if (std::memcmp(buf.data(), a->pValue, len) != 0)
      return false;
  }
  return true;
}

} // namespace

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
  VHSM_C_TRY
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!phObject)
    return CKR_ARGUMENTS_BAD;
  auto s = p11_get_session(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;

  ObjectType type;
  bool sensitive, extractable, token, priv;
  if (!parse_class_and_flags(pTemplate, ulCount, type, sensitive, extractable,
                             token, priv))
    return CKR_TEMPLATE_INCOMPLETE;

  auto [handle, ptr] = s->getObjectStore().v_create_object<HsmObject>(
      type, sensitive, extractable, token, priv);
  CK_RV rv = p11_apply_template(*ptr, pTemplate, ulCount);
  if (rv != CKR_OK) {
    s->getObjectStore().v_destroy_object(handle);
    return rv;
  }
  p11_register_object(hSession, handle);
  *phObject = handle;
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject) {
  VHSM_C_TRY
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!phNewObject)
    return CKR_ARGUMENTS_BAD;
  auto s = p11_get_session(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  auto src = p11_get_object(hSession, hObject);
  if (!src)
    return CKR_OBJECT_HANDLE_INVALID;

  // PKCS#11: sensitive objects may not be copied – duplicating them would
  // expose otherwise-unextractable secret material.
  if (src->isSensitive())
    return CKR_ACTION_PROHIBITED;

  auto [handle, ptr] = s->getObjectStore().v_create_object<HsmObject>(
      src->getType(), src->isSensitive(), src->isExtractable(), src->isToken(),
      src->isPrivate());
  copy_material(*ptr, *src);
  CK_RV rv = p11_apply_template(*ptr, pTemplate, ulCount);
  if (rv != CKR_OK) {
    s->getObjectStore().v_destroy_object(handle);
    return rv;
  }
  p11_register_object(hSession, handle);
  *phNewObject = handle;
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  VHSM_C_TRY
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  auto s = p11_get_session(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  if (!s->getObjectStore().v_is_valid_handle(hObject))
    return CKR_OBJECT_HANDLE_INVALID;
  if (!s->getObjectStore().v_destroy_object(hObject))
    return CKR_OBJECT_HANDLE_INVALID;
  p11_unregister_object(hSession, hObject);

  // Audit + notify: key lifecycle event DESTROY
  auto *token = p11_get_token_for_session(hSession);
  int slot_id = static_cast<int>(s->getSlotID());
  std::string token_label = token ? token->get_label() : "unknown";
  std::stringstream detail_ss;
  detail_ss << R"({"destroyed_object_handle":)" << hObject << R"(})";
  p11_publish_event(
      vhsm::notification::NotificationEvent::EventType::KEY_DESTROYED,
      vhsm::notification::NotificationEvent::Severity::WARNING, slot_id,
      token_label, std::to_string(hObject),
      "C_DestroyObject completed for handle " + std::to_string(hObject),
      detail_ss.str(), std::nullopt, "C_DestroyObject");
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                      CK_ULONG_PTR pulSize) {
  VHSM_C_TRY
  if (!pulSize)
    return CKR_ARGUMENTS_BAD;
  auto o = p11_get_object(hSession, hObject);
  if (!o)
    return CKR_OBJECT_HANDLE_INVALID;
  CK_ULONG sz = 0;
  const std::vector<u8> *v = o->findAttribute(CKA_VALUE);
  if (v)
    sz = static_cast<CK_ULONG>(v->size());
  else {
    v = o->findAttribute(CKA_VHSM_RSA_PRIV);
    if (v)
      sz = static_cast<CK_ULONG>(v->size());
    else {
      v = o->findAttribute(CKA_VHSM_EC_PRIV);
      if (v)
        sz = static_cast<CK_ULONG>(v->size());
    }
  }
  *pulSize = sz;
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  VHSM_C_TRY
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  auto o = p11_get_object(hSession, hObject);
  if (!o)
    return CKR_OBJECT_HANDLE_INVALID;
  CK_RV rv = CKR_OK;
  for (CK_ULONG i = 0; i < ulCount; ++i) {
    CK_RV r = p11_get_attr(*o, &pTemplate[i]);
    if (r != CKR_OK && r != CKR_BUFFER_TOO_SMALL)
      rv = r;
  }
  return rv;
VHSM_C_CATCH
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  VHSM_C_TRY
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  auto o = p11_get_object(hSession, hObject);
  if (!o)
    return CKR_OBJECT_HANDLE_INVALID;
  vhsm::keystore::internal::v_AttributeStore_M1 store(*o);
  CK_RV rv = CKR_OK;
  for (CK_ULONG i = 0; i < ulCount; ++i) {
    CK_RV r = store.v_set_attribute(&pTemplate[i]);
    if (r != CKR_OK)
      rv = r;
  }
  if (rv == CKR_OK) {
    // Keep secondary indices consistent for CKA_LABEL/ID/CLASS
    auto s = p11_get_session(hSession);
    if (s) {
      s->getObjectStore().v_reindex(hObject);
    }
  }
  return rv;
VHSM_C_CATCH
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount) {
  VHSM_C_TRY
  if (!p11_is_initialized())
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  auto s = p11_get_session(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  // Find state now lives on the Session; a second Init while one is active is
  // CKR_OPERATION_ACTIVE (same semantics as the old g_findResults map check).
  if (s->hasFindResults() || s->findActive())
    return CKR_OPERATION_ACTIVE;

  std::vector<CK_OBJECT_HANDLE> results;
  bool use_index = false;
  if (pTemplate && ulCount > 0 && ulCount <= 3) {
    bool all_indexed = true;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
      CK_ATTRIBUTE_TYPE t = pTemplate[i].type;
      if (t != CKA_CLASS && t != CKA_LABEL && t != CKA_ID) { all_indexed = false; break; }
    }
    if (all_indexed) use_index = true;
  }
  if (use_index) {
    std::unordered_map<CK_ATTRIBUTE_TYPE, std::vector<uint8_t>> tmpl;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
      auto &a = pTemplate[i];
      tmpl[a.type] = std::vector<uint8_t>(static_cast<uint8_t*>(a.pValue),
                                          static_cast<uint8_t*>(a.pValue) + a.ulValueLen);
    }
    // Session store IS the session's object universe — no g_objectRegistry
    // intersection needed anymore (it could diverge from the store).
    results = s->getObjectStore().v_find_all_by_attributes(tmpl);
  } else {
    // Enumerate all handles from the session's own store.
    auto handles = s->getObjectStore().v_all_handles();
    for (CK_OBJECT_HANDLE h : handles) {
      auto o = s->getObjectStore().v_get_object(h);
      if (o && match_object(*o, pTemplate, ulCount))
        results.push_back(h);
    }
  }
  s->setFindResults(std::move(results));
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
  VHSM_C_TRY
  if (!pulObjectCount)
    return CKR_ARGUMENTS_BAD;
  auto s = p11_get_session(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  // Cursor advance on Session — O(k) slice copy, no O(n) vector::erase.
  if (!s->findActive())
    return CKR_OPERATION_NOT_INITIALIZED;
  *pulObjectCount = static_cast<CK_ULONG>(
      s->findNextBatch(phObject, static_cast<size_t>(ulMaxObjectCount)));
  return CKR_OK;
VHSM_C_CATCH
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  VHSM_C_TRY
  auto s = p11_get_session(hSession);
  if (!s)
    return CKR_SESSION_HANDLE_INVALID;
  s->clearFindResults();
  return CKR_OK;
VHSM_C_CATCH
}

} // namespace vhsm::pkcs11
