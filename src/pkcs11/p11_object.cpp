#include "pkcs11_internal.h"
#include "pkcs11.h"
#include "pkcs11_types.h"

#include "../keystore/hsm_object.h"
#include "../keystore/attribute_store.h"

#include <cstring>
#include <sstream>
#include <vector>
#include <unordered_map>

namespace vhsm::pkcs11 {

namespace {

ObjectType class_from_attr(CK_OBJECT_CLASS c) {
    switch (c) {
        case CKO_DATA:         return ObjectType::DATA;
        case CKO_CERTIFICATE:  return ObjectType::CERTIFICATE;
        case CKO_PUBLIC_KEY:   return ObjectType::PUBLIC_KEY;
        case CKO_PRIVATE_KEY:  return ObjectType::PRIVATE_KEY;
        case CKO_SECRET_KEY:   return ObjectType::SECRET_KEY;
        default:               return ObjectType::OTHER;
    }
}

// Determine the object class and flags from a creation template.
bool parse_class_and_flags(CK_ATTRIBUTE_PTR t, CK_ULONG n, ObjectType& outType,
                           bool& sensitive, bool& extractable, bool& token, bool& priv) {
    outType = ObjectType::DATA;
    sensitive = false; extractable = true; token = false; priv = false;
    CK_OBJECT_CLASS cls = CKO_DATA;
    bool haveCls = false;
    for (CK_ULONG i = 0; i < n; ++i) {
        if (t[i].type == CKA_CLASS && t[i].pValue && t[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            std::memcpy(&cls, t[i].pValue, sizeof(CK_OBJECT_CLASS));
            haveCls = true;
        } else if (t[i].type == CKA_TOKEN && t[i].pValue && t[i].ulValueLen == sizeof(CK_BBOOL)) {
            CK_BBOOL b; std::memcpy(&b, t[i].pValue, sizeof(CK_BBOOL)); token = (b == CK_TRUE);
        } else if (t[i].type == CKA_PRIVATE && t[i].pValue && t[i].ulValueLen == sizeof(CK_BBOOL)) {
            CK_BBOOL b; std::memcpy(&b, t[i].pValue, sizeof(CK_BBOOL)); priv = (b == CK_TRUE);
        } else if (t[i].type == CKA_SENSITIVE && t[i].pValue && t[i].ulValueLen == sizeof(CK_BBOOL)) {
            CK_BBOOL b; std::memcpy(&b, t[i].pValue, sizeof(CK_BBOOL)); sensitive = (b == CK_TRUE);
        } else if (t[i].type == CKA_EXTRACTABLE && t[i].pValue && t[i].ulValueLen == sizeof(CK_BBOOL)) {
            CK_BBOOL b; std::memcpy(&b, t[i].pValue, sizeof(CK_BBOOL)); extractable = (b == CK_TRUE);
        }
    }
    if (!haveCls) return false;
    outType = class_from_attr(cls);
    return true;
}

// Copy key/secret material from src to dst (for C_CopyObject).
void copy_material(HsmObject& dst, const HsmObject& src) {
    static const CK_ATTRIBUTE_TYPE mat[] = {
        CKA_VALUE, CKA_KEY_TYPE, CKA_EC_PARAMS, CKA_EC_POINT,
        CKA_VHSM_RSA_PUB, CKA_VHSM_RSA_PRIV, CKA_VHSM_EC_PUB, CKA_VHSM_EC_PRIV,
        CKA_LABEL, CKA_ID, CKA_MODULUS_BITS, CKA_CLASS
    };
    for (CK_ATTRIBUTE_TYPE t : mat) {
        const std::vector<u8>* v = src.findAttribute(t);
        if (v && !v->empty()) dst.setAttribute(t, v->data(), v->size());
    }
}

bool match_object(const HsmObject& obj, CK_ATTRIBUTE_PTR t, CK_ULONG n) {
    vhsm::keystore::internal::v_AttributeStore_M1 store(const_cast<HsmObject&>(obj));
    for (CK_ULONG i = 0; i < n; ++i) {
        CK_ATTRIBUTE_PTR a = &t[i];
        if (a->type & CKF_ARRAY_ATTRIBUTE) continue;
        if (a->pValue == nullptr) {
            // attribute must simply be present
            std::vector<u8> tmp(1);
            CK_ULONG len = 0;
            CK_RV rv = store.v_get_attribute(a->type, nullptr, &len);
            if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_OK) continue;
            return false;
        }
        std::vector<u8> buf(a->ulValueLen);
        CK_ULONG len = a->ulValueLen;
        CK_RV rv = store.v_get_attribute(a->type, buf.data(), &len);
        if (rv != CKR_OK) return false;
        if (len != a->ulValueLen) return false;
        if (std::memcmp(buf.data(), a->pValue, len) != 0) return false;
    }
    return true;
}

} // namespace

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE_PTR phObject) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!phObject) return CKR_ARGUMENTS_BAD;
    auto s = p11_get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;

    ObjectType type; bool sensitive, extractable, token, priv;
    if (!parse_class_and_flags(pTemplate, ulCount, type, sensitive, extractable, token, priv))
        return CKR_TEMPLATE_INCOMPLETE;

    auto [handle, ptr] = s->getObjectStore().v_create_object<HsmObject>(
        type, sensitive, extractable, token, priv);
    CK_RV rv = p11_apply_template(*ptr, pTemplate, ulCount);
    if (rv != CKR_OK) { s->getObjectStore().v_destroy_object(handle); return rv; }
    p11_register_object(hSession, handle);
    *phObject = handle;
    return CKR_OK;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!phNewObject) return CKR_ARGUMENTS_BAD;
    auto s = p11_get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    auto src = p11_get_object(hSession, hObject);
    if (!src) return CKR_OBJECT_HANDLE_INVALID;

    // PKCS#11: sensitive objects may not be copied – duplicating them would
    // expose otherwise-unextractable secret material.
    if (src->isSensitive()) return CKR_ACTION_PROHIBITED;

    auto [handle, ptr] = s->getObjectStore().v_create_object<HsmObject>(
        src->getType(), src->isSensitive(), src->isExtractable(), src->isToken(), src->isPrivate());
    copy_material(*ptr, *src);
    CK_RV rv = p11_apply_template(*ptr, pTemplate, ulCount);
    if (rv != CKR_OK) { s->getObjectStore().v_destroy_object(handle); return rv; }
    p11_register_object(hSession, handle);
    *phNewObject = handle;
    return CKR_OK;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    auto s = p11_get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!s->getObjectStore().v_is_valid_handle(hObject)) return CKR_OBJECT_HANDLE_INVALID;
    if (!s->getObjectStore().v_destroy_object(hObject)) return CKR_OBJECT_HANDLE_INVALID;
    p11_unregister_object(hSession, hObject);

    // Audit + notify: key lifecycle event DESTROY
    auto* token = p11_get_token_for_session(hSession);
    int slot_id = static_cast<int>(s->getSlotID());
    std::string token_label = token ? token->get_label() : "unknown";
    std::stringstream detail_ss;
    detail_ss << R"({"destroyed_object_handle":)" << hObject << R"(})";
    p11_publish_event(
        vhsm::notification::NotificationEvent::EventType::KEY_DESTROYED,
        vhsm::notification::NotificationEvent::Severity::WARNING,
        slot_id, token_label,
        std::to_string(hObject),
        "C_DestroyObject completed for handle " + std::to_string(hObject),
        detail_ss.str(),
        std::nullopt,
        "C_DestroyObject");
    return CKR_OK;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
    if (!pulSize) return CKR_ARGUMENTS_BAD;
    auto o = p11_get_object(hSession, hObject);
    if (!o) return CKR_OBJECT_HANDLE_INVALID;
    CK_ULONG sz = 0;
    const std::vector<u8>* v = o->findAttribute(CKA_VALUE);
    if (v) sz = static_cast<CK_ULONG>(v->size());
    else {
        v = o->findAttribute(CKA_VHSM_RSA_PRIV);
        if (v) sz = static_cast<CK_ULONG>(v->size());
        else {
            v = o->findAttribute(CKA_VHSM_EC_PRIV);
            if (v) sz = static_cast<CK_ULONG>(v->size());
        }
    }
    *pulSize = sz;
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    auto o = p11_get_object(hSession, hObject);
    if (!o) return CKR_OBJECT_HANDLE_INVALID;
    CK_RV rv = CKR_OK;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        CK_RV r = p11_get_attr(*o, &pTemplate[i]);
        if (r != CKR_OK && r != CKR_BUFFER_TOO_SMALL) rv = r;
    }
    return rv;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    auto o = p11_get_object(hSession, hObject);
    if (!o) return CKR_OBJECT_HANDLE_INVALID;
    vhsm::keystore::internal::v_AttributeStore_M1 store(*o);
    CK_RV rv = CKR_OK;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        CK_RV r = store.v_set_attribute(&pTemplate[i]);
        if (r != CKR_OK) rv = r;
    }
    return rv;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    if (!p11_is_initialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    auto s = p11_get_session(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (g_findResults.count(hSession)) return CKR_OPERATION_ACTIVE;
    }

    std::vector<CK_OBJECT_HANDLE> results;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        auto it = g_objectRegistry.find(hSession);
        if (it != g_objectRegistry.end()) {
            for (CK_OBJECT_HANDLE h : it->second) {
                auto o = s->getObjectStore().v_get_object(h);
                if (o && match_object(*o, pTemplate, ulCount)) results.push_back(h);
            }
        }
        g_findResults[hSession] = std::move(results);
    }
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
    if (!pulObjectCount) return CKR_ARGUMENTS_BAD;
    CK_ULONG n = 0;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        auto it = g_findResults.find(hSession);
        if (it == g_findResults.end()) return CKR_OPERATION_NOT_INITIALIZED;
        for (CK_ULONG i = 0; i < it->second.size() && n < ulMaxObjectCount; ++i) {
            if (phObject) phObject[n] = it->second[i];
            ++n;
        }
        *pulObjectCount = n;
        // Remove returned handles so subsequent calls return the rest.
        it->second.erase(it->second.begin(), it->second.begin() + n);
    }
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_findResults.erase(hSession);
    return CKR_OK;
}

} // namespace vhsm::pkcs11
