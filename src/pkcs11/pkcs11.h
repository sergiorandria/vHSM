#ifndef VHSM_PKCS11_H
#define VHSM_PKCS11_H

/*
 * pkcs11.h
 *
 * Public entry points of the vHSM PKCS#11 module.
 *
 * WHY this is the C ABI boundary: vHSM's implementation is C++ (safer, faster
 * to develop). But PKCS#11 applications are written in C and expect C function
 * pointers. This header declares all C functions that vHSM exports.
 * Applications call these, which delegate to C++ implementations (in p11_*.cpp
 * files). The extern "C" prevents C++ name mangling (without it, dlsym would
 * fail to find C_Initialize).
 *
 * WHY provide both direct functions and C_GetFunctionList: Some applications
 * dlsym() each function individually (C_Initialize, C_Finalize, etc.). Others
 * call C_GetFunctionList() to get a pointer to a static CK_FUNCTION_LIST struct
 * (table of function pointers). Both patterns are valid in PKCS#11; we support
 * both.
 *
 * WHY every C_* function returns CK_RV (error code, not exceptions): C doesn't
 * have exceptions. PKCS#11 defines standard error codes (CKR_OK,
 * CKR_ARGUMENTS_BAD, CKR_SESSION_HANDLE_INVALID, etc.). The C++ implementation
 * converts exceptions to error codes before returning.
 *
 * The complete ABI surface (CK_* types, constants and CK_FUNCTION_LIST) is
 * defined in "pkcs11_types.h".  This header declares the C linkage entry
 * points that the module exports.  Applications are expected to go through
 * C_GetFunctionList() (or load the shared object and dlsym the individual
 * symbols); both are provided.
 */

#include "pkcs11_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// WHY C_Initialize/C_Finalize: Lifecycle methods. C_Initialize() sets up the
// library (singleton pattern for slot manager, session manager, token).
// C_Finalize() tears it down. Between these two calls, applications can open
// sessions and perform operations. After C_Finalize(), all sessions are closed
// and keys are wiped.
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
CK_RV C_Finalize(CK_VOID_PTR pReserved);

// WHY C_GetInfo / C_GetSlotList / C_GetSlotInfo / C_GetTokenInfo: Discovery
// methods. Applications query the library (C_GetInfo: library name, version),
// slots (C_GetSlotList: which slots have tokens, C_GetSlotInfo: slot
// capabilities), and tokens (C_GetTokenInfo: token label, model, serial). This
// is metadata; callers don't perform crypto here.
CK_RV C_GetInfo(CK_INFO_PTR pInfo);
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount);
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);

// WHY C_GetMechanismList / C_GetMechanismInfo: Advertise capabilities.
// Applications query what mechanisms (signing algorithms, encryption modes) are
// supported. vHSM advertises RSA-PKCS, ECDSA, AES-GCM, etc. This lets
// applications adapt (e.g., fall back if AES-GCM not supported).
CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                         CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount);
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo);

// WHY C_InitToken / C_InitPIN / C_SetPIN: Admin operations. C_InitToken
// initializes a token (set SO PIN). C_InitPIN initializes the user PIN (must be
// SO). C_SetPIN changes PIN (logged-in user). These are rare; most deployments
// pre-initialize tokens. But the standard requires them.
CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                  CK_UTF8CHAR_PTR pLabel);
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                CK_ULONG ulPinLen);
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
               CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

// WHY C_OpenSession / C_CloseSession / C_CloseAllSessions: Session lifecycle.
// A session is a connection to a token. Multiple sessions can be open on the
// same token (for concurrent operations, or different login states).
// CloseAllSessions tears down all sessions on a slot (rare; usually
// applications close individual sessions).
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);

// WHY C_GetSessionInfo: Query session state (logged-in user, flags, etc.).
// Applications need to know if they're logged in, read-only or read-write, etc.
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);

// WHY C_GetOperationState / C_SetOperationState: Save/restore operation state
// (rarely used). Not implemented in vHSM; provided for compliance.
CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG_PTR pulOperationStateLen);
CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG ulOperationStateLen,
                          CK_OBJECT_HANDLE hEncryptionKey,
                          CK_OBJECT_HANDLE hAuthenticationKey);

// WHY C_Login / C_Logout: Authentication. C_Login verifies the PIN (user or
// SO). Successful login changes session state (now in "user" or "SO" functions
// state). C_Logout returns to public session state. Some operations require
// login (e.g., key generation with SO).
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV C_Logout(CK_SESSION_HANDLE hSession);

// WHY object management
// (Create/Copy/Destroy/GetSize/GetAttributeValue/SetAttributeValue): Objects
// are keys, certificates, and data. Applications create them (C_CreateObject),
// copy them (C_CopyObject), delete them (C_DestroyObject), query size
// (C_GetObjectSize), and get/set attributes
// (C_GetAttributeValue/C_SetAttributeValue).
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

// WHY C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal: Search for
// objects. Find is a three-step process: init (set criteria), fetch (get
// matches), final (cleanup). This allows incremental retrieval (don't load all
// objects at once).
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount);
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);

// WHY encrypt/decrypt operations: Not implemented in vHSM (signing-focused
// HSM). Provided for PKCS#11 compliance, but return CKR_FUNCTION_NOT_SUPPORTED.
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
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                      CK_ULONG_PTR pulPartLen);
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                     CK_ULONG_PTR pulLastPartLen);

// WHY digest operations: Hashing (not implemented in vHSM; return
// CKR_FUNCTION_NOT_SUPPORTED).
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
               CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
               CK_ULONG_PTR pulDigestLen);
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen);
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                    CK_ULONG_PTR pulDigestLen);

// WHY C_SignInit / C_Sign / C_SignUpdate / C_SignFinal: Core signing
// operations. C_SignInit selects the key and mechanism. C_Sign performs
// single-part signing (all data at once). C_SignUpdate/C_SignFinal perform
// multi-part signing (accumulate data, then finalize). This is the main entry
// point for applications; all vHSM signing flows through here.
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hKey);
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                   CK_ULONG ulPartLen);
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                  CK_ULONG_PTR pulSignatureLen);

// WHY C_SignRecoverInit / C_SignRecover: RSA signature recovery (rarely used,
// not implemented).
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                    CK_ULONG_PTR pulSignatureLen);

// WHY C_VerifyInit / C_Verify / C_VerifyUpdate / C_VerifyFinal: Signature
// verification. Similar to signing, but with a public key. Verify returns
// CKR_OK (valid) or CKR_SIGNATURE_INVALID (invalid).
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hKey);
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
               CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
               CK_ULONG ulSignatureLen);
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen);
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                    CK_ULONG ulSignatureLen);

// WHY C_VerifyRecoverInit / C_VerifyRecover: RSA signature recovery (rarely
// used, not implemented).
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                      CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                      CK_ULONG_PTR pulDataLen);

// WHY combined operations (DigestEncrypt, DecryptDigest, SignEncrypt,
// DecryptVerify): Rarely used. Not implemented in vHSM; provided for
// compliance.
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                            CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG_PTR pulEncryptedPartLen);
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                            CK_ULONG_PTR pulPartLen);
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                          CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                          CK_ULONG_PTR pulEncryptedPartLen);
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                            CK_ULONG_PTR pulPartLen);

// WHY C_GenerateKey / C_GenerateKeyPair: Generate keys. C_GenerateKey generates
// symmetric keys (AES, etc.). C_GenerateKeyPair generates asymmetric keys (RSA,
// EC). vHSM supports both.
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
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession);
CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession);
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
                         CK_VOID_PTR pReserved);

#ifdef __cplusplus
}
#endif

#endif // VHSM_PKCS11_H