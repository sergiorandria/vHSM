#ifndef VHSM_PKCS11_TYPES_H
#define VHSM_PKCS11_TYPES_H

/*
 * pkcs11_types.h
 *
 * The public PKCS#11 (v3.0) ABI surface used by the vHSM PKCS#11 module.
 *
 * The scalar base types (CK_ULONG, CK_BYTE, ...) and a first batch of
 * constants are shared with the rest of the project via "../core/types.h".
 * Everything the PKCS#11 ABI still needs on top of that is defined here:
 * the CK_* structures, the remaining constants and the CK_FUNCTION_LIST
 * function pointer table.
 *
 * Attribute/object-class/key-type constants deliberately use C++ inline
 * constexpr variables in the global namespace instead of preprocessor
 * macros: the keystore layer already exposes identically-named constexpr
 * constants inside namespace vhsm::keystore, and macros with the same name
 * would corrupt those declarations when both headers are included by the
 * same translation unit.
 *
 * This header is C++-only (it builds on "../core/types.h"), matching the
 * rest of the project. The exported C symbol entry points live in the
 * function_list.cpp translation unit and are declared `extern "C"` there.
 */

#include "../core/types.h"

#include <cstddef>

// ---------------------------------------------------------------------------
// Miscellaneous standard values
// ---------------------------------------------------------------------------
#define CK_UNAVAILABLE_INFORMATION       (~(CK_ULONG)0)
#define CK_EFFECTIVELY_INFINITE          0UL

inline constexpr CK_ULONG CK_INVALID_HANDLE = 0UL;

// ---------------------------------------------------------------------------
// CK_C_INITIALIZE_ARGS
// ---------------------------------------------------------------------------
typedef struct CK_C_INITIALIZE_ARGS {
    CK_VOID_PTR CreateMutex;
    CK_VOID_PTR DestroyMutex;
    CK_VOID_PTR LockMutex;
    CK_VOID_PTR UnlockMutex;
    CK_FLAGS flags;
    CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;

typedef CK_C_INITIALIZE_ARGS *CK_C_INITIALIZE_ARGS_PTR;

#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001UL
#define CKF_OS_LOCKING_OK                   0x00000002UL

// ---------------------------------------------------------------------------
// CK_VERSION / CK_INFO / CK_SLOT_INFO / CK_TOKEN_INFO
// ---------------------------------------------------------------------------
typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef CK_VERSION *CK_VERSION_PTR;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

typedef CK_INFO *CK_INFO_PTR;

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef CK_SLOT_INFO *CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_CHAR serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_CHAR utcTime[16];
} CK_TOKEN_INFO;

typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;

// Token flags
#define CKF_RNG                          0x00000001UL
#define CKF_WRITE_PROTECTED              0x00000002UL
#define CKF_LOGIN_REQUIRED               0x00000004UL
#define CKF_USER_PIN_INITIALIZED         0x00000008UL
#define CKF_RESTORE_KEY_NOT_NEEDED       0x00000020UL
#define CKF_CLOCK_ON_TOKEN               0x00000040UL
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100UL
#define CKF_DUAL_CRYPTO_OPERATIONS       0x00000200UL
#define CKF_TOKEN_INITIALIZED            0x00000400UL
#define CKF_SECONDARY_AUTHENTICATION     0x00000800UL
#define CKF_USER_PIN_COUNT_LOW           0x00010000UL
#define CKF_USER_PIN_FINAL_TRY           0x00020000UL
#define CKF_USER_PIN_LOCKED              0x00040000UL
#define CKF_USER_PIN_TO_BE_CHANGED       0x00080000UL
#define CKF_SO_PIN_COUNT_LOW             0x00100000UL
#define CKF_SO_PIN_FINAL_TRY             0x00200000UL
#define CKF_SO_PIN_LOCKED                0x00400000UL
#define CKF_SO_PIN_TO_BE_CHANGED         0x00800000UL
#define CKF_ERROR_STATE                  0x01000000UL

// ---------------------------------------------------------------------------
// CK_MECHANISM / CK_MECHANISM_INFO
// ---------------------------------------------------------------------------
typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef CK_MECHANISM *CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;

typedef CK_MECHANISM_INFO *CK_MECHANISM_INFO_PTR;

// Mechanism capability flags
#define CKF_ENCRYPT             0x00000100UL
#define CKF_DECRYPT             0x00000200UL
#define CKF_DIGEST              0x00000400UL
#define CKF_SIGN                0x00000800UL
#define CKF_SIGN_RECOVER        0x00001000UL
#define CKF_VERIFY              0x00002000UL
#define CKF_VERIFY_RECOVER      0x00004000UL
#define CKF_GENERATE            0x00008000UL
#define CKF_GENERATE_KEY_PAIR   0x00010000UL
#define CKF_WRAP                0x00020000UL
#define CKF_UNWRAP              0x00040000UL
#define CKF_DERIVE              0x00080000UL
#define CKF_EC_F_P              0x00100000UL
#define CKF_EC_F_2M             0x00200000UL
#define CKF_EC_ECPARAMETERS     0x00400000UL
#define CKF_EC_NAMEDCURVE       0x00800000UL
#define CKF_EC_UNCOMPRESS       0x01000000UL
#define CKF_EC_COMPRESS         0x02000000UL
#define CKF_EXTENSION           0x80000000UL

#define CKF_DONT_BLOCK          0x00000001UL

// ---------------------------------------------------------------------------
// Object classes (globally-scoped inline constexpr, not macros — see header
// comment).
// ---------------------------------------------------------------------------
inline constexpr CK_ULONG CKO_DATA             = 0x00000000UL;
inline constexpr CK_ULONG CKO_CERTIFICATE      = 0x00000001UL;
inline constexpr CK_ULONG CKO_PUBLIC_KEY       = 0x00000002UL;
inline constexpr CK_ULONG CKO_PRIVATE_KEY      = 0x00000003UL;
inline constexpr CK_ULONG CKO_SECRET_KEY       = 0x00000004UL;
inline constexpr CK_ULONG CKO_HW_FEATURE       = 0x00000005UL;
inline constexpr CK_ULONG CKO_DOMAIN_PARAMETERS = 0x00000006UL;
inline constexpr CK_ULONG CKO_MECHANISM        = 0x00000007UL;
inline constexpr CK_ULONG CKO_OTP_KEY          = 0x00000008UL;
inline constexpr CK_ULONG CKO_VENDOR_DEFINED   = 0x80000000UL;

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------
inline constexpr CK_ULONG CKK_RSA              = 0x00000000UL;
inline constexpr CK_ULONG CKK_DSA              = 0x00000001UL;
inline constexpr CK_ULONG CKK_DH               = 0x00000002UL;
inline constexpr CK_ULONG CKK_EC               = 0x00000003UL;
inline constexpr CK_ULONG CKK_X9_42_DH         = 0x00000004UL;
inline constexpr CK_ULONG CKK_KEA              = 0x00000005UL;
inline constexpr CK_ULONG CKK_GENERIC_SECRET   = 0x00000010UL;
inline constexpr CK_ULONG CKK_RC4              = 0x00000012UL;
inline constexpr CK_ULONG CKK_DES              = 0x00000013UL;
inline constexpr CK_ULONG CKK_DES2             = 0x00000014UL;
inline constexpr CK_ULONG CKK_DES3             = 0x00000015UL;
inline constexpr CK_ULONG CKK_CAST128          = 0x00000018UL;
inline constexpr CK_ULONG CKK_RC5              = 0x00000019UL;
inline constexpr CK_ULONG CKK_AES              = 0x0000001FUL;
inline constexpr CK_ULONG CKK_BLOWFISH         = 0x00000020UL;
inline constexpr CK_ULONG CKK_TWOFISH          = 0x00000021UL;
inline constexpr CK_ULONG CKK_SHA_1_HMAC       = 0x00000028UL;
inline constexpr CK_ULONG CKK_SHA256_HMAC      = 0x0000002BUL;
inline constexpr CK_ULONG CKK_SHA384_HMAC      = 0x0000002CUL;
inline constexpr CK_ULONG CKK_SHA512_HMAC      = 0x0000002DUL;
inline constexpr CK_ULONG CKK_EC_EDWARDS       = 0x00000040UL;
inline constexpr CK_ULONG CKK_EC_MONTGOMERY    = 0x00000041UL;
inline constexpr CK_ULONG CKK_VENDOR_DEFINED   = 0x80000000UL;

// ---------------------------------------------------------------------------
// Attribute types
// ---------------------------------------------------------------------------
inline constexpr CK_ULONG CKA_CLASS            = 0x00000000UL;
inline constexpr CK_ULONG CKA_TOKEN            = 0x00000001UL;
inline constexpr CK_ULONG CKA_PRIVATE          = 0x00000002UL;
inline constexpr CK_ULONG CKA_LABEL            = 0x00000003UL;
inline constexpr CK_ULONG CKA_APPLICATION      = 0x00000010UL;
inline constexpr CK_ULONG CKA_VALUE            = 0x00000011UL;
inline constexpr CK_ULONG CKA_OBJECT_ID        = 0x00000012UL;
inline constexpr CK_ULONG CKA_CERTIFICATE_TYPE = 0x00000080UL;
inline constexpr CK_ULONG CKA_ISSUER           = 0x00000081UL;
inline constexpr CK_ULONG CKA_SERIAL_NUMBER    = 0x00000082UL;
inline constexpr CK_ULONG CKA_ATTR_TYPES       = 0x00000085UL;
inline constexpr CK_ULONG CKA_TRUSTED          = 0x00000086UL;
inline constexpr CK_ULONG CKA_URL              = 0x00000089UL;
inline constexpr CK_ULONG CKA_CHECK_VALUE      = 0x00000090UL;
inline constexpr CK_ULONG CKA_KEY_TYPE         = 0x00000100UL;
inline constexpr CK_ULONG CKA_SUBJECT          = 0x00000101UL;
inline constexpr CK_ULONG CKA_ID               = 0x00000102UL;
inline constexpr CK_ULONG CKA_SENSITIVE        = 0x00000103UL;
inline constexpr CK_ULONG CKA_ENCRYPT          = 0x00000104UL;
inline constexpr CK_ULONG CKA_DECRYPT          = 0x00000105UL;
inline constexpr CK_ULONG CKA_WRAP             = 0x00000106UL;
inline constexpr CK_ULONG CKA_UNWRAP           = 0x00000107UL;
inline constexpr CK_ULONG CKA_SIGN             = 0x00000108UL;
inline constexpr CK_ULONG CKA_SIGN_RECOVER     = 0x00000109UL;
inline constexpr CK_ULONG CKA_VERIFY           = 0x0000010AUL;
inline constexpr CK_ULONG CKA_VERIFY_RECOVER   = 0x0000010BUL;
inline constexpr CK_ULONG CKA_DERIVE           = 0x0000010CUL;
inline constexpr CK_ULONG CKA_START_DATE       = 0x00000110UL;
inline constexpr CK_ULONG CKA_END_DATE         = 0x00000111UL;
inline constexpr CK_ULONG CKA_MODULUS          = 0x00000120UL;
inline constexpr CK_ULONG CKA_MODULUS_BITS     = 0x00000121UL;
inline constexpr CK_ULONG CKA_PUBLIC_EXPONENT  = 0x00000122UL;
inline constexpr CK_ULONG CKA_PRIVATE_EXPONENT = 0x00000123UL;
inline constexpr CK_ULONG CKA_PRIME_1          = 0x00000124UL;
inline constexpr CK_ULONG CKA_PRIME_2          = 0x00000125UL;
inline constexpr CK_ULONG CKA_EXPONENT_1       = 0x00000126UL;
inline constexpr CK_ULONG CKA_EXPONENT_2       = 0x00000127UL;
inline constexpr CK_ULONG CKA_COEFFICIENT      = 0x00000128UL;
inline constexpr CK_ULONG CKA_PUBLIC_KEY_INFO  = 0x00000129UL;
inline constexpr CK_ULONG CKA_PRIME            = 0x00000130UL;
inline constexpr CK_ULONG CKA_SUBPRIME         = 0x00000131UL;
inline constexpr CK_ULONG CKA_BASE             = 0x00000132UL;
inline constexpr CK_ULONG CKA_PRIME_BITS       = 0x00000133UL;
inline constexpr CK_ULONG CKA_SUBPRIME_BITS    = 0x00000134UL;
inline constexpr CK_ULONG CKA_VALUE_BITS       = 0x00000160UL;
inline constexpr CK_ULONG CKA_VALUE_LEN        = 0x00000161UL;
inline constexpr CK_ULONG CKA_EXTRACTABLE      = 0x00000162UL;
inline constexpr CK_ULONG CKA_LOCAL            = 0x00000163UL;
inline constexpr CK_ULONG CKA_NEVER_EXTRACTABLE = 0x00000164UL;
inline constexpr CK_ULONG CKA_ALWAYS_SENSITIVE = 0x00000165UL;
inline constexpr CK_ULONG CKA_KEY_GEN_MECHANISM = 0x00000166UL;
inline constexpr CK_ULONG CKA_MODIFIABLE       = 0x00000170UL;
inline constexpr CK_ULONG CKA_COPYABLE         = 0x00000171UL;
inline constexpr CK_ULONG CKA_DESTROYABLE      = 0x00000172UL;
inline constexpr CK_ULONG CKA_EC_PARAMS        = 0x00000180UL;
inline constexpr CK_ULONG CKA_EC_POINT         = 0x00000181UL;
inline constexpr CK_ULONG CKA_ALWAYS_AUTHENTICATE = 0x00000202UL;
inline constexpr CK_ULONG CKA_WRAP_WITH_TRUSTED = 0x00000210UL;
inline constexpr CK_ULONG CKA_ALLOWED_MECHANISMS = 0x00000600UL;
inline constexpr CK_ULONG CKA_VENDOR_DEFINED   = 0x80000000UL;

// ---------------------------------------------------------------------------
// Remaining return codes
// ---------------------------------------------------------------------------
#define CKR_CRYPTOKI_NOT_INITIALIZED     ((CK_RV) 0x000000D0UL)
#define CKR_CRYPTOKI_ALREADY_INITIALIZED ((CK_RV) 0x000000D1UL)
#define CKR_FUNCTION_NOT_PARALLEL        ((CK_RV) 0x000000D2UL)
#define CKR_FUNCTION_NOT_SUPPORTED       ((CK_RV) 0x00000054UL)
#define CKR_SIGNATURE_INVALID            ((CK_RV) 0x00000056UL)
#define CKR_SIGNATURE_LEN_RANGE          ((CK_RV) 0x00000057UL)
#define CKR_GENERATE_KEY_RANDOM          ((CK_RV) 0x00000058UL)
#define CKR_GENERATE_KEY_PAIR_RANDOM     ((CK_RV) 0x00000059UL)
#define CKR_KEY_SIZE_RANGE               ((CK_RV) 0x000000A1UL)
#define CKR_KEY_TYPE_RANGE               ((CK_RV) 0x000000A3UL)

// ---------------------------------------------------------------------------
// PKCS#11 v3.0 mechanism types (additional to the subset in core/types.h)
// ---------------------------------------------------------------------------
#define CKM_RSA_PKCS_KEY_PAIR_GEN  0x00000000UL
#define CKM_RSA_PKCS               0x00000001UL
#define CKM_RSA_X_509              0x00000003UL
#define CKM_RSA_PKCS_PSS           0x0000000DUL
#define CKM_RSA_PKCS_OAEP          0x00000009UL
#define CKM_SHA1_RSA_PKCS          0x00000042UL
#define CKM_RSA_PKCS_OAEP_SHA256   0x00000088UL
#define CKM_RSA_PKCS_OAEP_SHA384   0x00000089UL
#define CKM_RSA_PKCS_OAEP_SHA512   0x0000008AUL
#define CKM_SHA1_RSA_PKCS_PSS      0x0000000EUL
#define CKM_SHA256_RSA_PKCS_PSS    0x0000000FUL
#define CKM_SHA384_RSA_PKCS_PSS    0x00000010UL
#define CKM_SHA512_RSA_PKCS_PSS    0x00000011UL

#define CKM_ECDSA_PKCS             0x00000040UL
#define CKM_ECDSA                  0x00000041UL
#define CKM_ECDSA_KEY_PAIR_GEN     0x00000040UL
#define CKM_ECDSA_SHA1             0x00000042UL
#define CKM_ECDSA_SHA256           0x00001043UL
#define CKM_ECDSA_SHA384           0x00001044UL
#define CKM_ECDSA_SHA512           0x00001045UL

#define CKM_EC_KEY_PAIR_GEN        0x00001040UL

#define CKM_SHA_1                  0x00000220UL
#define CKM_SHA_224                0x00000225UL
#define CKM_SHA_256                0x00000250UL
#define CKM_SHA_384                0x00000260UL
#define CKM_SHA_512                0x00000270UL

#define CKM_AES_KEY_WRAP           0x00002109UL

// ---------------------------------------------------------------------------
// CK_GCM_PARAMS (used by CKM_AES_GCM)
// ---------------------------------------------------------------------------
typedef struct CK_GCM_PARAMS {
    CK_BYTE_PTR pIv;
    CK_ULONG ulIvLen;
    CK_ULONG ulIvBits;
    CK_BYTE_PTR pAAD;
    CK_ULONG ulAADLen;
    CK_ULONG ulTagBits;
} CK_GCM_PARAMS;

typedef CK_GCM_PARAMS *CK_GCM_PARAMS_PTR;

// ---------------------------------------------------------------------------
// C/C++ POD pointer aliases
// ---------------------------------------------------------------------------
typedef CK_SLOT_ID *CK_SLOT_ID_PTR;
typedef CK_MECHANISM_TYPE *CK_MECHANISM_TYPE_PTR;
typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;

// ---------------------------------------------------------------------------
// CK_FUNCTION_LIST: function pointer table
// (the struct type itself is defined after the per-function typedefs)
// ---------------------------------------------------------------------------
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;

typedef CK_RV (*CK_C_Initialize)(CK_VOID_PTR pInitArgs);
typedef CK_RV (*CK_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV (*CK_C_GetInfo)(CK_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV (*CK_C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV (*CK_C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
typedef CK_RV (*CK_C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*CK_C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
typedef CK_RV (*CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (*CK_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CloseAllSessions)(CK_SLOT_ID slotID);
typedef CK_RV (*CK_C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV (*CK_C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV (*CK_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*CK_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV (*CK_C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (*CK_C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV (*CK_C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
typedef CK_RV (*CK_C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*CK_C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
typedef CK_RV (*CK_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
typedef CK_RV (*CK_C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (*CK_C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
typedef CK_RV (*CK_C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
typedef CK_RV (*CK_C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*CK_C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*CK_C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*CK_C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*CK_C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (*CK_C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef CK_RV (*CK_C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
typedef CK_RV (*CK_C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
typedef CK_RV (*CK_C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
typedef CK_RV (*CK_C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CancelFunction)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_C_Initialize C_Initialize;
    CK_C_Finalize C_Finalize;
    CK_C_GetInfo C_GetInfo;
    CK_C_GetFunctionList C_GetFunctionList;
    CK_C_GetSlotList C_GetSlotList;
    CK_C_GetSlotInfo C_GetSlotInfo;
    CK_C_GetTokenInfo C_GetTokenInfo;
    CK_C_GetMechanismList C_GetMechanismList;
    CK_C_GetMechanismInfo C_GetMechanismInfo;
    CK_C_InitToken C_InitToken;
    CK_C_InitPIN C_InitPIN;
    CK_C_SetPIN C_SetPIN;
    CK_C_OpenSession C_OpenSession;
    CK_C_CloseSession C_CloseSession;
    CK_C_CloseAllSessions C_CloseAllSessions;
    CK_C_GetSessionInfo C_GetSessionInfo;
    CK_C_GetOperationState C_GetOperationState;
    CK_C_SetOperationState C_SetOperationState;
    CK_C_Login C_Login;
    CK_C_Logout C_Logout;
    CK_C_CreateObject C_CreateObject;
    CK_C_CopyObject C_CopyObject;
    CK_C_DestroyObject C_DestroyObject;
    CK_C_GetObjectSize C_GetObjectSize;
    CK_C_GetAttributeValue C_GetAttributeValue;
    CK_C_SetAttributeValue C_SetAttributeValue;
    CK_C_FindObjectsInit C_FindObjectsInit;
    CK_C_FindObjects C_FindObjects;
    CK_C_FindObjectsFinal C_FindObjectsFinal;
    CK_C_EncryptInit C_EncryptInit;
    CK_C_Encrypt C_Encrypt;
    CK_C_EncryptUpdate C_EncryptUpdate;
    CK_C_EncryptFinal C_EncryptFinal;
    CK_C_DecryptInit C_DecryptInit;
    CK_C_Decrypt C_Decrypt;
    CK_C_DecryptUpdate C_DecryptUpdate;
    CK_C_DecryptFinal C_DecryptFinal;
    CK_C_DigestInit C_DigestInit;
    CK_C_Digest C_Digest;
    CK_C_DigestUpdate C_DigestUpdate;
    CK_C_DigestKey C_DigestKey;
    CK_C_DigestFinal C_DigestFinal;
    CK_C_SignInit C_SignInit;
    CK_C_Sign C_Sign;
    CK_C_SignUpdate C_SignUpdate;
    CK_C_SignFinal C_SignFinal;
    CK_C_SignRecoverInit C_SignRecoverInit;
    CK_C_SignRecover C_SignRecover;
    CK_C_VerifyInit C_VerifyInit;
    CK_C_Verify C_Verify;
    CK_C_VerifyUpdate C_VerifyUpdate;
    CK_C_VerifyFinal C_VerifyFinal;
    CK_C_VerifyRecoverInit C_VerifyRecoverInit;
    CK_C_VerifyRecover C_VerifyRecover;
    CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
    CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
    CK_C_SignEncryptUpdate C_SignEncryptUpdate;
    CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
    CK_C_GenerateKey C_GenerateKey;
    CK_C_GenerateKeyPair C_GenerateKeyPair;
    CK_C_WrapKey C_WrapKey;
    CK_C_UnwrapKey C_UnwrapKey;
    CK_C_DeriveKey C_DeriveKey;
    CK_C_SeedRandom C_SeedRandom;
    CK_C_GenerateRandom C_GenerateRandom;
    CK_C_GetFunctionStatus C_GetFunctionStatus;
    CK_C_CancelFunction C_CancelFunction;
    CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};

#endif // VHSM_PKCS11_TYPES_H