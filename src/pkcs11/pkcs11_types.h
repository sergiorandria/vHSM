/*
 * pkcs11_types.h
 *
 * The public PKCS#11 (v3.0) ABI surface used by the vHSM PKCS#11 module.
 *
 * WHY this header exists: The PKCS#11 standard defines a C ABI (structs,
 * constants, function pointers). Applications link against this ABI, not the
 * implementation. This header declares all types, constants, and the function
 * pointer table (CK_FUNCTION_LIST). The implementation lives in
 * function_list.cpp (which exports C symbols) and p11_*.cpp files (which
 * implement each C function).
 *
 * WHY scalar types are in ../core/types.h: CK_ULONG, CK_BYTE, CK_UTF8CHAR, etc.
 * are base types used by multiple modules (core, keystore, crypto). Defining
 * them once (in core/types.h) avoids duplication and ensures consistency.
 *
 * WHY constants use inline constexpr (not macros): PKCS#11 traditionally uses
 * #define macros (e.g., #define CKO_PRIVATE_KEY 0x03). But macros pollute the
 * namespace and can't be scoped. vHSM uses inline constexpr variables in the
 * global namespace instead: inline constexpr CK_ULONG CKO_PRIVATE_KEY =
 * 0x00000003UL; This is cleaner (can be namespaced if needed) and the compiler
 * can optimize them away. However, we avoid C++ namespaces for CKO_/CKK_/CKA_
 * constants to match PKCS#11 conventions (other code may have
 * vhsm::keystore::CKO_PRIVATE_KEY, so we don't shadow them).
 *
 * WHY CK_FUNCTION_LIST is a struct of function pointers: PKCS#11 spec defines
 * this pattern. Applications get a pointer to CK_FUNCTION_LIST, then call
 * functions through it: CK_FUNCTION_LIST_PTR pFL; C_GetFunctionList(&pFL);
 *   pFL->C_Sign(...);  // Call through the pointer
 * This allows the library to export multiple implementations (e.g., FIPS and
 * non-FIPS).
 *
 * The scalar base types (CK_ULONG, CK_BYTE, ...) and a first batch of
 * constants are shared with the rest of the project via "../core/types.h".
 * Everything the PKCS#11 ABI still needs on top of that is defined here:
 * the CK_* structures, the remaining constants and the CK_FUNCTION_LIST
 * function pointer table.
 *
 * This header is C++-only (it builds on "../core/types.h"), matching the
 * rest of the project. The exported C symbol entry points live in the
 * function_list.cpp translation unit and are declared `extern "C"` there.
 */

#ifndef VHSM_PKCS11_TYPES_H
#define VHSM_PKCS11_TYPES_H

#include "../core/types.h"

#include <cstddef>

// ---------------------------------------------------------------------------
// Miscellaneous standard values
// ---------------------------------------------------------------------------
// WHY CK_UNAVAILABLE_INFORMATION: PKCS#11 uses this special value (~0UL) to
// indicate "information not available" (e.g., ulFreePublicMemory when not
// supported). Defined as a macro for C compatibility; also used as a
// placeholder in token info.
#define CK_UNAVAILABLE_INFORMATION (~(CK_ULONG)0)

// WHY CK_EFFECTIVELY_INFINITE: Represents unlimited capacity (e.g., max session
// count). Set to 0UL by convention; callers interpret 0 as "unlimited".
#define CK_EFFECTIVELY_INFINITE 0UL

// WHY CK_INVALID_HANDLE: All PKCS#11 handles (slot, session, object) use
// CK_ULONG. 0 is reserved to mean "invalid" (CK_INVALID_HANDLE). Valid handles
// are >0.
inline constexpr CK_ULONG CK_INVALID_HANDLE = 0UL;

// ---------------------------------------------------------------------------
// CK_C_INITIALIZE_ARGS
// ---------------------------------------------------------------------------
// WHY CK_C_INITIALIZE_ARGS: Passed to C_Initialize to configure the library.
// Includes function pointers for mutex operations (if the application wants to
// provide threading support). vHSM uses the OS mutexes (pthread); the C++ layer
// handles locking. Most applications pass NULL for pInitArgs (use library
// defaults).
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
#define CKF_OS_LOCKING_OK 0x00000002UL

// ---------------------------------------------------------------------------
// CK_VERSION / CK_INFO / CK_SLOT_INFO / CK_TOKEN_INFO
// ---------------------------------------------------------------------------
// WHY CK_VERSION: Major.minor version pair (e.g., 3.0 for PKCS#11 v3.0).
// Used in CK_INFO (library version), CK_SLOT_INFO (hardware/firmware version),
// and CK_TOKEN_INFO. Each field is a single byte.
typedef struct CK_VERSION {
  CK_BYTE major;
  CK_BYTE minor;
} CK_VERSION;

typedef CK_VERSION *CK_VERSION_PTR;

// WHY CK_INFO: Library metadata. Returned by C_GetInfo. Includes PKCS#11
// version (cryptokiVersion), library name (manufacturerID), description, and
// library version. Applications use this to verify compatibility before using
// the library.
typedef struct CK_INFO {
  CK_VERSION cryptokiVersion;
  CK_UTF8CHAR manufacturerID[32];
  CK_FLAGS flags;
  CK_UTF8CHAR libraryDescription[32];
  CK_VERSION libraryVersion;
} CK_INFO;

typedef CK_INFO *CK_INFO_PTR;

// WHY CK_SLOT_INFO: Slot metadata. Returned by C_GetSlotInfo. A slot is a
// logical card reader. vHSM presents one slot (slotID=0). Applications query
// slot info to check if a token is present, hardware version, firmware version,
// etc.
typedef struct CK_SLOT_INFO {
  CK_UTF8CHAR slotDescription[64];
  CK_UTF8CHAR manufacturerID[32];
  CK_FLAGS flags;
  CK_VERSION hardwareVersion;
  CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef CK_SLOT_INFO *CK_SLOT_INFO_PTR;

// WHY CK_TOKEN_INFO: Token (card) metadata. Returned by C_GetTokenInfo.
// Includes token label, manufacturer, model, serial, flags (logged-in state,
// PIN locked, etc.), memory statistics, hardware/firmware version, and UTC time
// (if clock is on token). Applications use this to determine token capabilities
// and state.
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

// WHY token flags (CKF_RNG, CKF_LOGIN_REQUIRED, etc.): Communicate capabilities
// and state. CKF_LOGIN_REQUIRED means a PIN is needed. CKF_USER_PIN_INITIALIZED
// means the user PIN has been set. CKF_USER_PIN_LOCKED means PIN is locked
// (too many failed attempts). Applications use these to adapt (e.g., prompt for
// PIN if CKF_LOGIN_REQUIRED and not yet logged in).

// Token flags
#define CKF_RNG 0x00000001UL
#define CKF_WRITE_PROTECTED 0x00000002UL
#define CKF_LOGIN_REQUIRED 0x00000004UL
#define CKF_USER_PIN_INITIALIZED 0x00000008UL
#define CKF_RESTORE_KEY_NOT_NEEDED 0x00000020UL
#define CKF_CLOCK_ON_TOKEN 0x00000040UL
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100UL
#define CKF_DUAL_CRYPTO_OPERATIONS 0x00000200UL
#define CKF_TOKEN_INITIALIZED 0x00000400UL
#define CKF_SECONDARY_AUTHENTICATION 0x00000800UL
#define CKF_USER_PIN_COUNT_LOW 0x00010000UL
#define CKF_USER_PIN_FINAL_TRY 0x00020000UL
#define CKF_USER_PIN_LOCKED 0x00040000UL
#define CKF_USER_PIN_TO_BE_CHANGED 0x00080000UL
#define CKF_SO_PIN_COUNT_LOW 0x00100000UL
#define CKF_SO_PIN_FINAL_TRY 0x00200000UL
#define CKF_SO_PIN_LOCKED 0x00400000UL
#define CKF_SO_PIN_TO_BE_CHANGED 0x00800000UL
#define CKF_ERROR_STATE 0x01000000UL
// WHY CKF_SO_PIN_INITIALIZED: vHSM-specific token flag indicating the SO PIN
// has been initialized (similar to CKF_USER_PIN_INITIALIZED but for the SO).
#define CKF_SO_PIN_INITIALIZED 0x02000000UL

// ---------------------------------------------------------------------------
// CK_MECHANISM / CK_MECHANISM_INFO
// ---------------------------------------------------------------------------
// WHY CK_MECHANISM: Specifies an algorithm and optional parameters for an
// operation. mechanism: the algorithm (e.g., CKM_SHA256_RSA_PKCS for RSA-SHA256
// signing). pParameter: optional algorithm-specific parameters (e.g., RSA-PSS
// salt, AES-GCM IV). ulParameterLen: length of pParameter (0 if no parameters).
typedef struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR pParameter;
  CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef CK_MECHANISM *CK_MECHANISM_PTR;

// WHY CK_MECHANISM_INFO: Capabilities of a mechanism. Returned by
// C_GetMechanismInfo. ulMinKeySize, ulMaxKeySize: valid key size range (e.g.,
// RSA: 512-4096 bits). flags: what operations are supported (CKF_SIGN,
// CKF_VERIFY, CKF_ENCRYPT, etc.).
typedef struct CK_MECHANISM_INFO {
  CK_ULONG ulMinKeySize;
  CK_ULONG ulMaxKeySize;
  CK_FLAGS flags;
} CK_MECHANISM_INFO;

typedef CK_MECHANISM_INFO *CK_MECHANISM_INFO_PTR;

// WHY mechanism capability flags (CKF_ENCRYPT, CKF_SIGN, etc.): Applications
// query mechanism info to check if a capability is supported. For example, if
// an application needs CKM_SHA256_RSA_PKCS for signing but the library doesn't
// support it, it can try an alternative (e.g., CKM_SHA512_RSA_PKCS).

// Mechanism capability flags
#define CKF_HW 0x00000001UL
#define CKF_ENCRYPT 0x00000100UL
#define CKF_DECRYPT 0x00000200UL
#define CKF_DIGEST 0x00000400UL
#define CKF_SIGN 0x00000800UL
#define CKF_SIGN_RECOVER 0x00001000UL
#define CKF_VERIFY 0x00002000UL
#define CKF_VERIFY_RECOVER 0x00004000UL
#define CKF_GENERATE 0x00008000UL
#define CKF_GENERATE_KEY_PAIR 0x00010000UL
#define CKF_WRAP 0x00020000UL
#define CKF_UNWRAP 0x00040000UL
#define CKF_DERIVE 0x00080000UL
#define CKF_EC_F_P 0x00100000UL
#define CKF_EC_F_2M 0x00200000UL
#define CKF_EC_ECPARAMETERS 0x00400000UL
#define CKF_EC_NAMEDCURVE 0x00800000UL
#define CKF_EC_UNCOMPRESS 0x01000000UL
#define CKF_EC_COMPRESS 0x02000000UL
#define CKF_EXTENSION 0x80000000UL

#define CKF_DONT_BLOCK 0x00000001UL

// WHY CKF_ARRAY_ATTRIBUTE: Flag bit on attribute types indicating the attribute
// contains an array of values (not a single value). Used to skip array-type
// attributes during certain operations where they're not meaningful.
#define CKF_ARRAY_ATTRIBUTE 0x40000000UL

// ---------------------------------------------------------------------------
// Object classes (globally-scoped inline constexpr, not macros — see header
// comment).
// ---------------------------------------------------------------------------
// WHY object classes: PKCS#11 organizes objects by type. CKO_PRIVATE_KEY is a
// private key. CKO_PUBLIC_KEY is a public key. CKO_CERTIFICATE is a
// certificate. CKO_DATA is arbitrary data. The class determines which
// operations are valid (e.g., CKO_PRIVATE_KEY can be used to sign;
// CKO_PUBLIC_KEY can verify). vHSM supports PRIVATE_KEY, PUBLIC_KEY, and
// CERTIFICATE.
inline constexpr CK_ULONG CKO_DATA = 0x00000000UL;
inline constexpr CK_ULONG CKO_CERTIFICATE = 0x00000001UL;
inline constexpr CK_ULONG CKO_PUBLIC_KEY = 0x00000002UL;
inline constexpr CK_ULONG CKO_PRIVATE_KEY = 0x00000003UL;
inline constexpr CK_ULONG CKO_SECRET_KEY = 0x00000004UL;
inline constexpr CK_ULONG CKO_HW_FEATURE = 0x00000005UL;
inline constexpr CK_ULONG CKO_DOMAIN_PARAMETERS = 0x00000006UL;
inline constexpr CK_ULONG CKO_MECHANISM = 0x00000007UL;
inline constexpr CK_ULONG CKO_OTP_KEY = 0x00000008UL;
inline constexpr CK_ULONG CKO_VENDOR_DEFINED = 0x80000000UL;

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------
// WHY key types (CKK_RSA, CKK_EC, CKK_AES): Specify the algorithm of a key.
// CKK_RSA = RSA key. CKK_EC = Elliptic curve key. CKK_AES = AES symmetric key.
// vHSM supports RSA and EC for signing/verification, AES for (potential)
// encryption. The key type determines which operations are valid (e.g., RSA can
// sign with PKCS or PSS).
inline constexpr CK_ULONG CKK_RSA = 0x00000000UL;
inline constexpr CK_ULONG CKK_DSA = 0x00000001UL;
inline constexpr CK_ULONG CKK_DH = 0x00000002UL;
inline constexpr CK_ULONG CKK_EC = 0x00000003UL;
inline constexpr CK_ULONG CKK_X9_42_DH = 0x00000004UL;
inline constexpr CK_ULONG CKK_KEA = 0x00000005UL;
inline constexpr CK_ULONG CKK_GENERIC_SECRET = 0x00000010UL;
inline constexpr CK_ULONG CKK_RC4 = 0x00000012UL;
inline constexpr CK_ULONG CKK_DES = 0x00000013UL;
inline constexpr CK_ULONG CKK_DES2 = 0x00000014UL;
inline constexpr CK_ULONG CKK_DES3 = 0x00000015UL;
inline constexpr CK_ULONG CKK_CAST128 = 0x00000018UL;
inline constexpr CK_ULONG CKK_RC5 = 0x00000019UL;
inline constexpr CK_ULONG CKK_AES = 0x0000001FUL;
inline constexpr CK_ULONG CKK_BLOWFISH = 0x00000020UL;
inline constexpr CK_ULONG CKK_TWOFISH = 0x00000021UL;
inline constexpr CK_ULONG CKK_SHA_1_HMAC = 0x00000028UL;
inline constexpr CK_ULONG CKK_SHA256_HMAC = 0x0000002BUL;
inline constexpr CK_ULONG CKK_SHA384_HMAC = 0x0000002CUL;
inline constexpr CK_ULONG CKK_SHA512_HMAC = 0x0000002DUL;
inline constexpr CK_ULONG CKK_EC_EDWARDS = 0x00000040UL;
inline constexpr CK_ULONG CKK_EC_MONTGOMERY = 0x00000041UL;
inline constexpr CK_ULONG CKK_VENDOR_DEFINED = 0x80000000UL;

// ---------------------------------------------------------------------------
// Attribute types
// ---------------------------------------------------------------------------
// WHY attribute types (CKA_LABEL, CKA_ID, CKA_SIGN, etc.): Objects are
// described by attributes. CKA_LABEL is the human-readable name. CKA_ID is a
// unique identifier within a token. CKA_SIGN indicates if the key can be used
// for signing. CKA_PRIVATE indicates if the object is private (session or token
// private) or public. vHSM validates attributes on object creation
// (C_CreateObject) and supports querying them (C_GetAttributeValue).
inline constexpr CK_ULONG CKA_CLASS = 0x00000000UL;
inline constexpr CK_ULONG CKA_TOKEN = 0x00000001UL;
inline constexpr CK_ULONG CKA_PRIVATE = 0x00000002UL;
inline constexpr CK_ULONG CKA_LABEL = 0x00000003UL;
inline constexpr CK_ULONG CKA_APPLICATION = 0x00000010UL;
inline constexpr CK_ULONG CKA_VALUE = 0x00000011UL;
inline constexpr CK_ULONG CKA_OBJECT_ID = 0x00000012UL;
inline constexpr CK_ULONG CKA_CERTIFICATE_TYPE = 0x00000080UL;
inline constexpr CK_ULONG CKA_ISSUER = 0x00000081UL;
inline constexpr CK_ULONG CKA_SERIAL_NUMBER = 0x00000082UL;
inline constexpr CK_ULONG CKA_ATTR_TYPES = 0x00000085UL;
inline constexpr CK_ULONG CKA_TRUSTED = 0x00000086UL;
inline constexpr CK_ULONG CKA_URL = 0x00000089UL;
inline constexpr CK_ULONG CKA_CHECK_VALUE = 0x00000090UL;
inline constexpr CK_ULONG CKA_KEY_TYPE = 0x00000100UL;
inline constexpr CK_ULONG CKA_SUBJECT = 0x00000101UL;
inline constexpr CK_ULONG CKA_ID = 0x00000102UL;
inline constexpr CK_ULONG CKA_SENSITIVE = 0x00000103UL;
inline constexpr CK_ULONG CKA_ENCRYPT = 0x00000104UL;
inline constexpr CK_ULONG CKA_DECRYPT = 0x00000105UL;
inline constexpr CK_ULONG CKA_WRAP = 0x00000106UL;
inline constexpr CK_ULONG CKA_UNWRAP = 0x00000107UL;
inline constexpr CK_ULONG CKA_SIGN = 0x00000108UL;
inline constexpr CK_ULONG CKA_SIGN_RECOVER = 0x00000109UL;
inline constexpr CK_ULONG CKA_VERIFY = 0x0000010AUL;
inline constexpr CK_ULONG CKA_VERIFY_RECOVER = 0x0000010BUL;
inline constexpr CK_ULONG CKA_DERIVE = 0x0000010CUL;
inline constexpr CK_ULONG CKA_START_DATE = 0x00000110UL;
inline constexpr CK_ULONG CKA_END_DATE = 0x00000111UL;
inline constexpr CK_ULONG CKA_MODULUS = 0x00000120UL;
inline constexpr CK_ULONG CKA_MODULUS_BITS = 0x00000121UL;
inline constexpr CK_ULONG CKA_PUBLIC_EXPONENT = 0x00000122UL;
inline constexpr CK_ULONG CKA_PRIVATE_EXPONENT = 0x00000123UL;
inline constexpr CK_ULONG CKA_PRIME_1 = 0x00000124UL;
inline constexpr CK_ULONG CKA_PRIME_2 = 0x00000125UL;
inline constexpr CK_ULONG CKA_EXPONENT_1 = 0x00000126UL;
inline constexpr CK_ULONG CKA_EXPONENT_2 = 0x00000127UL;
inline constexpr CK_ULONG CKA_COEFFICIENT = 0x00000128UL;
inline constexpr CK_ULONG CKA_PUBLIC_KEY_INFO = 0x00000129UL;
inline constexpr CK_ULONG CKA_PRIME = 0x00000130UL;
inline constexpr CK_ULONG CKA_SUBPRIME = 0x00000131UL;
inline constexpr CK_ULONG CKA_BASE = 0x00000132UL;
inline constexpr CK_ULONG CKA_PRIME_BITS = 0x00000133UL;
inline constexpr CK_ULONG CKA_SUBPRIME_BITS = 0x00000134UL;
inline constexpr CK_ULONG CKA_VALUE_BITS = 0x00000160UL;
inline constexpr CK_ULONG CKA_VALUE_LEN = 0x00000161UL;
inline constexpr CK_ULONG CKA_EXTRACTABLE = 0x00000162UL;
inline constexpr CK_ULONG CKA_LOCAL = 0x00000163UL;
inline constexpr CK_ULONG CKA_NEVER_EXTRACTABLE = 0x00000164UL;
inline constexpr CK_ULONG CKA_ALWAYS_SENSITIVE = 0x00000165UL;
inline constexpr CK_ULONG CKA_KEY_GEN_MECHANISM = 0x00000166UL;
inline constexpr CK_ULONG CKA_MODIFIABLE = 0x00000170UL;
inline constexpr CK_ULONG CKA_COPYABLE = 0x00000171UL;
inline constexpr CK_ULONG CKA_DESTROYABLE = 0x00000172UL;
inline constexpr CK_ULONG CKA_EC_PARAMS = 0x00000180UL;
inline constexpr CK_ULONG CKA_EC_POINT = 0x00000181UL;
inline constexpr CK_ULONG CKA_ALWAYS_AUTHENTICATE = 0x00000202UL;
inline constexpr CK_ULONG CKA_WRAP_WITH_TRUSTED = 0x00000210UL;
inline constexpr CK_ULONG CKA_ALLOWED_MECHANISMS = 0x00000600UL;
inline constexpr CK_ULONG CKA_VENDOR_DEFINED = 0x80000000UL;

// ---------------------------------------------------------------------------
// Remaining return codes
// ---------------------------------------------------------------------------
// WHY error codes (CKR_*): Each C function returns a CK_RV (return value). The
// standard defines error codes like CKR_OK (success), CKR_ARGUMENTS_BAD
// (invalid args), CKR_SIGNATURE_INVALID (verify failed). The C++ implementation
// throws exceptions; the C wrapper converts exceptions to error codes before
// returning. This preserves the PKCS#11 error model for C applications.
#define CKR_CRYPTOKI_NOT_INITIALIZED ((CK_RV)0x000000D0UL)
#define CKR_CRYPTOKI_ALREADY_INITIALIZED ((CK_RV)0x000000D1UL)
#define CKR_FUNCTION_NOT_PARALLEL ((CK_RV)0x000000D2UL)
#define CKR_FUNCTION_NOT_SUPPORTED ((CK_RV)0x00000054UL)
#define CKR_SIGNATURE_INVALID ((CK_RV)0x00000056UL)
#define CKR_SIGNATURE_LEN_RANGE ((CK_RV)0x00000057UL)
#define CKR_GENERATE_KEY_RANDOM ((CK_RV)0x00000058UL)
#define CKR_GENERATE_KEY_PAIR_RANDOM ((CK_RV)0x00000059UL)
#define CKR_KEY_SIZE_RANGE ((CK_RV)0x000000A1UL)
#define CKR_KEY_TYPE_RANGE ((CK_RV)0x000000A3UL)
#define CKR_KEY_UNEXTRACTABLE ((CK_RV)0x00000130UL)
#define CKR_ACTION_PROHIBITED ((CK_RV)0x00000148UL)

// ---------------------------------------------------------------------------
// PKCS#11 v3.0 mechanism types (additional to the subset in core/types.h)
// ---------------------------------------------------------------------------
// WHY mechanism types (CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_ECDSA_SHA256,
// etc.): The mechanism tells the library what algorithm to use and how to
// process data. CKM_RSA_PKCS: RSA signature with PKCS#1 v1.5 padding
// (RSA-PKCS). CKM_SHA256_RSA_PKCS: RSA signature with SHA256 digest and PKCS#1
// v1.5 padding. CKM_RSA_PKCS_PSS: RSA-PSS padding (with configurable salt
// length). CKM_ECDSA_SHA256: ECDSA with SHA256. vHSM advertises these
// mechanisms; applications select which to use.
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000UL
#define CKM_RSA_PKCS 0x00000001UL
#define CKM_RSA_X_509 0x00000003UL
#define CKM_RSA_PKCS_PSS 0x0000000DUL
#define CKM_RSA_PKCS_OAEP 0x00000009UL
#define CKM_VENDOR_DEFINED 0x80000000UL
#define CKM_SHA1_RSA_PKCS 0x00000042UL
#define CKM_RSA_PKCS_OAEP_SHA256 0x00000088UL
#define CKM_RSA_PKCS_OAEP_SHA384 0x00000089UL
#define CKM_RSA_PKCS_OAEP_SHA512 0x0000008AUL
#define CKM_SHA1_RSA_PKCS_PSS 0x0000000EUL
#define CKM_SHA256_RSA_PKCS_PSS 0x0000000FUL
#define CKM_SHA384_RSA_PKCS_PSS 0x00000010UL
#define CKM_SHA512_RSA_PKCS_PSS 0x00000011UL

#define CKM_ECDSA_PKCS 0x00000040UL
#define CKM_ECDSA 0x00000041UL
#define CKM_ECDSA_KEY_PAIR_GEN 0x00000040UL
#define CKM_ECDSA_SHA1 0x00000042UL
#define CKM_ECDSA_SHA256 0x00001043UL
#define CKM_ECDSA_SHA384 0x00001044UL
#define CKM_ECDSA_SHA512 0x00001045UL

#define CKM_EC_KEY_PAIR_GEN 0x00001040UL

#define CKM_SHA_1 0x00000220UL
#define CKM_SHA_224 0x00000225UL
#define CKM_SHA_256 0x00000250UL
#define CKM_SHA_384 0x00000260UL
#define CKM_SHA_512 0x00000270UL

#define CKM_AES_KEY_WRAP 0x00002109UL
#define CKM_ECDH1_DERIVE 0x00000030UL

typedef CK_ULONG *CK_ULONG_PTR;
typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;
typedef CK_SLOT_ID *CK_SLOT_ID_PTR;
typedef CK_MECHANISM_TYPE *CK_MECHANISM_TYPE_PTR;
typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;

// ---------------------------------------------------------------------------
// CK_GCM_PARAMS (used by CKM_AES_GCM)
// ---------------------------------------------------------------------------
// WHY CK_GCM_PARAMS: AES-GCM (authenticated encryption) requires IV
// (Initialization Vector), optional AAD (Additional Authenticated Data), and
// tag length. This struct packages them. pIv: pointer to IV bytes. pAAD:
// optional pointer to AAD bytes. ulTagBits: tag length in bits. Not implemented
// in vHSM (signing-focused); provided for PKCS#11 compliance skeleton.
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
// CK_FUNCTION_LIST: function pointer table
// (the struct type itself is defined after the per-function typedefs)
// ---------------------------------------------------------------------------
// WHY CK_FUNCTION_LIST: The standard way for PKCS#11 libraries to export
// functions. Applications call C_GetFunctionList() to get a pointer to this
// table, then invoke functions through it:
//   CK_FUNCTION_LIST_PTR pFL = NULL;
//   C_GetFunctionList(&pFL);
//   pFL->C_Initialize(NULL);
// This pattern allows the library to provide multiple implementations (e.g.,
// FIPS vs non-FIPS) or thread-safe vs non-thread-safe variants. vHSM provides
// one standard implementation.
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;

// WHY individual function pointer typedefs (CK_C_Initialize, CK_C_Finalize,
// etc.): Each C function is represented by a typedef. These are used in the
// CK_FUNCTION_LIST struct to define the table of function pointers. Typedefs
// ensure type safety: if the implementation has the wrong signature, the
// compiler catches it.
typedef CK_RV (*CK_C_Initialize)(CK_VOID_PTR pInitArgs);
typedef CK_RV (*CK_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV (*CK_C_GetInfo)(CK_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV (*CK_C_GetSlotList)(CK_BBOOL tokenPresent,
                                  CK_SLOT_ID_PTR pSlotList,
                                  CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetMechanismList)(CK_SLOT_ID slotID,
                                       CK_MECHANISM_TYPE_PTR pMechanismList,
                                       CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetMechanismInfo)(CK_SLOT_ID slotID,
                                       CK_MECHANISM_TYPE type,
                                       CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV (*CK_C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
                                CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
typedef CK_RV (*CK_C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                              CK_ULONG ulPinLen);
typedef CK_RV (*CK_C_SetPIN)(CK_SESSION_HANDLE hSession,
                             CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                             CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
typedef CK_RV (*CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags,
                                  CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                                  CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (*CK_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CloseAllSessions)(CK_SLOT_ID slotID);
typedef CK_RV (*CK_C_GetSessionInfo)(CK_SESSION_HANDLE hSession,
                                     CK_SESSION_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetOperationState)(CK_SESSION_HANDLE hSession,
                                        CK_BYTE_PTR pOperationState,
                                        CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV (*CK_C_SetOperationState)(CK_SESSION_HANDLE hSession,
                                        CK_BYTE_PTR pOperationState,
                                        CK_ULONG ulOperationStateLen,
                                        CK_OBJECT_HANDLE hEncryptionKey,
                                        CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV (*CK_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                            CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*CK_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CreateObject)(CK_SESSION_HANDLE hSession,
                                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                   CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV (*CK_C_CopyObject)(CK_SESSION_HANDLE hSession,
                                 CK_OBJECT_HANDLE hObject,
                                 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                 CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (*CK_C_DestroyObject)(CK_SESSION_HANDLE hSession,
                                    CK_OBJECT_HANDLE hObject);
typedef CK_RV (*CK_C_GetObjectSize)(CK_SESSION_HANDLE hSession,
                                    CK_OBJECT_HANDLE hObject,
                                    CK_ULONG_PTR pulSize);
typedef CK_RV (*CK_C_GetAttributeValue)(CK_SESSION_HANDLE hSession,
                                        CK_OBJECT_HANDLE hObject,
                                        CK_ATTRIBUTE_PTR pTemplate,
                                        CK_ULONG ulCount);
typedef CK_RV (*CK_C_SetAttributeValue)(CK_SESSION_HANDLE hSession,
                                        CK_OBJECT_HANDLE hObject,
                                        CK_ATTRIBUTE_PTR pTemplate,
                                        CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjectsInit)(CK_SESSION_HANDLE hSession,
                                      CK_ATTRIBUTE_PTR pTemplate,
                                      CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjects)(CK_SESSION_HANDLE hSession,
                                  CK_OBJECT_HANDLE_PTR phObject,
                                  CK_ULONG ulMaxObjectCount,
                                  CK_ULONG_PTR pulObjectCount);
typedef CK_RV (*CK_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_EncryptInit)(CK_SESSION_HANDLE hSession,
                                  CK_MECHANISM_PTR pMechanism,
                                  CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                              CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                              CK_ULONG_PTR pulEncryptedDataLen);
typedef CK_RV (*CK_C_EncryptUpdate)(CK_SESSION_HANDLE hSession,
                                    CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                    CK_BYTE_PTR pEncryptedPart,
                                    CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_EncryptFinal)(CK_SESSION_HANDLE hSession,
                                   CK_BYTE_PTR pLastEncryptedPart,
                                   CK_ULONG_PTR pulLastEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptInit)(CK_SESSION_HANDLE hSession,
                                  CK_MECHANISM_PTR pMechanism,
                                  CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Decrypt)(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pEncryptedData,
                              CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                              CK_ULONG_PTR pulDataLen);
typedef CK_RV (*CK_C_DecryptUpdate)(CK_SESSION_HANDLE hSession,
                                    CK_BYTE_PTR pEncryptedPart,
                                    CK_ULONG ulEncryptedPartLen,
                                    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_DecryptFinal)(CK_SESSION_HANDLE hSession,
                                   CK_BYTE_PTR pLastPart,
                                   CK_ULONG_PTR pulLastPartLen);
typedef CK_RV (*CK_C_DigestInit)(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism);
typedef CK_RV (*CK_C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                             CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
                             CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*CK_C_DigestUpdate)(CK_SESSION_HANDLE hSession,
                                   CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_DigestKey)(CK_SESSION_HANDLE hSession,
                                CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_DigestFinal)(CK_SESSION_HANDLE hSession,
                                  CK_BYTE_PTR pDigest,
                                  CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*CK_C_SignInit)(CK_SESSION_HANDLE hSession,
                               CK_MECHANISM_PTR pMechanism,
                               CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                           CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                           CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                                 CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_SignFinal)(CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pSignature,
                                CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_SignRecoverInit)(CK_SESSION_HANDLE hSession,
                                      CK_MECHANISM_PTR pMechanism,
                                      CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                                  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                                  CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_VerifyInit)(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                             CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                             CK_ULONG ulSignatureLen);
typedef CK_RV (*CK_C_VerifyUpdate)(CK_SESSION_HANDLE hSession,
                                   CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_VerifyFinal)(CK_SESSION_HANDLE hSession,
                                  CK_BYTE_PTR pSignature,
                                  CK_ULONG ulSignatureLen);
typedef CK_RV (*CK_C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession,
                                        CK_MECHANISM_PTR pMechanism,
                                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_VerifyRecover)(CK_SESSION_HANDLE hSession,
                                    CK_BYTE_PTR pSignature,
                                    CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                                    CK_ULONG_PTR pulDataLen);
typedef CK_RV (*CK_C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                          CK_BYTE_PTR pEncryptedPart,
                                          CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pEncryptedPart,
                                          CK_ULONG ulEncryptedPartLen,
                                          CK_BYTE_PTR pPart,
                                          CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession,
                                        CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                        CK_BYTE_PTR pEncryptedPart,
                                        CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pEncryptedPart,
                                          CK_ULONG ulEncryptedPartLen,
                                          CK_BYTE_PTR pPart,
                                          CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_GenerateKey)(CK_SESSION_HANDLE hSession,
                                  CK_MECHANISM_PTR pMechanism,
                                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                  CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_GenerateKeyPair)(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef CK_RV (*CK_C_WrapKey)(CK_SESSION_HANDLE hSession,
                              CK_MECHANISM_PTR pMechanism,
                              CK_OBJECT_HANDLE hWrappingKey,
                              CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey,
                              CK_ULONG_PTR pulWrappedKeyLen);
typedef CK_RV (*CK_C_UnwrapKey)(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_DeriveKey)(CK_SESSION_HANDLE hSession,
                                CK_MECHANISM_PTR pMechanism,
                                CK_OBJECT_HANDLE hBaseKey,
                                CK_ATTRIBUTE_PTR pTemplate,
                                CK_ULONG ulAttributeCount,
                                CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                                 CK_ULONG ulSeedLen);
typedef CK_RV (*CK_C_GenerateRandom)(CK_SESSION_HANDLE hSession,
                                     CK_BYTE_PTR RandomData,
                                     CK_ULONG ulRandomLen);
typedef CK_RV (*CK_C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CancelFunction)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
                                       CK_VOID_PTR pReserved);

// WHY CK_FUNCTION_LIST struct: Aggregates all function pointers. The version
// field indicates which set of functions are available (for binary
// compatibility). Applications should check version and only call functions
// they know about. The struct members are named identically to the C symbols
// (C_Initialize, C_Sign, etc.) for consistency.
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
