#ifndef VHSM_CORE_TYPES_H
#define VHSM_CORE_TYPES_H

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

typedef std::uint8_t u8;
typedef std::uint16_t u16;
typedef std::uint32_t u32;
typedef std::uint64_t u64;

// Will be used in future implementations
// Preferred overed their std::uintXX correspondance,
// Better for multi-threaded applications,
typedef std::atomic_int8_t ts8;
typedef std::atomic_int16_t ts16;
typedef std::atomic_int32_t ts32;
typedef std::atomic_int64_t ts64;

typedef std::int8_t i8;
typedef std::int16_t i16;
typedef std::int32_t i32;
typedef std::int64_t i64;

// PKCS#11 types
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_CERTIFICATE_TYPE;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;

// PKCS#11 attribute types
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef void*    CK_VOID_PTR;
typedef CK_ULONG* CK_ULONG_PTR;

// PKCS#11 v3.0 mechanism types — AES family
// Source: PKCS#11 Base Specification v3.0, Table 9-14
#define CKM_AES_KEY_GEN     0x00001080UL
#define CKM_AES_ECB         0x00001081UL
#define CKM_AES_CBC         0x00001082UL
#define CKM_AES_MAC         0x00001083UL
#define CKM_AES_MAC_GENERAL 0x00001084UL
#define CKM_AES_CBC_PAD     0x00001085UL
#define CKM_AES_OFB         0x00001086UL
#define CKM_AES_CFB64       0x00001087UL
#define CKM_AES_CFB8        0x00001088UL
#define CKM_AES_CFB128      0x00001089UL
#define CKM_AES_CFB1        0x0000108AUL
#define CKM_AES_XCBC_MAC    0x0000108BUL
#define CKM_AES_XCBC_MAC_96 0x0000108CUL
#define CKM_SHA256_RSA_PKCS 0x00000241UL

// The CK_ATTRIBUTE structure
typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR       pValue;
    CK_ULONG          ulValueLen;
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;

#define CK_FALSE 0
#define CK_TRUE  1

// an unsigned 8-bit value 
typedef unsigned char CK_BYTE;

// an unsigned 8-bit character
typedef CK_BYTE CK_CHAR;

// an 8-bit UTF-8 character
typedef CK_BYTE CK_UTF8CHAR;

// a BYTE-sized Boolean flag
typedef CK_BYTE CK_BBOOL;

/* a signed value, the same size as a CK_ULONG */
typedef long int CK_LONG;

/* at least 32 bits; each bit is a Boolean flag */
typedef CK_ULONG CK_FLAGS;

// Status return values (CK_RV)
typedef CK_ULONG CK_RV;

#define CKR_OK                            ((CK_RV) 0x00000000UL)
#define CKR_CANCEL                        ((CK_RV) 0x00000001UL)
#define CKR_HOST_MEMORY                   ((CK_RV) 0x00000002UL)
#define CKR_SLOT_ID_INVALID               ((CK_RV) 0x00000003UL)
#define CKR_GENERAL_ERROR                 ((CK_RV) 0x00000005UL)
#define CKR_FUNCTION_FAILED               ((CK_RV) 0x00000006UL)
#define CKR_ARGUMENTS_BAD                 ((CK_RV) 0x00000007UL)
#define CKR_BUFFER_TOO_SMALL              ((CK_RV) 0x00000150UL)
#define CKR_NO_EVENT                      ((CK_RV) 0x00000008UL)
#define CKR_NEED_TO_CREATE_THREADS        ((CK_RV) 0x00000009UL)
#define CKR_CANT_LOCK                     ((CK_RV) 0x0000000AUL)
#define CKR_ATTRIBUTE_READ_ONLY           ((CK_RV) 0x00000010UL)
#define CKR_ATTRIBUTE_SENSITIVE           ((CK_RV) 0x00000011UL)
#define CKR_ATTRIBUTE_TYPE_INVALID        ((CK_RV) 0x00000012UL)
#define CKR_ATTRIBUTE_VALUE_INVALID       ((CK_RV) 0x00000013UL)
#define CKR_DATA_INVALID                  ((CK_RV) 0x00000014UL)
#define CKR_DATA_LEN_RANGE                ((CK_RV) 0x00000015UL)
#define CKR_DEVICE_ERROR                  ((CK_RV) 0x00000030UL)
#define CKR_DEVICE_MEMORY                 ((CK_RV) 0x00000031UL)
#define CKR_DEVICE_REMOVED                ((CK_RV) 0x00000032UL)
#define CKR_ENCRYPTED_DATA_INVALID        ((CK_RV) 0x00000040UL)
#define CKR_ENCRYPTED_DATA_LEN_RANGE      ((CK_RV) 0x00000041UL)
#define CKR_DECRYPTED_DATA_LEN_RANGE      ((CK_RV) 0x00000042UL)
#define CKR_DATA_RANGE                    ((CK_RV) 0x00000043UL)
#define CKR_MECHANISM_INVALID             ((CK_RV) 0x00000050UL)
#define CKR_MECHANISM_PARAM_INVALID       ((CK_RV) 0x00000051UL)
#define CKR_OBJECT_HANDLE_INVALID         ((CK_RV) 0x00000052UL)
#define CKR_OPERATION_ACTIVE              ((CK_RV) 0x00000053UL)
#define CKR_OPERATION_NOT_INITIALIZED     ((CK_RV) 0x00000054UL)
#define CKR_PIN_INCORRECT                 ((CK_RV) 0x0000005AUL)
#define CKR_PIN_INVALID                   ((CK_RV) 0x0000005BUL)
#define CKR_PIN_LEN_RANGE                 ((CK_RV) 0x0000005CUL)
#define CKR_PIN_EXPIRED                   ((CK_RV) 0x0000005DUL)
#define CKR_PIN_LOCKED                    ((CK_RV) 0x0000005EUL)
#define CKR_SESSION_CLOSED                ((CK_RV) 0x0000005FUL)
#define CKR_SESSION_COUNT                 ((CK_RV) 0x00000060UL)
#define CKR_SESSION_HANDLE_INVALID        ((CK_RV) 0x00000061UL)
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED ((CK_RV) 0x00000062UL)
#define CKR_SESSION_READ_ONLY             ((CK_RV) 0x00000063UL)
#define CKR_SESSION_EXISTS                ((CK_RV) 0x00000064UL)
#define CKR_SESSION_READ_ONLY_SO_EXISTS   ((CK_RV) 0x00000065UL)
#define CKR_SESSION_WRITE_SO_EXISTS       ((CK_RV) 0x00000066UL)
#define CKR_SPI                           ((CK_RV) 0x00000067UL)
#define CKR_SPI_ATTRIBUTE_READ_ONLY       ((CK_RV) 0x00000068UL)
#define CKR_SPI_ATTRIBUTE_SENSITIVE       ((CK_RV) 0x00000069UL)
#define CKR_TEMPLATE_INCOMPLETE           ((CK_RV) 0x00000070UL)
#define CKR_TEMPLATE_INCONSISTENT         ((CK_RV) 0x00000071UL)
#define CKR_TOKEN_NOT_PRESENT             ((CK_RV) 0x00000072UL)
#define CKR_TOKEN_NOT_RECOGNIZED          ((CK_RV) 0x00000073UL)
#define CKR_TOKEN_WRITE_PROTECTED         ((CK_RV) 0x00000074UL)
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID ((CK_RV) 0x00000075UL)
#define CKR_UNWRAPPING_KEY_SIZE_RANGE     ((CK_RV) 0x00000076UL)
#define CKR_UNWRAPPING_KEY_TYPE_INVALID   ((CK_RV) 0x00000077UL)
#define CKR_USER_ALREADY_LOGGED_IN        ((CK_RV) 0x00000078UL)
#define CKR_USER_NOT_LOGGED_IN            ((CK_RV) 0x00000079UL)
#define CKR_USER_PIN_NOT_INITIALIZED      ((CK_RV) 0x0000007AUL)
#define CKR_USER_TYPE_INVALID             ((CK_RV) 0x0000007BUL)
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN ((CK_RV) 0x0000007CUL)
#define CKR_USER_TOO_MANY_TYPES           ((CK_RV) 0x0000007DUL)
#define CKR_WRAPPED_KEY_INVALID           ((CK_RV) 0x0000007EUL)
#define CKR_WRAPPED_KEY_LEN_RANGE         ((CK_RV) 0x0000007FUL)
#define CKR_WRAPPED_KEY_TYPE_INVALID      ((CK_RV) 0x00000080UL)
#define CKR_PKEY_LT_KEY                   ((CK_RV) 0x00000090UL)
#define CKR_PKEY_GT_KEY                   ((CK_RV) 0x00000091UL)
#define CKR_TOKEN_WRITE_WITH_SO_SESSION   ((CK_RV) 0x00000092UL)
#define CKR_KEY_HANDLE_INVALID            ((CK_RV) 0x00000093UL)
#define CKR_KEY_CHANGED                   ((CK_RV) 0x00000094UL)
#define CKR_KEY_NEEDED                    ((CK_RV) 0x00000095UL)
#define CKR_KEY_INDIGESTIBLE              ((CK_RV) 0x00000096UL)
#define CKR_KEY_FUNCTION_NOT_PERMITTED    ((CK_RV) 0x00000097UL)
#define CKR_KEY_NOT_WRAPPABLE             ((CK_RV) 0x00000098UL)
#define CKR_KEY_EXTRACTABLE               ((CK_RV) 0x00000099UL)
#define CKR_KEY_TYPE_INCONSISTENT         ((CK_RV) 0x0000009AUL)
#define CKR_KEY_NOT_NEEDS_CHANGE          ((CK_RV) 0x0000009BUL)
#define CKR_HASH_KEY                      ((CK_RV) 0x000000A0UL)
#define CKR_APPLICATION_NAME_INVALID      ((CK_RV) 0x00000101UL)
#define CKR_USER_PIN_ALREADY_INITIALIZED  ((CK_RV) 0x00000102UL)
#define CKR_USER_PIN_LOCKED               ((CK_RV) 0x00000103UL)
#define CKR_USER_PIN_EXPIRED              ((CK_RV) 0x00000104UL)
#define CKR_USER_PIN_INCORRECT            ((CK_RV) 0x00000105UL)
#define CKR_USER_ELSE_LOCKED              ((CK_RV) 0x00000106UL)
#define CKR_SO_PIN_NOT_INITIALIZED        ((CK_RV) 0x00000107UL)
#define CKR_SO_PIN_ALREADY_INITIALIZED    ((CK_RV) 0x00000108UL)
#define CKR_SO_PIN_LOCKED                 ((CK_RV) 0x00000109UL)
#define CKR_SO_PIN_EXPIRED                ((CK_RV) 0x00000110UL)
#define CKR_SO_PIN_INCORRECT              ((CK_RV) 0x00000111UL)
#define CKU_INVALID 0
#define CKU_USER 1
#define CKU_SO 2

// PKCS#11 slot ID
typedef CK_ULONG CK_SLOT_ID;

// PKCS#11 session state
typedef CK_ULONG CK_STATE;

// Session state values
#define CKS_RO_PUBLIC_SESSION               ((CK_STATE) 0x00000000UL)
#define CKS_RO_USER_FUNCTIONS               ((CK_STATE) 0x00000001UL)
#define CKS_RO_SO_FUNCTIONS                 ((CK_STATE) 0x00000005UL)
#define CKS_RW_PUBLIC_SESSION               ((CK_STATE) 0x00000002UL)
#define CKS_RW_USER_FUNCTIONS               ((CK_STATE) 0x00000003UL)
#define CKS_RW_SO_FUNCTIONS                 ((CK_STATE) 0x00000004UL)

// PKCS#11 session flags
#define CKF_RW_SESSION                      0x00000002UL
#define CKF_SERIAL_SESSION                  0x00000004UL
#define CKF_TOKEN_PRESENT                   0x00000001UL
#define CKF_HW_SLOT                         0x00000002UL
#define CKF_REMOVABLE_DEVICE                0x00000004UL    

// PKCS#11 notification types
typedef CK_ULONG CK_NOTIFICATION;

// PKCS#11 notification callback
typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication);

// PKCS#11 notification types
#define CKN_SURRENDER               0
#define CKN_COMPLETE                1
#define CKN_FACTOR                  2
#define CKN_RELOCATE                3

// The CK_SESSION_INFO structure
typedef struct CK_SESSION_INFO {
    CK_SLOT_ID      slotID;
    CK_STATE        state;
    CK_FLAGS        flags;
    CK_ULONG        ulDeviceError;
} CK_SESSION_INFO;

typedef CK_SESSION_INFO* CK_SESSION_INFO_PTR;

// Pointer to CK_SESSION_HANDLE
typedef CK_SESSION_HANDLE* CK_SESSION_HANDLE_PTR;

namespace vhsm::crypto {
// SignResult struct returned by CryptoEngine::sign()
struct SignResult {
    std::vector<u8> signature;      // raw DER bytes
    std::string          mechanism_str;  // e.g., "CKM_ECDSA_SHA256"
    std::string          digest_alg;     // e.g., "SHA-256"
    std::string          payload_digest; // hex SHA-256 of input
    size_t               payload_size;
};

// Enumerations for NotificationEvent
enum class EventType {
    SIGN_CREATED,
    VERIFY_COMPLETED,
    VERIFY_FAILED,
    KEY_ROTATED,
    KEY_DESTROYED,
    INTEGRITY_ALERT,
    DB_WRITE_FAILED,
    ADMIN_LOGIN,
    PIN_LOCKOUT
};

enum class Severity {
    INFO,
    WARN,
    CRITICAL
};

// NotificationEvent struct used by the notification bus
struct NotificationEvent {
    std::string  event_id;       // UUID v4
    EventType    type;           // SIGN_CREATED, VERIFY_FAILED, etc.
    Severity     severity;       // INFO | WARN | CRITICAL
    int64_t      timestamp;      // epoch ms
    std::string  source;         // "slot:N/token:label"
    std::string  actor;          // user_label or "SO"
    std::string  summary;        // short human-readable
    std::string  detail_json;    // JSON payload
    std::string  hsm_instance;   // instance_id from db_meta
};
} // namespace vhsm::crypto

struct version {
    u8 major_version;
    u8  minor_version;
};

// SignatureRecord represents a signature operation to be persisted and anchored.
struct SignatureRecord {
    std::string record_id;          // UUID v4, primary key
    int64_t     created_at;         // epoch milliseconds
    int         slot_id;
    std::string token_label;
    std::string key_id;
    std::string key_fingerprint;
    std::string mechanism;          // e.g., "CKM_ECDSA_SHA256"
    std::string digest_algorithm;   // e.g., "SHA-256"
    std::string payload_digest;     // hex string
    std::string signature_b64;      // base64 URL-safe signature
    int         payload_size;       // original payload size in bytes
    std::string session_handle;
    std::optional<std::string> user_label;
    std::optional<std::string> app_context;
    // Ledger fields (filled later by ledger worker)
    std::optional<std::string> ledger_tx_id;
    std::optional<int64_t>     ledger_block_num;
    std::string                ledger_status; // "PENDING", "COMMITTED", "FAILED", "DISABLED"
};

#endif // VHSM_CORE_TYPES_H