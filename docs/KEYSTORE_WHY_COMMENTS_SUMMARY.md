# WHY Comments Added to src/keystore

## Overview
Comprehensive "WHY" comments have been added to all keystore module files. These explain the **design reasoning and trade-offs** behind each component, not just what the code does.

## Files Updated

### 1. **hsm_object.h / hsm_object.cpp**
**Purpose**: Base class for all HSM objects (keys, certificates, data).

**Key WHY comments**:
- Why abstract base class: Unified interface for diverse PKCS#11 object types
- Why non-copyable for sensitive: Prevent accidental key duplication
- Why moves are noexcept: Container compatibility and exception safety
- Why SecureBuffer for id_: Defense-in-depth against memory forensics
- Why separate wipe() method: Ensure derived classes zero data in correct order
- Why copy constructor throws: Runtime check allows non-sensitive subclasses flexibility
- Why copy-assignment wipes before overwrite: Prevent key material lingering in memory
- Why move constructor resets source state: Ensure moved-from objects are valid to destroy

---

### 2. **key_wrap.h / key_wrap.cpp**
**Purpose**: RFC 3394 AES Key Wrap (protect keys at rest with integrity check).

**Key WHY comments**:
- Why RFC 3394 encapsulation: Designed specifically for key material with integrity check (not general encryption)
- Why AESECB (not CBC, CTR): Deterministic output enables integrity verification without separate IV storage
- Why require exactly 32 bytes: AES-256 demands 256-bit key; smaller keys weaken security
- Why fail-closed on integrity mismatch: Reject corrupted/tampered keys immediately
- Why mlock in constructor: Prevent OS from swapping KEK to disk (forensic recovery defense)
- Why OPENSSL_cleanse before munlock: Overwrite memory while locked to prevent swap-to-disk
- Why 6 rounds in RFC 3394: Standard proven against known-plaintext attacks
- Why counter (t) embedded in ICV: Prevents block reordering attacks
- Why copy KEK into internal buffer: Own a copy so we can apply security controls (mlock)
- Why wipe temporary block before return: Don't leave plaintext blocks in stack

---

### 3. **token.h / token.cpp**
**Purpose**: Public GLIBC-style facade for a Token (PKCS#11 interface).

**Key WHY comments**:
- Why separate facade layer: Bridge from C API (raw pointers, error codes) to C++ (exceptions, smart pointers)
- Why non-copyable: Each Token manages unique identity and shared state; copying violates uniqueness
- Why input validation here (not core): Facade handles C API quirks; core focuses on PKCS#11 semantics
- Why template methods forward to core: Templates can't be virtual; wrapping them in facade keeps instantiation centralized
- Why consistent null-check pattern for PINs: Catch C API mistakes early (null with non-zero length)
- Why per-session login state (not token): PKCS#11 allows different sessions with different login states
- Why get_kek() accessible: KeyWrap needs KEK; core generates/stores it; we expose for rest of system
- Why SystemHsmClock for production: Tests inject FrozenHsmClock; public Token uses system clock

---

### 4. **object_store.h**
**Purpose**: Handle-based object storage with version tracking (GDT-like pattern).

**Key WHY comments**:
- Why handle-based API (not pointers): PKCS#11 is C; pointers allow use-after-free. Handles are indices we validate.
- Why version bits: Detect stale handles (old index + version) when slots are reused
- Why std::unique_ptr: Objects owned by store; automatic cleanup; no reference counting
- Why non-copyable: Copying violates ownership semantics
- Why template v_create_object: Type-safe creation of derived types; compile-time instantiation
- Why nodiscard on getters: Discarding a handle is usually a bug
- Why CK_INVALID_HANDLE = 0: By PKCS#11 convention; enables null-like checks
- Why extract/compose functions: Separate concerns of handle packing/unpacking
- Why v_table_ dynamic vector: Cache-friendly; slots are reused; avoids hash table overhead
- Why mutex protects v_table_: Prevent concurrent create/destroy/get races
- Why atomic v_next_index_: Relaxed stores/loads without locking improve performance
- Why template implementation in header: C++ requires template definitions at instantiation sites
- Why scan from v_next_index_: Improves cache locality (recently-freed slots are hot)
- Why O(1) amortized table growth: Vector reallocation strategy

---

### 5. **slot.h**
**Purpose**: Virtual reader slot (PKCS#11 model) hosting a Token.

**Key WHY comments**:
- Why Slot abstraction: PKCS#11 models hardware readers; vHSM follows same model for API compatibility
- Why non-copyable: Each Slot has unique ID and mutex; copying violates identity
- Why thread-safe token insert/remove: Applications can query slot and submit transactions concurrently
- Why shared_ptr<Token>: Application holds tokens across async calls; ensures token survives removal
- Why is_token_present() separate from get_token(): One returns boolean (no allocation); other returns shared_ptr
- Why get_token() returns shared_ptr: Caller gets reference; token stays alive if slot removes it
- Why flags computed on-the-fly (not cached): May change (token inserted/removed); cheap recomputation is accurate
- Why mutable mutex in const method: get_token() is query-only but locks to read token_ safely
- Why slot_id_ immutable: It's the Slot's identity; applications use it to find Slots

---

### 6. **key_fingerprint.h**
**Purpose**: Cryptographic fingerprints of keys (SHA-256 hash of public key material).

**Key WHY comments**:
- Why static utility class: Fingerprinting is pure function; no state; prevents instantiation
- Why fingerprints from keys/SPKI: Same key in different formats must produce same fingerprint
- Why 32-byte (256-bit) fingerprints: Collision-resistant; SHA-256 produces 256 bits
- Why overloads for ECC/RSA: Different key types have different layouts; extract canonical bytes per type

---

### 7. **attribute_store.h**
**Purpose**: Bridge between C API (CK_ATTRIBUTE) and C++ objects; enforces PKCS#11 semantics.

**Key WHY comments**:
- Why separate from object: Attributes are metadata; store interprets PKCS#11 semantics
- Why takes HsmObject& reference: Doesn't own object; constructed per-session to read/write
- Why separate v_is_read_only method: Centralized enforcement; examples: CKA_CLASS, CKA_KEY_SIZE
- Why separate v_validate_attribute: Different attributes have different validation rules
- Why CK_RV return types: Matches PKCS#11 C API convention; callers expect standard error codes

---

## Design Philosophy Reinforced

The WHY comments emphasize recurring themes:

1. **PKCS#11 Compliance**: Keystore must follow standard API patterns (handles, error codes, attribute model)
2. **Security-First**: Sensitive data is non-copyable, wiped, mlock-ed, and fail-closed
3. **Clean Separation**: Facade (Token) handles C API; core (v_TokenCore_M1) handles semantics
4. **Layering**: Input validation at facade; business logic in core
5. **Thread Safety**: Mutexes protect shared state; shared_ptr outlives scope
6. **Memory Safety**: RAII patterns; unique_ptr ownership; volatile writes for security
7. **Performance**: Lazy allocation (unordered_map), cache locality (slot scanning), lock-free where possible

---

## Reading Guide

**Start here for architecture**:
- Read `token.h` comments first (facade pattern)
- Then `hsm_object.h` (base object design)
- Then `object_store.h` (handle + version system)

**For cryptography**:
- Read `key_wrap.h/cpp` (RFC 3394 internals)
- Then `key_fingerprint.h` (hash-based fingerprinting)

**For system design**:
- Read `slot.h` (PKCS#11 model)
- Then `attribute_store.h` (metadata bridge)

---

## Key Takeaways

1. **Non-copyable sensitive objects**: Prevents accidental key duplication
2. **Version bits in handles**: Detects use-after-free from stale handles
3. **Fail-closed on integrity failure**: Reject corrupted/tampered keys immediately
4. **Mlock + OPENSSL_cleanse**: Defense-in-depth against forensic recovery
5. **Facade + core pattern**: Separates C API quirks from PKCS#11 semantics
6. **shared_ptr for token lifetime**: Token survives removal if caller holds reference
7. **Template methods in facade**: Keeps template instantiation in one place
8. **Volatile writes for security**: Forces compiler to actually zero sensitive memory

---

## Files Modified

```
src/keystore/hsm_object.h          (+WHY comments on copyability, move semantics, SecureBuffer)
src/keystore/hsm_object.cpp        (+WHY comments on constructor/destructor, wipe logic)
src/keystore/key_wrap.h            (+WHY comments on RFC 3394, AES-ECB, integrity)
src/keystore/key_wrap.cpp          (+WHY comments on mlock, cleanse, wrap/unwrap algorithm)
src/keystore/token.h               (+WHY comments on facade pattern, PIN validation)
src/keystore/token.cpp             (+WHY comments on null-check pattern)
src/keystore/object_store.h        (+WHY comments on handles, version bits, templates)
src/keystore/slot.h                (+WHY comments on PKCS#11 model, shared_ptr, flags)
src/keystore/key_fingerprint.h     (+WHY comments on fingerprinting, overloads)
src/keystore/attribute_store.h     (+WHY comments on validation, read-only attributes)
```

Total: 10 files, ~200+ WHY comments added across ~2000+ lines of code.
