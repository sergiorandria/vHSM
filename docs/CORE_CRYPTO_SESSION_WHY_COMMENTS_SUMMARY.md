# WHY Comments Added to Core, Crypto, and Session Modules

## Overview
Comprehensive "WHY" comments have been added to 15 critical files across three foundational modules: `core`, `crypto`, and `session`. These explain the **design reasoning and architectural choices** behind each component, emphasizing security-first design, PKCS#11 compliance, and production-grade patterns.

---

## Module 1: Core (Foundational Infrastructure)

The core module provides abstractions that everything else depends on: types, error handling, secure memory, and timing semantics.

### 1.1 types.h
**Purpose**: Unified type system and PKCS#11 constants.

**Key WHY comments**:
- Why fixed-width aliases (u8, u16, u32, u64): Brevity + systems programming convention
- Why atomic type aliases (ts8, ts16, etc.) are reserved: Anticipate multi-threading without premature optimization
- Why PKCS#11 types centralized: Standard compliance + easy platform adaptation
- Why AES mechanism constants defined here: Discoverable reference to PKCS#11 v3.0 spec
- Why CK_ATTRIBUTE structure is explicit: Must match standard exactly (compliance bug if wrong)
- Why CK_FALSE/CK_TRUE macros: Explicit boolean representation (some legacy systems use 0xFF)
- Why CK_BYTE, CK_CHAR, CK_UTF8CHAR distinctions: Semantic clarity (all map to unsigned char at runtime)

**Design principle**: PKCS#11 compliance is non-negotiable. Centralizing constants prevents duplication and makes deviations immediately obvious.

### 1.2 error.h
**Purpose**: Exception hierarchy and validation macros.

**Key WHY comments**:
- Why exception hierarchy (HsmException, CryptoException, DbError): Domain-specific error handling
- Why VHSM_CHECK embeds __FILE__ and __LINE__: Production debugging without printf
- Why VHSM_CHECK_MSG separate from VHSM_CHECK: Context-specific error messages
- Why DbError::Kind enum: Classify failures for differentiated recovery (ConnectionError → retry; SchemaError → escalate)

**Design principle**: Fail-fast with clear attribution. Macro-embedded source location provides immediate context.

### 1.3 secure_buffer.h
**Purpose**: Secure memory management (locking + zeroing).

**Key WHY comments**:
- Why SecureBuffer locks memory with mlock(): Prevent OS from swapping secrets to disk
- Why memory is zeroed before freeing: Defense-in-depth against forensic recovery
- Why template parameter rejected: Bloat avoidance + security audit simplicity
- Why explicit constructor with default: Prevent accidental implicit conversions
- Why non-copyable: Single ownership of secrets (prevent duplication)
- Why moves are noexcept: Container exception safety
- Why separate wipe() method: Allow explicit zeroing before destruction
- Why write()/read() take offset+length: Bounds checking prevents overruns
- Why equals() method (not operator==): Distinguish content equality from identity
- Why _VHSMXX_NODISCARD on getters: Catch accidental non-use of pointer

**Design principle**: Memory-safe-by-design. Every byte of sensitive data is tracked, locked, and wiped.

### 1.4 hsm_clock.h
**Purpose**: Clock abstraction for deterministic testing.

**Key WHY comments**:
- Why HsmTimePoint uses millisecond precision: NTP accuracy limit + avoids false ordering guarantees
- Why IHsmClock is an interface: Dependency injection enables FrozenHsmClock for deterministic tests
- Why [[nodiscard]] on now(): Forgetting to use now() is almost always a bug

**Design principle**: Testability through dependency injection. Production gets system clock; tests get frozen time.

---

## Module 2: Crypto (Cryptographic Operations & Policy)

The crypto module encapsulates all cryptographic operations and enforces vHSM's fail-closed security policy.

### 2.1 ctx_guard.h
**Purpose**: RAII wrappers for OpenSSL EVP contexts.

**Key WHY comments**:
- Why CtxGuard template + C++20 concepts: Type-safe OpenSSL context cleanup (wrong type = compile error)
- Why concepts instead of specialization: Constraints explicit at declaration, caught early
- Why EVP_CTX_CONCEPT lists three types: Restrict to proven-safe types (cipher, digest, key)
- Why base class template: Derived classes specialize destructor with appropriate OpenSSL free function
- Why pure virtual destructor needs inline implementation: C++ requires body for pure virtual destructors
- Why non-copyable: Each guard owns one context pointer (copy would cause double-free)

**Design principle**: RAII guarantees cleanup. Concepts enforce type safety at compile time.

### 2.2 crypto_engine.h
**Purpose**: Single orchestration point for all signing operations.

**Key WHY comments**:
- Why CryptoEngine is a single entry point: Centralize policy (mechanism selection, fallback, auditability)
- Why fail-closed on mechanism mismatch: Silently producing wrong-algorithm signature is unacceptable
- Why recorded mechanism in SignResult: Enables auditability (ledger reveals what was actually used)
- Why mechanism is a string hint (not enforced): Allow fallback if hint conflicts with key type
- Why EVP_PKEY ownership is caller's: Explicit ownership prevents surprise deallocations

**Design principle**: Fail-closed, policy-driven. No silent failures or bypasses possible.

### 2.3 secure_rng.h
**Purpose**: Thread-safe wrapper around CTR_DRBG_AES256.

**Key WHY comments**:
- Why SecureRNG wraps CTR_DRBG_AES256: Add threading, entropy management, and API simplicity
- Why separate engine and wrapper: Engine implements NIST spec precisely; wrapper adds production concerns
- Why unique_ptr<CTR_DRBG_AES256>: Exclusive ownership (no shared state between threads)
- Why mutex protects engine: CTR_DRBG_AES256 is not internally thread-safe
- Why get_system_entropy is private: Entropy management is automatic (not caller's concern)
- Why force_reseed() method: Allows tests to force reseed without generating 100,000 requests

**Design principle**: Wrap low-level primitives with production concerns (threading, testability).

### 2.4 ctr_drbg_aes256.h
**Purpose**: NIST SP 800-90A deterministic random bit generator.

**Key WHY comments**:
- Why CTR_DRBG_AES256 implements NIST standard: Proven secure, widely reviewed, compliance requirement
- Why use AES-256 (not ChaCha20, Salsa20): Hardware-accelerated (AES-NI), NIST-approved, proven
- Why not a singleton: Avoid global state + simplify testing (no lock contention)
- Why explicit constructor takes entropy: Force caller to provide seed (prevents uninitialized use)
- Why separate reseed method: NIST mandates reseeding periodically (every 100,000 blocks)
- Why generate returns std::vector: Simpler than buffer-filling API
- Why private helper methods: NIST algorithm internals; callers use only generate() and reseed()

**Design principle**: Standards compliance. Conservative, widely-audited design.

### 2.5 aes_gcm.h
**Purpose**: Authenticated encryption (confidentiality + authenticity).

**Key WHY comments**:
- Why AES-256-GCM (not ECB, CBC, CTR): GCM combines encryption with authentication in one operation
- Why bundle nonce+tag+ciphertext in AESGCMResult: Prevents accidental mismatches (all three travel together)
- Why separate AESGCMResult struct: Prevents losing components during transport
- Why static methods: No state needed (pure cryptographic utilities)
- Why decrypt returns std::vector (not optional): On success, plaintext. On failure, throw (fail-closed).

**Design principle**: Authenticated encryption prevents tampering. Fail-closed on tag mismatch.

### 2.6 rsa.h
**Purpose**: RSA operations (key generation, signing, verification).

**Key WHY comments**:
- Why low-level EVP_PKEY interface: Crypto layer doesn't own keys (keystore does)
- Why caller manages EVP_PKEY lifetime: Explicit ownership (caller calls EVP_PKEY_free when done)
- Why struct RSAKeyPair: Wrap EVP_PKEY for semantic clarity (not just a void pointer)
- Why generate_key takes bits parameter: Allow 2048-bit (basic), 3072-bit (standard), 4096-bit (high-security)
- Why sign returns std::vector: Raw DER signature bytes (no encoding/mechanism labels)
- Why verify returns bool: Predicate (true = valid, false = invalid). Caller decides recovery strategy.

**Design principle**: Low-level utilities that policy layers (CryptoEngine) orchestrate.

### 2.7 ecc.h
**Purpose**: Elliptic Curve operations (signing, verification, key agreement).

**Key WHY comments**:
- Why elliptic curves in addition to RSA: Smaller keys (256-bit curve ≈ 3072-bit RSA) + faster + shorter signatures
- Why three curves (P256, P384, P521): NIST-approved with different security levels (fast/standard/high-security)
- Why Curve enum: Explicit curve selection (prevents accidental weak curves)
- Why derive_shared_secret for ECDH: EC supports key agreement; RSA does not
- Why sign/verify have same signature as RSAUtil: Interchangeable interface (CryptoEngine dispatches uniformly)
- Why ECCKeyPair struct: Consistency with RSAKeyPair (uniform API across algorithm families)

**Design principle**: Support both RSA and EC with interchangeable APIs. ECDH for key agreement.

---

## Module 3: Session (Session Management & Operation Context)

The session module implements PKCS#11 session state machines and operation contexts for signing/finding.

### 3.1 session.h
**Purpose**: PKCS#11 session representation (state, login, operations, object store).

**Key WHY comments**:
- Why Session represents a PKCS#11 session: Stateful connection between application and token
- Why each Session has its own ObjectStore: Simplifies object visibility scope
- Why non-copyable due to mutex: Duplication would break synchronization (two copies with separate locks)
- Why separate getters for each field: PKCS#11 C_GetSessionInfo queries individual attributes
- Why state transition methods: Explicit login/logout prevent logic bugs
- Why login takes userType and PIN in SecureBuffer: PIN is sensitive data (zeroed after use)
- Why initializeOperation / finalizeOperation: Prevent accidental operation state reuse
- Why mutable reference to ObjectStore: Sessions need to create/find/destroy objects
- Why getSessionInfo populates a pointer: PKCS#11 uses caller-allocated structs
- Why handle_ is unique: Session identity (immutable, opaque handle)
- Why operationInitialized_ tracks state: Prevents mixing operations (can't encrypt while signing)
- Why pApplication_ and notify_: PKCS#11 callback mechanism for events (rarely used, included for compliance)
- Why mutable mutex_: Protects state; mutable allows const methods to lock if needed

**Design principle**: PKCS#11 compliance with strong encapsulation. One session = one object store + one operation.

### 3.2 session_manager.h
**Purpose**: Public facade managing session lifecycle and handle registry.

**Key WHY comments**:
- Why SessionManager is a public facade: Separate input validation (facade) from state management (core)
- Why sessions stored in registry (not pointers): PKCS#11 uses opaque handles (prevents use-after-free)
- Why SystemHsmClock injected: Tests inject FrozenHsmClock for deterministic timing
- Why openSession validates and delegates: Facade handles C API quirks; core manages registry
- Why closeSession takes handle (not Session*): Callers have handles, not pointers
- Why closeAllSessions per-slot: Cleanup when token removed or library finalized
- Why getSessionInfo populates struct: PKCS#11 API pattern (caller allocates, we fill)
- Why getSession returns raw pointer: Internal callers need to work with session (no copy overhead)
- Why haveSession and haveROSession: Quick checks without iteration

**Design principle**: Handle-based API prevents use-after-free. Facade + core layering.

### 3.3 sign_context.h
**Purpose**: Multi-part signing operation context (accumulate data, then sign).

**Key WHY comments**:
- Why SignContext accumulates data: PKCS#11 allows streaming (C_SignInit + C_SignUpdate* + C_SignFinal)
- Why store mechanism and key_handle: Both required when C_SignFinal is called
- Why throw CryptoException on invalid key_handle: Fail early with clear error (vs. deferred failure)
- Why constructor fixes mechanism and key_handle: Can't change key or algorithm mid-operation
- Why update appends bytes: Streaming fashion (append now, sign later)
- Why clear() is noexcept: Cleanup in error handlers requires no-throw guarantee
- Why data() returns const vector: Read-only access (prevent accidental modification)
- Why app_context_json optional: Application-provided metadata (e.g., document info) forwarded to audit records
- Why m_accumulator is std::vector: Simple resizable buffer (no special memory-locking needed here)

**Design principle**: Streaming operations without loading entire payload into memory at once.

### 3.4 find_context.h
**Purpose**: Iterator over object search results.

**Key WHY comments**:
- Why FindContext provides iterator interface: PKCS#11 C_FindObjects* returns results incrementally
- Why store full match list upfront: Simplifies interface (no stateful search continuation)
- Why non-copyable but movable: Iteration state shouldn't be accidentally duplicated
- Why throw HsmException on next() when empty: Calling next() without has_next() is a logic error
- Why explicit constructor: Prevent accidental implicit conversions (vector → FindContext)
- Why has_next() is const noexcept: Query operation (doesn't throw or modify state)
- Why next() returns single handle: Callers may process one at a time (simplifies API)
- Why reset() is separate: Allow restarting iteration without reconstructing FindContext

**Design principle**: Simple cursor-based iterator for PKCS#11 compatibility.

---

## Cross-Module Architecture

### Layering (Core → Crypto → Session → Keystore)

```
PKCS#11 C API (external)
  ↓
Session Manager (facade: input validation) + Session (PKCS#11 state machine)
  ↓
SignContext, FindContext (operation contexts)
  ↓
CryptoEngine (policy orchestration)
  ↓
RSA/ECC/AES-GCM (low-level utilities)
  ↓
CtxGuard (OpenSSL context cleanup)
  ↓
Core: SecureBuffer, error.h, types.h, hsm_clock.h
```

### Key Design Patterns

1. **Facade + Core**: Input validation in public layer; business logic in internal core
2. **Fail-Closed**: Never silently produce wrong behavior; reject when uncertain
3. **RAII Everything**: Destructors guarantee cleanup (SecureBuffer wipes, CtxGuard frees)
4. **Dependency Injection**: Clock abstraction enables deterministic testing
5. **Policy Layer**: CryptoEngine centralizes cryptographic policy (mechanism selection, fallback, auditability)
6. **Handle-Based API**: PKCS#11 handles prevent use-after-free (no raw Session pointers to callers)
7. **Type Safety**: C++20 concepts enforce EVP context types at compile time

### Security-First Decisions

- **Memory locking (mlock)**: Prevent key swapping to disk
- **Secure zeroing**: Volatile pointers force actual writes (can't be optimized away)
- **Non-copyable sensitive objects**: Prevent accidental key duplication
- **Authenticated encryption (GCM)**: Prevent tampering with encrypted data
- **Fail-closed on integrity failure**: Reject corrupted/tampered data immediately
- **Centralized policy (CryptoEngine)**: No bypasses; all signatures routed through one point

---

## Reading Guide

### Start Here (Architecture Overview)

1. **core/types.h**: Understand the type system and PKCS#11 constants
2. **core/error.h**: Learn the exception hierarchy and validation macro pattern
3. **core/secure_buffer.h**: Study memory-locking and secure-zeroing strategy
4. **core/hsm_clock.h**: See dependency injection pattern for testing

### Cryptographic Policy

5. **crypto/crypto_engine.h**: Understand fail-closed policy and mechanism fallback
6. **crypto/ctx_guard.h**: Learn C++20 concepts for type-safe OpenSSL wrappers
7. **crypto/secure_rng.h**: See thread-safe wrapper pattern
8. **crypto/ctr_drbg_aes256.h**: Study NIST-compliant DRBG implementation

### Cryptographic Primitives

9. **crypto/aes_gcm.h**: Learn authenticated encryption design
10. **crypto/rsa.h**: Study RSA utilities (low-level, policy-agnostic)
11. **crypto/ecc.h**: Study EC utilities and curve selection

### Session Management

12. **session/session_manager.h**: Understand handle-based session registry
13. **session/session.h**: Study PKCS#11 session state machine
14. **session/sign_context.h**: See operation context for streaming operations
15. **session/find_context.h**: Learn iterator pattern for search results

---

## Key Takeaways

### 1. Security-First Design
- Memory locking prevents disk exposure
- Secure zeroing resists forensic recovery
- Non-copyable sensitive objects prevent duplication
- Fail-closed on cryptographic failures

### 2. PKCS#11 Compliance
- Handle-based API follows standard (no raw pointers to callers)
- Exception hierarchy maps PKCS#11 error domains
- Session state machine enforces PKCS#11 semantics
- Mechanism fallback ensures backwards compatibility

### 3. Policy Centralization
- CryptoEngine is the single signing policy point
- All mechanisms route through one place (no bypasses)
- Fail-closed fallback (incompatible request → native algorithm)
- Auditability (actual mechanism recorded in ledger)

### 4. Testability
- Dependency injection (clock) enables frozen-time testing
- Facade + core separation allows unit testing of logic
- Non-copyable design prevents accidental state sharing

### 5. Failure Semantics
- Exceptions are semantic (HsmException vs. DbError)
- Macros embed source location (no manual attribution)
- RAII guarantees cleanup (no resource leaks)
- Type safety at compile time (concepts prevent wrong EVP types)

---

## Files Modified (15 Total)

### Core Module (4 files)
- `src/core/types.h` — Type system + PKCS#11 constants
- `src/core/error.h` — Exception hierarchy + validation macros
- `src/core/secure_buffer.h` — Memory locking + secure zeroing
- `src/core/hsm_clock.h` — Clock abstraction + dependency injection

### Crypto Module (7 files)
- `src/crypto/ctx_guard.h` — RAII OpenSSL context cleanup
- `src/crypto/crypto_engine.h` — Fail-closed policy orchestration
- `src/crypto/secure_rng.h` — Thread-safe RNG wrapper
- `src/crypto/ctr_drbg_aes256.h` — NIST SP 800-90A DRBG
- `src/crypto/aes_gcm.h` — Authenticated encryption
- `src/crypto/rsa.h` — RSA utilities
- `src/crypto/ecc.h` — Elliptic Curve utilities

### Session Module (4 files)
- `src/session/session_manager.h` — Handle-based session registry
- `src/session/session.h` — PKCS#11 session state machine
- `src/session/sign_context.h` — Multi-part signing context
- `src/session/find_context.h` — Object search iterator

**Total WHY comments added**: ~350+ comments across ~4000+ lines of code

---

## Next Steps

1. **Code Review**: Team reviews production documents + WHY comments
2. **Standards Enforcement**: Enforce "WHY before WHAT" in new code (pre-commit hooks)
3. **Onboarding**: New engineers read this guide first (before diving into code)
4. **Maintenance**: Update WHY comments when design decisions change
5. **Audit Trail**: Comments serve as design documentation for compliance audits

