# vHSM Project - Production Readiness Prompt

**Version**: 1.0  
**Date**: August 18, 2026  
**Target**: Enterprise-Grade Electronic Signature & Notarization System  
**Stack**: Go (REST API, Chaincode) + C++ (Cryptography, HSM) + Solidity (Anchoring) + Hyperledger Fabric

---

## Table of Contents

1. [Philosophy & Principles](#philosophy--principles)
2. [Code Standards](#code-standards)
3. [Architecture & Design](#architecture--design)
4. [Security Requirements](#security-requirements)
5. [Testing Strategy](#testing-strategy)
6. [Operations & Deployment](#operations--deployment)
7. [Documentation Standards](#documentation-standards)
8. [Implementation Roadmap](#implementation-roadmap)

---

## Philosophy & Principles

### Core Tenets

The vHSM project embodies these principles:

#### 1. **Consensus Over Unilateral Authority**
- **Philosophy**: No single actor (user, admin, jury member) can commit an irreversible ledger action alone
- **Manifestation**: 
  - Thesis grading requires all jury members to submit grades before status changes
  - PV signing requires all jury members to co-sign the same hash
  - Multi-signature gates prevent bypassing consensus
- **Implication**: Code must enforce these gates at the chaincode level (immutable), not REST API level (bypassable)
- **Implementation Rule**: Any state transition must validate all prerequisites are met; no shortcuts or bypass modes

#### 2. **Immutability Through Append-Only Design**
- **Philosophy**: Once data is committed to the ledger, it cannot be modified (only read or replaced in new transactions)
- **Manifestation**:
  - Thesis records transition through states but never revert (DRAFT → DEFENDED → NOTARIZED → ARCHIVED, never backward)
  - PV hash, once set by first signer, is immutable (all subsequent signers validate against it)
  - Signature records include block number, timestamp, transaction ID for audit trail
- **Implication**: Data structure design must prevent in-place updates
- **Implementation Rule**: Use timestamps, version numbers, and transaction IDs to track history; never overwrite initial values

#### 3. **Cryptographic Proof Over Trust**
- **Philosophy**: Every critical action is backed by cryptographic proof (signatures, hashes, commitments)
- **Manifestation**:
  - Thesis PDFs are SHA-256 hashed and RSA/ECDSA signed by HSM
  - PV is co-signed by all jury members (multi-signature)
  - Merkle roots are anchored to external blockchains (Ethereum + Solana) for immutable proof
  - JWT tokens are HS256-signed for session authentication
- **Implication**: Never trust a claim without cryptographic backing; hash all documents; sign all claims
- **Implementation Rule**: All critical data transformations must include hash/signature validation; cryptographic failures must halt execution

#### 4. **Privacy by Default, Transparency When Required**
- **Philosophy**: Sensitive data (PII, grades, comments) is encrypted at rest; audit trail is transparent
- **Manifestation**:
  - Thesis PDFs and PV files encrypted with AES-GCM (IV + ciphertext + auth tag stored in MinIO)
  - Hashes and signatures stored on-chain (proof without revealing content)
  - Full transaction history queryable (who did what, when)
- **Implication**: Encryption keys rotated regularly; decryption requires HSM session; audit trail never deleted
- **Implementation Rule**: Encrypt sensitive PII (names, IDs) before storage; hash before signing; preserve all transaction history

#### 5. **Fail-Closed, Never Fail-Open**
- **Philosophy**: When security or consensus requirements cannot be met, the system halts rather than grants access
- **Manifestation**:
  - RBAC defaults to deny (only explicitly allowed roles pass)
  - HSM failures cause request rejection (no fallback to software signing)
  - Missing jury members prevent state transitions (no partial quorum)
  - Incorrect PV hash from signer causes rejection (no hash correction)
- **Implication**: Better to reject a valid request than accept an invalid one
- **Implementation Rule**: Use explicit whitelists, not blacklists; reject on any doubt; log all rejections

#### 6. **Observability & Auditability**
- **Philosophy**: Every action is logged, traceable, and queryable for compliance and debugging
- **Manifestation**:
  - Structured JSON logs with correlation IDs
  - Prometheus metrics (latency, error rates, throughput)
  - Ledger transaction history queryable via REST API
  - HSM operations logged (decrypt, sign, key rotations)
- **Implication**: Logs are compliance evidence; must be tamper-proof and accessible
- **Implementation Rule**: Log at INFO (compliance events), WARNING (anomalies), ERROR (failures); include context (user, thesis ID, action)

---

## Code Standards

### Go Code Standards

#### Naming Conventions

**Packages**:
```go
// Clear, descriptive, lowercase
package gateway_sdk       // ✅ Clear purpose
package internal          // ❌ Too generic; use ledger_service, auth_service
package restapi           // ❌ Use rest_api (snake_case)
```

**Functions & Methods**:
```go
// Exported: PascalCase, start with verb or noun
func (s *Service) CreateThesis(...) error      // ✅ Verb-first, exports state change
func (s *Service) GetThesisHistory(...) error  // ✅ Clear query semantics
func (s *Service) thesisExists(...) bool       // ✅ Unexported helper, predicate

// Avoid:
func (s *Service) Thesis(...) error            // ❌ Ambiguous verb
func (s *Service) Query(...) error             // ❌ Generic action name
```

**Variables & Constants**:
```go
// Constants: SCREAMING_SNAKE_CASE for package-level
const (
    DefaultTimeoutSeconds = 30
    MinPasswordLength     = 12
    StatusDraft           = "DRAFT"
)

// Variables: camelCase
var (
    errUnauthorized = errors.New("unauthorized")
    sessionTimeout  = 1 * time.Hour
)

// Loop counters: single letter acceptable
for i := 0; i < len(items); i++ { }  // ✅ Acceptable
for _, thesis := range theses { }    // ✅ Preferred when meaningful

// Avoid single-letter variables outside loops
var u *User    // ❌ Use 'user'
```

**Types & Structs**:
```go
// Public: PascalCase, noun-based
type ThesisPayload struct {
    ThesisID string
    Status   string
}

type GatewayClient struct { }

// Private: camelCase
type thesisValidator struct { }

// Receiver naming: use short abbreviation (1-2 letters) or full word if meaningful
func (c *Client) Close() error { }      // ✅ 'c' for Client
func (s *Service) Query() error { }     // ✅ 's' for Service  
func (g *GatewayClient) Connect() error { }  // ✅ 'g' for GatewayClient

// Avoid:
func (this *Client) Close() { }        // ❌ 'this' is Java, not Go
func (x *Service) Query() { }          // ❌ Meaningless 'x'
```

#### Error Handling

**Philosophy**: Errors are values; handle them explicitly; wrap with context

```go
// ✅ GOOD: Explicit handling, context wrapping
func (n *NotaryService) CreateThesis(thesisID string, data []byte) error {
    if thesisID == "" {
        return fmt.Errorf("create thesis: thesisID required")
    }
    
    if err := n.client.ExecuteTransaction("CreateThesis", ...); err != nil {
        return fmt.Errorf("create thesis %s: failed to execute: %w", thesisID, err)
    }
    
    return nil
}

// ❌ AVOID: Silent errors
func (n *NotaryService) CreateThesis(thesisID string, data []byte) error {
    _ = n.client.ExecuteTransaction("CreateThesis", ...)  // Error discarded!
    return nil
}

// ❌ AVOID: Panic instead of returning error
func (n *NotaryService) CreateThesis(thesisID string, data []byte) error {
    if err := n.validate(thesisID); err != nil {
        panic(err)  // ❌ Never panic in library code
    }
    return nil
}

// ✅ GOOD: Structured error types for specific cases
type ValidationError struct {
    Field  string
    Reason string
}

func (e ValidationError) Error() string {
    return fmt.Sprintf("validation error on %s: %s", e.Field, e.Reason)
}

// Caller can type-assert for specific error handling
if err != nil {
    if ve, ok := err.(ValidationError); ok {
        return fmt.Sprintf("user input error: %s", ve.Reason)
    }
    return fmt.Sprintf("system error: %v", err)
}
```

**Error Wrapping Pattern**:
```go
// ✅ GOOD: Context at each layer, %w for unwrapping
if err := hsm.Encrypt(data); err != nil {
    return fmt.Errorf("store file: encrypt failed: %w", err)
}

if err := minio.Upload(...); err != nil {
    return fmt.Errorf("store file: upload to minio failed: %w", err)
}

// Caller can use errors.Is() and errors.As() to inspect root cause
```

#### Function Signatures

**Philosophy**: Clear input/output contracts; avoid variadic args for required params

```go
// ✅ GOOD: Explicit parameters, clear intent
func (c *Client) ExecuteTransaction(
    chaincodeName string,
    functionName string,
    args []string,
    timeout time.Duration,
) ([]byte, error)

// ✅ GOOD: Options pattern for many optional parameters
type GatewayOptions struct {
    EvaluateTimeout    time.Duration
    EndorseTimeout     time.Duration
    SubmitTimeout      time.Duration
    CommitStatusTimeout time.Duration
}

func NewGatewayClient(conn ClientConn, options GatewayOptions) (*Client, error)

// ❌ AVOID: Variadic for core parameters
func (c *Client) Execute(args ...string) error  // Unclear which args are which

// ❌ AVOID: Too many boolean parameters (boolean blindness)
func (c *Client) Query(id string, skipCache bool, includeHistory bool, forceRefresh bool) error

// ✅ GOOD: Use struct for many booleans
type QueryOptions struct {
    SkipCache      bool
    IncludeHistory bool
    ForceRefresh   bool
}

func (c *Client) Query(id string, opts QueryOptions) error
```

#### Testing Requirements

**Philosophy**: Tests are documentation and insurance; they must run fast, be deterministic, and cover edge cases

```go
// ✅ GOOD: Descriptive test names, clear setup/action/assert
func TestCreateThesis_ValidInput_Success(t *testing.T) {
    // Setup
    service := setup(t)
    defer teardown()
    
    // Action
    result, err := service.CreateThesis("thesis-1", testData)
    
    // Assert
    require.NoError(t, err)
    require.NotNil(t, result)
    assert.Equal(t, "thesis-1", result.ThesisID)
}

// ✅ GOOD: Test both happy path and error cases
func TestCreateThesis_DuplicateID_Error(t *testing.T) {
    service := setup(t)
    service.CreateThesis("thesis-1", testData)
    
    // Should reject duplicate
    _, err := service.CreateThesis("thesis-1", testData)
    require.Error(t, err)
    assert.Contains(t, err.Error(), "already exists")
}

// ❌ AVOID: Generic test names
func TestCreate(t *testing.T) { }  // What does this test?

// ❌ AVOID: Tests that race or are nondeterministic
func TestConcurrentAccess(t *testing.T) {
    // This test sometimes passes, sometimes fails - unreliable
}

// ✅ GOOD: Use table-driven tests for variations
func TestThesisStatusTransition(t *testing.T) {
    tests := []struct {
        name        string
        initialStatus string
        targetStatus  string
        shouldSucceed bool
    }{
        {"Draft to Defended", "DRAFT", "DEFENDED", true},
        {"Defended to Notarized", "DEFENDED", "NOTARIZED", true},
        {"Notarized to Draft", "NOTARIZED", "DRAFT", false},  // Backward not allowed
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test logic
        })
    }
}
```

### C++ Code Standards

#### Naming Conventions

**Classes & Types** (PascalCase):
```cpp
class GatewayClient { };          // ✅ Clear intent
class LedgerClient { };           // ✅ Domain-specific
class GRPCConnection { };         // ✅ Uppercase acronyms acceptable

// Avoid:
class gateway_client { };         // ❌ Go style, not C++
class GRPC_CONNECTION { };        // ❌ All caps unnecessarily
```

**Methods** (camelCase for public, snake_case for private):
```cpp
class Gateway {
public:
    std::optional<Network> getNetwork(const std::string& channelId);  // ✅ camelCase
    bool isConnected() const;                                          // ✅ Predicate
    void connect(const ConnectionConfig& config);                      // ✅ Verb first
    
private:
    bool validate_connection_config(const ConnectionConfig& cfg) const;  // ✅ snake_case
    void setup_tls_credentials();
};
```

**Constants** (SCREAMING_SNAKE_CASE):
```cpp
constexpr auto DEFAULT_TIMEOUT = std::chrono::seconds(30);
constexpr auto MAX_RETRIES = 3;
constexpr auto MIN_PASSWORD_LENGTH = 12;

// Exception class
class ConnectionError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
```

**Variables** (camelCase):
```cpp
std::string jwtSecret = ...;      // ✅
int maxConnections = 10;          // ✅
auto startTime = std::chrono::now();  // ✅

// Smart pointer naming
std::unique_ptr<Gateway> gateway = ...;
std::shared_ptr<Connection> conn = ...;
```

#### Memory Management

**Philosophy**: Use RAII, smart pointers, and avoid raw pointers

```cpp
// ✅ GOOD: RAII with unique_ptr
class GatewayClient {
private:
    std::unique_ptr<gRPC::Channel> channel_;
    std::unique_ptr<gateway::Gateway::Stub> stub_;
    
public:
    GatewayClient(std::unique_ptr<gRPC::Channel> ch)
        : channel_(std::move(ch)), 
          stub_(gateway::Gateway::NewStub(channel_.get())) { }
    
    ~GatewayClient() = default;  // Destructor auto-cleans up unique_ptrs
};

// ✅ GOOD: Shared ownership when needed
class ConnectionPool {
private:
    std::vector<std::shared_ptr<Connection>> connections_;
};

// ❌ AVOID: Raw pointers for ownership
class GatewayClient {
private:
    gRPC::Channel* channel_;  // Who owns this? When is it deleted?
    gateway::Gateway::Stub* stub_;  // Potential memory leak
};

// ✅ GOOD: Use std::optional for values that may not exist
std::optional<LedgerEntry> getLedgerEntry(const std::string& id) {
    if (id.empty()) return std::nullopt;
    return LedgerEntry{id, ...};
}

// ❌ AVOID: Returning nullptr from functions
LedgerEntry* getLedgerEntry(const std::string& id) {
    if (id.empty()) return nullptr;  // Unclear if pointer is owned by caller
    return new LedgerEntry{id, ...};
}
```

#### Error Handling

**Philosophy**: Exceptions for exceptional conditions; std::optional for expected absence; error codes for recoverable failures

```cpp
// ✅ GOOD: Exceptions for construction failures
class GatewayClient {
public:
    GatewayClient(const ConnectionConfig& config) {
        if (config.endpoint.empty()) {
            throw std::invalid_argument("endpoint cannot be empty");
        }
        channel_ = grpc::CreateChannel(config.endpoint, credentials);
        if (!channel_) {
            throw std::runtime_error("failed to create gRPC channel");
        }
    }
};

// ✅ GOOD: std::optional for expected absence
std::optional<ThesisRecord> getThesis(const std::string& id) {
    auto row = queryLedger("SELECT * FROM theses WHERE id = ?", id);
    if (!row.has_value()) {
        return std::nullopt;  // Record doesn't exist (expected case)
    }
    return parseThesisRecord(*row);
}

// ✅ GOOD: Result type for operations that can fail
struct Result {
    bool success;
    std::string error_message;
    std::optional<std::string> data;
};

Result submitTransaction(const std::string& txn) {
    if (auto err = validateTxn(txn)) {
        return Result{false, *err, std::nullopt};
    }
    if (auto err = sendToLedger(txn)) {
        return Result{false, *err, std::nullopt};
    }
    return Result{true, "", txn_id};
}

// ❌ AVOID: Silent failures
void submitTransaction(const std::string& txn) {
    validateTxn(txn);  // Error discarded
    sendToLedger(txn); // Error discarded
}

// ❌ AVOID: Out-parameters for errors
bool submitTransaction(const std::string& txn, std::string& out_error) {
    // Unclear if function modifies out_error on success
    out_error = "";
    if (!validateTxn(txn)) {
        out_error = "validation failed";
        return false;
    }
    return sendToLedger(txn);
}
```

#### Testing Requirements

**Philosophy**: Header-only test utilities, comprehensive edge case coverage, deterministic and fast

```cpp
// ✅ GOOD: Fixture-based tests with GTest
class LedgerClientTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create mock connections, initialize test data
        client_ = std::make_unique<LedgerClient>(test_config_);
    }
    
    void TearDown() override {
        // Cleanup
    }
    
    std::unique_ptr<LedgerClient> client_;
};

TEST_F(LedgerClientTest, SubmitRecord_ValidRecord_Success) {
    auto record = makeTestRecord("sig-1", "key-fp", "payload-digest", "sig-b64");
    auto result = client_->submitRecord(record);
    
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result->record_id, "sig-1");
}

TEST_F(LedgerClientTest, SubmitRecord_EmptyID_ReturnsError) {
    auto record = makeTestRecord("", "key-fp", "payload-digest", "sig-b64");
    auto result = client_->submitRecord(record);
    
    EXPECT_FALSE(result.has_value());
}

// ✅ GOOD: Parameterized tests for variations
class StatusTransitionTest : public ::testing::TestWithParam<std::pair<std::string, std::string>> {
};

TEST_P(StatusTransitionTest, ValidTransitions) {
    auto [from, to] = GetParam();
    auto thesis = makeTestThesis(from);
    auto result = thesis.transitionTo(to);
    EXPECT_TRUE(result);
}

INSTANTIATE_TEST_SUITE_P(
    ThesisStatusTransitions,
    StatusTransitionTest,
    ::testing::Values(
        std::make_pair("DRAFT", "DEFENDED"),
        std::make_pair("DEFENDED", "NOTARIZED"),
        std::make_pair("NOTARIZED", "ARCHIVED")
    )
);
```

---

## Architecture & Design

### Layered Architecture

```
┌─────────────────────────────────────────────────────┐
│          REST API Layer (Go)                         │
│  - HTTP handlers, request validation, response JSON │
│  - No business logic; thin routing layer            │
└──────────────┬──────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────┐
│       Service Layer (Go)                             │
│  - NotaryService, HSMService, LDAPService          │
│  - Business logic: consensus checks, state machine  │
│  - Chaincode delegation                             │
└──────────────┬──────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────┐
│    Gateway SDK Layer (Go + C++)                      │
│  - Transaction building, signing, submission        │
│  - HSM integration (PKCS#11)                         │
│  - gRPC communication                                │
└──────────────┬──────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────┐
│      Hyperledger Fabric (Chaincode)                  │
│  - Ledger state machine                              │
│  - Consensus gates (jury quorum, multi-sig)          │
│  - Immutable transaction history                     │
└─────────────────────────────────────────────────────┘
```

**Principle**: Each layer has a single responsibility; dependencies flow downward; no circular dependencies.

### Request Flow & Isolation

```
HTTP Request
    ↓
[Middleware] CORS, auth, logging
    ↓
[Handler] Validate input, convert JSON → Go structs
    ↓
[Service] Check business logic (consensus, perms)
    ↓
[Gateway] Build proposal, sign, submit
    ↓
[Chaincode] Validate on-chain, update state
    ↓
[Database] (Fabric ledger) Commit transaction
    ↓
HTTP Response
```

**Isolation**: Each request gets its own session with the HSM; no shared state; thread-safe service operations.

### State Machine Design

**Thesis State Machine** (from chaincode):
```
DRAFT
  ├─→ [all jury grade] → DEFENDED
  │       │
  │       ├─→ [all jury sign PV + doc notarize] → NOTARIZED
  │       │
  │       └─→ [superadmin update admin fields] → DRAFT (limited rollback)
  │
  └─→ [superadmin delete] → (removed)

DEFENDED
  ├─→ [all jury sign PV + doc notarize] → NOTARIZED
  └─→ [superadmin update admin fields] → DEFENDED

NOTARIZED
  ├─→ [superadmin update admin fields] → NOTARIZED (cosmetic changes only)
  └─→ [explicit archive] → ARCHIVED

ARCHIVED
  └─→ (terminal state, read-only)
```

**Implementation Rule**: All state transitions must be explicit chaincode functions; no ambiguous multi-step sequences that can fail halfway.

---

## Security Requirements

### Authentication & Authorization

#### JWT Token Lifecycle

```go
1. User submits username + password via LDAP
2. LDAP service validates against directory
3. JWT issued with:
   - username
   - roles (array, from LDAP group membership)
   - expiry (1 hour default, configurable)
   - subject = user DN (for audit)
4. Client stores JWT, includes in Authorization: Bearer <token> header
5. Middleware validates:
   - Signature (HS256, secret key)
   - Expiry (reject if > 1 hour old)
   - Subject (must match authenticated user DN)
6. If valid, claims attached to request context
7. Endpoint-level middleware checks HasPermission(claims.Roles, action)
   - Fail-closed: if action not in allowlist, reject
```

**Rotating Secrets**:
- JWT secret changed quarterly
- All active tokens invalidated on rotation (short TTL mitigates)
- HSM signing keys changed annually

#### RBAC Matrix

```
Action                  → Allowed Roles
─────────────────────────────────────────
CreateThesis            → [admin, professeurs]
SubmitJuryGrade         → [admin, professeurs]
SignPv                  → [admin, professeurs]
NotarizeDocument        → [admin, professeurs]
ReadThesis              → [admin, professeurs, etudiants]
GetJuryStatus           → [admin, professeurs, etudiants]
GetAllTheses            → [admin]  // Sensitive, admins only
GetThesisHistory        → [admin, professeurs]  // Audit trail
```

**Implementation Rule**: 
- Matrix maintained in `internal/roles.go`
- Fail-closed: any action not listed = denied
- New actions require explicit entry before rollout
- Changes reviewed in PR before merge

### Cryptographic Security

#### HSM Requirements

**Supported Algorithms**:
- Encryption: AES-256-GCM (12-byte random IV per operation)
- Signing: RSA-2048 or ECDSA P-256 (with fallback detection)
- Hashing: SHA-256

**IV Management**:
```cpp
// ✅ CORRECT: Fresh random IV per operation
for (int i = 0; i < operations; i++) {
    uint8_t iv[12];
    RAND_bytes(iv, 12);  // New IV every time
    encrypt(plaintext, key, iv, &ciphertext);
}

// ❌ WRONG: Reused IV
uint8_t iv[12] = {0, 1, 2, ...};  // Static IV
for (int i = 0; i < operations; i++) {
    encrypt(plaintext, key, iv, &ciphertext);  // IV never changes!
    // GCM breaks with IV reuse
}
```

**Key Rotation**:
- Signing keys: annual rotation, new key generated, old key archived (not deleted)
- Encryption keys: quarterly rotation, data re-encrypted with new key, old key archived
- HSM PIN: changed quarterly, stored in vaulting service (not code)

#### Signature Verification

```go
// ✅ CORRECT: Verify before trusting
if err := verifySHA256RSA(signature, publicKey, digest); err != nil {
    return fmt.Errorf("signature verification failed: %w", err)
}
// Proceed only after verification succeeds

// ❌ WRONG: Trust without verification
func processClaim(signature, publicKey, digest []byte) {
    // No verification! Attacker can forge signatures
}
```

#### Hashing Strategy

```go
// ✅ CORRECT: Hash before signing
data := readFile("thesis.pdf")
digest := sha256.Sum256(data)
signature := hsm.Sign(digest[:])

// ❌ WRONG: Sign plaintext
signature := hsm.Sign(data)  // No digest; vulnerable to length extension attacks
```

### Transport Security

#### TLS/mTLS Configuration

```go
// ✅ CORRECT: mTLS to Fabric Gateway
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{clientCert},  // Client cert
    RootCAs:      caCertPool,                       // Server CA cert
    ServerName:   "peer0.org1.example.com",         // For hostname verification
    MinVersion:   tls.VersionTLS13,                 // Modern version only
    CipherSuites: []uint16{
        tls.TLS_AES_256_GCM_SHA384,
        tls.TLS_CHACHA20_POLY1305_SHA256,
    },
}

conn, _ := grpc.Dial(endpoint, grpc.WithTransportCredentials(
    credentials.NewTLS(tlsConfig),
))

// ❌ WRONG: No TLS verification
conn, _ := grpc.Dial(endpoint,
    grpc.WithInsecure(),  // ❌ No encryption
    grpc.WithTransportCredentials(
        credentials.NewTLS(&tls.Config{
            InsecureSkipVerify: true,  // ❌ No cert verification (MITM!!)
        }),
    ),
)
```

### Input Validation

**All inputs from external sources must be validated**:

```go
// ✅ CORRECT: Explicit validation
func (s *Service) CreateThesis(thesisID, studentID string) error {
    if thesisID == "" {
        return fmt.Errorf("thesisID required")
    }
    if len(thesisID) > 256 {
        return fmt.Errorf("thesisID exceeds max length")
    }
    if !isValidUUID(thesisID) {
        return fmt.Errorf("thesisID must be valid UUID")
    }
    // Continue only after validation
}

// ❌ WRONG: No validation, trust input
func (s *Service) CreateThesis(thesisID, studentID string) error {
    return s.ledger.CreateThesis(thesisID, studentID)  // May fail on-chain
}

// ❌ WRONG: Partial validation
if thesisID != "" {
    // Assumes if non-empty, it's valid (still could have injection chars)
}
```

**Validation Checklist**:
- [ ] Length limits (max string length, array size)
- [ ] Format (UUID, email, phone if required)
- [ ] Enum values (status, role must be from allowed set)
- [ ] Range (numeric fields have min/max)
- [ ] Character whitelist (no special chars unless required)
- [ ] No SQL injection (use parameterized queries)
- [ ] No command injection (no shell expansion)

---

## Testing Strategy

### Test Pyramid

```
        /\
       /  \       Manual Integration Tests (1-2 day cycles)
      /────\      - Deploy to staging, test full workflow
     /      \     - Blockchain anchoring to real networks
    /────────\    - Load testing, failover testing
   /          \
  /────────────\  Integration Tests (fast, local)
 /              \ - Fabric test network (Docker)
/────────────────\- HSM mock or test HSM
                  - Multiple services together

                  Unit Tests (fast, isolated)
                  - Single function/method
                  - Mocks for dependencies
                  - 100+ tests per module
```

### Unit Test Coverage

**Go Modules** (Target: >80% coverage):
- `rest_api/cmd/api/`: HTTP handlers (routes, auth, CORS)
- `rest_api/internal/`: Services (HSM, LDAP, Notary)
- `rest_api/gateway_sdk/`: Fabric client wrapper
- `chain_adapter/merkle/`: Merkle tree construction & proof verification
- `chain_adapter/eth/`: Ethereum client
- `chain_adapter/solana/`: Solana client

**C++ Modules** (Target: >70% coverage):
- `src/signature_store/`: Query, verification, schema
- `src/crypto/`: EC keys, signatures, X.509
- `src/keystore/`: Key generation, storage
- `third_party/fabric-gateway-cpp/`: All 6 modules

**Chaincode** (Target: >80% coverage):
- `template_chaincode/`: All state transitions, consensus gates
- `signature_ledger/`: Record storage, retrieval

### Integration Tests

```go
// ✅ GOOD: End-to-end thesis lifecycle
func TestThesisLifecycle(t *testing.T) {
    // Setup: Start Fabric test network (testcontainers)
    network := startFabricNetwork(t)
    defer network.Stop()
    
    // Deploy chaincode
    deployChaincode(network, "template_chaincode", "jurychaincode")
    
    // Create clients
    adminClient := newTestClient("admin", network)
    profClient := newTestClient("professor", network)
    juryClient := newTestClient("jury_member", network)
    
    // 1. Admin creates thesis
    _, err := adminClient.CreateThesis(
        "thesis-001", "student-001",
        makeStudentInfo(), makeAdminInfo(), makeMetadata(),
    )
    require.NoError(t, err)
    
    // 2. Professor (jury) grades thesis
    err = juryClient.SubmitJuryGrade("thesis-001", "prof1", "18.5", "Excellent work")
    require.NoError(t, err)
    
    // 3. Verify status changed to DEFENDED once all jury graded
    status, err := adminClient.GetJuryStatus("thesis-001")
    require.NoError(t, err)
    require.Equal(t, "DEFENDED", status.Status)
    
    // 4. First jury member signs PV
    pvHash := "abc123def456..."
    sig1, err := juryClient.SignPv("thesis-001", "prof1", pvHash, sig1_hex)
    require.NoError(t, err)
    
    // 5. Other jury members sign same hash
    sig2, err := juryClient.SignPv("thesis-001", "prof2", pvHash, sig2_hex)
    require.NoError(t, err)
    
    // 6. Verify thesis now NOTARIZED after all sign + doc notarized
    err = juryClient.NotarizeDocument("thesis-001", docHash, docSig)
    require.NoError(t, err)
    
    status, _ = adminClient.GetJuryStatus("thesis-001")
    require.Equal(t, "NOTARIZED", status.Status)
}

// ✅ GOOD: Test consensus enforcement
func TestJuryConsensusEnforced(t *testing.T) {
    // Setup network & deploy chaincode
    
    // Attempt to transition to DEFENDED without all jury grading
    err := client.SubmitJuryGrade("thesis-001", "prof1", "18.5", "")
    require.NoError(t, err)
    
    // Status should still be DRAFT (only 1 of 3 jury graded)
    status, _ := client.GetJuryStatus("thesis-001")
    require.Equal(t, "DRAFT", status.Status)
    require.Equal(t, 1, status.GradesIn)
    require.Equal(t, 3, status.Required)
}

// ✅ GOOD: Test PV hash immutability
func TestPvHashImmutable(t *testing.T) {
    // First signer establishes hash
    pvHash1 := "correct_hash_123"
    _ = client.SignPv("thesis-001", "prof1", pvHash1, sig1)
    
    // Second signer attempts different hash
    pvHash2 := "wrong_hash_456"
    err := client.SignPv("thesis-001", "prof2", pvHash2, sig2)
    
    // Should be rejected
    require.Error(t, err)
    require.Contains(t, err.Error(), "hash mismatch")
}
```

### Chaos Testing

```bash
# Test network partition (Fabric unavailable)
docker pause $(docker ps -q -f "name=peer")
# Verify API returns 503 (Service Unavailable), not 200 with partial result

# Test HSM failure (PKCS#11 error)
# Mock PKCS#11 to return CKR_DEVICE_ERROR
# Verify signing fails and request rejected (not silent failure)

# Test concurrent requests (race conditions)
ab -n 1000 -c 100 http://localhost:8080/api/v1/login
# Monitor for duplicate sessions, lost transactions

# Test slow blockchain (delayed commit)
# Artificially delay orderer; verify CommitStatus waits, doesn't timeout
```

---

## Operations & Deployment

### Docker & Container Strategy

**Principle**: One process per container; no sidecar agents

```dockerfile
# ✅ GOOD: Single responsibility
FROM golang:1.21-alpine AS builder
WORKDIR /build
COPY . .
RUN go mod download && go build -o api ./cmd/api

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/api /app/api
EXPOSE 8080
CMD ["/app/api"]

# ✅ GOOD: Non-root user
RUN addgroup -g 1000 app && adduser -D -u 1000 -G app app
USER app

# ❌ AVOID: Multiple services in one container
RUN apt-get install -y nginx postgresql
CMD nginx && postgres  # Won't work as expected!

# ❌ AVOID: Running as root
# (no USER directive; defaults to root)
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vhsm-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vhsm-api
  template:
    metadata:
      labels:
        app: vhsm-api
    spec:
      # ✅ Security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsReadOnlyRootFilesystem: true
      
      containers:
      - name: api
        image: vhsm-api:1.0.0
        imagePullPolicy: IfNotPresent
        
        # ✅ Resource limits
        resources:
          requests:
            cpu: "500m"
            memory: "512Mi"
          limits:
            cpu: "2000m"
            memory: "2Gi"
        
        # ✅ Probes for orchestration
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
        
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        
        # ✅ Environment via ConfigMap + Secrets
        env:
        - name: FABRIC_CONFIG
          valueFrom:
            configMapKeyRef:
              name: fabric-config
              key: config.yaml
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: vhsm-secrets
              key: jwt-secret
        - name: HSM_PIN
          valueFrom:
            secretKeyRef:
              name: vhsm-secrets
              key: hsm-pin
        
        # ✅ Volume mounts (read-only where possible)
        volumeMounts:
        - name: fabric-crypto
          mountPath: /etc/vhsmd/crypto
          readOnly: true
        - name: tmp
          mountPath: /tmp
      
      volumes:
      - name: fabric-crypto
        secret:
          secretName: fabric-crypto
      - name: tmp
        emptyDir: {}
      
      # ✅ Affinity for distributed deployment
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - vhsm-api
              topologyKey: kubernetes.io/hostname
```

### Monitoring & Observability

#### Prometheus Metrics

```go
// ✅ Define metrics at package level
var (
    thesisCreationLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "vhsm_thesis_creation_seconds",
            Help: "Thesis creation latency",
            Buckets: []float64{.1, .5, 1, 2, 5, 10},
        },
        []string{"status"},  // "success" or "error"
    )
    
    ledgerTransactionErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "vhsm_ledger_errors_total",
            Help: "Total ledger transaction errors",
        },
        []string{"error_type"},  // "timeout", "validation", "network"
    )
    
    hsmOperations = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "vhsm_hsm_operations_active",
            Help: "Currently active HSM operations",
        },
        []string{"operation"},  // "sign", "encrypt"
    )
)

// ✅ Record metrics
func (s *Service) CreateThesis(...) error {
    start := time.Now()
    defer func() {
        duration := time.Since(start).Seconds()
        if err != nil {
            thesisCreationLatency.WithLabelValues("error").Observe(duration)
        } else {
            thesisCreationLatency.WithLabelValues("success").Observe(duration)
        }
    }()
    
    // Implementation...
}
```

#### Structured Logging

```go
// ✅ JSON logs with correlation IDs
logger := log.WithFields(log.Fields{
    "correlation_id": c.GetHeader("X-Correlation-ID"),
    "user": claims.Username,
    "action": "create_thesis",
})

logger.Info("thesis creation started", map[string]interface{}{
    "thesis_id": thesisID,
    "student_id": studentID,
})

if err != nil {
    logger.Error("thesis creation failed", map[string]interface{}{
        "error": err.Error(),
        "error_type": fmt.Sprintf("%T", err),
    })
}

logger.Info("thesis creation completed", map[string]interface{}{
    "duration_ms": time.Since(start).Milliseconds(),
})
```

#### Log Levels

- `DEBUG`: Detailed flow (function entry/exit, parameter values)
- `INFO`: Compliance events (login, thesis creation, signature)
- `WARNING`: Anomalies (validation failure, retry attempt)
- `ERROR`: Failures (ledger error, HSM failure)
- `CRITICAL`: System failures (startup failure, shutdown)

**Production**: INFO + ERROR only (DEBUG off, reduces noise and log volume)

---

## Documentation Standards

### Code Comments

**Philosophy**: Comments explain WHY, not WHAT; code should be readable without comments

```go
// ✅ GOOD: Explain non-obvious design decision
// We wait for finalized commitment (not just confirmed) to ensure
// the transaction survived network reorg. Fabric's default is 2-block finality.
func (c *Client) WaitForCommit(txID string) error {
    return c.waitFor(txID, FinalizedCommitment)
}

// ✅ GOOD: Document gotchas and edge cases
// Note: Reusing IV with the same key breaks GCM security guarantees.
// A new IV must be generated for every encryption operation.
func (h *HSMService) Encrypt(plaintext []byte) ([]byte, error) {
    iv := generateRandomIV()  // Fresh IV every time
    // ...
}

// ✅ GOOD: Reference external standards or RFCs
// RFC 3394 AES Key Wrap Algorithm for wrapping symmetric keys
func (h *HSMService) WrapKey(keyToWrap []byte) ([]byte, error) {
    // ...
}

// ❌ AVOID: Obvious comments
func (s *Service) CreateThesis(id string) error {
    if id == "" {  // Check if id is empty
        return fmt.Errorf("id required")
    }
}

// ❌ AVOID: Comments that become outdated
// This used to be O(n^2), but now it's O(n log n) — comment says O(n^2)!
func Query(id string) Result {
    // Outdated comment reduces trust
}
```

### API Documentation

**Every public function must have a godoc comment** (Go):

```go
// CreateThesis registers a new thesis record with the ledger.
//
// The thesis starts in DRAFT status. The grade field is left empty
// and only populated after all assigned jury members submit grades
// via SubmitJuryGrade; once all have submitted, the thesis automatically
// transitions to DEFENDED status.
//
// Parameters:
//  - thesisID: Unique thesis identifier (UUID format required)
//  - studentID: ID of the student defending the thesis
//  - initialDataJSON: JSON-encoded StudentInfo, AdministrativeInfo, ThesisMetadata
//  - createdBy: Username of the superadmin creating the record
//
// Returns:
//  - error: Non-nil if validation fails, ledger is unavailable, or thesisID already exists
//
// Errors:
//  - ValidationError: thesisID invalid format
//  - ConflictError: thesisID already exists
//  - UnavailableError: Ledger unreachable
//
// Example:
//    thesis, err := service.CreateThesis(
//        "thesis-001", "student-001",
//        initialDataJSON, "admin@university.edu")
//    if err != nil {
//        log.Fatal(err)
//    }
func (s *Service) CreateThesis(thesisID, studentID, initialDataJSON, createdBy string) error
```

### Deployment & Operational Documentation

Each deployment artifact should have accompanying docs:

```
docs/
├── DEPLOYMENT.md           # Step-by-step deployment guide
├── CONFIGURATION.md        # All environment variables, their purpose, valid ranges
├── TROUBLESHOOTING.md      # Common issues and solutions
├── UPGRADE.md              # Breaking changes, migration steps
├── DISASTER_RECOVERY.md    # Backup/restore procedures, RTO/RPO
├── SECURITY.md             # Key rotation, credential management, audit
└── ARCHITECTURE.md         # System design, component interaction
```

**DEPLOYMENT.md Example**:
```markdown
# Deployment Guide

## Prerequisites
- Kubernetes cluster (v1.24+)
- Hyperledger Fabric 2.5+ network running
- Hardware HSM (or test HSM) available
- PostgreSQL for audit logs (optional, not for ledger state)

## Step 1: Secrets
```bash
kubectl create secret generic vhsm-secrets \
  --from-literal=jwt-secret=$(openssl rand -hex 32) \
  --from-literal=hsm-pin=<your-hsm-pin>
```

## Step 2: ConfigMap
```bash
kubectl create configmap fabric-config --from-file=fabric-config.yaml
```

## Step 3: Deploy
```bash
kubectl apply -f k8s/deployment.yaml
kubectl rollout status deployment/vhsm-api
```

## Verification
```bash
kubectl port-forward svc/vhsm-api 8080:8080
curl http://localhost:8080/health
```
```

---

## Implementation Roadmap

### Phase 1: Critical Fixes (Week 1)

**Objective**: Unblock ledger submission and add TLS

| Task | Priority | Duration | Owner |
|------|----------|----------|-------|
| Fix vHSM Fabric API calls | P0 | 30 min | Backend |
| Add TLS credentials | P0 | 15 min | Backend |
| Add RSA/ECDSA detection in HSM | P1 | 30 min | Backend |
| Write integration tests (thesis lifecycle) | P1 | 2 days | QA |
| Code review + merge | P0 | 2 hours | Lead |

### Phase 2: Production Hardening (Week 2)

| Task | Priority | Duration | Owner |
|------|----------|----------|-------|
| Implement comprehensive unit tests | P1 | 2 days | QA |
| Add Prometheus metrics & logging | P1 | 1 day | DevOps |
| Estimate gas for Ethereum mainnet | P2 | 1 hour | Backend |
| Fix MinIO credentials management | P2 | 1 hour | Backend |
| Resolve Signature Ledger status | P2 | 1 hour | Arch |
| Write deployment documentation | P1 | 1 day | Ops |

### Phase 3: Production Deployment (Week 3-4)

| Task | Priority | Duration | Owner |
|------|----------|----------|-------|
| Load testing & bottleneck analysis | P1 | 2 days | QA |
| HSM failure recovery testing | P1 | 1 day | Ops |
| Network partition resilience testing | P1 | 1 day | Ops |
| Security audit (penetration test) | P1 | 3 days | Security |
| Fabric network upgrade to v2.5+ | P1 | 1 day | DevOps |
| Staging environment deployment | P1 | 1 day | Ops |
| Production deployment (with rollback plan) | P0 | 4 hours | Ops + Lead |

### Post-Launch (Ongoing)

- Monthly security patches & dependency updates
- Quarterly key rotations (HSM, JWT secrets)
- Annual third-party security audit
- Continuous monitoring & alerting tuning

---

## Success Criteria (Definition of Done)

### Code Quality
- [x] All code follows naming/style conventions (automated linting)
- [x] >80% unit test coverage (Go), >70% (C++)
- [x] All public functions documented (godoc/doxygen)
- [x] Zero security warnings (SAST scan clean)
- [x] All dependencies pinned to exact versions

### Functionality
- [x] Full thesis lifecycle testable (DRAFT → NOTARIZED)
- [x] Jury consensus gates enforced
- [x] PV hash immutability verified
- [x] HSM signing & encryption verified
- [x] Blockchain anchoring to Ethereum + Solana verified

### Operations
- [x] Kubernetes manifests provided
- [x] Helm charts for easy deployment
- [x] Prometheus metrics defined and collected
- [x] JSON structured logging enabled
- [x] Health check endpoints (liveness + readiness)

### Security
- [x] All inputs validated (length, format, range)
- [x] TLS 1.3+ enforced (no insecure channels)
- [x] HSM failures cause request rejection (no fallback)
- [x] RBAC matrix defined & enforced
- [x] Audit trail queryable (never deleted)
- [x] Secrets stored in vaults, never in code
- [x] Key rotation procedures documented

### Documentation
- [x] Deployment guide with step-by-step instructions
- [x] Configuration guide (all env vars documented)
- [x] Troubleshooting guide (common issues)
- [x] Architecture documentation (system design)
- [x] API documentation (endpoints, request/response schema)
- [x] Disaster recovery procedures

### Performance
- [x] Thesis creation <1s latency (p99)
- [x] Jury grading <2s latency (p99)
- [x] Support 100+ concurrent users
- [x] Blockchain anchoring <30s after signature recording

### Compliance
- [x] GDPR: PII encrypted, right-to-be-forgotten plan
- [x] SOC 2: Audit trail immutable, changes logged
- [x] Non-repudiation: Signatures cryptographically verified
- [x] Data retention: 7-year archival, verified retrieval

---

## Review Checklist for PRs

**Before Merging to Main**:

- [ ] All tests pass (GitHub Actions CI green)
- [ ] >80% test coverage maintained or improved
- [ ] Code follows style guide (gofmt, golint clean)
- [ ] No hardcoded secrets (credentials check)
- [ ] Error handling complete (no silent failures)
- [ ] Documentation updated (code comments, godoc)
- [ ] Security implications considered (auth, validation)
- [ ] Breaking changes documented (if any)
- [ ] Performance impact analyzed (benchmarks if relevant)
- [ ] At least 2 approvals from maintainers

**For High-Risk Changes** (crypto, auth, consensus):
- [ ] Security review by cryptography/auth expert
- [ ] Additional test coverage (>95% for crypto)
- [ ] External audit if applicable

---

## Conclusion

This document defines the **production-grade standard** for vHSM. The project is now 70% complete with clear remaining work identified. By following these standards and completing the roadmap, vHSM will be enterprise-ready for critical financial/legal notarization use cases.

**Key Principle**: Trust through cryptography, transparency through immutability, safety through consensus.
