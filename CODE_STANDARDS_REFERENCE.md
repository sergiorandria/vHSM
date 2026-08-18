# vHSM Code Standards - Quick Reference Card

**Print this out and keep it by your desk!**

---

## Go Naming Conventions

```go
// ✅ GOOD
const MaxRetries = 3              // Package-level const: PascalCase
const DefaultTimeout = 30         // Multi-word: CamelCase or InitialCaps
var sessionTimeout = time.Hour()  // Package-level var: camelCase

func CreateThesis(...) error { }  // Exported func: PascalCase + verb
func (s *Service) GetThesis(...) // Receiver: short (1-2 char) or clear
func getThesis(...) bool { }      // Unexported: camelCase
func (c *Client) isValid() bool { } // Unexported method: camelCase
func isJuryMember(...) bool { }   // Helper func: camelCase

type ThesisPayload struct { }      // Public type: PascalCase
type thesisValidator struct { }   // Private type: camelCase

for _, thesis := range theses { } // Iterate: use full name, not 't'
for i := 0; i < len(items); i++ { } // Counter: single letter OK in loops

// ❌ AVOID
const max_retries = 3             // snake_case (Go style is camelCase)
var u *User                       // Single letter outside loops
func query(...) error { }         // Ambiguous; use getThesis or query*By methods
type user struct { }              // Private type: still PascalCase
```

---

## Go Error Handling Pattern

```go
// ✅ GOOD
func (s *Service) CreateThesis(id string) error {
    if id == "" {
        return fmt.Errorf("create thesis: id required")  // Prefix with function
    }
    
    if err := s.ledger.CreateThesis(id); err != nil {
        return fmt.Errorf("create thesis: ledger failed: %w", err)  // Use %w for wrapping
    }
    
    return nil
}

// ❌ AVOID
func (s *Service) CreateThesis(id string) error {
    _ = s.ledger.CreateThesis(id)  // Error discarded!
    return nil
}

func (s *Service) CreateThesis(id string) {
    if err := s.ledger.CreateThesis(id); err != nil {
        panic(err)  // Never panic in library code
    }
}
```

---

## Go Testing Template

```go
// ✅ GOOD
func TestCreateThesis_ValidID_Success(t *testing.T) {
    // Setup
    service := NewTestService(t)
    defer service.Close()
    
    // Action
    err := service.CreateThesis("thesis-001")
    
    // Assert
    require.NoError(t, err)
    
    thesis, err := service.GetThesis("thesis-001")
    require.NoError(t, err)
    assert.Equal(t, "thesis-001", thesis.ID)
}

func TestCreateThesis_DuplicateID_Error(t *testing.T) {
    service := NewTestService(t)
    defer service.Close()
    
    service.CreateThesis("thesis-001")
    
    // Should reject duplicate
    err := service.CreateThesis("thesis-001")
    require.Error(t, err)
    assert.Contains(t, err.Error(), "already exists")
}

// ✅ GOOD: Table-driven
func TestThesisStatus(t *testing.T) {
    tests := []struct{
        name    string
        from    string
        to      string
        wantErr bool
    }{
        {"Draft to Defended", "DRAFT", "DEFENDED", false},
        {"Backward is invalid", "DEFENDED", "DRAFT", true},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // test logic
        })
    }
}
```

---

## C++ Naming Conventions

```cpp
// ✅ GOOD
const int DEFAULT_TIMEOUT = 30;           // Constant: SCREAMING_SNAKE_CASE
class GatewayClient { };                  // Class: PascalCase
void connect();                           // Method: camelCase
std::optional<Result> getResult();        // Return optional for absence
std::unique_ptr<Connection> conn_;        // Member: camelCase with _

// ❌ AVOID
const int default_timeout = 30;           // snake_case (C++ uses SCREAMING_SNAKE_CASE)
class gateway_client { };                 // Go style, not C++
void CONNECT();                           // All caps (not a constant)
Result* getResult();                      // Raw pointer (use optional or unique_ptr)
```

---

## C++ Memory Management

```cpp
// ✅ GOOD: RAII with unique_ptr
class Client {
private:
    std::unique_ptr<Channel> channel_;
public:
    Client(std::unique_ptr<Channel> ch) : channel_(std::move(ch)) { }
    ~Client() = default;  // Automatically cleans up
};

// ✅ GOOD: std::optional for absence
std::optional<Entry> getEntry(const std::string& id) {
    if (id.empty()) return std::nullopt;
    return Entry{id, ...};
}

// ❌ AVOID: Raw pointers
Channel* channel_;  // Who owns this? When is it deleted?

// ❌ AVOID: Returning nullptr
Entry* getEntry(const std::string& id) {
    if (id.empty()) return nullptr;
    return new Entry{...};  // Memory leak!
}
```

---

## C++ Error Handling

```cpp
// ✅ GOOD: Exceptions for exceptional conditions
class Client {
public:
    Client(const ConnectionConfig& cfg) {
        if (cfg.endpoint.empty()) {
            throw std::invalid_argument("endpoint required");
        }
    }
};

// ✅ GOOD: std::optional for expected absence
std::optional<ThesisRecord> getThesis(const std::string& id) {
    auto row = queryLedger("SELECT * FROM theses WHERE id = ?", id);
    if (!row.has_value()) return std::nullopt;  // Not an error
    return parseThesis(*row);
}

// ❌ AVOID: Silent failures
void submitTransaction(const std::string& txn) {
    validateTxn(txn);  // Error discarded!
}

// ❌ AVOID: Out-parameters for errors
bool submit(const std::string& txn, std::string& out_error) {
    // Unclear if out_error is modified on success
}
```

---

## Security Checklist

```
Every PR must pass:

☐ Input Validation
  - Length limits checked
  - Format validated (UUID, email, etc.)
  - Enum values whitelisted
  - Range checks (min/max)
  - No SQL injection (parameterized queries)
  - No command injection

☐ Error Handling
  - All errors caught
  - Error messages don't leak secrets
  - Errors logged with context

☐ Cryptography
  - Hashing done before signing
  - IV freshness (never reused with same key)
  - Signature verification before trust
  - Random IV generation (not static)

☐ Authentication & Authorization
  - JWT validated on every request
  - Expiry checked
  - RBAC enforced (fail-closed)
  - Session timeout enforced

☐ HSM Operations
  - HSM failures = request rejection
  - No fallback to software signing
  - PIN not hardcoded
  - Key rotation procedures in place

☐ Logging
  - No passwords logged
  - No tokens logged
  - Correlation IDs included
  - Structured (JSON) format
```

---

## Testing Checklist

```
Every module must have:

☐ Unit Tests
  - >80% coverage (Go), >70% (C++)
  - Happy path test
  - Error case test (for each error type)
  - Edge case test (empty, null, max size)
  - Concurrency test (if concurrent)

☐ Integration Tests
  - Multi-service interaction
  - Ledger commit + verify
  - HSM sign + verify round-trip
  - Error recovery

☐ Security Tests
  - Invalid input rejection
  - Unauthorized access rejection
  - Wrong PV hash rejection
  - Missing jury member rejection
```

---

## Code Review Questions

**Ask yourself before submitting PR**:

1. **Naming**: Would someone reading this code know what each variable does without comments?
2. **Errors**: Are all errors caught and logged? Are error messages clear?
3. **Security**: Could this code accept invalid input? Could it leak secrets?
4. **Testing**: Are happy path AND error cases tested?
5. **Performance**: Is this operation fast enough for production?
6. **Documentation**: Would someone reading this in 6 months understand why it was written this way?
7. **Style**: Does this match project conventions?
8. **Dependencies**: Are all dependencies pinned to exact versions?

---

## Common Mistakes

### Go
```go
// ❌ Wrong: Silent error
if err := operation(); err != nil {
}  // Error ignored!

// ✅ Right: Explicit handling
if err := operation(); err != nil {
    return fmt.Errorf("operation failed: %w", err)
}

// ❌ Wrong: Panic in library
if err != nil {
    panic(err)
}

// ✅ Right: Return error
if err != nil {
    return err
}

// ❌ Wrong: Boolean blindness
func Query(id string, skipCache bool, includeHistory bool, forceRefresh bool)

// ✅ Right: Use struct
type QueryOptions struct {
    SkipCache      bool
    IncludeHistory bool
    ForceRefresh   bool
}
func Query(id string, opts QueryOptions)
```

### C++
```cpp
// ❌ Wrong: Raw pointer ownership unclear
Class::Class(Channel* channel) : channel_(channel) { }
// Who owns channel_? Will it leak?

// ✅ Right: Clear ownership
Class::Class(std::unique_ptr<Channel> channel) 
    : channel_(std::move(channel)) { }

// ❌ Wrong: Nullptr instead of optional
Entry* getEntry();  // Is nullptr an error or normal?

// ✅ Right: Use optional
std::optional<Entry> getEntry();

// ❌ Wrong: Exception for expected case
try {
    auto entry = ledger.getEntry(id);  // Throws if not found
} catch (...) { }

// ✅ Right: Optional for expected absence
if (auto entry = ledger.getEntry(id)) {
    // use *entry
}
```

---

## Key Files by Purpose

| Goal | Read File |
|------|-----------|
| **Understand project philosophy** | PRODUCTION_READINESS_PROMPT.md (Principles section) |
| **Check what's done/missing** | VHSM_PROJECT_COMPLETION_STATUS.md |
| **Write production Go code** | PRODUCTION_READINESS_PROMPT.md (Go Standards) |
| **Write production C++ code** | PRODUCTION_READINESS_PROMPT.md (C++ Standards) |
| **Ensure test coverage** | PRODUCTION_READINESS_PROMPT.md (Testing Strategy) |
| **Design secure system** | PRODUCTION_READINESS_PROMPT.md (Security Requirements) |
| **Deploy to Kubernetes** | PRODUCTION_READINESS_PROMPT.md (Operations & Deployment) |
| **Quick reference** | This file (CODE_STANDARDS_REFERENCE.md) |

---

## Automation Tools

### Pre-commit Hooks
```bash
# Install
pip install pre-commit

# Create .pre-commit-config.yaml
repos:
  - repo: https://github.com/golangci/golangci-lint
    hooks:
      - id: golangci-lint

  - repo: https://github.com/pre-commit/pre-commit-hooks
    hooks:
      - id: detect-secrets
      - id: check-added-large-files

# Install hook
pre-commit install
```

### GitHub Actions
```yaml
name: CI
on: [pull_request, push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Run tests
        run: go test -v -cover ./...
      
      - name: Coverage
        run: |
          go test -coverprofile=coverage.out ./...
          if [[ $(go tool cover -func coverage.out | tail -1 | awk '{print $3}' | sed 's/%//') < 80 ]]; then
            echo "Coverage below 80%"
            exit 1
          fi
```

---

## Reminders

- **Consensus is mandatory**: No unilateral state changes
- **Cryptography is law**: All critical actions must have proof
- **Fail-closed**: Reject when uncertain
- **Audit everything**: Logs are compliance evidence
- **Test extensively**: Happy path + error cases + edge cases
- **Document always**: Comments explain WHY, not WHAT
- **Security first**: Validate all input, check all output

---

**Last Updated**: August 18, 2026  
**Valid For**: vHSM Project v1.0+  
**Maintained By**: Development Team
