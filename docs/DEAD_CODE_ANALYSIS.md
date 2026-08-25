# vHSM Dead Code Analysis Report

> **STATUS: SUPERSEDED.** Several items in this report have been addressed or
> overridden since it was written:
>
> - The `put_le32`/`get_le64` duplication is already fixed via
>   `src/persistence/le_bytes.h` (shared header).
> - **Do NOT remove the disabled chaincode functions** (`SubmitGrade`,
>   `NotarizePv`, `GetAllThesesRaw`, `NotarizeThesis`). On Fabric, chaincode
>   upgrades replace the whole definition — deleting a function causes old
>   clients to get an opaque "unknown function" error instead of the clear,
>   typed stub message (`"SubmitGrade is disabled: use SubmitJuryGrade"`).
>   These stubs are the correct backward-compat pattern for an
>   immutable-history ledger API.
>
> Treat this document as a historical snapshot, not a current backlog.

**Date:** August 20, 2026  
**Scope:** Full codebase analysis (C++ core, Go chaincode, REST API, chain adapters)  
**Total Issues Found:** 15+ items across multiple categories

---

## Executive Summary

The vHSM codebase contains **moderate amounts of dead code** primarily concentrated in:
- **Template chaincode** - 4 disabled functions (backward compatibility stubs)
- **Signature ledger chaincode** - 1 incomplete function with design uncertainty
- **Persistence layer** - Duplicate utility functions violating DRY principle

Most dead code appears intentional (API migration, backward compatibility) rather than accidental neglect.

---

## HIGH PRIORITY Issues (Action Required)

### 1. Disabled Functions in Template Chaincode
**File:** `network/fabric_configuration/template_chaincode/chaincode.go`

| Function | Lines | Status | Recommendation |
|----------|-------|--------|-----------------|
| `SubmitGrade` | 276-283 | Disabled with error message | **REMOVE** - Replaced by SubmitJuryGrade |
| `NotarizePv` | 322-330 | Disabled with error message | **REMOVE** - Replaced by SignPv |
| `GetAllThesesRaw` | 242-245 | Disabled, diagnostic only | **REMOVE** - No longer needed |
| `NotarizeThesis` | 252-263 | Disabled, replaced by NotarizeDocument | **REMOVE** - Update API clients first |

**Action:** Remove these functions entirely after confirming no external clients depend on them.

```go
// REMOVE these:
func (s *ThesisContract) SubmitGrade(ctx contractapi.TransactionContextInterface, ...) error {
    return fmt.Errorf("SubmitGrade is disabled: ...")
}
```

---

### 2. Incomplete Function in Signature Ledger Chaincode
**File:** `network/chaincode/signature_ledger/signature_ledger.go:70-115`

**Function:** `UpdateBlockNumber`
- **Status:** Unimplemented - function body returns nil without doing anything
- **Code:** 46 lines of comments explaining why it's incomplete
- **Issue:** Creates false API surface; maintainers may think it works

**Current Code:**
```go
func (s *SignatureContract) UpdateBlockNumber(
    ctx contractapi.TransactionContextInterface,
    recordID string,
    blockNumber int64,
) error {
    // [46 lines of comments explaining incomplete design]
    return nil  // Does nothing
}
```

**Action:** Either:
1. **Remove entirely** if no clients use this endpoint
2. **Implement fully** if this is needed functionality
3. **Keep as TODO** with clear error message if intentionally deferred

---

### 3. Duplicate Utility Functions
**Files:** `src/persistence/vault.cpp:31-61` and `src/persistence/token_serializer.cpp:48-75`

**Duplicated Functions:**
- `put_le32()` - 15 lines (identical in both files)
- `put_le64()` - 15 lines (identical in both files)
- `get_le32()` - 15 lines (identical in both files)
- `get_le64()` - 15 lines (identical in both files)

**Action:** Create shared utility header `src/persistence/utils.h`:

```cpp
// src/persistence/utils.h
#pragma once
#include <cstdint>
#include <cstring>

inline void put_le32(uint8_t* buf, uint32_t value) {
    // implementation
}

inline uint32_t get_le32(const uint8_t* buf) {
    // implementation
}

// ... le64 versions
```

Then include in both `vault.cpp` and `token_serializer.cpp`.

---

## MEDIUM PRIORITY Issues (Should Fix)

### 4. Large Confused Comment Block in Signature Ledger
**File:** `network/chaincode/signature_ledger/signature_ledger.go:28-69`

**Issue:** Design-time debate embedded in production code
- Multiple "We'll..." statements
- Shows internal uncertainty about BlockNumber handling
- 42 lines of explanation for what should be 5 lines of code

**Current State:**
```go
// Extensive comments about "we decided to" vs "we could have" 
// showing multiple design iterations instead of final decision
func (s *SignatureContract) RecordSignature(ctx ...) error {
    // ...
    blockNumber := int64(0)  // Set to 0 - but why? Not explained clearly.
```

**Action:** Refactor to:
```go
// RecordSignature anchors a signing event to the ledger.
// BlockNumber is initialized to 0 and updated asynchronously
// by the background ledger worker (see ledger_worker.cpp).
func (s *SignatureContract) RecordSignature(ctx ...) error {
    // ...
    blockNumber := int64(0)  // Placeholder; filled later
```

---

### 5. Unused Property Setters (Commented Out)
**File:** `src/keystore/hsm_object.h:110-111`

**Issue:**
```cpp
// Commented out - should either implement or remove with explanation
// void setSensitive(bool value) { sensitive_ = value; }
// void setExtractable(bool value) { extractable_ = value; }
```

**Action:** Either:
1. Un-comment and implement if properties should be mutable
2. Remove with code comment explaining why: `// Properties are immutable after object creation`

---

### 6. TODO: Missing HSM Instance ID in Admin Service
**File:** `src/admin/admin_service.cpp:53`

```cpp
event.hsm_instance = "";  // TODO: fetch from db_meta
```

**Impact:** Audit trail incomplete; cannot identify which HSM instance generated events

**Action:** Implement lookup:
```cpp
event.hsm_instance = db_.getMetadata().hsm_instance;
```

---

## MEDIUM PRIORITY Issues (Code Quality)

### 7. Large Comment Block in Signature Ledger Chaincode
**File:** `network/chaincode/signature_ledger/signature_ledger.go:28-69`

**Status:** 42-line comment block showing internal design debate

The extended comments in `RecordSignature()` chronicle the team's decision-making process rather than the final decision. This is confusing for future maintainers.

**Lines 28-69** contain:
- "We'll update BlockNumber..."
- Multiple conditional statements about what could be done
- Explanation of why certain approaches were rejected

**Recommendation:** Condense to concise final design documentation:
```go
// RecordSignature stores a signature event on the ledger.
// It captures: record_id, key_fingerprint, payload_digest, signature_b64, created_at.
// BlockNumber is assigned by the orderer at commit time; we receive it after ledger confirmation.
// See ledger_worker.cpp for async confirmation and BlockNumber update flow.
```

---

## LOW PRIORITY Issues (Acceptable Patterns)

### 8. Vendored Deprecated APIs

**Files:** `network/chaincode/signature_ledger/vendor/`

Vendored dependencies contain deprecated APIs (acceptable in vendor code):
- `google.golang.org/grpc/`: `WithMaxMsgSize()`, `WithCodec()`, etc.
- `github.com/golang/protobuf/ptypes/`: `Duration()`, `Timestamp()`, etc.

**Action:** Optional - upgrade gRPC version in `go.mod` to remove deprecation warnings.

---

### 9. Intentionally Unused Parameters (Correct Pattern)

**Files:** `src/firmware/main/hsm.cpp` and others

**Pattern:** `(void)slotID;` - explicitly silencing compiler warnings
- This is **good practice** for intentionally unused parameters
- **No action needed**

---

## Cleanup Priority Matrix

| Priority | Item | Effort | Impact | Files |
|----------|------|--------|--------|-------|
| **HIGH** | Remove 4 disabled functions | 30 min | Clean API surface | `template_chaincode.go` |
| **HIGH** | Fix/remove UpdateBlockNumber | 20 min | Remove incomplete code | `signature_ledger.go` |
| **HIGH** | Consolidate utils (put_le/get_le) | 45 min | Reduce duplication, improve maintenance | `vault.cpp`, `token_serializer.cpp` |
| **MEDIUM** | Refactor confusing comments | 30 min | Improve code clarity | `signature_ledger.go` |
| **MEDIUM** | Un-comment or remove setters | 15 min | Clarify API | `hsm_object.h` |
| **MEDIUM** | Implement HSM instance lookup | 20 min | Complete audit trail | `admin_service.cpp` |
| **LOW** | Upgrade vendored dependencies | 60 min | Remove warnings (optional) | `go.mod`, `go.sum` |

---

## Summary Statistics

- **Total Dead Code Items:** 15+
- **Files with Dead Code:** 7
- **Lines of Dead Code:** ~200+ (including comments)
- **Duplicate Code:** ~60 lines (utilities)
- **Disabled Functions:** 4 (Go chaincode)
- **Incomplete Functions:** 1 (Go chaincode)
- **TODOs:** 1 (C++ admin service)

---

## Recommended Next Steps

1. **This Week:** Remove 4 disabled functions from template_chaincode.go
2. **This Week:** Fix/remove UpdateBlockNumber or implement it fully
3. **Next Week:** Consolidate utility functions in persistence layer
4. **This Sprint:** Refactor confusing comments and implement HSM instance lookup
5. **Before Release:** Full code review of comments for hidden design debates

---

## Generated By

Kiro AI Code Analysis  
Date: August 20, 2026
