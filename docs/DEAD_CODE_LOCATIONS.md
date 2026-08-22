# Dead Code - Exact File Locations

## HIGH PRIORITY - MUST FIX

### 1. Disabled Functions in Template Chaincode
**File:** `network/fabric_configuration/template_chaincode/chaincode.go`

#### GetAllThesesRaw()
- **Lines:** 193-196
- **Status:** Disabled with error message
- **Code:**
  ```go
  func (c *ThesisContract) GetAllThesesRaw(ctx contractapi.TransactionContextInterface) ([]string, error) {
      return nil, fmt.Errorf("GetAllThesesRaw is disabled: use GetAllTheses for typed, validated reads")
  }
  ```
- **Action:** REMOVE - This is a debugging function that should not exist in production

#### NotarizeThesis()
- **Lines:** 204-210 (approx.)
- **Status:** Disabled, replaced by NotarizeDocument
- **Action:** REMOVE after confirming no clients depend on it

#### SubmitGrade()
- **Lines:** 276-283 (approx.)
- **Status:** Disabled, replaced by SubmitJuryGrade
- **Message:** "SubmitGrade is disabled: grading now requires one submission per jury member via SubmitJuryGrade"
- **Action:** REMOVE - API migration complete

#### NotarizePv()
- **Lines:** 322-325+ (approx.)
- **Status:** Disabled, replaced by SignPv
- **Message:** "NotarizePv is disabled: the PV now requires one signature per jury member via SignPv"
- **Action:** REMOVE - API migration complete

---

### 2. Incomplete Function - Signature Ledger Chaincode
**File:** `network/chaincode/signature_ledger/signature_ledger.go`

#### UpdateBlockNumber()
- **Lines:** 96-115 (approx.)
- **Status:** Function exists but does nothing (returns nil without implementation)
- **Issue:** This creates a false API surface - maintainers may think it's implemented
- **Code:**
  ```go
  func (s *SignatureLedgerContract) UpdateBlockNumber(
      ctx contractapi.TransactionContextInterface, 
      txID string, 
      blockNumber int64,
  ) error {
      // We need to find the record by transaction ID?
      // We don't have an index by transaction ID.
      // [... more unresolved design discussion ...]
      return nil  // DOES NOTHING
  }
  ```
- **Action:** Either REMOVE or IMPLEMENT FULLY

---

### 3. Extensive Design Debate Comments
**File:** `network/chaincode/signature_ledger/signature_ledger.go`

#### RecordSignature() - Confusing Comment Block
- **Lines:** ~59-62+ (design discussion)
- **Issue:** Stream-of-consciousness design debate instead of clear final decision
- **Content:**
  ```
  "We'll decide to store the block number as 0 and then the ledger worker will update it..."
  "We'll add a function UpdateBlockNumber that takes the transaction ID..."
  "But then we need to invoke that function from the worker..."
  "We'll do that."
  ```
- **Problem:** Multiple "We'll..." statements show internal debate, not final implementation
- **Action:** REFACTOR - Replace with concise final design explanation

---

## MEDIUM PRIORITY - SHOULD FIX

### 4. Duplicate Utility Functions
**Files:** 
- `src/persistence/vault.cpp`
- `src/persistence/token_serializer.cpp`

#### Duplicated Functions
- `put_le32()` - exists in both files (identical)
- `put_le64()` - exists in both files (identical)
- `get_le32()` - exists in both files (identical)
- `get_le64()` - exists in both files (identical)

**Action:** Create `src/persistence/utils.h` with these utilities as inline functions

---

### 5. Commented-Out Setter Methods
**File:** `src/keystore/hsm_object.h`

#### Commented Properties
- **Lines:** ~110-111 (approx.)
- **Code:**
  ```cpp
  // void setSensitive(bool value) { sensitive_ = value; }
  // void setExtractable(bool value) { extractable_ = value; }
  ```
- **Issue:** Unclear if properties are intentionally immutable or accidentally commented out
- **Action:** Either UN-COMMENT (if mutable) or ADD COMMENT explaining why immutable

---

### 6. TODO - Missing HSM Instance Lookup
**File:** `src/admin/admin_service.cpp`

#### Incomplete Event Population
- **Line:** ~53
- **Code:**
  ```cpp
  event.hsm_instance = "";  // TODO: fetch from db_meta
  ```
- **Impact:** Audit trail missing HSM instance ID
- **Action:** Implement lookup from database metadata

---

## LOW PRIORITY - OPTIONAL

### 7. Deprecated Vendor APIs
**File:** `network/chaincode/signature_ledger/vendor/google.golang.org/grpc/`

**Deprecated Functions:**
- `WithMaxMsgSize()`
- `WithCodec()`
- `WithCompressor()`
- `WithDecompressor()`
- `WithTimeout()`
- `WithDialer()`

**Note:** These are in vendored code, which is acceptable. Consider upgrading gRPC version to remove deprecation warnings.

---

## Summary by Severity

| Severity | Count | Action | Files |
|----------|-------|--------|-------|
| **HIGH** | 5 | Remove/Implement | 2 Go files |
| **MEDIUM** | 3 | Refactor/Consolidate | 3 C++ files |
| **LOW** | 1+ | Optional | Vendor dir |

**Total:** 9+ actionable items

---

## Recommended Cleanup Order

1. **Today:** Remove 4 disabled functions from template_chaincode.go (30 min)
2. **Today:** Remove or implement UpdateBlockNumber() (20 min)
3. **This week:** Consolidate duplicate utilities (45 min)
4. **This week:** Refactor confusing comments (30 min)
5. **This sprint:** Implement HSM instance lookup (20 min)

**Total Effort:** ~2.5 hours for all HIGH + MEDIUM items

---

## Generated
Kiro Dead Code Analysis  
Date: August 20, 2026
