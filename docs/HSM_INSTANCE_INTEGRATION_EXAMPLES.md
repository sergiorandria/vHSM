# HSM Instance ID — Integration Examples

This document shows concrete code examples for integrating the HSM instance ID into different parts of the vHSM system.

## Table of Contents

1. [PKCS#11 Initialization](#pkcs11-initialization)
2. [Audit Event Tracking](#audit-event-tracking)
3. [Notification Events](#notification-events)
4. [Ledger Integration (Optional)](#ledger-integration-optional)
5. [Multi-Instance Monitoring](#multi-instance-monitoring)

---

## PKCS#11 Initialization

### Current Code (Before Integration)

```cpp
// src/pkcs11/p11.cpp (hypothetical location)
CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  // Open database connection
  auto db = make_sqlite_connection("vhsm.sqlite");
  
  // Bootstrap schema
  DbSchema schema(*db);
  schema.bootstrap();
  
  // Create session manager
  auto session_manager = std::make_unique<SessionManager>();
  
  return CKR_OK;
}
```

### After Integration

```cpp
// src/pkcs11/p11.cpp
#include "src/core/hsm_instance.h"
#include "src/signature_store/db_connection.h"

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  // Open database connection
  auto db = make_sqlite_connection("vhsm.sqlite");
  
  // Bootstrap schema
  DbSchema schema(*db);
  schema.bootstrap();
  
  // NEW: Initialize instance ID tracking
  try {
    DatabaseHsmInstanceProvider provider(*db);
    HsmInstanceId instance_id = provider.getInstanceId();
    vhsm::core::set_hsm_instance_id(instance_id.value());
    
    // Log initialization with instance ID
    std::cout << "vHSM initialized on instance: " 
              << instance_id.value() << std::endl;
  } catch (const std::exception& e) {
    // Log error but don't fail initialization
    std::cerr << "Warning: Could not load instance ID: " << e.what() << std::endl;
    vhsm::core::set_hsm_instance_id("unknown");
  }
  
  // Create session manager
  auto session_manager = std::make_unique<SessionManager>();
  
  return CKR_OK;
}
```

### Key Points
- ✅ Catches exceptions gracefully (instance ID loading shouldn't fail init)
- ✅ Sets process-wide cache for later use
- ✅ Logs instance ID for debugging
- ✅ Defaults to "unknown" if loading fails

---

## Audit Event Tracking

### Current Code (Before Integration)

```cpp
// src/audit/audit_log.h
struct AuditEvent {
  std::string id;              // Event ID
  std::string timestamp;       // ISO 8601
  std::string user_label;      // "alice"
  std::string operation;       // "SIGN"
  std::string result;          // "SUCCESS" or "FAILURE"
  std::string key_id;          // Key identifier
  std::string mechanism;       // "CKM_ECDSA_SHA256"
};

// src/audit/audit_log.cpp
void AuditLog::append(const AuditEvent& event) {
  // Persist to database or audit file
  auto record = fmt::format(
    R"({{ "id": "{}", "timestamp": "{}", "user": "{}", "operation": "{}" }})",
    event.id, event.timestamp, event.user_label, event.operation
  );
  db_.exec("INSERT INTO audit_log (record) VALUES (?);", {record});
}
```

### After Integration

```cpp
// src/audit/audit_log.h
struct AuditEvent {
  std::string id;              // Event ID
  std::string instance_id;     // NEW: 550e8400-e29b-41d4-a716-446655440000
  std::string timestamp;       // ISO 8601
  std::string user_label;      // "alice"
  std::string operation;       // "SIGN"
  std::string result;          // "SUCCESS" or "FAILURE"
  std::string key_id;          // Key identifier
  std::string mechanism;       // "CKM_ECDSA_SHA256"
};

// src/audit/audit_log.cpp
#include "src/core/hsm_instance.h"

void AuditLog::append(const AuditEvent& event) {
  // NEW: Include instance_id for multi-instance deployments
  auto record = fmt::format(
    R"({{
      "id": "{}",
      "instance_id": "{}",
      "timestamp": "{}",
      "user": "{}",
      "operation": "{}",
      "result": "{}",
      "key_id": "{}",
      "mechanism": "{}"
    }})",
    event.id,
    !event.instance_id.empty() ? event.instance_id 
                                : vhsm::core::hsm_instance_id(),  // Fallback
    event.timestamp,
    event.user_label,
    event.operation,
    event.result,
    event.key_id,
    event.mechanism
  );
  db_.exec("INSERT INTO audit_log (record) VALUES (?);", {record});
}
```

### Usage in C_Sign

```cpp
// src/pkcs11/p11_crypto.cpp
CK_RV C_Sign(CK_SESSION_HANDLE h, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  // ... existing code ...
  
  if (rv == CKR_OK) {
    auto *dispatcher = p11_signature_dispatcher();
    if (dispatcher) {
      // ... existing setup ...
      
      // Create audit event
      AuditEvent audit_evt;
      audit_evt.id = vhsm::utils::uuid_v4();
      audit_evt.instance_id = vhsm::core::hsm_instance_id();  // NEW
      audit_evt.timestamp = vhsm::utils::iso8601_now();
      audit_evt.user_label = get_logged_in_user(h);
      audit_evt.operation = "SIGN";
      audit_evt.result = "SUCCESS";
      audit_evt.key_id = key_id;
      audit_evt.mechanism = sign_result.mechanism_str;
      
      audit_log->append(audit_evt);
    }
  }
  
  return rv;
}
```

### Database Schema Update (Optional)

```sql
-- Extend audit_log table to include instance_id
ALTER TABLE audit_log ADD COLUMN instance_id TEXT;
CREATE INDEX idx_audit_instance_id ON audit_log(instance_id);

-- Query audits by instance
SELECT * FROM audit_log WHERE instance_id = '550e8400-e29b-41d4-a716-446655440000'
ORDER BY created_at DESC;
```

### Key Points
- ✅ Audit events now tagged with instance ID
- ✅ Enables correlation in multi-instance deployments
- ✅ Index on `instance_id` speeds up queries
- ✅ Fallback to `hsm_instance_id()` if not set in event struct

---

## Notification Events

### Current Code (Before Integration)

```cpp
// src/notification/notification_event.h
struct NotificationEvent {
  std::string event_id;              // UUID
  std::string timestamp;             // ISO 8601
  std::string severity;              // "INFO", "WARN", "CRITICAL"
  std::string event_type;            // "SIGNATURE_CREATED", "PIN_FAILURE"
  std::string message;               // Human-readable description
  std::string related_object_id;     // key_id, signature_id, etc.
};

// src/notification/notification_bus.cpp
void NotificationBus::publish(const NotificationEvent& event) {
  // Send to subscribers
  for (auto& sub : subscribers_) {
    if (sub->interested_in(event.severity)) {
      sub->on_event(event);  // Email, webhook, gRPC push
    }
  }
}
```

### After Integration

```cpp
// src/notification/notification_event.h
struct NotificationEvent {
  std::string event_id;              // UUID
  std::string instance_id;           // NEW: 550e8400-e29b-41d4-a716-446655440000
  std::string timestamp;             // ISO 8601
  std::string severity;              // "INFO", "WARN", "CRITICAL"
  std::string event_type;            // "SIGNATURE_CREATED", "PIN_FAILURE"
  std::string message;               // Human-readable description
  std::string related_object_id;     // key_id, signature_id, etc.
};

// src/notification/notification_bus.cpp
#include "src/core/hsm_instance.h"

void NotificationBus::publish(const NotificationEvent& event) {
  // NEW: Tag with instance ID if not already set
  NotificationEvent event_tagged = event;
  if (event_tagged.instance_id.empty()) {
    event_tagged.instance_id = vhsm::core::hsm_instance_id();
  }
  
  // Send to subscribers
  for (auto& sub : subscribers_) {
    if (sub->interested_in(event_tagged.severity)) {
      sub->on_event(event_tagged);  // Email, webhook, gRPC push
    }
  }
}
```

### Usage in Signature Dispatcher

```cpp
// src/signature_store/signature_dispatcher.cpp
bool SignatureDispatcher::dispatch(const vhsm::crypto::SignResult& sign_result,
                                   /* ... other params ... */) {
  // ... existing persistence logic ...
  
  // NEW: Create notification with instance ID
  vhsm::notification::NotificationEvent notify_event;
  notify_event.event_id = vhsm::utils::uuid_v4();
  notify_event.instance_id = vhsm::core::hsm_instance_id();  // NEW
  notify_event.timestamp = vhsm::utils::iso8601_now();
  notify_event.severity = "INFO";
  notify_event.event_type = "SIGNATURE_CREATED";
  notify_event.message = fmt::format(
    "Signature created for key {} using mechanism {}",
    key_id, sign_result.mechanism_str
  );
  notify_event.related_object_id = signature_id;
  
  notification_bus_.publish(notify_event);
  
  return true;
}
```

### Example Webhook Payload

```json
{
  "event_id": "evt-20250822-001",
  "instance_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-08-22T10:30:45.123Z",
  "severity": "INFO",
  "event_type": "SIGNATURE_CREATED",
  "message": "Signature created for key key-xyz using mechanism CKM_ECDSA_SHA256",
  "related_object_id": "sig-abc123"
}
```

### Email Template Update

```html
<!-- notification/templates/email_signature_created.html -->
<html>
<body>
  <h2>Signature Created</h2>
  <p><strong>HSM Instance:</strong> {{ event.instance_id }}</p>
  <p><strong>Timestamp:</strong> {{ event.timestamp }}</p>
  <p><strong>Message:</strong> {{ event.message }}</p>
  <p><strong>Key ID:</strong> {{ event.related_object_id }}</p>
  
  <!-- NEW: Add instance ID to email for admin reference -->
  <p style="font-size: 0.9em; color: #666;">
    Event ID: {{ event.event_id }} | Instance: {{ event.instance_id }}
  </p>
</body>
</html>
```

### Key Points
- ✅ Notifications now include instance ID
- ✅ Enables filtering/routing by instance in webhook handlers
- ✅ Multi-instance deployments can correlate events
- ✅ Email/SMS templates can reference instance for clarity

---

## Ledger Integration (Optional)

### Current Code (Before Integration)

```cpp
// src/ledger/ledger_entry.h
struct LedgerEntry {
  std::string ledger_tx_id;      // Blockchain transaction ID
  int64_t ledger_block_num;      // Block height
  std::string ledger_tx_time;    // Timestamp from blockchain
  std::string ledger_tx_proof;   // Merkle proof
  std::string ledger_tx_set_b64; // Transaction set (base64)
};

// src/ledger/ledger_client.cpp
std::optional<LedgerEntry> LedgerClient::submit_record(
    const SignatureRecord& rec) {
  // Submit to Fabric chaincode
  // Returns blockchain metadata
}
```

### After Integration (Optional)

```cpp
// src/ledger/ledger_entry.h
struct LedgerEntry {
  std::string instance_id;       // NEW: Source HSM instance
  std::string ledger_tx_id;      // Blockchain transaction ID
  int64_t ledger_block_num;      // Block height
  std::string ledger_tx_time;    // Timestamp from blockchain
  std::string ledger_tx_proof;   // Merkle proof
  std::string ledger_tx_set_b64; // Transaction set (base64)
};

// src/ledger/ledger_client.cpp
std::optional<LedgerEntry> LedgerClient::submit_record(
    const SignatureRecord& rec) {
  // NEW: Include instance ID in ledger submission
  json ledger_payload = {
    {"signature_id", rec.record_id},
    {"instance_id", vhsm::core::hsm_instance_id()},
    {"timestamp", rec.created_at},
    {"mechanism", rec.mechanism},
    {"key_fingerprint", rec.key_fingerprint},
    {"signature_hash", rec.payload_digest}
  };
  
  // Submit to Fabric chaincode
  auto entry = fabric_client_.anchor_signature(ledger_payload);
  
  if (entry.has_value()) {
    entry->instance_id = vhsm::core::hsm_instance_id();  // NEW
  }
  
  return entry;
}
```

### Hyperledger Fabric Chaincode Example

```go
// network/chaincode/signature_ledger/signature_ledger.go (Go)
func (s *SmartContract) AnchorSignature(ctx contractapi.TransactionContextInterface,
    signatureData string) error {
  
  // Parse incoming JSON
  var payload struct {
    SignatureID   string `json:"signature_id"`
    InstanceID    string `json:"instance_id"`    // NEW
    Timestamp     int64  `json:"timestamp"`
    Mechanism     string `json:"mechanism"`
    KeyFingerprint string `json:"key_fingerprint"`
    SignatureHash string `json:"signature_hash"`
  }
  json.Unmarshal([]byte(signatureData), &payload)
  
  // Create ledger entry with instance tracking
  entry := map[string]interface{}{
    "objectType": "signature",
    "id": payload.SignatureID,
    "instanceId": payload.InstanceID,  // NEW: Store for queries
    "timestamp": payload.Timestamp,
    "mechanism": payload.Mechanism,
    "keyFingerprint": payload.KeyFingerprint,
    "signatureHash": payload.SignatureHash,
  }
  
  entryBytes, _ := json.Marshal(entry)
  
  // Store in blockchain
  ctx.GetStub().PutState(payload.SignatureID, entryBytes)
  
  // NEW: Create index by instance ID for multi-instance queries
  compositeKey, _ := ctx.GetStub().CreateCompositeKey(
    "instanceId~signatureId",
    []string{payload.InstanceID, payload.SignatureID})
  ctx.GetStub().PutState(compositeKey, []byte{0x00})
  
  return nil
}

// Query by instance ID (Fabric)
func (s *SmartContract) GetSignaturesByInstance(ctx contractapi.TransactionContextInterface,
    instanceID string) ([]interface{}, error) {
  
  // Use composite key index for efficient queries
  resultsIterator, _ := ctx.GetStub().GetStateByPartialCompositeKey(
    "instanceId~signatureId",
    []string{instanceID})
  defer resultsIterator.Close()
  
  var results []interface{}
  for resultsIterator.HasNext() {
    kv, _ := resultsIterator.Next()
    var entry interface{}
    json.Unmarshal(kv.Value, &entry)
    results = append(results, entry)
  }
  
  return results, nil
}
```

### Query Example

```bash
# Query all signatures anchored by a specific HSM instance
peer chaincode query -C mychannel -n signature_ledger -c \
  '{"Args":["GetSignaturesByInstance","550e8400-e29b-41d4-a716-446655440000"]}'

# Returns: [
#   { "id": "sig-001", "instanceId": "550e8400-e29b-41d4-a716-446655440000", ... },
#   { "id": "sig-002", "instanceId": "550e8400-e29b-41d4-a716-446655440000", ... }
# ]
```

### Key Points
- ✅ Optional enhancement (Ledger integration)
- ✅ Enables blockchain-visible instance correlation
- ✅ Composite keys enable efficient queries
- ✅ Useful for multi-instance deployments

---

## Multi-Instance Monitoring

### Example: Monitoring Dashboard

```python
# monitoring/vhsm_monitor.py (hypothetical)
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta

class VHSMMonitor:
    def __init__(self):
        self.databases = {
            "hsmA": sqlite3.connect("/data/hsmA.sqlite"),
            "hsmB": sqlite3.connect("/data/hsmB.sqlite"),
            "hsmC": sqlite3.connect("/data/hsmC.sqlite"),
        }
    
    def get_instance_ids(self):
        """Get instance ID for each HSM"""
        instances = {}
        for name, db in self.databases.items():
            cursor = db.cursor()
            cursor.execute(
                "SELECT value FROM db_meta WHERE key = 'instance_id'"
            )
            row = cursor.fetchone()
            instances[name] = row[0] if row else "unknown"
        return instances
    
    def audit_summary_by_instance(self, hours=24):
        """Summary of audit events by instance"""
        summary = defaultdict(lambda: {"total": 0, "successes": 0, "failures": 0})
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        for name, db in self.databases.items():
            cursor = db.cursor()
            cursor.execute("""
                SELECT instance_id, COUNT(*) as total,
                       SUM(CASE WHEN result = 'SUCCESS' THEN 1 ELSE 0 END) as successes,
                       SUM(CASE WHEN result = 'FAILURE' THEN 1 ELSE 0 END) as failures
                FROM audit_log
                WHERE timestamp > ?
                GROUP BY instance_id
            """, (cutoff.isoformat(),))
            
            for instance_id, total, successes, failures in cursor.fetchall():
                key = f"{name}:{instance_id}"
                summary[key] = {
                    "total": total,
                    "successes": successes,
                    "failures": failures
                }
        
        return summary
    
    def cross_instance_latency(self):
        """Compare signature latency across instances"""
        latencies = {}
        
        for name, db in self.databases.items():
            cursor = db.cursor()
            cursor.execute("""
                SELECT AVG(ledger_latency_ms) as avg_latency
                FROM signature_records
                WHERE ledger_status = 'COMMITTED'
                  AND ledger_latency_ms > 0
                LIMIT 1000
            """)
            row = cursor.fetchone()
            latencies[name] = row[0] if row else 0
        
        return latencies
    
    def print_status(self):
        """Print multi-instance status"""
        instances = self.get_instance_ids()
        summary = self.audit_summary_by_instance(hours=24)
        latencies = self.cross_instance_latency()
        
        print("\n=== vHSM Multi-Instance Status ===\n")
        
        print("Instance IDs:")
        for name, instance_id in instances.items():
            print(f"  {name}: {instance_id}")
        
        print("\nAudit Summary (24h):")
        for instance, stats in sorted(summary.items()):
            print(f"  {instance}:")
            print(f"    Total: {stats['total']}")
            print(f"    Success: {stats['successes']}")
            print(f"    Failures: {stats['failures']}")
        
        print("\nLedger Latency:")
        for name, latency in latencies.items():
            print(f"  {name}: {latency:.2f}ms")

# Usage
if __name__ == "__main__":
    monitor = VHSMMonitor()
    monitor.print_status()
```

### Output Example

```
=== vHSM Multi-Instance Status ===

Instance IDs:
  hsmA: 550e8400-e29b-41d4-a716-446655440000
  hsmB: 6b5c38ea-b56e-4f1e-92d0-123456789000
  hsmC: 7c6d49fb-c67f-502f-03e1-234567890111

Audit Summary (24h):
  hsmA:550e8400-e29b-41d4-a716-446655440000:
    Total: 15432
    Success: 15398
    Failures: 34
  hsmB:6b5c38ea-b56e-4f1e-92d0-123456789000:
    Total: 14921
    Success: 14889
    Failures: 32
  hsmC:7c6d49fb-c67f-502f-03e1-234567890111:
    Total: 15087
    Success: 15065
    Failures: 22

Ledger Latency:
  hsmA: 142.53ms
  hsmB: 138.92ms
  hsmC: 145.17ms
```

### Key Points
- ✅ Cross-instance monitoring enabled by instance ID
- ✅ Audit event filtering by instance
- ✅ Performance comparison across instances
- ✅ Operational insight for multi-instance deployments

---

## Summary

| Integration | Status | Effort | Impact |
|------------|--------|--------|--------|
| PKCS#11 Init | Ready | 30 min | Enables instance tracking |
| Audit Events | Ready | 45 min | Full event correlation |
| Notifications | Ready | 30 min | Multi-instance routing |
| Ledger (Optional) | Ready | 1 hour | Blockchain visibility |
| Monitoring | Ready | 2 hours | Operational dashboards |

---

**Next Step:** Pick one integration from the list above and implement it!
