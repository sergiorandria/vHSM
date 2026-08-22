# HSM Instance ID Design and Integration

## Overview

The HSM instance ID system provides a unique identifier for each vHSM database instance. This enables:
- **Event correlation** across distributed deployments
- **Multi-instance audit trail** association
- **Database/instance isolation** in shared environments
- **Reproducible testing** with deterministic instance IDs

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────────────┐
│ vHSM Deployment                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ PKCS#11 Layer (C API)                                       │  │
│  │  → C_Sign() dispatches signature via SignatureDispatcher    │  │
│  │  → Includes process-wide hsm_instance_id() in audit events  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                        ↓                                            │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ DbSchema (Bootstrap Layer)                                  │  │
│  │  ├─ bootstrap()                                             │  │
│  │  │   └─ Generates UUID v4, seeds db_meta.instance_id       │  │
│  │  └─ get_instance_id()                                       │  │
│  │      └─ Reads from database (cached after first read)       │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                        ↓                                            │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ Core Layer (HsmInstanceId, DatabaseHsmInstanceProvider)     │  │
│  │  ├─ HsmInstanceId value object (UUID string)                │  │
│  │  │   └─ Immutable, copyable, equality operators             │  │
│  │  ├─ DatabaseHsmInstanceProvider                             │  │
│  │  │   └─ Reads from IDbConnection, caches result            │  │
│  │  └─ Process-wide accessors                                  │  │
│  │      ├─ set_hsm_instance_id() — Set after bootstrap         │  │
│  │      └─ hsm_instance_id() — Get for audit/notification      │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                        ↓                                            │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ Database (SQLite/PostgreSQL/MySQL)                          │  │
│  │  └─ db_meta table                                           │  │
│  │     ├─ key: "instance_id" → value: "550e8400-e29b-..."      │  │
│  │     ├─ key: "schema_version" → value: "5"                   │  │
│  │     ├─ key: "created_at" → value: "1692374400000"           │  │
│  │     └─ key: "hmac_key_wrapped" → value: "UNSET" (legacy)    │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Bootstrap (First Time)**
   ```
   C_Initialize()
   └─ DbSchema::bootstrap()
      └─ Generates UUID v4
      └─ Inserts into db_meta (instance_id, schema_version, created_at)
      └─ set_hsm_instance_id() caches it process-wide
   ```

2. **Runtime (Every C_Sign)**
   ```
   C_Sign()
   └─ SignatureDispatcher::dispatch()
      └─ Gets instance_id via hsm_instance_id()
      └─ Includes in audit log event
      └─ Publishes to notification bus with instance_id tag
      └─ Queues for ledger submission
   ```

3. **Subsequent Bootstrap (Existing DB)**
   ```
   C_Initialize()
   └─ DbSchema::bootstrap()
      └─ Detects existing db_meta
      └─ Reuses existing instance_id (no new UUID)
      └─ set_hsm_instance_id() caches it
   ```

## API Reference

### `HsmInstanceId` — Value Object

```cpp
class HsmInstanceId {
public:
  // Construct with a UUID string
  explicit HsmInstanceId(std::string id) noexcept;

  // Get the UUID value
  const std::string& value() const noexcept;

  // Equality comparison
  bool operator==(const HsmInstanceId& other) const noexcept;
  bool operator!=(const HsmInstanceId& other) const noexcept;
};
```

**Example:**
```cpp
HsmInstanceId id("550e8400-e29b-41d4-a716-446655440000");
std::cout << id.value() << std::endl;  // 550e8400-e29b-41d4-a716-446655440000

HsmInstanceId id2("550e8400-e29b-41d4-a716-446655440000");
assert(id == id2);
```

### `IHsmInstanceProvider` — Interface

```cpp
class IHsmInstanceProvider {
public:
  virtual ~IHsmInstanceProvider() = default;
  virtual HsmInstanceId getInstanceId() const = 0;
};
```

### `DatabaseHsmInstanceProvider` — Implementation

```cpp
class DatabaseHsmInstanceProvider : public IHsmInstanceProvider {
public:
  // Construct with a database connection
  explicit DatabaseHsmInstanceProvider(IDbConnection& db);

  // Get the cached instance ID from the database
  // Throws std::runtime_error if not seeded
  HsmInstanceId getInstanceId() const override;

  // Seed a new instance ID (idempotent via INSERT OR REPLACE)
  bool seedInstanceId(const HsmInstanceId& id);
};
```

**Example:**
```cpp
auto db = make_sqlite_connection("vhsm.sqlite");
DatabaseHsmInstanceProvider provider(*db);

// After bootstrap, read the instance ID
HsmInstanceId id = provider.getInstanceId();
std::cout << "Instance: " << id.value() << std::endl;
```

### Process-Wide Accessors

```cpp
// Set the process-wide instance ID (called once after bootstrap)
void set_hsm_instance_id(std::string id);

// Get the process-wide instance ID (used by audit/notification)
const std::string& hsm_instance_id();
```

**Example:**
```cpp
// During bootstrap (e.g., in DbSchema::bootstrap())
HsmInstanceId id = provider.getInstanceId();
vhsm::core::set_hsm_instance_id(id.value());

// Later in C_Sign()
std::string instance = vhsm::core::hsm_instance_id();
event.instance_id = instance;  // Include in audit event
```

## Database Schema

### `db_meta` Table

The instance ID is stored in the `db_meta` table:

```sql
CREATE TABLE db_meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO db_meta (key, value) VALUES ('instance_id', '550e8400-e29b-41d4-a716-446655440000');
INSERT INTO db_meta (key, value) VALUES ('schema_version', '5');
INSERT INTO db_meta (key, value) VALUES ('created_at', '1692374400000');
INSERT INTO db_meta (key, value) VALUES ('hmac_key_wrapped', 'UNSET');
```

### Meta Keys

| Key | Description | Format | Set By |
|-----|-------------|--------|--------|
| `instance_id` | Unique HSM/database instance identifier | UUID v4 (36 chars) | `DbSchema::bootstrap()` |
| `schema_version` | Current database schema version | Integer string (e.g., "5") | `DbSchema::bootstrap()` / migrations |
| `created_at` | Timestamp when database was created | Epoch milliseconds | `DbSchema::bootstrap()` |
| `hmac_key_wrapped` | Legacy placeholder (unused since v4) | "UNSET" | `DbSchema::bootstrap()` |

## Integration Points

### 1. Database Bootstrap (`DbSchema::bootstrap()`)

**Status:** Already integrated ✅

The database schema bootstrap automatically:
- Generates a UUID v4 if bootstrapping a new database
- Seeds it into `db_meta` (instance_id)
- Reuses existing instance_id if the database already exists

**Location:** `src/signature_store/db_schema.cpp`

```cpp
void DbSchema::bootstrap() {
  // ... existing code ...
  
  if (version == -1) {
    // Brand-new DB
    conn_.with_transaction([this](IDbTransaction& tx) {
      // ... create tables ...
      
      tx.exec("INSERT INTO db_meta(key,value) VALUES(?,?);",
              {std::string(meta_key::kInstanceId), vhsm::utils::uuid_v4()});
      
      // ... other meta fields ...
    });
  }
}
```

### 2. PKCS#11 Initialization (`C_Initialize`)

**Status:** Ready to integrate

To add instance ID to audit events:

```cpp
// In C_Initialize or similar entry point:
auto db = make_sqlite_connection(db_path);
DatabaseHsmInstanceProvider provider(*db);
HsmInstanceId id = provider.getInstanceId();
vhsm::core::set_hsm_instance_id(id.value());
```

### 3. Audit/Notification Events

**Status:** Ready to integrate

When creating audit events or notifications:

```cpp
// In SignatureDispatcher::dispatch() or AuditLog::append():
std::string instance_id = vhsm::core::hsm_instance_id();
audit_event.instance_id = instance_id;
notification_event.instance_id = instance_id;
```

## Caching Strategy

### Why Cache?

- **Performance:** Database queries are avoided on every audit event
- **Stability:** Instance ID doesn't change during runtime (immutable after bootstrap)
- **Correctness:** Consistent value across the process lifetime

### Cache Implementation

**In `DatabaseHsmInstanceProvider`:**
```cpp
mutable std::optional<HsmInstanceId> cached_id_;

HsmInstanceId getInstanceId() const {
  if (cached_id_.has_value()) {
    return *cached_id_;
  }
  // Query database...
  cached_id_ = HsmInstanceId(...);
  return *cached_id_;
}
```

**At Process Level:**
```cpp
static std::string g_hsm_instance_id;  // Cached in src/core/hsm_instance.cpp

const std::string& hsm_instance_id() {
  return g_hsm_instance_id;
}
```

### Cache Invalidation

- **Never invalidated during runtime** (instance ID is immutable)
- **Invalidated after `seedInstanceId()`** if using `DatabaseHsmInstanceProvider`
- **Cleared in tests** via `set_hsm_instance_id("")`

## Testing

### Unit Tests

Comprehensive tests are in `tests/unit/core/hsm_instance_test.cpp`:

**Test Coverage:**
- `HsmInstanceIdTest` — Value object construction, equality, copyability
- `DatabaseHsmInstanceProviderTest` — Caching, persistence, seeding
- `ProcessWideInstanceTest` — Process-wide accessors
- `HsmInstanceIntegrationTest` — Real SQLite integration

**Run Tests:**
```bash
cd build
cmake .. && make
ctest --output-on-failure -R "hsm_instance"
```

### Integration Test Example

```cpp
// tests/unit/core/hsm_instance_test.cpp
TEST_F(HsmInstanceIntegrationTest, BootstrapSeeds InstanceId) {
  // After bootstrap, the schema should have seeded an instance_id
  std::string instance_id = schema_->get_instance_id();
  EXPECT_FALSE(instance_id.empty());
  EXPECT_EQ(instance_id.length(), 36);  // UUID v4 format
}
```

## Multi-Instance Deployment Example

```
┌─────────────────────────────────────────────────────────────┐
│ Environment: Production (3 HSMs)                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ HSM 1 (Data Center A)                                       │
│  └─ Database: /data/dc-a/vhsm.sqlite                        │
│  └─ Instance ID: 550e8400-e29b-41d4-a716-446655440000      │
│  └─ Audit Events: [..., instance_id: "550e8400-...", ...]   │
│                                                             │
│ HSM 2 (Data Center B)                                       │
│  └─ Database: /data/dc-b/vhsm.sqlite                        │
│  └─ Instance ID: 6b5c38ea-b56e-4f1e-92d0-123456789000      │
│  └─ Audit Events: [..., instance_id: "6b5c38ea-...", ...]   │
│                                                             │
│ HSM 3 (Data Center C)                                       │
│  └─ Database: /data/dc-c/vhsm.sqlite                        │
│  └─ Instance ID: 7c6d49fb-c67f-502f-03e1-234567890111      │
│  └─ Audit Events: [..., instance_id: "7c6d49fb-...", ...]   │
│                                                             │
│ Central Audit Log (Elasticsearch/Splunk/etc.)               │
│  └─ Queries by instance_id to correlate events across DCs   │
│  └─ Example: "Show all signatures from HSM 2 (6b5c38ea...)" │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## UUID v4 Format

The instance ID is a UUID v4 (Universally Unique Identifier, version 4):

```
550e8400-e29b-41d4-a716-446655440000
├─────┬─────────┬─────────┬─────────┬──────────┤
│ time_low    │low  │mid   │high    │reserved  │ node
│ 32 bits     │16b  │16b   │16b     │8b        │ 48b
```

**Properties:**
- **Random:** Generated via `std::random_device` and `std::mt19937`
- **Unique:** Probability of collision is negligible for practical purposes
- **Human-readable:** Can be printed, logged, and searched
- **Standard:** RFC 4122 compliant

**Generation (in `src/core/utils.cpp`):**
```cpp
std::string uuid_v4() {
  // Generate 16 random bytes
  // Format as UUID v4 (set version and variant bits)
  // Return as 36-character string with hyphens
}
```

## Security Considerations

### Confidentiality
- ✅ Instance ID is **not secret** — it's just a correlation tag
- ✅ Safe to log, emit in events, and expose to monitoring systems

### Integrity
- ✅ Instance ID is **immutable after bootstrap** (database as source of truth)
- ✅ Changes can only occur via explicit `seedInstanceId()` (admin operation)

### Availability
- ✅ Instance ID is **cached** to avoid database dependency at query-time
- ✅ Process continues if cache is cleared (re-queries database)

## Migration Path

### v1 Databases (Legacy)

For databases created before instance ID support:
- **On bootstrap:** Existing `db_meta` is detected
- **Fallback:** New instance ID is generated and seeded (v1 DB is upgraded)
- **Result:** Old and new instances have different IDs (safe for migration)

### v4/v5 Databases (Current)

- Instance ID is already seeded during bootstrap
- No migration needed

## Future Enhancements

### Potential Extensions

1. **Cluster ID** — Group multiple HSMs by cluster
   ```sql
   INSERT INTO db_meta (key, value) VALUES ('cluster_id', '...');
   ```

2. **Instance Name** — Human-readable label
   ```sql
   INSERT INTO db_meta (key, value) VALUES ('instance_name', 'HSM-DC-A-01');
   ```

3. **HSM Pairing** — Link backup/redundant instances
   ```sql
   INSERT INTO db_meta (key, value) VALUES ('paired_instance_id', '...');
   ```

4. **Audit Integrity Chain** — Link to next event via hash
   ```cpp
   struct AuditEvent {
     std::string instance_id;
     std::string prev_event_hash;  // Integrity chain
     std::string signature;         // Digital signature
   };
   ```

## Troubleshooting

### Problem: "HSM instance ID not seeded in database"

**Cause:** Database not bootstrapped or migration incomplete

**Solution:**
```cpp
// Ensure DbSchema::bootstrap() is called before creating provider
DbSchema schema(db);
schema.bootstrap();

DatabaseHsmInstanceProvider provider(db);
HsmInstanceId id = provider.getInstanceId();  // Now succeeds
```

### Problem: Instance ID changes between restarts

**Cause:** Process-wide cache was cleared but database wasn't (or vice versa)

**Solution:**
- Process-wide cache is cleared automatically when the PKCS#11 library is unloaded
- On next `C_Initialize()`, call `set_hsm_instance_id()` again
- Database value is immutable, so it's always correct source of truth

### Problem: Multiple HSMs with same Instance ID

**Cause:** Database was copied without generating new UUIDs

**Solution:** For cloned instances, explicitly seed a new ID:
```cpp
HsmInstanceId new_id(vhsm::utils::uuid_v4());
provider.seedInstanceId(new_id);
```

## References

- UUID v4 (RFC 4122): https://tools.ietf.org/html/rfc4122
- vHSM Architecture: `docs/CORE_CRYPTO_SESSION_WHY_COMMENTS_SUMMARY.md`
- Database Schema: `sql/schema_sqlite.sql`
- Audit/Notification: `src/audit/`, `src/notification/`

---

**Document Version:** 1.0  
**Last Updated:** 2025-08-22  
**Maintainer:** vHSM Core Team
