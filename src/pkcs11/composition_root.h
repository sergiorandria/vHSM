#ifndef VHSM_PKCS11_COMPOSITION_ROOT_H
#define VHSM_PKCS11_COMPOSITION_ROOT_H

#include <memory>
#include <string>

#include "../core/hsm_instance.h"
#include "../domain/signing/isignature_store.h"
#include "../session/slot_manager.h"
#include "../signature_store/db_connection.h"

// Forward declares for impl to keep header light
#ifdef VHSM_LEDGER
namespace vhsm::ledger {
class LedgerClient;
class LedgerWorker;
} // namespace vhsm::ledger
#endif
namespace vhsm::notification {
class BoundedNotificationBus;
class NotificationBus;
} // namespace vhsm::notification
namespace vhsm::audit {
class AuditLog;
}
namespace vhsm::signature_store::db {
class NotificationDispatcher;
class NotificationRepository;
class OutboxPoller;
class SignatureDispatcher;
} // namespace vhsm::signature_store::db
namespace vhsm::persistence {
class Vault;
}

namespace vhsm::pkcs11 {

// WHY a composition root: Before `AppContainer`, `p11_init.cpp:99` held 8
// `g_*` globals (`g_dbConnection`, `g_ledgerWorker`, ...) each created in a
// separate `init_*` helper with duplicated `resolve_db_path` logic. Tests
// could not create an isolated DB (`:memory:`) without touching the globals,
// and `VHSM_LEDGER` vs `VHSM_STORE_BACKEND=db|ledger` diverged. A single
// `AppContainer` owns the whole object graph (`db → bus → ledger → dispatcher
// → vault` in that order) so `create_app_container()` is the only place that
// knows the wiring, `p11_init` becomes a thin `C_Initialize` adapter that
// moves the container's members into the legacy globals, and tests can
// `create_app_container()` with `:memory:` without polluting the process.
// AppContainer — composition root (DDD application layer).
// Owns all long-lived services that p11_init previously held as globals
// (g_dbConnection, g_ledgerWorker, ...). Keeping them together makes the
// dependency graph explicit and testable: tests can create a container with
// :memory: DB and mock ledger, while production uses file DB + Fabric gateway.
// p11_init still mirrors globals for ABI compat but now delegates creation
// to this factory.
struct AppContainer {
  enum class StoreBackend { Db, Ledger };
  StoreBackend backend = StoreBackend::Db;
  std::string instance_id;

  // --- DB backend (mutually exclusive with ledger) ---
  std::unique_ptr<vhsm::signature_store::db::IDbConnection> db;
  std::string db_path;

  // --- Ledger backend (mutually exclusive with DB) ---
#ifdef VHSM_LEDGER
  std::unique_ptr<vhsm::ledger::LedgerClient> ledger_client;
  std::unique_ptr<vhsm::ledger::LedgerWorker> ledger_worker;
#endif

  // Common notification bus + dispatcher (used by both backends, but DB
  // tables only exist when backend==Db; ledger backend uses in-memory bus)
  std::unique_ptr<vhsm::notification::BoundedNotificationBus> bounded_bus;
  vhsm::notification::NotificationBus *bus = nullptr; // non-owning view
  std::unique_ptr<vhsm::audit::AuditLog> audit_log;
  std::unique_ptr<vhsm::signature_store::db::NotificationRepository> notif_repo;
  std::unique_ptr<vhsm::signature_store::db::NotificationDispatcher>
      notif_dispatcher;
  // Outbox poller for transactional SIGN_CREATED (replaces direct publish)
  // WHY poller: The dispatcher writes SIGN_CREATED into `event_outbox` in the
  // same DB transaction as `signature_records`. The poller replays PENDING rows
  // on a timer and on C_Initialize, so a crash between DB commit and bus
  // publish does not lose the event — no distributed transaction needed.
  std::unique_ptr<vhsm::signature_store::db::OutboxPoller> outbox_poller;

  // Unified signature store port — scaffolding for a future migration.
  // NOT the production write path: C_Sign/C_Verify use `dispatcher` below.
  // The port exists so new code CAN target ISignatureStore, but the
  // adapters are incomplete (DbStoreAdapter::load() fills only record_id;
  // FabricStoreAdapter::load() returns nullopt; list() returns {} on both).
  // Finishing this migration (routing C_Sign through store, deleting
  // dispatcher) is tracked as future work — see ARCHITECTURE_REVIEW.md §3.
  std::unique_ptr<vhsm::domain::signing::ISignatureStore> store;

  // Signature pipeline — THE production write path. C_Sign/C_SignFinal
  // call p11_signature_dispatcher() which returns this object. Persists to
  // signature_records table, publishes SIGN_CREATED to notification bus,
  // optionally anchors to ledger via LedgerWorker.
  std::unique_ptr<vhsm::signature_store::db::SignatureDispatcher> dispatcher;

  // Vault (optional)
  std::unique_ptr<vhsm::persistence::Vault> vault;

  // Slot manager — owns the virtual slot registry. Injected (not a
  // singleton) so tests can create isolated containers with independent
  // slot sets.
  std::unique_ptr<vhsm::session::SlotManager> slot_manager;

  AppContainer() = default;
  ~AppContainer();
  AppContainer(const AppContainer &) = delete;
  AppContainer &operator=(const AppContainer &) = delete;
  AppContainer(AppContainer &&) noexcept;
  AppContainer &operator=(AppContainer &&) noexcept;
};

// Creates a fully wired container from environment (VHSM_DB_PATH, VHSM_HOME,
// VHSM_VAULT_*, VHSM_LEDGER_*). The default token is ensured before wiring
// so SignatureDispatcher has a Token to bind to. Throws on fatal errors;
// ledger/vault failures are swallowed (local-only fallback) to match
// previous C_Initialize semantics.
std::unique_ptr<AppContainer> create_app_container();

// Tears down a container in the correct order (dispatcher → ledger → bus → db).
// Safe to call with nullptr.
void destroy_app_container(std::unique_ptr<AppContainer> &container) noexcept;

// Helpers exposed for testing
std::string resolve_db_path_for_container();
std::string resolve_fabric_config_dir(); // /etc/vhsmd or network/... fallback

} // namespace vhsm::pkcs11

#endif // VHSM_PKCS11_COMPOSITION_ROOT_H
