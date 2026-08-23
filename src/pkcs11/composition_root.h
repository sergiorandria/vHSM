#ifndef VHSM_PKCS11_COMPOSITION_ROOT_H
#define VHSM_PKCS11_COMPOSITION_ROOT_H

#include <memory>
#include <string>

#include "../core/hsm_instance.h"
#include "../signature_store/db_connection.h"

// Forward declares for impl to keep header light
#ifdef VHSM_LEDGER
namespace vhsm::ledger {
class LedgerClient;
class LedgerWorker;
}
#endif
namespace vhsm::notification {
class BoundedNotificationBus;
class NotificationBus;
}
namespace vhsm::audit {
class AuditLog;
}
namespace vhsm::signature_store::db {
class NotificationDispatcher;
class NotificationRepository;
class SignatureDispatcher;
}
namespace vhsm::persistence {
class Vault;
}

namespace vhsm::pkcs11 {

// AppContainer — composition root (DDD application layer).
// Owns all long-lived services that p11_init previously held as globals
// (g_dbConnection, g_ledgerWorker, ...). Keeping them together makes the
// dependency graph explicit and testable: tests can create a container with
// :memory: DB and mock ledger, while production uses file DB + Fabric gateway.
// p11_init still mirrors globals for ABI compat but now delegates creation
// to this factory.
struct AppContainer {
  // DB + schema
  std::unique_ptr<vhsm::signature_store::db::IDbConnection> db;
  std::string db_path;
  std::string instance_id;

  // Notification bus + dispatcher
  std::unique_ptr<vhsm::notification::BoundedNotificationBus> bounded_bus;
  vhsm::notification::NotificationBus* bus = nullptr; // non-owning view of bounded_bus
  std::unique_ptr<vhsm::audit::AuditLog> audit_log;
  std::unique_ptr<vhsm::signature_store::db::NotificationRepository> notif_repo;
  std::unique_ptr<vhsm::signature_store::db::NotificationDispatcher> notif_dispatcher;

  // Ledger (optional, only when VHSM_LEDGER is ON)
#ifdef VHSM_LEDGER
  std::unique_ptr<vhsm::ledger::LedgerClient> ledger_client;
  std::unique_ptr<vhsm::ledger::LedgerWorker> ledger_worker;
#endif

  // Signature pipeline
  std::unique_ptr<vhsm::signature_store::db::SignatureDispatcher> dispatcher;

  // Vault (optional)
  std::unique_ptr<vhsm::persistence::Vault> vault;

  AppContainer() = default;
  ~AppContainer();
  AppContainer(const AppContainer&) = delete;
  AppContainer& operator=(const AppContainer&) = delete;
  AppContainer(AppContainer&&) noexcept;
  AppContainer& operator=(AppContainer&&) noexcept;
};

// Creates a fully wired container from environment (VHSM_DB_PATH, VHSM_HOME,
// VHSM_VAULT_*, VHSM_LEDGER_*). The default token is ensured before wiring
// so SignatureDispatcher has a Token to bind to. Throws on fatal errors;
// ledger/vault failures are swallowed (local-only fallback) to match
// previous C_Initialize semantics.
std::unique_ptr<AppContainer> create_app_container();

// Tears down a container in the correct order (dispatcher → ledger → bus → db).
// Safe to call with nullptr.
void destroy_app_container(std::unique_ptr<AppContainer>& container) noexcept;

// Helpers exposed for testing
std::string resolve_db_path_for_container();

} // namespace vhsm::pkcs11

#endif // VHSM_PKCS11_COMPOSITION_ROOT_H
