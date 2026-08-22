#include "pkcs11.h"
#include "pkcs11_internal.h"
#include "pkcs11_types.h"

#include "../keystore/slot.h"
#include "../keystore/token.h"
#include "../ledger/ledger_client.h"
#include "../ledger/ledger_entry.h"
#include "../ledger/ledger_worker.h"
#include "../notification/bounded_notification_bus.h"
#include "../notification/email_adapter.h"
#include "../notification/grpc_push_adapter.h"
#include "../notification/webhook_adapter.h"
#include "../persistence/token_serializer.h"
#include "../persistence/vault.h"
#include "../signature_store/db_connection.h"
#include "../signature_store/db_schema.h"
#include "../signature_store/ledger_retry_queue.h"
#include "../signature_store/notification_dispatcher.h"
#include "../signature_store/notification_repository.h"
#include "../signature_store/signature_dispatcher.h"
#include "../signature_store/signature_repository.h"
#include "../core/hsm_instance.h"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>

#include "vhsm/version.h"

namespace vhsm::pkcs11 {

static void ensure_default_token() {
  auto &sm = vhsm::session::SlotManager::get_instance();
  if (!sm.get_slot(0)) {
    auto slot = std::make_shared<vhsm::keystore::Slot>(0);
    auto tok = std::make_shared<vhsm::keystore::Token>("vHSM Software Token",
                                                       "vhsm-token-0");
    slot->insert_token(tok);
    sm.register_slot(0);
  }
}

// Open (or create) the optional encrypted vault that backs the default token.
//
// Vault persistence is opt-in: it is enabled only when BOTH VHSM_VAULT_PATH and
// VHSM_VAULT_PASSWORD are set.  On first run (no vault file yet) we create a
// fresh vault from the current token snapshot so subsequent finalize() calls
// have a place to save.  On later runs we open the existing vault and restore
// the durable token state (flags, counters, KEK) so a process restart recovers
// the token exactly as it was.  Failures are swallowed here — a missing/wrong
// password must not prevent C_Initialize from succeeding (the token just starts
// in its fresh state).
static void init_vault() {
  const char *path_cstr = std::getenv("VHSM_VAULT_PATH");
  const char *pass_cstr = std::getenv("VHSM_VAULT_PASSWORD");
  if (!path_cstr || !*path_cstr || !pass_cstr)
    return;

  const std::filesystem::path vault_path(path_cstr);
  const std::string password = pass_cstr;

  auto *token = p11_get_token(0);
  if (!token)
    return;

  try {
    if (std::filesystem::exists(vault_path)) {
      g_vault =
          std::make_unique<vhsm::persistence::Vault>(vault_path, password);
      if (g_vault->is_valid()) {
        vhsm::persistence::restore_token_from_vault(*token, *g_vault);
      }
    } else {
      const std::vector<u8> snap = vhsm::persistence::serialize_token_snapshot(
          vhsm::persistence::snapshot_from_token(*token));
      g_vault = std::make_unique<vhsm::persistence::Vault>(
          vhsm::persistence::Vault::create(vault_path, password, snap));
    }
  } catch (const std::exception &) {
    // Vault unavailable (corrupt file / bad password / I/O error): proceed
    // with the in-memory token.
    g_vault.reset();
  }
}

// Resolve the file-backed SQLite database path.
//
// Precedence:
//   1. VHSM_DB_PATH  — explicit path (highest precedence; used by tests and
//   admins)
//   2. VHSM_HOME     — data directory; DB lives at $VHSM_HOME/vhsm.sqlite
//   3. ~/.vhs        — platform default; DB lives at ~/.vhs/vhsm.sqlite
//
// The parent directory is created (recursively) if it does not exist so the
// module can bootstrap a fresh data store on first run.
static std::string resolve_db_path() {
  const char *explicit_path = std::getenv("VHSM_DB_PATH");
  if (explicit_path && *explicit_path) {
    return explicit_path;
  }

  std::filesystem::path base;
  const char *home = std::getenv("VHSM_HOME");
  if (home && *home) {
    base = std::filesystem::path(home);
  } else {
#ifdef _WIN32
    const char *local = std::getenv("LOCALAPPDATA");
    if (local && *local) {
      base = std::filesystem::path(local) / "vHSM";
    } else {
      const char *up = std::getenv("USERPROFILE");
      base = std::filesystem::path(up ? up : ".") / "vHSM";
    }
#else
    const char *home_dir = std::getenv("HOME");
    base = std::filesystem::path(home_dir ? home_dir : ".") / ".vhs";
#endif
  }

  std::filesystem::path db_path = base / "vhsm.sqlite";
  std::error_code ec;
  std::filesystem::create_directories(base, ec);
  // If the directory could not be created (e.g., read-only mount), fall back
  // to a per-process temp DB rather than failing C_Initialize outright.
  if (ec) {
    return ":memory:";
  }
  return db_path.string();
}

static void init_signature_dispatcher() {
  // Open (or create) the file-backed SQLite database and bootstrap the schema.
  // A second C_Initialize (after C_Finalize) reuses the same file, so
  // signature records persist across module load/unload cycles.
  std::string db_path = resolve_db_path();
  g_dbConnection = vhsm::signature_store::db::make_sqlite_connection(db_path);
  if (!g_dbConnection)
    return;

  // Bootstrap the canonical schema (signature_records, verifications, etc.).
  try {
    vhsm::signature_store::db::DbSchema schema(*g_dbConnection);
    schema.bootstrap();
    vhsm::core::set_hsm_instance_id(schema.get_instance_id());
  } catch (...) {
    // Schema creation failed, continue without dispatcher
    return;
  }

  // Create the in-process notification bus and the background dispatcher.
  // Producers (signature dispatcher, ledger worker, keystore) publish into
  // the bounded bus; the dispatcher resolves the DB-backed subscriber list
  // and delivers via the channel adapters.
  g_boundedBus =
      std::make_unique<vhsm::notification::BoundedNotificationBus>(1024);
  g_notificationBus =
      std::unique_ptr<vhsm::notification::NotificationBus>(g_boundedBus.get());
  g_auditLog = std::make_unique<P11AuditLog>();

  // Get the default token for the dispatcher
  auto *token = p11_get_token(0);
  if (!token)
    return;

  // Wire the notification pipeline (optional if the DB is unavailable).
  if (g_dbConnection) {
    try {
      g_notificationRepo =
          std::make_unique<vhsm::signature_store::db::NotificationRepository>(
              *g_dbConnection);

      auto dispatcher =
          std::make_unique<vhsm::signature_store::db::NotificationDispatcher>(
              *g_boundedBus, *g_notificationRepo);
      static vhsm::notification::EmailAdapter email_adapter;
      static vhsm::notification::WebhookAdapter webhook_adapter;
      static vhsm::notification::GrpcPushAdapter grpc_push_adapter;
      dispatcher->add_adapter(email_adapter);
      dispatcher->add_adapter(webhook_adapter);
      dispatcher->add_adapter(grpc_push_adapter);
      dispatcher->start();
      g_notificationDispatcher = std::move(dispatcher);
    } catch (...) {
      // Notification pipeline unavailable; events still flow through the
      // bounded bus and can be drained later.
    }
  }

  // Ledger anchoring is optional: only construct the worker + client when a
  // Fabric gateway endpoint is configured via environment variables.  When
  // unset, the dispatcher runs in local-only mode (no blockchain anchoring).
  const char *endpoint = std::getenv("VHSM_LEDGER_ENDPOINT");
  const char *cert = std::getenv("VHSM_LEDGER_CERT");
  const char *key = std::getenv("VHSM_LEDGER_KEY");
  if (endpoint && cert && key && *endpoint && *cert && *key) {
    try {
      g_ledgerClient = std::make_unique<vhsm::ledger::LedgerClient>(
          endpoint, cert, key,
          std::getenv("VHSM_LEDGER_CA") ? std::getenv("VHSM_LEDGER_CA") : "",
          std::getenv("VHSM_LEDGER_SERVER_NAME")
              ? std::getenv("VHSM_LEDGER_SERVER_NAME")
              : "",
          std::getenv("VHSM_LEDGER_MSP_ID") ? std::getenv("VHSM_LEDGER_MSP_ID")
                                            : "vHSMMSP");

      auto *db = g_dbConnection.get();
      auto *bus = g_notificationBus.get();
      g_ledgerWorker = std::make_unique<vhsm::ledger::LedgerWorker>(
          *g_ledgerClient, *bus,
          [db](const SignatureRecord &record,
               const vhsm::ledger::LedgerEntry &entry) {
            vhsm::signature_store::db::SignatureRepository repo(
                *db, *p11_get_token(0));
            repo.update_ledger_fields(record.record_id, entry);
          });
      g_ledgerWorker->start();

      // Crash recovery: any record left with ledger_status='PENDING'
      // (e.g. the worker was killed mid-submission) is re-submitted on
      // startup so the ledger and the DB converge.
      vhsm::signature_store::db::LedgerRetryQueue retry(*db);
      for (auto &rec : retry.load_pending_records()) {
        g_ledgerWorker->submit_record(rec);
      }
    } catch (...) {
      // Ledger setup failed (e.g., unreachable gateway); fall back to
      // local-only mode.  Signatures are still persisted and audited.
      g_ledgerClient.reset();
      g_ledgerWorker.reset();
    }
  }

  // Create SignatureDispatcher (may run with or without ledger anchoring).
  g_signatureDispatcher =
      std::make_unique<vhsm::signature_store::db::SignatureDispatcher>(
          *g_dbConnection, *token, *g_notificationBus, *g_auditLog,
          g_ledgerWorker.get());
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  if (g_initialized)
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  if (pInitArgs != nullptr) {
    auto *args = static_cast<CK_C_INITIALIZE_ARGS_PTR>(pInitArgs);
    if (args->flags & CKF_OS_LOCKING_OK) {
      // we always support locking; fine
    }
  }
  ensure_default_token();
  init_vault();
  init_signature_dispatcher();
  g_initialized = true;
  return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  if (!g_initialized)
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pReserved != nullptr)
    return CKR_ARGUMENTS_BAD;
  g_initialized = false;

  // Persist the default token's durable state into the vault before any
  // reset, so a subsequent C_Initialize recovers the same token.
  if (g_vault) {
    if (auto *token = p11_get_token(0)) {
      try {
        vhsm::persistence::persist_token_to_vault(*token, *g_vault);
      } catch (const std::exception &) {
        // Best-effort: keep going with finalization.
      }
    }
    g_vault.reset();
  }

  // Drain the notification pipeline first so queued events flush, then the
  // ledger worker so in-flight anchoring completes during normal shutdown.
  if (g_notificationDispatcher) {
    g_notificationDispatcher->drain_and_stop();
    g_notificationDispatcher.reset();
  }
  g_notificationRepo.reset();
  if (g_ledgerWorker) {
    g_ledgerWorker->drain_and_stop();
    g_ledgerWorker.reset();
  }
  g_ledgerClient.reset();
  g_signatureDispatcher.reset();
  g_notificationBus.reset();
  g_boundedBus.reset();
  g_dbConnection.reset();
  vhsm::session::SlotManager::get_instance().reset();
  return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
  if (!pInfo)
    return CKR_ARGUMENTS_BAD;
  std::memset(pInfo, 0, sizeof(CK_INFO));
  pInfo->cryptokiVersion.major = 2;
  pInfo->cryptokiVersion.minor = 40;
  pInfo->libraryVersion.major = VHSM_VERSION_MAJOR;
  pInfo->libraryVersion.minor = VHSM_VERSION_MINOR;
  const char *m = "vHSM";
  const char *d = "vHSM PKCS#11 Module";
  std::memcpy(pInfo->manufacturerID, m,
              std::min(std::strlen(m), sizeof(pInfo->manufacturerID)));
  std::memcpy(pInfo->libraryDescription, d,
              std::min(std::strlen(d), sizeof(pInfo->libraryDescription)));
  return CKR_OK;
}

} // namespace vhsm::pkcs11
