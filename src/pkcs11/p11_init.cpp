#include "composition_root.h"
#include "pkcs11.h"
#include "pkcs11_internal.h"
#include "pkcs11_types.h"

#include "../keystore/slot.h"
#include "../keystore/token.h"
#include "../persistence/token_serializer.h"
#include "../persistence/vault.h"

#include "../core/hsm_instance.h"

#include <cstring>
#include <memory>

#include "vhsm/version.h"

namespace vhsm::pkcs11 {

// All initialization logic lives in composition_root.cpp::create_app_container().
// The dead duplicate functions (ensure_default_token, init_vault,
// resolve_db_path, init_signature_dispatcher) were deleted — they were
// [[maybe_unused]] near-line-for-line copies of what create_app_container()
// does, and a future engineer fixing a DB-path bug had a 50/50 chance of
// editing the wrong copy. See commit history for the deleted code.

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  if (g_initialized)
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  if (pInitArgs != nullptr) {
    auto *args = static_cast<CK_C_INITIALIZE_ARGS_PTR>(pInitArgs);
    if (args->flags & CKF_OS_LOCKING_OK) {
      // we always support locking; fine
    }
  }
  // Single wiring via AppContainer (DDD composition root).
  try {
    g_appContainer = create_app_container();
    // Move ownership into legacy globals for ABI compat; g_appContainer
    // retains non-global members (store, backend info) for future use.
    g_dbConnection = std::move(g_appContainer->db);
    g_boundedBus = std::move(g_appContainer->bounded_bus);
    g_notificationBus = g_boundedBus.get();
    g_auditLog = std::move(g_appContainer->audit_log);
    g_notificationRepo = std::move(g_appContainer->notif_repo);
    g_notificationDispatcher = std::move(g_appContainer->notif_dispatcher);
#ifdef VHSM_LEDGER
    g_ledgerClient = std::move(g_appContainer->ledger_client);
    g_ledgerWorker = std::move(g_appContainer->ledger_worker);
#endif
    g_signatureDispatcher = std::move(g_appContainer->dispatcher);
    g_vault = std::move(g_appContainer->vault);
    // NOTE: g_appContainer->store (ISignatureStore port) is NOT moved to
    // a global — the dispatcher is the production write path. The port
    // exists as scaffolding for a future migration; see ARCHITECTURE_REVIEW.md.
  } catch (const std::exception &) {
    // Fail-closed: storage init failure must not silently degrade to
    // in-memory mode (P6/#7). If the DB path is bad or vault fails,
    // C_Initialize returns CKR_GENERAL_ERROR rather than accepting
    // signatures into an audit trail that will be lost.
    g_appContainer.reset();
    g_dbConnection.reset();
    g_boundedBus.reset();
    g_notificationBus = nullptr;
    g_auditLog.reset();
    g_notificationRepo.reset();
    g_notificationDispatcher.reset();
#ifdef VHSM_LEDGER
    g_ledgerClient.reset();
    g_ledgerWorker.reset();
#endif
    g_signatureDispatcher.reset();
    g_vault.reset();
    return CKR_GENERAL_ERROR;
  }
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
#ifdef VHSM_LEDGER
  if (g_ledgerWorker) {
    g_ledgerWorker->drain_and_stop();
    g_ledgerWorker.reset();
  }
  g_ledgerClient.reset();
#endif
  g_signatureDispatcher.reset();
  g_notificationBus = nullptr;
  g_boundedBus.reset();
  g_dbConnection.reset();
  g_appContainer.reset();
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
