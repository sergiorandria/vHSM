#include "composition_root.h"

#include "../core/hsm_instance.h"
#include "../keystore/slot.h"
#include "../keystore/token.h"
#ifdef VHSM_LEDGER
#include "../ledger/ledger_client.h"
#include "../ledger/ledger_worker.h"
#include "../signature_store/ledger_retry_queue.h"
#include "../signature_store/signature_repository.h"
#endif
#include "../notification/bounded_notification_bus.h"
#include "../notification/email_adapter.h"
#include "../notification/grpc_push_adapter.h"
#include "../notification/webhook_adapter.h"
#include "../persistence/token_serializer.h"
#include "../persistence/vault.h"
#include "../signature_store/db_connection.h"
#include "../signature_store/db_schema.h"
#include "../signature_store/notification_dispatcher.h"
#include "../signature_store/notification_repository.h"
#include "../signature_store/signature_dispatcher.h"

#include "pkcs11_internal.h"

#include <cstdlib>
#include <filesystem>
#include <memory>

namespace vhsm::pkcs11 {

AppContainer::~AppContainer() = default;
AppContainer::AppContainer(AppContainer &&) noexcept = default;
AppContainer &AppContainer::operator=(AppContainer &&) noexcept = default;

std::string resolve_db_path_for_container() {
  const char *explicit_path = std::getenv("VHSM_DB_PATH");
  if (explicit_path && *explicit_path)
    return explicit_path;

  std::filesystem::path base;
  const char *home = std::getenv("VHSM_HOME");
  if (home && *home) {
    base = std::filesystem::path(home);
  } else {
#ifdef _WIN32
    const char *local = std::getenv("LOCALAPPDATA");
    if (local && *local)
      base = std::filesystem::path(local) / "vHSM";
    else {
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
  if (ec)
    return ":memory:";
  return db_path.string();
}

static void ensure_default_token_for_container() {
  auto &sm = vhsm::session::SlotManager::get_instance();
  if (!sm.get_slot(0)) {
    auto slot = std::make_shared<vhsm::keystore::Slot>(0);
    auto tok = std::make_shared<vhsm::keystore::Token>("vHSM Software Token",
                                                       "vhsm-token-0");
    slot->insert_token(tok);
    sm.register_slot(0);
  }
}

static std::unique_ptr<vhsm::persistence::Vault> open_or_create_vault() {
  const char *path_cstr = std::getenv("VHSM_VAULT_PATH");
  const char *pass_cstr = std::getenv("VHSM_VAULT_PASSWORD");
  if (!path_cstr || !*path_cstr || !pass_cstr)
    return nullptr;

  const std::filesystem::path vault_path(path_cstr);
  const std::string password = pass_cstr;
  auto *token = p11_get_token(0);
  if (!token)
    return nullptr;

  try {
    if (std::filesystem::exists(vault_path)) {
      auto v = std::make_unique<vhsm::persistence::Vault>(vault_path, password);
      if (v->is_valid())
        vhsm::persistence::restore_token_from_vault(*token, *v);
      return v;
    } else {
      const std::vector<u8> snap = vhsm::persistence::serialize_token_snapshot(
          vhsm::persistence::snapshot_from_token(*token));
      return std::make_unique<vhsm::persistence::Vault>(
          vhsm::persistence::Vault::create(vault_path, password, snap));
    }
  } catch (...) {
    return nullptr;
  }
}

std::unique_ptr<AppContainer> create_app_container() {
  ensure_default_token_for_container();

  auto c = std::make_unique<AppContainer>();
  c->db_path = resolve_db_path_for_container();
  c->db = vhsm::signature_store::db::make_sqlite_connection(c->db_path);
  if (!c->db)
    return c;

  try {
    vhsm::signature_store::db::DbSchema schema(*c->db);
    schema.bootstrap();
    c->instance_id = schema.get_instance_id();
    vhsm::core::set_hsm_instance_id(c->instance_id);
  } catch (...) {
    return c;
  }

  c->bounded_bus =
      std::make_unique<vhsm::notification::BoundedNotificationBus>(1024);
  c->bus = c->bounded_bus.get();
  c->audit_log = std::make_unique<P11AuditLog>();

  auto *token = p11_get_token(0);
  if (!token)
    return c;

  if (c->db) {
    try {
      c->notif_repo =
          std::make_unique<vhsm::signature_store::db::NotificationRepository>(
              *c->db);
      auto disp =
          std::make_unique<vhsm::signature_store::db::NotificationDispatcher>(
              *c->bounded_bus, *c->notif_repo);
      static vhsm::notification::EmailAdapter email_adapter;
      static vhsm::notification::WebhookAdapter webhook_adapter;
      static vhsm::notification::GrpcPushAdapter grpc_push_adapter;
      disp->add_adapter(email_adapter);
      disp->add_adapter(webhook_adapter);
      disp->add_adapter(grpc_push_adapter);
      disp->start();
      c->notif_dispatcher = std::move(disp);
    } catch (...) {
    }
  }

#ifdef VHSM_LEDGER
  const char *endpoint = std::getenv("VHSM_LEDGER_ENDPOINT");
  const char *cert = std::getenv("VHSM_LEDGER_CERT");
  const char *key = std::getenv("VHSM_LEDGER_KEY");
  if (endpoint && cert && key && *endpoint && *cert && *key) {
    try {
      c->ledger_client = std::make_unique<vhsm::ledger::LedgerClient>(
          endpoint, cert, key,
          std::getenv("VHSM_LEDGER_CA") ? std::getenv("VHSM_LEDGER_CA") : "",
          std::getenv("VHSM_LEDGER_SERVER_NAME")
              ? std::getenv("VHSM_LEDGER_SERVER_NAME")
              : "",
          std::getenv("VHSM_LEDGER_MSP_ID") ? std::getenv("VHSM_LEDGER_MSP_ID")
                                            : "vHSMMSP");
      auto *db = c->db.get();
      auto *bus = c->bus;
      c->ledger_worker = std::make_unique<vhsm::ledger::LedgerWorker>(
          *c->ledger_client, *bus,
          [db](const SignatureRecord &rec, const vhsm::ledger::LedgerEntry &e) {
            vhsm::signature_store::db::SignatureRepository repo(
                *db, *p11_get_token(0));
            repo.update_ledger_fields(rec.record_id, e);
          });
      c->ledger_worker->start();
      vhsm::signature_store::db::LedgerRetryQueue retry(*db);
      for (auto &rec : retry.load_pending_records())
        c->ledger_worker->submit_record(rec);
    } catch (...) {
      c->ledger_client.reset();
      c->ledger_worker.reset();
    }
  }
#endif

  // SignatureDispatcher accepts optional ledger worker (nullptr = local-only
  // mode)
#ifdef VHSM_LEDGER
  c->dispatcher =
      std::make_unique<vhsm::signature_store::db::SignatureDispatcher>(
          *c->db, *token, *c->bus, *c->audit_log, c->ledger_worker.get());
#else
  c->dispatcher =
      std::make_unique<vhsm::signature_store::db::SignatureDispatcher>(
          *c->db, *token, *c->bus, *c->audit_log, nullptr);
#endif

  c->vault = open_or_create_vault();

  return c;
}

void destroy_app_container(std::unique_ptr<AppContainer> &container) noexcept {
  if (!container)
    return;
  // Order mirrors p11_init.cpp: dispatcher → ledger → bus → db
  if (container->notif_dispatcher) {
    container->notif_dispatcher->drain_and_stop();
    container->notif_dispatcher.reset();
  }
  container->notif_repo.reset();
#ifdef VHSM_LEDGER
  if (container->ledger_worker) {
    container->ledger_worker->drain_and_stop();
    container->ledger_worker.reset();
  }
  container->ledger_client.reset();
#endif
  container->dispatcher.reset();
  // vault is closed after dispatcher (persist token before reset in p11)
  container->vault.reset();
  container->bounded_bus.reset();
  container->bus = nullptr;
  container->db.reset();
  container.reset();
}

} // namespace vhsm::pkcs11
