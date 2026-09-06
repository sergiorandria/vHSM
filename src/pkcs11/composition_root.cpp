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
#include "../notification/mobile_push_adapter.h"
#include "../notification/webhook_adapter.h"
#include "../audit/audit_log.h"
#include "../persistence/kdf.h"
#include "../persistence/token_serializer.h"
#include "../persistence/vault.h"
#include "../session/login_throttle.h"
#include "../signature_store/db_connection.h"
#include "../signature_store/db_schema.h"
#include "../signature_store/notification_dispatcher.h"
#include "../signature_store/notification_repository.h"
#include "../signature_store/outbox_poller.h"
#include "../signature_store/signature_dispatcher.h"

#include "pkcs11_internal.h"

#include "../domain/signing/adapters/db_store_adapter.h"
#ifdef VHSM_LEDGER
#include "../domain/signing/adapters/fabric_store_adapter.h"
#endif

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <mutex>

namespace vhsm::pkcs11 {

AppContainer::~AppContainer() = default;
AppContainer::AppContainer(AppContainer &&) noexcept = default;
AppContainer &AppContainer::operator=(AppContainer &&) noexcept = default;

// =============================================================================
// In-memory store — STRICTLY for tests / explicit opt-in.
// Production must use a persistent backend (DB or ledger). Instantiation is
// gated by allow_inmemory() → VHSM_ALLOW_INMEMORY=1 or VHSM_TEST, otherwise
// create_app_container() throws fail-closed (no silent fallback).
// =============================================================================
static bool
allow_inmemory()
{
  if (auto* v = std::getenv("VHSM_ALLOW_INMEMORY"))
    return std::string(v) == "1";
#ifdef VHSM_TEST
  return true;
#endif
  return false;
}

class InMemoryStore final : public vhsm::domain::signing::ISignatureStore
{
public:
  std::optional<std::string>
  store(const SignatureRecord& rec) override
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(data_.begin(), data_.end(),
                           [&](const auto& r) { return r.record_id == rec.record_id; });
    if (it != data_.end())
      return it->record_id;

    data_.push_back(rec);
    return rec.record_id;
  }

  std::optional<SignatureRecord>
  load(const std::string& id) const override
  {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& r : data_)
      if (r.record_id == id)
        return r;
    return std::nullopt;
  }

  std::vector<SignatureRecord>
  list() const override
  {
    std::lock_guard<std::mutex> lk(mu_);
    return data_;
  }

private:
  mutable std::mutex         mu_;
  std::vector<SignatureRecord> data_;
};

static AppContainer::StoreBackend resolve_backend() {
#ifdef VHSM_STORE_BACKEND_ledger
  AppContainer::StoreBackend def = AppContainer::StoreBackend::Ledger;
#else
  AppContainer::StoreBackend def = AppContainer::StoreBackend::Db;
#endif
  if (auto *env = std::getenv("VHSM_STORE_BACKEND")) {
    std::string v(env);
    if (v == "ledger")
      return AppContainer::StoreBackend::Ledger;
    if (v == "db")
      return AppContainer::StoreBackend::Db;
  }
  return def;
}

// Enforce backend exclusivity: DB + ledger anchoring simultaneously is the
// "stacked" configuration the ISignatureStore port was designed to prevent.
// If VHSM_STORE_BACKEND=db and ledger env vars are set, that's a misconfig
// (leftover staging env, shared .env) — fail fast rather than silently
// activating both paths.
static void check_backend_exclusivity(AppContainer::StoreBackend backend) {
  if (backend == AppContainer::StoreBackend::Db) {
    const char *ep = std::getenv("VHSM_LEDGER_ENDPOINT");
    const char *cert = std::getenv("VHSM_LEDGER_CERT");
    const char *key = std::getenv("VHSM_LEDGER_KEY");
    if (ep && *ep && cert && *cert && key && *key)
      throw std::runtime_error(
          "VHSM_STORE_BACKEND=db but VHSM_LEDGER_ENDPOINT/CERT/KEY are set. "
          "Backends are mutually exclusive: unset the LEDGER_* vars or "
          "switch to VHSM_STORE_BACKEND=ledger.");
  }
}

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

std::string resolve_fabric_config_dir() {
  if (auto *env = std::getenv("VHSM_FABRIC_CONFIG_DIR"))
    return env;
  if (std::filesystem::exists("/etc/vhsmd"))
    return "/etc/vhsmd";
  // Dev fallback: repo layout when running without generated /etc/vhsmd
  // (e.g., `ctest` on a fresh checkout). The Conf_with_fabric-CA dir is the
  // source that `generate.sh` turns into /etc/vhsmd.
  auto dev = std::filesystem::path(__FILE__)
                 .parent_path()
                 .parent_path()
                 .parent_path() /
             "network" / "fabric_configuration" / "Conf_with_fabric-CA";
  std::error_code ec;
  if (std::filesystem::exists(dev, ec))
    return dev.string();
  return "/etc/vhsmd";
}

static void ensure_default_token_for_container(vhsm::session::SlotManager &sm) {
  if (!sm.get_slot(0)) {
    // WHY register-then-fetch: register_slot creates the manager-owned Slot;
    // inserting into a locally created Slot would be discarded (the manager
    // keeps only slots from its own registry).
    sm.register_slot(0);
  }
  auto slot = sm.get_slot(0);
  if (!slot)
    return; // registration failed — leave slot absent rather than crash
  if (!slot->is_token_present()) {
    auto tok = std::make_shared<vhsm::keystore::Token>("vHSM Software Token",
                                                       "vhsm-token-0");
    slot->insert_token(std::move(tok));
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
  auto c = std::make_unique<AppContainer>();

  // Logger: stderr sink always (Docker/container compat), syslog sink on
  // Linux for journald/syslog integration. Both are thread-safe.
  c->logger = std::make_shared<vhsm::log::Logger>();
  c->logger->add_sink(std::make_shared<vhsm::log::StderrSink>());
#ifdef __linux__
  c->logger->add_sink(std::make_shared<vhsm::log::SyslogSink>("vhsmd"));
#endif
  // Install as process-wide fallback so header-only modules (ThreadPool)
  // and legacy call sites route through the same sinks.
  vhsm::log::set_global_logger(c->logger.get());

  // Slot manager: owned by the container (not a singleton). Set as the
  // process-wide global for legacy PKCS#11 call sites during DI migration.
  c->slot_manager = std::make_unique<vhsm::session::SlotManager>();
  vhsm::session::detail::set_global_slot_manager(c->slot_manager.get());
  ensure_default_token_for_container(*c->slot_manager);

  c->backend = resolve_backend();
  check_backend_exclusivity(c->backend);

  // Mutually exclusive backends: only one is wired.
  if (c->backend == AppContainer::StoreBackend::Ledger) {
#ifdef VHSM_LEDGER
    // Ledger backend: Fabric is the tamper-evident source of truth, but
    // signature_records MUST persist locally too (audit trail, C_Verify
    // read-back, admin queries). Use the same file-based DB resolution as
    // the DB backend but with a distinct filename so operators can see
    // this is the local index/audit cache, not the primary integrity store.
    c->db_path = resolve_db_path_for_container();
    // Swap filename: vhsm.sqlite -> vhsm_ledger.sqlite
    auto pos = c->db_path.rfind("vhsm.sqlite");
    if (pos != std::string::npos)
      c->db_path = c->db_path.substr(0, pos) + "vhsm_ledger.sqlite";
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
#else
    c->instance_id = "ledger-no-build";
    vhsm::core::set_hsm_instance_id(c->instance_id);
#endif
  } else {
    // DB backend (default): file DB is primary store. Fail-closed — if
    // the DB can't be opened or bootstrapped, C_Initialize must return
    // CKR_GENERAL_ERROR rather than accepting signatures into nothing.
    c->db_path = resolve_db_path_for_container();
    c->db = vhsm::signature_store::db::make_sqlite_connection(c->db_path);
    if (!c->db)
      throw std::runtime_error("VHSM: cannot open SQLite DB at " +
                               c->db_path);
    try {
      vhsm::signature_store::db::DbSchema schema(*c->db);
      schema.bootstrap();
      c->instance_id = schema.get_instance_id();
      vhsm::core::set_hsm_instance_id(c->instance_id);
    } catch (...) {
      throw std::runtime_error("VHSM: SQLite schema bootstrap failed at " +
                               c->db_path);
    }
  }

  c->bounded_bus =
      std::make_unique<vhsm::notification::BoundedNotificationBus>(1024);
  c->bus = c->bounded_bus.get();
  c->login_throttle = std::make_unique<vhsm::session::LoginThrottle>();

  // Audit log: hash-chained when a token KEK is available (tamper-evident);
  // falls back to stderr stub pre-initialization so early events still land.
  {
    auto *early_token = p11_get_token(0);
    const std::vector<std::uint8_t> kek =
        early_token ? early_token->get_kek() : std::vector<std::uint8_t>();
    if (!kek.empty()) {
      auto audit_path = c->db_path + ".audit";
      try {
        c->audit_log = std::make_unique<vhsm::audit::HashChainedAuditLog>(
            audit_path, vhsm::persistence::derive_audit_chain_key(kek));
      } catch (const std::exception &e) {
        VHSM_LOG_ERROR(*c->logger, "audit",
                       "hash-chained audit unavailable: " << e.what());
        c->audit_log = std::make_unique<P11AuditLog>(audit_path + ".fallback");
      }
    } else {
      VHSM_LOG_WARNING(*c->logger, "audit",
                       "no KEK — audit records are file-backed fallback, not hash-chained");
      auto audit_path = c->db_path + ".audit";
      c->audit_log = std::make_unique<P11AuditLog>(audit_path + ".fallback");
    }
  }

  auto *token = p11_get_token(0);
  if (!token) {
    if (!allow_inmemory()) {
      throw std::runtime_error(
          "VHSM: no token present and no persistent store configured — "
          "refusing to use InMemoryStore without VHSM_ALLOW_INMEMORY=1");
    }
    c->store = std::make_unique<InMemoryStore>();
    return c;
  }

  // Notification pipeline only makes sense with DB backend (needs tables).
  // Notification pipeline + outbox poller — enabled for BOTH backends.
  // Previously gated to Db only, which meant ledger-mode deployments never
  // dispatched SIGN_CREATED or DB_WRITE_FAILED events: the outbox table
  // accumulated rows forever and no email/webhook/gRPC alert fired.
  // After fix #1 (file-backed DB for ledger mode), both backends have a
  // persistent event_outbox table that the poller can drain.
  if (c->db) {
    try {
      c->notif_repo =
          std::make_unique<vhsm::signature_store::db::NotificationRepository>(
              *c->db);
      auto disp =
          std::make_unique<vhsm::signature_store::db::NotificationDispatcher>(
              *c->bounded_bus, *c->notif_repo);
      // Per-container adapters (NOT static locals): static adapters are
      // process-wide, so two AppContainer instances would share delivery
      // state. Each container owns its own set.
      vhsm::notification::EmailAdapter email_adapter;
      vhsm::notification::WebhookAdapter webhook_adapter;
      vhsm::notification::GrpcPushAdapter grpc_push_adapter;
      // Mobile push — FCM / Expo push for the vHSM Mobile app (channel mobile_push)
      // Uses Expo push when token is ExponentPushToken, otherwise FCM. Fails closed
      // when FCM_SERVER_KEY is not set, so operators notice misconfig.
      vhsm::notification::MobilePushAdapter mobile_adapter(
          vhsm::notification::MobilePushAdapter::default_expo_sender());
      disp->add_adapter(email_adapter);
      disp->add_adapter(webhook_adapter);
      disp->add_adapter(grpc_push_adapter);
      disp->add_adapter(mobile_adapter);
      disp->start();
      c->notif_dispatcher = std::move(disp);
    } catch (const std::exception &e) {
      VHSM_LOG_WARNING(*c->logger, "pkcs11",
                       "notification pipeline setup failed: " << e.what());
    }
    // Outbox poller — replays PENDING event_outbox rows written
    // transactionally by the dispatcher. Started after the dispatcher so
    // the first poll sees the just-committed rows.
    try {
      c->outbox_poller =
          std::make_unique<vhsm::signature_store::db::OutboxPoller>(*c->db,
                                                                    *c->bus);
      c->outbox_poller->start();
    } catch (const std::exception &e) {
      VHSM_LOG_WARNING(*c->logger, "pkcs11",
                       "outbox poller setup failed: " << e.what());
    }
  }

#ifdef VHSM_LEDGER
  // Ledger worker only for ledger backend and when endpoint is configured.
  // DB backend never gets a ledger worker — check_backend_exclusivity()
  // already rejected that combination at startup.
  if (c->backend == AppContainer::StoreBackend::Ledger) {
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
            std::getenv("VHSM_LEDGER_MSP_ID")
                ? std::getenv("VHSM_LEDGER_MSP_ID")
                : "vHSMMSP");
        auto *bus = c->bus;
        // Ledger backend: dispatch writes to local SQLite (audit trail),
        // LedgerWorker anchors to Fabric asynchronously. The callback
        // updates ledger_tx_id/block/status in the local DB after anchor.
        auto *db = c->db.get();
        auto *audit = c->audit_log.get();
        c->ledger_worker = std::make_unique<vhsm::ledger::LedgerWorker>(
            *c->ledger_client, *bus,
            [db, audit](const SignatureRecord &rec,
                        const vhsm::ledger::LedgerEntry &e) {
              vhsm::signature_store::db::SignatureRepository repo(
                  *db, *p11_get_token(0));
              repo.update_ledger_fields(rec.record_id, e);
              // Link the audit trail to the Fabric anchor: each successful
              // ledger commit writes a hash-chained audit entry that records
              // the on-chain tx_id/block, so the tamper-evident audit log
              // proves which signatures were anchored and where. Best-effort:
              // a failed append must not fail the already-succeeded commit.
              if (audit) {
                // Best-effort: a failed append must not fail the already
                // succeeded ledger commit. Consume the nodiscard result.
                if (auto st = audit->append(
                        "LEDGER_ANCHOR:" + rec.record_id,
                        "tx_id=" + e.tx_id +
                            " block=" + std::to_string(e.block_number));
                    !st) {
                  // intentionally ignored
                }
              }
            });
        // Exactly-once anchoring guard: mark the row PROCESSING as soon as the
        // worker accepts it, so a crash/restart between enqueue and commit does
        // not re-anchor an already-inflight record. (The chaincode upsert makes
        // the ledger write idempotent; this is the DB-side half.)
        c->ledger_worker->set_processing_callback(
            [db](const std::string &record_id) {
              vhsm::signature_store::db::SignatureRepository repo(
                  *db, *p11_get_token(0));
              repo.mark_processing(record_id);
            });
        // Anchor the audit hash-chain tail on the ledger after every append so
        // the tamper-evident audit log becomes externally verifiable (a
        // truncated/forged local audit file no longer matches the anchored
        // tail). Best-effort: failures are logged but never block the audit
        // path.
        if (auto *hca = dynamic_cast<vhsm::audit::HashChainedAuditLog *>(
                c->audit_log.get())) {
          vhsm::ledger::LedgerClient *lc = c->ledger_client.get();
          hca->set_tail_publisher(
              [lc](const std::string &tail_hash, uint64_t seq) {
                if (lc == nullptr)
                  return;
                const auto now_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
                lc->publish_audit_tail(tail_hash, static_cast<int64_t>(seq),
                                       std::to_string(now_ms));
              });
        }
        c->ledger_worker->start();
        // Replay any PENDING records from previous runs.
        vhsm::signature_store::db::LedgerRetryQueue retry(*db);
        for (auto &rec : retry.load_pending_records())
          c->ledger_worker->submit_record(rec);
      } catch (...) {
        c->ledger_client.reset();
        c->ledger_worker.reset();
      }
    }
  }
#endif

  // Unified store port — pick adapter based on backend. New code should use
  // `c->store`; legacy `dispatcher` still uses concrete DB/ledger for now.
  if (c->backend == AppContainer::StoreBackend::Ledger) {
#ifdef VHSM_LEDGER
    if (c->ledger_client) {
      c->store = std::make_unique<vhsm::domain::signing::FabricStoreAdapter>(
          *c->ledger_client);
    } else {
      if (!allow_inmemory()) {
        throw std::runtime_error(
            "VHSM: ledger backend without ledger_client — refusing InMemoryStore without VHSM_ALLOW_INMEMORY=1");
      }
      c->store = std::make_unique<InMemoryStore>();
    }
#else
    if (!allow_inmemory()) {
      throw std::runtime_error(
          "VHSM: ledger backend requested but VHSM_LEDGER not compiled — refusing InMemoryStore");
    }
    c->store = std::make_unique<InMemoryStore>();
#endif
  } else {
    if (c->db) {
      c->store = std::make_unique<vhsm::domain::signing::DbStoreAdapter>(
          *c->db, *token);
    } else {
      if (!allow_inmemory()) {
        throw std::runtime_error(
            "VHSM: DB backend without DB connection — refusing InMemoryStore without VHSM_ALLOW_INMEMORY=1");
      }
      c->store = std::make_unique<InMemoryStore>();
    }
  }

  // SignatureDispatcher accepts optional ledger worker (nullptr = local-only
  // mode) — kept for backward compat, new code should use `store`.
#ifdef VHSM_LEDGER
  c->dispatcher =
      std::make_unique<vhsm::signature_store::db::SignatureDispatcher>(
          *c->db, *token, *c->bus, *c->audit_log, c->ledger_worker.get());
#else
  c->dispatcher =
      std::make_unique<vhsm::signature_store::db::SignatureDispatcher>(
          *c->db, *token, *c->bus, *c->audit_log, nullptr);
#endif

  // Verification service — single place that answers "is this record trustworthy?"
  // Row-integrity HMAC (fail-closed) + ledger cross-check. See header comment.
  // C_Verify stays crypto-only; Admin::VerifySignature and REST /verify/:id call this.
  if (c->db && token) {
    c->verify_repo =
        std::make_unique<vhsm::signature_store::db::SignatureRepository>(
            *c->db, *token);
#ifdef VHSM_LEDGER
    c->verification_service =
        std::make_unique<vhsm::signature_store::db::VerificationService>(
            *c->db, c->ledger_client.get(), *c->verify_repo);
#else
    c->verification_service =
        std::make_unique<vhsm::signature_store::db::VerificationService>(
            *c->db, nullptr, *c->verify_repo);
#endif
  }

  c->vault = open_or_create_vault();

  return c;
}

void destroy_app_container(std::unique_ptr<AppContainer> &container) noexcept {
  if (!container)
    return;
  // Stop outbox poller first so it doesn't race with dispatcher drain.
  if (container->outbox_poller) {
    container->outbox_poller->stop();
    container->outbox_poller.reset();
  }
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
  container->verification_service.reset();
  container->verify_repo.reset();
  container->store.reset();
  // vault is closed after dispatcher (persist token before reset in p11)
  container->vault.reset();
  container->bounded_bus.reset();
  container->bus = nullptr;
  container->db.reset();
  vhsm::session::detail::set_global_slot_manager(nullptr);
  container->slot_manager.reset();
  container.reset();
}

} // namespace vhsm::pkcs11
