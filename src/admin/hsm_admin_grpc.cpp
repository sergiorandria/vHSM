#include "hsm_admin_grpc.h"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <grpc/grpc.h>
#include <grpcpp/security/auth_context.h>

#include "../keystore/slot.h"
#include "../log/logger.h"
#include "../keystore/token.h"
#include "../ledger/ledger_client.h"
#include "../ledger/ledger_worker.h"
#include "../audit/audit_log.h"
#include "../metrics/metrics.h"
#include "../signature_store/db_connection.h"
#include "../signature_store/ledger_retry_queue.h"
#include "../signature_store/notification_repository.h"
#include "../signature_store/signature_query.h"

namespace vhsm::admin {

HsmAdminServiceImpl::HsmAdminServiceImpl(
    vhsm::signature_store::db::IDbConnection *db, vhsm::keystore::Token *token,
    vhsm::ledger::LedgerClient *ledger_client,
    vhsm::ledger::LedgerWorker *ledger_worker,
    vhsm::notification::NotificationBus *bus, vhsm::audit::AuditLog *audit_log)
    : db_(db), token_(token), ledger_client_(ledger_client),
      ledger_worker_(ledger_worker), bus_(bus), audit_log_(audit_log) {}

namespace {

// Resolves slot -> token via the global SlotManager singleton (shared with the
// PKCS#11 module).  Returns nullptr (with a status string set) on failure.
std::shared_ptr<keystore::Token> resolve_token(uint32_t slot_id,
                                               std::string &err) {
  auto slot = vhsm::session::detail::global_slot_manager().get_slot(slot_id);
  if (!slot) {
    err = "slot not found: " + std::to_string(slot_id);
    return nullptr;
  }
  auto token = slot->get_token();
  if (!token) {
    err = "no token present in slot " + std::to_string(slot_id);
    return nullptr;
  }
  return token;
}

int64_t to_int64(const std::optional<std::string> &v, int64_t fallback = 0) {
  if (!v) {
    return fallback;
  }
  try {
    return std::stoll(*v);
  } catch (const std::exception &) {
    return fallback;
  }
}

// Row layout matches SignatureRepository::get_by_id() (21 columns):
// 0: id | 1: created_at | 2: slot_id | 3: token_label | 4: key_id
// 5: key_fingerprint | 6: mechanism | 7: payload_digest | 8: signature_b64
// 9: session_handle | 10: user_label | 11: app_context
// 12: ledger_tx_id | 13: ledger_block_num | 14: ledger_tx_time
// 15: ledger_tx_proof | 16: ledger_tx_set_b64 | 17: ledger_status
// 18: pqc_algo | 19: signature_pqc_b64 | 20: key_fingerprint_pqc
bool fill_signature_detail(const std::vector<std::optional<std::string>> &row,
                           SignatureDetail *detail) {
  if (row.size() < 21 || detail == nullptr) {
    return false;
  }
  auto str = [&row](std::size_t i) { return row[i].value_or(""); };
  detail->set_id(str(0));
  detail->set_created_at(to_int64(row[1]));
  detail->set_slot_id(static_cast<uint32_t>(to_int64(row[2])));
  detail->set_token_label(str(3));
  detail->set_key_id(str(4));
  detail->set_key_fingerprint(str(5));
  detail->set_mechanism(str(6));
  detail->set_payload_digest(str(7));
  detail->set_signature_b64(str(8));
  detail->set_session_handle(str(9));
  detail->set_user_label(str(10));
  detail->set_app_context(str(11));
  detail->set_ledger_tx_id(str(12));
  detail->set_ledger_block_num(to_int64(row[13]));
  detail->set_ledger_tx_time(str(14));
  detail->set_ledger_status(str(17));
  detail->set_pqc_algo(str(18));
  detail->set_signature_pqc_b64(str(19));
  detail->set_key_fingerprint_pqc(str(20));
  return true;
}

// Row layout matches NotificationRepository::get_subscriber() (7 columns):
// 0: id | 1: name | 2: channel | 3: address | 4: min_severity
// 5: event_filter | 6: enabled ("true"/"false")
bool fill_subscriber(const std::vector<std::optional<std::string>> &row,
                     Subscriber *sub) {
  if (row.size() < 7 || sub == nullptr) {
    return false;
  }
  auto str = [&row](std::size_t i) { return row[i].value_or(""); };
  sub->set_id(str(0));
  sub->set_name(str(1));
  sub->set_channel(str(2));
  sub->set_address(str(3));
  sub->set_min_severity(str(4));
  sub->set_event_filter(str(5));
  sub->set_enabled(str(6) == "true");
  return true;
}

} // namespace

namespace {

// Reads an environment variable, returning def when unset or empty.
std::string env_val(const char *name, const std::string &def = "") {
  const char *v = std::getenv(name);
  if (!v || *v == '\0')
    return def;
  return v;
}

bool cn_in_list(const std::string &cn, const std::string &csv) {
  size_t start = 0;
  while (start < csv.size()) {
    size_t comma = csv.find(',', start);
    size_t end = (comma == std::string::npos) ? csv.size() : comma;
    std::string item = csv.substr(start, end - start);
    size_t b = item.find_first_not_of(" \t");
    size_t e = item.find_last_not_of(" \t");
    if (b != std::string::npos)
      item = item.substr(b, e - b + 1);
    if (item == cn)
      return true;
    start = (comma == std::string::npos) ? csv.size() : comma + 1;
  }
  return false;
}

// Authorization gate for sensitive admin RPCs. Two mutually-exclusive,
// deployment-configured mechanisms:
//   1. mTLS: if VHSM_ADMIN_ALLOWED_CNS is set, the peer certificate CN must be
//      in the comma-separated allow-list.
//   2. Shared token: if VHSM_ADMIN_TOKEN is set, the gRPC metadata key
//      "vhsm-admin-token" must equal it.
// If neither is configured the server runs in an explicit dev/permissive mode
// and logs a one-time warning — there is NO silent default-allow in production
// once either env var is set (fail-closed).
bool require_admin(::grpc::ServerContext *ctx) {
  std::string allowed_cns = env_val("VHSM_ADMIN_ALLOWED_CNS");
  if (!allowed_cns.empty()) {
    auto auth = ctx->auth_context();
    if (auth && auth->IsPeerAuthenticated()) {
      auto prop = auth->GetPeerIdentityPropertyName();
      for (const auto &v : auth->FindPropertyValues(prop)) {
        if (cn_in_list(std::string(v.begin(), v.end()), allowed_cns))
          return true;
      }
    }
    return false;
  }
  std::string token = env_val("VHSM_ADMIN_TOKEN");
  if (!token.empty()) {
    const auto &md = ctx->client_metadata();
    auto it = md.find("vhsm-admin-token");
    if (it != md.end() &&
        std::string(it->second.begin(), it->second.end()) == token)
      return true;
    return false;
  }
  static std::once_flag warned;
  std::call_once(warned, [] {
    vhsm::log::global_logger().warning(
        "admin",
        "gRPC admin authorization is DISABLED (set VHSM_ADMIN_TOKEN or "
        "VHSM_ADMIN_ALLOWED_CNS to require authentication/authorization)");
  });
  return true;
}

} // namespace

::grpc::Status HsmAdminServiceImpl::AdminLogin(::grpc::ServerContext * /*ctx*/,
                                               const AdminLoginRequest *request,
                                               AdminLoginResponse *response) {
  if (!request || !response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }

  // Resolve the slot's token via the global SlotManager (the same registry
  // the PKCS#11 module uses).
  auto slot =
      vhsm::session::detail::global_slot_manager().get_slot(request->slot_id());
  if (!slot) {
    return ::grpc::Status(::grpc::StatusCode::NOT_FOUND,
                          "slot not found: " +
                              std::to_string(request->slot_id()));
  }
  auto token = slot->get_token();
  if (!token) {
    return ::grpc::Status(::grpc::StatusCode::NOT_FOUND,
                          "no token present in slot " +
                              std::to_string(request->slot_id()));
  }

  AdminLoginCore core(*token, bus_, audit_log_);
  const CK_RV rv =
      core.admin_login(request->role() == UserRole::SO ? CKU_SO : CKU_USER,
                       request->pin(), request->caller());

  // Map the PKCS#11 result to a gRPC status + a human-readable status string.
  // FAILED_PRECONDITION carries credential errors; callers should not treat
  // a wrong PIN as a server-side failure.
  // (We do not return the session token in this slice; that is added with the
  //  session/RPC-auth slice.)
  switch (rv) {
  case CKR_OK:
    response->set_status("OK");
    return ::grpc::Status::OK;
  case CKR_PIN_INCORRECT:
    response->set_status("PIN_INCORRECT");
    return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, "PIN_INCORRECT");
  case CKR_PIN_LOCKED:
    response->set_status("PIN_LOCKED");
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "PIN_LOCKED");
  default:
    response->set_status("LOGIN_FAILED");
    return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, "LOGIN_FAILED");
  }
}

::grpc::Status
HsmAdminServiceImpl::BackupToken(::grpc::ServerContext *ctx,
                                const BackupTokenRequest *request,
                                BackupTokenResponse *response) {
  if (!require_admin(ctx))
    return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED,
                          "admin authorization required");
  if (!request || !response || request->vault_path().empty() ||
      request->vault_password().empty()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "vault_path and vault_password are required");
  }
  std::string err;
  auto token = resolve_token(request->slot_id(), err);
  if (!token) {
    return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, err);
  }
  try {
    TokenBackupCore core(*token);
    core.backup(request->vault_path(), request->vault_password());
    response->set_status("OK");
    return ::grpc::Status::OK;
  } catch (const std::exception &e) {
    response->set_status(std::string("ERROR:") + e.what());
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION, e.what());
  }
}

::grpc::Status
HsmAdminServiceImpl::RestoreToken(::grpc::ServerContext *ctx,
                                 const RestoreTokenRequest *request,
                                 RestoreTokenResponse *response) {
  if (!require_admin(ctx))
    return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED,
                          "admin authorization required");
  if (!request || !response || request->vault_path().empty() ||
      request->vault_password().empty()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "vault_path and vault_password are required");
  }
  std::string err;
  auto token = resolve_token(request->slot_id(), err);
  if (!token) {
    return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, err);
  }
  try {
    TokenBackupCore core(*token);
    core.restore(request->vault_path(), request->vault_password());
    response->set_status("OK");
    return ::grpc::Status::OK;
  } catch (const std::exception &e) {
    response->set_status(std::string("ERROR:") + e.what());
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION, e.what());
  }
}

::grpc::Status
HsmAdminServiceImpl::GetSignature(::grpc::ServerContext * /*ctx*/,
                                  const GetSignatureRequest *request,
                                  GetSignatureResponse *response) {
  if (!request || !response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  if (!db_ || !token_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "signature store not configured");
  }
  if (request->signature_id().empty()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "signature_id is required");
  }
  signature_store::db::SignatureQuery query(*db_, *token_);
  auto row = query.get_signature_by_id(request->signature_id());
  if (!row) {
    return ::grpc::Status(::grpc::StatusCode::NOT_FOUND,
                          "signature not found: " + request->signature_id());
  }
  fill_signature_detail(*row, response->mutable_record());
  return ::grpc::Status::OK;
}

::grpc::Status
HsmAdminServiceImpl::QuerySignatures(::grpc::ServerContext * /*ctx*/,
                                     const SignatureQuery *request,
                                     SignatureList *response) {
  if (!request || !response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  if (!db_ || !token_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "signature store not configured");
  }
  if (request->key_fingerprint().empty() && request->start_time() == 0 &&
      request->end_time() == 0) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "provide key_fingerprint or a time range");
  }

  signature_store::db::SignatureQuery query(*db_, *token_);
  std::vector<std::string> ids;
  if (!request->key_fingerprint().empty()) {
    ids =
        query.get_signature_ids_by_key_fingerprint(request->key_fingerprint());
  } else {
    ids = query.get_signature_ids_by_time_range(request->start_time(),
                                                request->end_time());
  }

  const uint32_t limit = request->limit();
  uint32_t emitted = 0;
  for (const auto &id : ids) {
    if (limit > 0 && emitted >= limit) {
      break;
    }
    auto row = query.get_signature_by_id(id);
    if (!row) {
      continue;
    }
    auto *detail = response->add_records();
    if (!fill_signature_detail(*row, detail)) {
      response->mutable_records()->RemoveLast();
      continue;
    }
    ++emitted;
  }
  return ::grpc::Status::OK;
}

::grpc::Status
HsmAdminServiceImpl::VerifySignature(::grpc::ServerContext * /*ctx*/,
                                     const VerifySignatureRequest *request,
                                     VerifySignatureResponse *response) {
  if (!request || !response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  if (!db_ || !token_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "signature store not configured");
  }
  if (request->signature_id().empty()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "signature_id is required");
  }

  signature_store::db::SignatureQuery query(*db_, *token_);
  signature_store::db::SignatureQuery::VerificationResult res;
  if (request->check_ledger()) {
    if (!ledger_client_) {
      return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                            "ledger client not configured");
    }
    res = query.verify_signature(request->signature_id(), *ledger_client_);
  } else {
    res = query.verify_signature(request->signature_id());
  }

  response->set_record_found(res.record_found);
  response->set_ledger_cross_check_ok(res.ledger_cross_check_ok);
  response->set_valid(res.record_found &&
                      (!request->check_ledger() || res.ledger_cross_check_ok));
  response->set_ledger_status(res.ledger_status);
  if (res.ledger_tx_id) {
    response->set_ledger_tx_id(*res.ledger_tx_id);
  }
  if (res.ledger_block_num) {
    response->set_ledger_block_num(*res.ledger_block_num);
  }
  if (res.error_detail) {
    response->set_error_detail(*res.error_detail);
  }
  return ::grpc::Status::OK;
}

::grpc::Status
HsmAdminServiceImpl::ListPendingLedgerCommits(::grpc::ServerContext * /*ctx*/,
                                              const Empty * /*request*/,
                                              PendingLedgerList *response) {
  if (!response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  if (!db_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "signature store not configured");
  }
  signature_store::db::LedgerRetryQueue queue(*db_);
  for (auto &id : queue.scan_pending_ids()) {
    response->add_signature_ids(std::move(id));
  }
  return ::grpc::Status::OK;
}

::grpc::Status
HsmAdminServiceImpl::RetryLedgerCommits(::grpc::ServerContext *ctx,
                                       const Empty * /*request*/,
                                       RetryLedgerResponse *response) {
  if (!require_admin(ctx))
    return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED,
                          "admin authorization required");
  if (!response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  if (!db_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "signature store not configured");
  }

  signature_store::db::LedgerRetryQueue queue(*db_);
  auto records = queue.load_pending_records();
  if (records.empty()) {
    response->set_status("OK");
    response->set_resubmitted(0);
    return ::grpc::Status::OK;
  }
  if (!ledger_worker_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "ledger worker not configured");
  }

  uint32_t submitted = 0;
  for (auto &record : records) {
    ledger_worker_->submit_record(record);
    ++submitted;
  }
  response->set_status("OK");
  response->set_resubmitted(submitted);
  return ::grpc::Status::OK;
}

::grpc::Status
HsmAdminServiceImpl::AddSubscriber(::grpc::ServerContext *ctx,
                                  const Subscriber *request,
                                  SubscriberResponse *response) {
  if (!require_admin(ctx))
    return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED,
                          "admin authorization required");
  if (!request || !response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  if (!db_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "signature store not configured");
  }
  if (request->id().empty() || request->channel().empty() ||
      request->address().empty() || request->min_severity().empty()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "id, channel, address and min_severity are required");
  }

  signature_store::db::NotificationRepository repo(*db_);
  std::optional<std::string> event_filter;
  if (!request->event_filter().empty()) {
    event_filter = request->event_filter();
  }
  if (!repo.add_subscriber(request->id(), request->name(), request->channel(),
                           request->address(), request->min_severity(),
                           event_filter, request->enabled())) {
    response->set_status("ERROR:add_subscriber failed (id already exists?)");
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "failed to add subscriber");
  }
  response->set_status("OK");
  return ::grpc::Status::OK;
}

::grpc::Status
HsmAdminServiceImpl::ListSubscribers(::grpc::ServerContext * /*ctx*/,
                                     const Empty * /*request*/,
                                     SubscriberList *response) {
  if (!response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  if (!db_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "signature store not configured");
  }
  signature_store::db::NotificationRepository repo(*db_);
  for (auto &id : repo.get_all_subscriber_ids()) {
    auto row = repo.get_subscriber(id);
    if (!row) {
      continue;
    }
    auto *sub = response->add_subscribers();
    if (!fill_subscriber(*row, sub)) {
      response->mutable_subscribers()->RemoveLast();
    }
  }
  return ::grpc::Status::OK;
}

::grpc::Status
HsmAdminServiceImpl::RemoveSubscriber(::grpc::ServerContext * /*ctx*/,
                                      const SubscriberIdRequest *request,
                                      SubscriberResponse *response) {
  if (!request || !response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  if (!db_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "signature store not configured");
  }
  if (request->id().empty()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "id is required");
  }
  signature_store::db::NotificationRepository repo(*db_);
  repo.remove_subscriber(request->id());
  response->set_status("OK");
  return ::grpc::Status::OK;
}

::grpc::Status
HsmAdminServiceImpl::QueryNotificationLog(::grpc::ServerContext * /*ctx*/,
                                          const NotificationLogQuery *request,
                                          NotificationLogList *response) {
  if (!request || !response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  if (!db_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "signature store not configured");
  }
  signature_store::db::NotificationRepository repo(*db_);
  std::optional<std::string> subscriber_id;
  if (!request->subscriber_id().empty()) {
    subscriber_id = request->subscriber_id();
  }
  auto entries = repo.query_log(subscriber_id, request->since(),
                                static_cast<int>(request->limit()));
  for (const auto &e : entries) {
    auto *out = response->add_entries();
    out->set_id(e.id);
    out->set_sent_at(e.sent_at);
    out->set_event_id(e.event_id);
    out->set_subscriber_id(e.subscriber_id);
    out->set_outcome(e.outcome);
    out->set_attempt_count(static_cast<uint32_t>(e.attempt_count));
    out->set_error_detail(e.error_detail);
  }
  return ::grpc::Status::OK;
}

::grpc::Status HsmAdminServiceImpl::Metrics(::grpc::ServerContext * /*ctx*/,
                                            const Empty * /*request*/,
                                            MetricsResponse *response) {
  if (!response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  response->set_prometheus_text(vhsm::metrics::Metrics::instance().prometheus());
  return ::grpc::Status::OK;
}

::grpc::Status
HsmAdminServiceImpl::VerifyIntegrity(::grpc::ServerContext * /*ctx*/,
                                    const Empty * /*request*/,
                                    IntegrityReport *response) {
  if (!response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }
  response->set_ok(true);

  // 1) Local audit hash-chain integrity.
  if (auto *hca = dynamic_cast<vhsm::audit::HashChainedAuditLog *>(audit_log_)) {
    if (auto bad = hca->verify_chain()) {
      response->set_audit_chain_ok(false);
      response->set_audit_chain_error("first bad record at line " +
                                      std::to_string(*bad));
      response->set_ok(false);
    } else {
      response->set_audit_chain_ok(true);
    }
    if (ledger_client_) {
      if (auto anchored = ledger_client_->get_latest_audit_tail_hash()) {
        response->set_audit_tail_anchored(*anchored);
      }
    }
  } else {
    // No hash-chained audit sink (e.g. pre-init stub): nothing to verify.
    response->set_audit_chain_ok(true);
  }

  // 2) Per-row integrity HMAC + ledger cross-check for COMMITTED records.
  if (!db_ || !token_) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "signature store not configured");
  }
  vhsm::signature_store::db::SignatureRepository repo(*db_, *token_);
  const auto ids = repo.get_all_ids();
  response->set_records_checked(static_cast<int64_t>(ids.size()));

  for (const auto &id : ids) {
    if (repo.verify_integrity(id)) {
      response->set_rows_integrity_ok(response->rows_integrity_ok() + 1);
    } else {
      response->set_rows_integrity_failed(response->rows_integrity_failed() + 1);
      response->add_integrity_failures(id);
      response->set_ok(false);
    }

    auto row = repo.get_by_id(id);
    if (!row || row->size() < 18) {
      continue;
    }
    const std::string status = (*row)[17].value_or("");
    if (status != "COMMITTED") {
      continue;
    }
    response->set_committed_checked(response->committed_checked() + 1);
    const std::string local_tx = (*row)[12].value_or("");
    if (!ledger_client_) {
      // No ledger configured: cannot cross-check, but not a verification failure.
      continue;
    }
    auto ledger = ledger_client_->get_record(id);
    if (ledger && ledger->tx_id == local_tx) {
      response->set_ledger_cross_ok(response->ledger_cross_ok() + 1);
    } else {
      response->set_ledger_cross_failed(response->ledger_cross_failed() + 1);
      const std::string detail =
          id + ": local tx=" + local_tx +
          (ledger ? (" ledger tx=" + ledger->tx_id) : " (ledger missing)");
      response->add_ledger_mismatches(detail);
      response->set_ok(false);
    }
  }

  return ::grpc::Status::OK;
}

} // namespace vhsm::admin