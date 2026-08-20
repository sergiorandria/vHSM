#include "hsm_admin_grpc.h"

#include <cctype>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "../keystore/slot.h"
#include "../keystore/token.h"
#include "../ledger/ledger_client.h"
#include "../ledger/ledger_worker.h"
#include "../signature_store/db_connection.h"
#include "../signature_store/ledger_retry_queue.h"
#include "../signature_store/notification_repository.h"
#include "../signature_store/signature_query.h"

namespace vhsm::admin {

HsmAdminServiceImpl::HsmAdminServiceImpl(
    vhsm::signature_store::db::IDbConnection *db,
    vhsm::keystore::Token *token, vhsm::ledger::LedgerClient *ledger_client,
    vhsm::ledger::LedgerWorker *ledger_worker,
    vhsm::notification::NotificationBus *bus, vhsm::audit::AuditLog *audit_log)
    : db_(db), token_(token), ledger_client_(ledger_client),
      ledger_worker_(ledger_worker), bus_(bus), audit_log_(audit_log) {}

namespace {

// Resolves slot -> token via the global SlotManager singleton (shared with the
// PKCS#11 module).  Returns nullptr (with a status string set) on failure.
std::shared_ptr<keystore::Token> resolve_token(uint32_t slot_id,
                                               std::string &err) {
  auto slot = vhsm::session::SlotManager::get_instance().get_slot(slot_id);
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

// Row layout matches SignatureRepository::get_by_id() (18 columns):
// 0: id | 1: created_at | 2: slot_id | 3: token_label | 4: key_id
// 5: key_fingerprint | 6: mechanism | 7: payload_digest | 8: signature_b64
// 9: session_handle | 10: user_label | 11: app_context
// 12: ledger_tx_id | 13: ledger_block_num | 14: ledger_tx_time
// 15: ledger_tx_proof | 16: ledger_tx_set_b64 | 17: ledger_status
bool fill_signature_detail(const std::vector<std::optional<std::string>> &row,
                           SignatureDetail *detail) {
  if (row.size() < 18 || detail == nullptr) {
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
      vhsm::session::SlotManager::get_instance().get_slot(request->slot_id());
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
HsmAdminServiceImpl::BackupToken(::grpc::ServerContext * /*ctx*/,
                                 const BackupTokenRequest *request,
                                 BackupTokenResponse *response) {
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
HsmAdminServiceImpl::RestoreToken(::grpc::ServerContext * /*ctx*/,
                                  const RestoreTokenRequest *request,
                                  RestoreTokenResponse *response) {
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

::grpc::Status HsmAdminServiceImpl::GetSignature(
    ::grpc::ServerContext * /*ctx*/, const GetSignatureRequest *request,
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

::grpc::Status HsmAdminServiceImpl::QuerySignatures(
    ::grpc::ServerContext * /*ctx*/, const SignatureQuery *request,
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
    ids = query.get_signature_ids_by_key_fingerprint(
        request->key_fingerprint());
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

::grpc::Status HsmAdminServiceImpl::VerifySignature(
    ::grpc::ServerContext * /*ctx*/, const VerifySignatureRequest *request,
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

::grpc::Status HsmAdminServiceImpl::ListPendingLedgerCommits(
    ::grpc::ServerContext * /*ctx*/, const Empty * /*request*/,
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

::grpc::Status HsmAdminServiceImpl::RetryLedgerCommits(
    ::grpc::ServerContext * /*ctx*/, const Empty * /*request*/,
    RetryLedgerResponse *response) {
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

::grpc::Status HsmAdminServiceImpl::AddSubscriber(
    ::grpc::ServerContext * /*ctx*/, const Subscriber *request,
    SubscriberResponse *response) {
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

::grpc::Status HsmAdminServiceImpl::ListSubscribers(
    ::grpc::ServerContext * /*ctx*/, const Empty * /*request*/,
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

::grpc::Status HsmAdminServiceImpl::RemoveSubscriber(
    ::grpc::ServerContext * /*ctx*/, const SubscriberIdRequest *request,
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

::grpc::Status HsmAdminServiceImpl::QueryNotificationLog(
    ::grpc::ServerContext * /*ctx*/, const NotificationLogQuery *request,
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
  auto entries =
      repo.query_log(subscriber_id, request->since(),
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

} // namespace vhsm::admin