#include "fabric/gateway/transaction.h"

#include <utility>

#include "fabric/gateway/contract.h"
#include "fabric/gateway/gateway.h"
#include "fabric/grpc/grpc_status.h"
#include "fabric/protoutil/proposal_builder.h"

#include "peer/transaction.pb.h"

namespace fabric {
namespace gateway {

namespace {

std::string txValidationCodeName(int32_t code) {
    switch (code) {
        case ::protos::VALID: return "VALID";
        case ::protos::NIL_ENVELOPE: return "NIL_ENVELOPE";
        case ::protos::BAD_PAYLOAD: return "BAD_PAYLOAD";
        case ::protos::BAD_COMMON_HEADER: return "BAD_COMMON_HEADER";
        case ::protos::BAD_CREATOR_SIGNATURE: return "BAD_CREATOR_SIGNATURE";
        case ::protos::INVALID_ENDORSER_TRANSACTION: return "INVALID_ENDORSER_TRANSACTION";
        case ::protos::INVALID_CONFIG_TRANSACTION: return "INVALID_CONFIG_TRANSACTION";
        case ::protos::UNSUPPORTED_TX_PAYLOAD: return "UNSUPPORTED_TX_PAYLOAD";
        case ::protos::BAD_PROPOSAL_TXID: return "BAD_PROPOSAL_TXID";
        case ::protos::DUPLICATE_TXID: return "DUPLICATE_TXID";
        case ::protos::ENDORSEMENT_POLICY_FAILURE: return "ENDORSEMENT_POLICY_FAILURE";
        case ::protos::MVCC_READ_CONFLICT: return "MVCC_READ_CONFLICT";
        case ::protos::PHANTOM_READ_CONFLICT: return "PHANTOM_READ_CONFLICT";
        case ::protos::UNKNOWN_TX_TYPE: return "UNKNOWN_TX_TYPE";
        case ::protos::TARGET_CHAIN_NOT_FOUND: return "TARGET_CHAIN_NOT_FOUND";
        case ::protos::MARSHAL_TX_ERROR: return "MARSHAL_TX_ERROR";
        case ::protos::NIL_TXACTION: return "NIL_TXACTION";
        case ::protos::EXPIRED_CHAINCODE: return "EXPIRED_CHAINCODE";
        case ::protos::CHAINCODE_VERSION_CONFLICT: return "CHAINCODE_VERSION_CONFLICT";
        case ::protos::BAD_HEADER_EXTENSION: return "BAD_HEADER_EXTENSION";
        case ::protos::BAD_CHANNEL_HEADER: return "BAD_CHANNEL_HEADER";
        case ::protos::BAD_RESPONSE_PAYLOAD: return "BAD_RESPONSE_PAYLOAD";
        case ::protos::BAD_RWSET: return "BAD_RWSET";
        case ::protos::ILLEGAL_WRITESET: return "ILLEGAL_WRITESET";
        case ::protos::INVALID_WRITESET: return "INVALID_WRITESET";
        case ::protos::INVALID_CHAINCODE: return "INVALID_CHAINCODE";
        case ::protos::NOT_VALIDATED: return "NOT_VALIDATED";
        case ::protos::INVALID_OTHER_REASON: return "INVALID_OTHER_REASON";
        default: return "UNKNOWN";
    }
}

void throwOnError(const ::grpc::Status& status, const std::string& what) {
    if (!status.ok()) {
        throw fabric::grpc::StatusException(status.error_code(), status.error_message(), what);
    }
}

} // namespace

Transaction::Transaction(std::shared_ptr<Contract> contract,
                         std::string name,
                         std::map<std::string, std::string> transient)
    : contract_(std::move(contract)), name_(std::move(name)), transient_(std::move(transient)) {}

TransactionResult Transaction::submit() {
    return submit({});
}

TransactionResult Transaction::evaluate(const std::vector<std::string>& args) {
    auto gateway = contract_->gateway();
    const auto& identity = gateway->identity();
    const std::string channelId = contract_->channelId();
    const std::string txId = protoutil::createTransactionId(identity);

    std::vector<std::string> fullArgs;
    fullArgs.reserve(args.size() + 1);
    fullArgs.push_back(name_);
    fullArgs.insert(fullArgs.end(), args.begin(), args.end());

    ::protos::Proposal proposal = protoutil::createProposal(
        identity, channelId, txId, contract_->chaincodeName(), fullArgs, transient_);
    ::protos::SignedProposal signedProposal = protoutil::signProposal(identity, proposal);

    ::gateway::EvaluateRequest request;
    request.set_transaction_id(txId);
    request.set_channel_id(channelId);
    *request.mutable_proposed_transaction() = signedProposal;

    ::gateway::EvaluateResponse response;
    ::grpc::Status status = gateway->evaluate(request, &response);
    throwOnError(status, "Evaluate failed");

    TransactionResult result;
    result.responseStatus = response.result().status();
    result.responseMessage = response.result().message();
    result.payload = response.result().payload();
    result.txId = txId;
    return result;
}

TransactionResult Transaction::submit(const std::vector<std::string>& args) {
    auto gateway = contract_->gateway();
    const auto& identity = gateway->identity();
    const std::string channelId = contract_->channelId();
    const std::string txId = protoutil::createTransactionId(identity);

    std::vector<std::string> fullArgs;
    fullArgs.reserve(args.size() + 1);
    fullArgs.push_back(name_);
    fullArgs.insert(fullArgs.end(), args.begin(), args.end());

    ::protos::Proposal proposal = protoutil::createProposal(
        identity, channelId, txId, contract_->chaincodeName(), fullArgs, transient_);
    ::protos::SignedProposal signedProposal = protoutil::signProposal(identity, proposal);

    ::gateway::EndorseRequest endorseRequest;
    endorseRequest.set_transaction_id(txId);
    endorseRequest.set_channel_id(channelId);
    *endorseRequest.mutable_proposed_transaction() = signedProposal;

    ::gateway::EndorseResponse endorseResponse;
    ::grpc::Status status = gateway->endorse(endorseRequest, &endorseResponse);
    throwOnError(status, "Endorse failed");

    ::common::Envelope prepared = endorseResponse.prepared_transaction();
    if (prepared.payload().empty()) {
        throw fabric::grpc::StatusException(::grpc::StatusCode::INTERNAL,
                                            "gateway returned an empty prepared transaction",
                                            "Endorse");
    }

    protoutil::signEnvelope(identity, prepared);

    ::gateway::SubmitRequest submitRequest;
    submitRequest.set_transaction_id(txId);
    submitRequest.set_channel_id(channelId);
    *submitRequest.mutable_prepared_transaction() = prepared;

    ::gateway::SubmitResponse submitResponse;
    status = gateway->submit(submitRequest, &submitResponse);
    throwOnError(status, "Submit failed");

    ::gateway::CommitStatusRequest commitStatusRequest;
    commitStatusRequest.set_transaction_id(txId);
    commitStatusRequest.set_channel_id(channelId);
    commitStatusRequest.set_identity(protoutil::serializeIdentity(identity));

    const std::string requestBytes = commitStatusRequest.SerializeAsString();
    ::gateway::SignedCommitStatusRequest signedCommitRequest;
    signedCommitRequest.set_request(requestBytes);
    signedCommitRequest.set_signature(protoutil::signBytes(identity, requestBytes));

    ::gateway::CommitStatusResponse commitResponse;
    status = gateway->commitStatus(signedCommitRequest, &commitResponse);
    throwOnError(status, "CommitStatus failed");

    TransactionResult result;
    result.committed = (commitResponse.result() == ::protos::VALID);
    result.validationCode = commitResponse.result();
    result.validationMessage = txValidationCodeName(commitResponse.result());
    result.blockNumber = commitResponse.block_number();
    result.txId = txId;

    ::protos::Response chaincodeResponse = protoutil::extractProposalResponse(prepared);
    result.responseStatus = chaincodeResponse.status();
    result.responseMessage = chaincodeResponse.message();
    result.payload = chaincodeResponse.payload();
    return result;
}

} // namespace gateway
} // namespace fabric