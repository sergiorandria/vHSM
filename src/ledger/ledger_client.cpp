#include "ledger_client.h"
#include "ledger_entry.h"
#include "../core/types.h"
#include "../../third_party/fabric-gateway-cpp/gateway.h"
#include "../../third_party/fabric-gateway-cpp/network.h"
#include "../../third_party/fabric-gateway-cpp/contract.h"

#include <grpcpp/channel.h>
#include <grpcpp/security/credentials.h>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace vhsm::ledger {

LedgerClient::LedgerClient(const std::string& gateway_endpoint) {
    // For simplicity, we use insecure credentials. In production, we would use the client's MSP credentials.
    auto grpc_credentials = grpc::InsecureChannelCredentials();
    gateway_ = std::unique_ptr<fabric::Gateway>(fabric::Gateway::Create(gateway_endpoint, grpc_credentials.get()));
    network_ = std::unique_ptr<fabric::Network>(gateway_->GetNetwork("signaturechannel"));
    contract_ = std::unique_ptr<fabric::Contract>(network_->GetContract("signature_ledger"));
}

LedgerClient::~LedgerClient() {
    if (gateway_) {
        gateway_->Shutdown();
    }
}

std::optional<LedgerEntry> LedgerClient::submit_record(const SignatureRecord& record) {
    try {
        // Prepare arguments for the RecordSignature transaction
        std::vector<std::string> args = {
            record.record_id,
            record.key_fingerprint,
            record.payload_digest,
            record.signature_b64,
            std::to_string(record.created_at)
        };

        // Submit the transaction (this will block until the transaction is committed or fails)
        auto result = contract_->SubmitTransaction("RecordSignature", args);

        // The chaincode returns the transaction ID as a string (we'll implement the chaincode to return it)
        std::string tx_id = result.ToString();

        // We don't have the block number from the submit transaction, so we'll query the record to get it.
        // Alternatively, we can have the chaincode return both tx_id and block_number.
        // For now, we'll query the record immediately after submission to get the entry.
        // This is not ideal for performance but ensures we have the block number.
        auto entry_opt = get_record(record.record_id);
        if (entry_opt) {
            return entry_opt;
        }

        // If we couldn't retrieve the record, we return nullopt to indicate failure.
        return std::nullopt;
    } catch (const std::exception& e) {
        std::cerr << "Failed to submit transaction: " << e.what() << std::endl;
        return std::nullopt;
    }
}

std::optional<LedgerEntry> LedgerClient::get_record(const std::string& record_id) {
    try {
        // Prepare arguments for the GetRecord query
        std::vector<std::string> args = { record_id };

        // Evaluate the transaction (query)
        auto result = contract_->EvaluateTransaction("GetRecord", args);

        // Parse the JSON result
        auto json_result = json::parse(result.ToString());

        LedgerEntry entry;
        entry.record_id = json_result["record_id"];
        entry.key_fingerprint = json_result["key_fingerprint"];
        entry.payload_digest = json_result["payload_digest"];
        entry.signature_b64 = json_result["signature_b64"];
        entry.created_at = json_result["created_at"];
        entry.tx_id = json_result["tx_id"];
        entry.block_number = json_result["block_number"];

        return entry;
    } catch (const std::exception& e) {
        std::cerr << "Failed to evaluate transaction: " << e.what() << std::endl;
        return std::nullopt;
    }
}

} // namespace vhsm::ledger