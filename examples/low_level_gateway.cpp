#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "fabric/gateway/gateway.h"
#include "fabric/gateway/transaction.h"
#include "fabric/grpc/grpc_connection.h"
#include "fabric/identity/identity.h"
#include "fabric/protoutil/proposal_builder.h"
#include "util.h"

namespace {} // namespace

// Low-level walk through the Gateway RPCs, bypassing the Network/Contract
// convenience layer. Shows how a signed proposal is built with protoutil and
// then driven through Evaluate / Endorse -> Submit -> CommitStatus.
//
// usage: low_level_gateway <target> <tlsCa> <cert> <key> <mspId> <channel>
//        <chaincode> <function> [submit|evaluate] [args...]
int main(int argc, char **argv) {
  if (argc < 10) {
    std::cerr << "usage: " << argv[0]
              << " <target> <tlsCa> <cert> <key> <mspId> <channel> <chaincode>"
                 " <function> [submit|evaluate] [args...]\n";
    return 2;
  }
  const std::string target = argv[1];
  const std::string tlsCa = examples::readFile(argv[2]);
  const std::string cert = examples::readFile(argv[3]);
  examples::expectPem(cert, "certificate");
  examples::SecureString key = examples::readSecureFile(argv[4]);
  examples::expectPem(std::string(key.data(), key.size()), "private key");
  const std::string mspId = argv[5];
  const std::string channel = argv[6];
  const std::string chaincode = argv[7];
  const std::string function = argv[8];

  std::string mode = "evaluate";
  std::vector<std::string> args;
  int argStart = 9;
  if (argc > 9) {
    std::string maybe = argv[9];
    if (maybe == "submit" || maybe == "evaluate") {
      mode = maybe;
      argStart = 10;
    }
  }
  for (int i = argStart; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  try {
    fabric::identity::Identity id(mspId, cert,
                                  std::string(key.data(), key.size()));
    key.wipe(); // example no longer needs its copy; Identity holds its own
    fabric::grpc::TlsCredentials tls;
    tls.rootCert = tlsCa;
    auto conn = fabric::grpc::GrpcConnection::connect(target, tls);
    if (!conn->isReady()) {
      conn->waitForReady();
    }
    auto gw = fabric::gateway::Gateway::connect(conn, id);

    // Build + sign the proposal (this is exactly what Contract does
    // internally). Note: Contract prepends the function name to the arg list;
    // we do it here manually since we drive the proposal builder directly.
    std::vector<std::string> ccArgs;
    ccArgs.push_back(function);
    for (const auto &a : args) {
      ccArgs.push_back(a);
    }
    auto [txId, nonce] = fabric::protoutil::createTransactionId(id);
    ::protos::Proposal proposal = fabric::protoutil::createProposal(
        id, channel, nonce, chaincode, ccArgs);
    ::protos::SignedProposal sp = fabric::protoutil::signProposal(id, proposal);

    if (mode == "evaluate") {
      ::gateway::EvaluateRequest req;
      req.set_transaction_id(txId);
      req.set_channel_id(channel);
      *req.mutable_proposed_transaction() = sp;
      ::gateway::EvaluateResponse resp;
      auto st = gw->evaluate(req, &resp);
      if (!st.ok()) {
        std::cerr << "evaluate failed: " << st.error_message() << "\n";
        return 1;
      }
      const ::protos::Response &r = resp.result();
      std::cout << "txId           = " << txId << "\n";
      std::cout << "responseStatus = " << r.status() << "\n";
      std::cout << "responseMessage= " << r.message() << "\n";
      std::cout << "payload (text) = " << r.payload() << "\n";
      return r.status() == 200 ? 0 : 1;
    }

    // submit: Endorse -> Submit -> CommitStatus
    ::gateway::EndorseRequest ereq;
    ereq.set_transaction_id(txId);
    ereq.set_channel_id(channel);
    *ereq.mutable_proposed_transaction() = sp;
    ::gateway::EndorseResponse eresp;
    auto est = gw->endorse(ereq, &eresp);
    if (!est.ok()) {
      std::cerr << "endorse failed: " << est.error_message() << "\n";
      return 1;
    }
    ::common::Envelope env = eresp.prepared_transaction();
    // The gateway requires the prepared transaction to be signed by the
    // client before Submit (Contract does this internally).
    fabric::protoutil::signEnvelope(id, env);

    ::gateway::SubmitRequest sreq;
    sreq.set_transaction_id(txId);
    sreq.set_channel_id(channel);
    *sreq.mutable_prepared_transaction() = env;
    ::gateway::SubmitResponse sresp;
    auto sst = gw->submit(sreq, &sresp);
    if (!sst.ok()) {
      std::cerr << "submit failed: " << sst.error_message() << "\n";
      return 1;
    }

    ::gateway::CommitStatusRequest csr;
    csr.set_transaction_id(txId);
    csr.set_channel_id(channel);
    csr.set_identity(fabric::protoutil::serializeIdentity(id));
    std::string csrBytes;
    if (!csr.SerializeToString(&csrBytes)) {
      std::cerr << "commitStatus request serialization failed\n";
      return 1;
    }
    std::string sig = fabric::protoutil::signBytes(id, csrBytes);
    ::gateway::SignedCommitStatusRequest scsr;
    scsr.set_request(csrBytes);
    scsr.set_signature(sig);

    ::gateway::CommitStatusResponse cresp;
    auto cst = gw->commitStatus(scsr, &cresp);
    if (!cst.ok()) {
      std::cerr << "commitStatus failed: " << cst.error_message() << "\n";
      return 1;
    }
    std::cout << "txId           = " << txId << "\n";
    std::cout << "validationCode = " << static_cast<int>(cresp.result())
              << "\n";
    std::cout << "blockNumber    = " << cresp.block_number() << "\n";
    std::cout << "committed      = "
              << (cresp.result() == ::protos::VALID ? "true" : "false") << "\n";
    return cresp.result() == ::protos::VALID ? 0 : 1;
  } catch (const std::exception &e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  }
}
