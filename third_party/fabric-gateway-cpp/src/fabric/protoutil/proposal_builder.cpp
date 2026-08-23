#include "fabric/protoutil/proposal_builder.h"

#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstring>
#include <stdexcept>

#include <google/protobuf/timestamp.pb.h>

#include "fabric/crypto/ec.h"
#include "fabric/crypto/hash.h"
#include "fabric/crypto/x509.h"

#include "peer/chaincode.pb.h"
#include "peer/proposal.pb.h"
#include "peer/proposal_response.pb.h"

namespace fabric {
namespace protoutil {

namespace {

// Fabric computes the transaction ID as the lower-case hex encoding of
// sha256(nonce || creator). (Historically some builds use base64; this
// network's peers validate against the hex form.)
std::string hexEncode(const std::string &in) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(in.size() * 2);
  for (unsigned char c : in) {
    out.push_back(kHex[c >> 4]);
    out.push_back(kHex[c & 0x0F]);
  }
  return out;
}

std::string randomNonce(size_t length) {
  std::string nonce(length, '\0');
  if (!nonce.empty() &&
      RAND_bytes(reinterpret_cast<unsigned char *>(nonce.data()),
                 static_cast<int>(length)) != 1) {
    throw std::runtime_error("Failed to generate nonce");
  }
  return nonce;
}

msp::SerializedIdentity
makeSerializedIdentity(const identity::Identity &identity) {
  msp::SerializedIdentity serialized;
  serialized.set_mspid(identity.getMSPID());
  // Fabric's MSP deserializes the identity by PEM-decoding id_bytes
  // (https://github.com/hyperledger/fabric/blob/master/msp/mspimpl.go),
  // so the certificate MUST be supplied as PEM, not raw DER.
  serialized.set_id_bytes(
      crypto::X509Certificate(identity.getCertificate()).getPEM());
  return serialized;
}

} // namespace

std::string serializeIdentity(const identity::Identity &identity) {
  msp::SerializedIdentity serialized = makeSerializedIdentity(identity);
  return serialized.SerializeAsString();
}

std::pair<std::string, std::string>
createTransactionId(const identity::Identity &identity) {
  const std::string nonce = randomNonce(24);
  const std::string creator = serializeIdentity(identity);
  return {hexEncode(crypto::sha256(nonce + creator)), nonce};
}

::protos::Proposal
createProposal(const identity::Identity &identity, const std::string &channelId,
               const std::string &nonce, const std::string &chaincodeName,
               const std::vector<std::string> &args,
               const std::map<std::string, std::string> &transient) {
  msp::SerializedIdentity serialized = makeSerializedIdentity(identity);
  const std::string creator = serialized.SerializeAsString();

  // The txId is derived from the SAME nonce that seeds the SignatureHeader,
  // so the peer recomputes an identical txId when validating the proposal.
  const std::string txId = hexEncode(crypto::sha256(nonce + creator));

  ::common::ChannelHeader channelHeader;
  channelHeader.set_type(::common::ENDORSER_TRANSACTION);
  channelHeader.set_tx_id(txId);
  channelHeader.set_channel_id(channelId);
  channelHeader.set_epoch(0);

  // Fabric's peer/chaincode derive GetTxTimestamp() from the ChannelHeader
  // timestamp. Without it, chaincodes that read the transaction time (e.g. via
  // ctx.GetStub().GetTxTimestamp()) get a nil *timestamp.Timestamp and panic.
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto secs =
      std::chrono::duration_cast<std::chrono::seconds>(now).count();
  const auto nanos =
      std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() %
      1000000000;
  channelHeader.mutable_timestamp()->set_seconds(
      static_cast<google::protobuf::int64>(secs));
  channelHeader.mutable_timestamp()->set_nanos(static_cast<int32_t>(nanos));

  // Fabric's peer validates the proposal against the chaincode named in the
  // ChannelHeader extension (ChaincodeHeaderExtension.ChaincodeId). Without
  // it the endorser rejects with "ChaincodeHeaderExtension.ChaincodeId is nil".
  ::protos::ChaincodeHeaderExtension che;
  che.mutable_chaincode_id()->set_name(chaincodeName);
  channelHeader.set_extension(che.SerializeAsString());

  ::common::SignatureHeader signatureHeader;
  signatureHeader.set_creator(creator);
  signatureHeader.set_nonce(nonce);

  ::common::Header header;
  header.set_channel_header(channelHeader.SerializeAsString());
  header.set_signature_header(signatureHeader.SerializeAsString());

  ::protos::ChaincodeSpec spec;
  spec.set_type(::protos::ChaincodeSpec_Type_GOLANG);
  spec.mutable_chaincode_id()->set_name(chaincodeName);
  ::protos::ChaincodeInput *input = spec.mutable_input();
  for (const auto &arg : args) {
    input->add_args(arg);
  }

  ::protos::ChaincodeInvocationSpec invocation;
  *invocation.mutable_chaincode_spec() = spec;

  ::protos::ChaincodeProposalPayload payload;
  payload.set_input(invocation.SerializeAsString());
  for (const auto &[key, value] : transient) {
    (*payload.mutable_transientmap())[key] = value;
  }

  ::protos::Proposal proposal;
  proposal.set_header(header.SerializeAsString());
  proposal.set_payload(payload.SerializeAsString());
  return proposal;
}

::protos::SignedProposal signProposal(const identity::Identity &identity,
                                      const ::protos::Proposal &proposal) {
  ::protos::SignedProposal signedProposal;
  signedProposal.set_proposal_bytes(proposal.SerializeAsString());
  signedProposal.set_signature(
      signBytes(identity, signedProposal.proposal_bytes()));
  return signedProposal;
}

void signEnvelope(const identity::Identity &identity,
                  ::common::Envelope &envelope) {
  envelope.set_signature(signBytes(identity, envelope.payload()));
}

std::string signBytes(const identity::Identity &identity,
                      const std::string &message) {
  return crypto::ECKeyPair(identity.getPrivateKey())
      .signDigest(crypto::sha256(message));
}

::protos::Response extractProposalResponse(const ::common::Envelope &envelope) {
  ::protos::Response empty;
  if (envelope.payload().empty()) {
    return empty;
  }

  ::common::Payload payload;
  if (!payload.ParseFromString(envelope.payload())) {
    return empty;
  }

  ::protos::Transaction transaction;
  if (!transaction.ParseFromString(payload.data())) {
    return empty;
  }

  if (transaction.actions_size() == 0) {
    return empty;
  }

  const ::protos::TransactionAction &action = transaction.actions(0);
  ::protos::ChaincodeActionPayload actionPayload;
  if (!actionPayload.ParseFromString(action.payload())) {
    return empty;
  }

  if (!actionPayload.has_action()) {
    return empty;
  }

  // action() is a ChaincodeEndorsedAction whose proposal_response_payload is a
  // (marshaled) ProposalResponsePayload. Its extension field is a (marshaled)
  // ChaincodeAction, which finally carries the chaincode Response.
  const ::protos::ChaincodeEndorsedAction &endorsed = actionPayload.action();
  ::protos::ProposalResponsePayload responsePayload;
  if (!responsePayload.ParseFromString(endorsed.proposal_response_payload())) {
    return empty;
  }

  ::protos::ChaincodeAction chaincodeAction;
  if (!chaincodeAction.ParseFromString(responsePayload.extension())) {
    return empty;
  }

  if (!chaincodeAction.has_response()) {
    return empty;
  }

  return chaincodeAction.response();
}

} // namespace protoutil
} // namespace fabric