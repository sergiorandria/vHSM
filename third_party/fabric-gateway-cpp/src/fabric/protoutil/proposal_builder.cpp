#include "fabric/protoutil/proposal_builder.h"

#include <openssl/rand.h>

#include <array>
#include <cstring>
#include <stdexcept>

#include "fabric/crypto/ec.h"
#include "fabric/crypto/hash.h"
#include "fabric/crypto/x509.h"

#include "peer/chaincode.pb.h"
#include "peer/proposal.pb.h"
#include "peer/proposal_response.pb.h"

namespace fabric {
namespace protoutil {

namespace {

const char kBase64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string base64UrlEncode(const std::string &in) {
  std::string out;
  out.reserve(((in.size() + 2) / 3) * 4);
  size_t i = 0;
  for (; i + 2 < in.size(); i += 3) {
    unsigned b0 = static_cast<unsigned char>(in[i]);
    unsigned b1 = static_cast<unsigned char>(in[i + 1]);
    unsigned b2 = static_cast<unsigned char>(in[i + 2]);
    out.push_back(kBase64UrlAlphabet[b0 >> 2]);
    out.push_back(kBase64UrlAlphabet[((b0 & 0x03) << 4) | (b1 >> 4)]);
    out.push_back(kBase64UrlAlphabet[((b1 & 0x0F) << 2) | (b2 >> 6)]);
    out.push_back(kBase64UrlAlphabet[b2 & 0x3F]);
  }
  size_t rem = in.size() - i;
  if (rem == 1) {
    unsigned b0 = static_cast<unsigned char>(in[i]);
    out.push_back(kBase64UrlAlphabet[b0 >> 2]);
    out.push_back(kBase64UrlAlphabet[(b0 & 0x03) << 4]);
  } else if (rem == 2) {
    unsigned b0 = static_cast<unsigned char>(in[i]);
    unsigned b1 = static_cast<unsigned char>(in[i + 1]);
    out.push_back(kBase64UrlAlphabet[b0 >> 2]);
    out.push_back(kBase64UrlAlphabet[((b0 & 0x03) << 4) | (b1 >> 4)]);
    out.push_back(kBase64UrlAlphabet[(b1 & 0x0F) << 2]);
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
  serialized.set_id_bytes(
      crypto::X509Certificate(identity.getCertificate()).getDER());
  return serialized;
}

} // namespace

std::string serializeIdentity(const identity::Identity &identity) {
  msp::SerializedIdentity serialized = makeSerializedIdentity(identity);
  return serialized.SerializeAsString();
}

std::string createTransactionId(const identity::Identity &identity) {
  const std::string nonce = randomNonce(24);
  const std::string creator = serializeIdentity(identity);
  return base64UrlEncode(crypto::sha256(nonce + creator));
}

::protos::Proposal
createProposal(const identity::Identity &identity, const std::string &channelId,
               const std::string &txId, const std::string &chaincodeName,
               const std::vector<std::string> &args,
               const std::map<std::string, std::string> &transient) {
  msp::SerializedIdentity serialized = makeSerializedIdentity(identity);

  ::common::ChannelHeader channelHeader;
  channelHeader.set_type(::common::ENDORSER_TRANSACTION);
  channelHeader.set_tx_id(txId);
  channelHeader.set_channel_id(channelId);
  channelHeader.set_epoch(0);

  ::common::SignatureHeader signatureHeader;
  signatureHeader.set_creator(serialized.SerializeAsString());
  signatureHeader.set_nonce(randomNonce(24));

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

  if (!actionPayload.has_action() ||
      actionPayload.action().proposal_response_payload().empty()) {
    return empty;
  }

  ::protos::ChaincodeAction chaincodeAction;
  if (!chaincodeAction.ParseFromString(
          actionPayload.action().proposal_response_payload())) {
    return empty;
  }

  if (!chaincodeAction.has_response()) {
    return empty;
  }

  return chaincodeAction.response();
}

} // namespace protoutil
} // namespace fabric