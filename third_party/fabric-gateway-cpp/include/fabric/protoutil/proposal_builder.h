#ifndef FABRIC_PROTOUTIL_PROPOSAL_BUILDER_H
#define FABRIC_PROTOUTIL_PROPOSAL_BUILDER_H

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "fabric/identity/identity.h"

#include "common/common.pb.h"
#include "msp/identities.pb.h"
#include "peer/proposal.pb.h"
#include "peer/transaction.pb.h"

namespace fabric {
namespace protoutil {

/**
 * Build the fabric SerializedIdentity (MSP ID + DER-encoded certificate)
 * for the given identity.
 * @param identity The signing identity
 * @return Serialized SerializedIdentity bytes
 */
std::string serializeIdentity(const identity::Identity &identity);

/**
 * Generate a transaction ID and the nonce it was derived from, in the same
 * fashion as the SDKs: txId = base64(sha256(nonce || serializedIdentity)).
 * The same nonce MUST be reused when building the proposal (it seeds the
 * SignatureHeader) so the peer recomputes an identical txId.
 * @param identity The signing identity
 * @return {txId, nonce}
 */
std::pair<std::string, std::string>
createTransactionId(const identity::Identity &identity);

/**
 * Build an unsigned protos.Proposal for a chaincode invocation: a combined
 * common.Header (channel_header + signature_header) plus a serialized
 * ChaincodeInvocationSpec payload.
 * @param identity The signing identity
 * @param channelId Channel name
 * @param nonce Nonce (returned by createTransactionId) used for both the
 *               SignatureHeader and the txId embedded in the ChannelHeader
 * @param chaincodeName Chaincode to invoke
 * @param args Chaincode function name followed by arguments
 * @param transient Optional transient data (private data, never persisted)
 * @return Filled proposal
 */
::protos::Proposal
createProposal(const identity::Identity &identity, const std::string &channelId,
               const std::string &nonce, const std::string &chaincodeName,
               const std::vector<std::string> &args,
               const std::map<std::string, std::string> &transient = {});

/**
 * Sign a proposal, producing a protos.SignedProposal.
 * @param identity Signing identity
 * @param proposal Proposal to sign
 * @return Signed proposal
 */
::protos::SignedProposal signProposal(const identity::Identity &identity,
                                      const ::protos::Proposal &proposal);

/**
 * Sign the payload of a common.Envelope with a DER-encoded ECDSA signature.
 * @param identity Signing identity
 * @param envelope Envelope to sign (signature field set in place)
 */
void signEnvelope(const identity::Identity &identity,
                  ::common::Envelope &envelope);

/**
 * Derive a raw DER-encoded ECDSA signature over SHA-256 of the supplied bytes.
 * @param identity Signing identity
 * @param message Bytes to sign
 * @return DER signature
 */
std::string signBytes(const identity::Identity &identity,
                      const std::string &message);

/**
 * Extract the chaincode response from the transaction carried by a prepared
 * (endorsed) common.Envelope.
 * @param envelope Endorsed envelope as returned by the gateway Endorse call
 * @return Parsed proposal response; status code 0 indicates failure
 */
::protos::Response extractProposalResponse(const ::common::Envelope &envelope);

} // namespace protoutil
} // namespace fabric

#endif // FABRIC_PROTOUTIL_PROPOSAL_BUILDER_H