package blockchain

import (
	"context"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
)

/**
 * @brief Struct encapsulating the Hyperledger Fabric Gateway SDK connections and credentials.
 *
 * This structure manages the lifecycle of the low-level gRPC connection, the active 
 * MSP Identity, and provides a handle to the target Smart Contract (Chaincode).
 */
type GatewayClient struct {
	gw       *client.Gateway  /**< Internal handle for the Fabric Gateway SDK client. */
	contract *client.Contract /**< Contract instance used to invoke transactions. */
}

/**
 * @brief Initializes a new modular instance of GatewayClient with an explicit Identity and Signer.
 *
 * Bridges the low-level gRPC network connection with the channel and smart contract 
 * abstractions, using the provided MSP identity and cryptographic signing function.
 *
 * @param grpcConn Active gRPC client connection interface pointing to the Gateway Peer.
 * @param channelName String representing the target Fabric channel name.
 * @param chaincodeID String representing the unique ID of the deployed Smart Contract.
 * @param id The X.509 MSP Identity representing the acting user/organization.
 * @param sign The cryptographic signing function associated with the identity's private key.
 *
 * @return A pointer to the initialized GatewayClient instance.
 * @return An error if the connection to the Gateway fails, otherwise nil.
 */
func NewGatewayClient(
	grpcConn grpc.ClientConnInterface, 
	channelName string, 
	chaincodeID string,
	id identity.Identity,
	sign identity.Sign,
) (*GatewayClient, error) {
	
	// Connect to the Gateway SDK using the injected Identity and Signing configuration
	gw, err := client.Connect(
		id,
		client.WithSign(sign), 
		client.WithClientConnection(grpcConn),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to fabric gateway: %w", err)
	}

	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeID)

	return &GatewayClient{gw: gw, contract: contract}, nil
}

/**
 * @brief Gracefully closes the connection to the Gateway SDK and releases resources.
 *
 * @return An error if the gateway shutdown fails, otherwise nil.
 */
func (gc *GatewayClient) Close() error {
	return gc.gw.Close()
}

/**
 * @brief Transmits and appends a canonical JSON metadata payload directly to the Distributed Ledger.
 *
 * @param thesisID Unique identifier extracted from the payload used as the ledger state key.
 * @param canonicalJSON Byte slice containing the strictly canonicalized JSON document payload.
 *
 * @return An error if the transaction submission is rejected or fails, otherwise nil.
 */
func (gc *GatewayClient) AppendCanonicalMetadata(thesisID string, canonicalJSON []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Execute and submit the transaction to the distributed network using the configured identity
	_, err := gc.contract.Submit(
		"AppendThesis",
		client.WithContext(ctx),
		client.WithArguments(thesisID, string(canonicalJSON)),
	)
	if err != nil {
		return fmt.Errorf("failed to submit canonical json to ledger: %w", err)
	}

	return nil
}