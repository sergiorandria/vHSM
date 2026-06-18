package gateway_sdk

import (
	"fmt"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
)

/**
 * @brief Exposes the internal Contract instance to allow executing explicit EvaluateTransaction or custom queries in test contexts.
 *
 * @return A pointer to the underlying fabric client.Contract.
 */
func (gc *GatewayClient) GetContract() *client.Contract {
	return gc.contract
}

/**
 * @brief Struct encapsulating the Hyperledger Fabric Gateway SDK connections and handles.
 *
 * This structure decouples the low-level gRPC connection and identity management
 * from the execution layer, allowing generic transaction routing to any contract.
 */
type GatewayClient struct {
	gw       *client.Gateway  /**< Internal handle for the Fabric Gateway SDK client. */
	contract *client.Contract /**< Target contract instance used to execute ledger actions. */
}

/**
 * @brief Initializes a new independent instance of GatewayClient with an explicit Identity and Signer.
 *
 * Establishes a secure bridge between the gRPC networking layer, the selected channel,
 * and the specific chaincode deployment using pre-configured timeout policies.
 *
 * @param grpcConn Active gRPC client connection interface pointing to the Gateway Peer.
 * @param channelName String representing the target Fabric application channel.
 * @param chaincodeID String representing the unique ID of the deployed Smart Contract.
 * @param id The X.509 MSP Identity representing the acting client organization.
 * @param sign The cryptographic signing function bound to the identity's private key.
 *
 * @return A pointer to the initialized GatewayClient instance.
 * @return An error if the connection orchestration fails, otherwise nil.
 */
func NewGatewayClient(grpcConn grpc.ClientConnInterface, channelName string, chaincodeID string, id identity.Identity, sign identity.Sign) (*GatewayClient, error) {
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
 * @brief Gracefully terminates the connection to the Gateway SDK and releases active cluster resources.
 *
 * @return An error if the gateway engine shutdown encounters a structural failure, otherwise nil.
 */
func (gc *GatewayClient) Close() error {
	return gc.gw.Close()
}

/**
 * @brief Executes a state-changing transaction on the distributed ledger in a strictly modular, generic manner.
 *
 * This method remains entirely agnostic of host-specific payloads, execution platforms, or business logic
 * by shifting payload formatting responsibilities up to the calling context or API routing layers.
 *
 * @param chaincodeFuncName Target function name declared within the deployed Smart Contract.
 * @param args Variadic array of string arguments matching the target chaincode function signature requirements.
 *
 * @return An error if proposal generation, peer endorsement, or orderer submission fails, otherwise nil.
 */
func (gc *GatewayClient) ExecuteTransaction(chaincodeFuncName string, args ...string) error {
	// 1. Dynamically prepare the transaction proposal using the provided variadic arguments
	proposal, err := gc.contract.NewProposal(
		chaincodeFuncName,
		client.WithArguments(args...),
	)
	if err != nil {
		return fmt.Errorf("failed to create ledger proposal for %s: %w", chaincodeFuncName, err)
	}

	// 2. Transmit proposal to endorsing Peers using pre-configured gRPC timeout context
	endorsedProposal, err := proposal.Endorse()
	if err != nil {
		return fmt.Errorf("failed to endorse ledger proposal for %s: %w", chaincodeFuncName, err)
	}

	// 3. Submit endorsed transaction block to the Orderer service for definitive ledger commitment
	_, err = endorsedProposal.Submit()
	if err != nil {
		return fmt.Errorf("failed to submit transaction %s to ledger: %w", chaincodeFuncName, err)
	}

	return nil
}
