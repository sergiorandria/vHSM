package blockchain

import (
	"context"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"google.golang.org/grpc"
)

/**
 * @brief Struct encapsulating the Hyperledger Fabric Gateway SDK connections.
 *
 * This structure manages the lifecycle of the low-level gRPC connection and 
 * provides a handle to the target Smart Contract (Chaincode) instantiated on the channel.
 */
type GatewayClient struct {
	gw       *client.Gateway  /**< Internal handle for the Fabric Gateway SDK client. */
	contract *client.Contract /**< Contract instance used to invoke transactions. */
}

/**
 * @brief Initializes a new modular instance of GatewayClient.
 *
 * Bridges the low-level gRPC network connection with the channel and smart contract 
 * abstractions provided by the official Hyperledger Fabric Gateway SDK.
 *
 * @param grpcConn Active gRPC client connection interface pointing to the Gateway Peer.
 * @param channelName String representing the target Fabric channel name.
 * @param chaincodeID String representing the unique ID of the deployed Smart Contract.
 *
 * @return A pointer to the initialized GatewayClient instance.
 * @return An error if the connection to the Gateway fails, otherwise nil.
 */
func NewGatewayClient(grpcConn grpc.ClientConnInterface, channelName string, chaincodeID string) (*GatewayClient, error) {
	// Connect to the Gateway SDK (WithSign(nil) is used for basic/local testing setups)
	gw, err := client.Connect(
		client.WithSign(nil), 
		client.WithClientConnection(grpcConn),
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
 * This method should be called (typically via a defer statement) to prevent 
 * leaking network sockets or dangling gRPC connections during the application lifecycle.
 *
 * @return An error if the gateway shutdown fails, otherwise nil.
 */
func (gc *GatewayClient) Close() error {
	return gc.gw.Close()
}

/**
 * @brief Transmits and appends a raw JSON metadata payload directly to the Distributed Ledger.
 *
 * This function takes the raw JSON text representing the signed or unsigned metadata 
 * and forwards it as a single string argument to the "AppendThesis" function in the 
 * Smart Contract, ensuring the original payload structure is persisted with zero modifications.
 *
 * @note A strict timeout of 15 seconds is enforced using a Go Context 
 * to prevent blocking the execution thread indefinitely during network congestion.
 *
 * @param id Unique anchor key inside the Ledger State database (PutState key).
 * @param rawJSON String containing the unaltered, raw JSON document payload.
 *
 * @return An error if the transaction submission is rejected or fails, otherwise nil.
 */
func (gc *GatewayClient) AppendMetadata(id string, rawJSON string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Execute and submit the transaction to the distributed network
	_, err := gc.contract.Submit(
		"AppendThesis",
		client.WithContext(ctx),
		client.WithArguments(id, rawJSON),
	)
	if err != nil {
		return fmt.Errorf("failed to submit raw json to ledger: %w", err)
	}

	return nil
}