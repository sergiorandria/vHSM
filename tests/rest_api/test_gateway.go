package main

import (
	"encoding/json"
	"fmt"

	"github.com/sergiorandria/go-rest-api/gateway_sdk"
	"github.com/sergiorandria/go-rest-api/utils" // Importing your local library package
)

// Local data structures representing the transaction payload
type ThesisMetadata struct {
	ThesisTitle string `json:"thesisTitle"`
	DefenseDate string `json:"DefenseDate"`
}

type ThesisPayload struct {
	ThesisID string         `json:"thesisId"`
	Grade    float64        `json:"grade"`
	Metadata ThesisMetadata `json:"metadata"`
}

func main() {
	fmt.Println("Starting Gateway Client Execution...")

	// 1. Instantiate mock payload data
	payload := ThesisPayload{
		ThesisID: "T128",
		Grade:    16.5,
		Metadata: ThesisMetadata{
			ThesisTitle: "Distributed Ledger Integrity Verification",
			DefenseDate: "2026-06-16",
		},
	}

	thesisID := payload.ThesisID
	gradeStr := fmt.Sprintf("%.1f", payload.Grade)
	metadataBytes, _ := json.Marshal(payload.Metadata)

	// 2. Setup low-level connectivity using the utils library
	clientConn, err := utils.NewGrpcConnection()
	if err != nil {
		fmt.Printf("failed to create gRPC connection: %s\n", err)
		return
	}
	defer clientConn.Close()

	id, err := utils.NewIdentity()
	if err != nil {
		fmt.Printf("failed to create identity: %s\n", err)
		return
	}

	sign, err := utils.NewSign()
	if err != nil {
		fmt.Printf("failed to create signing function: %s\n", err)
		return
	}

	// 3. Initialize the modular GatewayClient SDK wrapper
	client, err := gateway_sdk.NewGatewayClient(clientConn, utils.ChannelName, utils.ChaincodeName, id, sign)
	if err != nil {
		fmt.Printf("failed to initialize gateway client: %s\n", err)
		return
	}
	defer client.Close()

	// 4. Submit the state-changing transaction to Hyperledger Fabric
	fmt.Printf("Executing transaction for key [%s]...\n", thesisID)
	err = client.ExecuteTransaction("CreateThesisRecord", thesisID, string(metadataBytes), gradeStr)
	if err != nil {
		fmt.Printf("transaction failed: %s\n", err)
		return
	}

	fmt.Println("Transaction successfully committed to the ledger!")
}