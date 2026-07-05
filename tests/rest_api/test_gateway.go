package main

import (
	"fmt"

	"github.com/sergiorandria/go-rest-api/gateway_sdk"
	"github.com/sergiorandria/go-rest-api/utils"
)

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

	// 1. Données de la soutenance
	payload := ThesisPayload{
		ThesisID: "T110",
		Grade:    16.5,
		Metadata: ThesisMetadata{
			ThesisTitle: "Distributed Ledger Integrity Verification",
			DefenseDate: "2026-06-16",
		},
	}

	// Conversion en string pour l'envoi variadique
	thesisID := payload.ThesisID
	gradeStr := fmt.Sprintf("%.1f", payload.Grade)
	titleStr := payload.Metadata.ThesisTitle
	dateStr := payload.Metadata.DefenseDate

	// 2. Configuration de la connectivité gRPC / Sécurité
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

	// 3. Initialisation du GatewayClient
	client, err := gateway_sdk.NewGatewayClient(clientConn, utils.ChannelName, utils.ChaincodeName, id, sign)
	if err != nil {
		fmt.Printf("failed to initialize gateway client: %s\n", err)
		return
	}
	defer client.Close()

	// 4. Soumission de la transaction avec les paramètres attendus par le Smart Contract
	fmt.Printf("Executing transaction for key [%s]...\n", thesisID)

	// Changement ici : Nom de fonction exact "CreateThesis" et passage des 4 arguments distincts
	err = client.ExecuteTransaction("CreateThesis", thesisID, gradeStr, titleStr, dateStr)
	if err != nil {
		fmt.Printf("transaction failed: %s\n", err)
		return
	}

	fmt.Println("Transaction successfully committed to the ledger!")
}
