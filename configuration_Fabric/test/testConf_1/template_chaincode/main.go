package main

import (
	"log"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	ccID := os.Getenv("CORE_CHAINCODE_ID_NAME")
	address := os.Getenv("CHAINCODE_SERVER_ADDRESS")

	if ccID == "" || address == "" {
		log.Fatal("❌ CORE_CHAINCODE_ID_NAME et CHAINCODE_SERVER_ADDRESS sont requis")
	}

	// On enregistre ThesisContract (défini dans chaincode.go)
	chaincode, err := contractapi.NewChaincode(&ThesisContract{})
	if err != nil {
		log.Fatalf("❌ Erreur création chaincode : %v", err)
	}

	server := &shim.ChaincodeServer{
		CCID:    ccID,
		Address: address,
		CC:      chaincode,
		TLSProps: shim.TLSProperties{
			Disabled: true, // passez à false si TLS activé dans connection.json
		},
	}

	log.Printf("🚀 ThesisContract CCaaS démarré sur %s", address)
	log.Printf("   Package ID : %s", ccID)

	if err := server.Start(); err != nil {
		log.Fatalf("❌ Erreur démarrage serveur : %v", err)
	}
}
