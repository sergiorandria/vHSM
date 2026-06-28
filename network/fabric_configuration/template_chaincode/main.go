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
		log.Fatal("CORE_CHAINCODE_ID_NAME or CHAINCODE_SERVER_ADDRESS env is not set")
	}

	// On enregistre ThesisContract (défini dans chaincode.go)
	chaincode, err := contractapi.NewChaincode(&ThesisContract{})
	if err != nil {
		log.Fatalf("Error creating new chaincode with the thesis contract : %v", err)
	}

	server := &shim.ChaincodeServer{
		CCID:    ccID,
		Address: address,
		CC:      chaincode,
		TLSProps: shim.TLSProperties{
			Disabled: true,
		},
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Cannot start the server : %v", err)
	}

	log.Printf("ThesisContract CCaaS started at %s", address)
	log.Printf("Package ID : %s", ccID)
}
