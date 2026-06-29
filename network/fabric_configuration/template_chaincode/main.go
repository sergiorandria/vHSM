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

	tlsDisabled := os.Getenv("CHAINCODE_TLS_DISABLED") == "true"

	tlsProps := shim.TLSProperties{Disabled: tlsDisabled}

	if !tlsDisabled {
		cert, err := os.ReadFile(os.Getenv("CHAINCODE_TLS_CERT"))
		if err != nil {
			log.Fatalf("Cannot read TLS cert: %v", err)
		}
		key, err := os.ReadFile(os.Getenv("CHAINCODE_TLS_KEY"))
		if err != nil {
			log.Fatalf("Cannot read TLS key: %v", err)
		}
		ca, err := os.ReadFile(os.Getenv("CHAINCODE_TLS_CA"))
		if err != nil {
			log.Fatalf("Cannot read TLS CA: %v", err)
		}
		tlsProps.Key = key
		tlsProps.Cert = cert
		tlsProps.ClientCACerts = ca
	}

	server := &shim.ChaincodeServer{
		CCID:     ccID,
		Address:  address,
		CC:       chaincode,
		TLSProps: tlsProps,
	}

	log.Printf("ThesisContract CCaaS started at %s", address)
	log.Printf("Package ID : %s", ccID)

	if err := server.Start(); err != nil {
		log.Fatalf("Cannot start the server : %v", err)
	}
}
