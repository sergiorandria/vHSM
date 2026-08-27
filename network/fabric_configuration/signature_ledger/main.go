package main

import (
	"log"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// NewSignatureLedger builds the contract with the name the vHSM C++ LedgerClient
// expects: contract "signature_ledger" on network "signaturechannel".
func NewSignatureLedger() *SignatureLedger {
	c := &SignatureLedger{}
	c.Name = "signature_ledger"
	return c
}

func main() {
	ccID := os.Getenv("CORE_CHAINCODE_ID_NAME")
	address := os.Getenv("CHAINCODE_SERVER_ADDRESS")

	if ccID == "" || address == "" {
		log.Fatal("CORE_CHAINCODE_ID_NAME or CHAINCODE_SERVER_ADDRESS env is not set")
	}

	chaincode, err := contractapi.NewChaincode(NewSignatureLedger())
	if err != nil {
		log.Fatalf("Error creating new chaincode with the signature ledger contract: %v", err)
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
		tlsProps.Cert = cert
		tlsProps.Key = key

		if caPath := os.Getenv("CHAINCODE_TLS_CA"); caPath != "" {
			ca, err := os.ReadFile(caPath)
			if err != nil {
				log.Fatalf("Cannot read TLS CA: %v", err)
			}
			tlsProps.ClientCACerts = ca
		}
	}

	server := &shim.ChaincodeServer{
		CCID:     ccID,
		Address:  address,
		CC:       chaincode,
		TLSProps: tlsProps,
	}

	log.Printf("SignatureLedger CCaaS started at %s", address)
	log.Printf("Package ID : %s", ccID)

	if err := server.Start(); err != nil {
		log.Fatalf("Cannot start the server : %v", err)
	}
}
