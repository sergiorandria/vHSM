package main

import (
	"fmt"
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

// CreateThesisRecord - Enregistre une nouvelle these
func (s *SmartContract) CreateThesisRecord(ctx contractapi.TransactionContextInterface, thesisID string, docHash string, grade string) (string, error) {
	exists, err := s.ThesisRecordExists(ctx, thesisID)
	if err != nil {
		return "", fmt.Errorf("failed to read from world state: %w", err)
	}
	if exists {
		return "", fmt.Errorf("the thesis record %s already exists", thesisID)
	}

	payloadJSON := fmt.Sprintf(`{"thesisId":"%s","docHash":"%s","grade":%s}`, thesisID, docHash, grade)

	err = ctx.GetStub().PutState(thesisID, []byte(payloadJSON))
	if err != nil {
		return "", fmt.Errorf("failed to write to world state: %w", err)
	}

	return fmt.Sprintf("Success: Thesis %s recorded", thesisID), nil
}

// GetThesisRecord - Lit une these existante
func (s *SmartContract) GetThesisRecord(ctx contractapi.TransactionContextInterface, thesisID string) (string, error) {
	thesisBytes, err := ctx.GetStub().GetState(thesisID)
	if err != nil {
		return "", fmt.Errorf("failed to read from world state: %w", err)
	}
	if thesisBytes == nil {
		return "", fmt.Errorf("the thesis record %s does not exist", thesisID)
	}

	return string(thesisBytes), nil
}

// ThesisRecordExists - Verifie l'existence d'une cle
func (s *SmartContract) ThesisRecordExists(ctx contractapi.TransactionContextInterface, thesisID string) (bool, error) {
	thesisBytes, err := ctx.GetStub().GetState(thesisID)
	if err != nil {
		return false, err
	}
	return thesisBytes != nil, nil
}

func main() {
	cc, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating jurychaincode: %v", err)
	}

	if err := cc.Start(); err != nil {
		log.Panicf("Error starting jurychaincode: %v", err)
	}
}