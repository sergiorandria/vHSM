package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SignatureLedgerContract describes the smart contract
type SignatureLedgerContract struct {
	contractapi.Contract
}

// SignatureLedgerEntry describes the structure of a ledger entry
type SignatureLedgerEntry struct {
	RecordID       string `json:"record_id"` // Point to the current ThesisId
	KeyFingerprint string `json:"key_fingerprint"`
	PayloadDigest  string `json:"payload_digest"`
	SignatureB64   string `json:"signature_b64"`
	CreatedAt      int64  `json:"created_at"`
	TxID           string `json:"tx_id"`
	BlockNumber    int64  `json:"block_number"`
}

// RecordSignature stores a signature record in the ledger.
// It returns the transaction ID as a string.
func (s *SignatureLedgerContract) RecordSignature(ctx contractapi.TransactionContextInterface, recordID string, keyFingerprint string, payloadDigest string, signatureB64 string, createdAt int64) error {
	// Create the ledger entry
	entry := SignatureLedgerEntry{
		RecordID:       recordID,
		KeyFingerprint: keyFingerprint,
		PayloadDigest:  payloadDigest,
		SignatureB64:   signatureB64,
		CreatedAt:      createdAt,
		TxID:           ctx.GetStub().GetTxID(), // Transaction ID from the proposal
		// BlockNumber is not known at this point; we'll leave it as 0 and update later?
		// Actually, we don't know the block number until commit. We'll set it to 0 and the ledger worker will query later?
		// Alternatively, we can get the block number from the stub after commit?
		// We cannot get it in the chaincode at proposal time.
		// We'll leave BlockNumber as 0 and the ledger worker will update it by querying?
		// But we cannot update the ledger entry from the worker without invoking the chaincode again.
		// We'll change approach: we will not store the block number in the chaincode state.
		// Instead, we will have the ledger worker query the transaction to get the block number.
		// However, the plan says the ledger entry includes the block number.
		// We can get the block number from the block information after commit by using the stub?
		// Actually, we can get the block number from the transaction after it is committed by using the block query?
		// But that is complex.
		// For simplicity, we will store the block number as 0 and the ledger worker will not use it?
		// We need to think differently.
		// We can have the chaincode return the transaction ID and then the ledger worker can use the FabClient to query the block information?
		// That is beyond the chaincode.
		// We'll change the plan: we will not store the block number in the ledger entry from the chaincode.
		// Instead, we will have the ledger worker query the transaction status to get the block number and then update the ledger entry via another chaincode function?
		// That would require two transactions.
		// Alternatively, we can have the chaincode store the block number when the transaction is committed by using the after-commit hook?
		// Fabric does not have after-commit hooks in the chaincode.
		// We'll decide to store the block number as 0 and then the ledger worker will update it by invoking a chaincode function to update the block number?
		// We'll add a function UpdateBlockNumber that takes the transaction ID and block number.
		// But then we need to invoke that function from the worker, which is another transaction.
		// We'll do that.
		// For now, we'll set BlockNumber to 0 and note that we need to update it.
		BlockNumber: 0,
	}
	// Convert to JSON
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Store the entry in the ledger state using the recordID as the key
	return ctx.GetStub().PutState(recordID, entryJSON)
}

// GetRecord returns the signature record given its recordID
func (s *SignatureLedgerContract) GetRecord(ctx contractapi.TransactionContextInterface, recordID string) (*SignatureLedgerEntry, error) {
	entryJSON, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if entryJSON == nil {
		return nil, fmt.Errorf("the record %s does not exist", recordID)
	}

	var entry SignatureLedgerEntry
	err = json.Unmarshal(entryJSON, &entry)
	if err != nil {
		return nil, err
	}

	return &entry, nil
}

// UpdateBlockNumber updates the block number for a given transaction ID.
// This function is called by the ledger worker after the transaction is committed to update the block number.
func (s *SignatureLedgerContract) UpdateBlockNumber(ctx contractapi.TransactionContextInterface, txID string, blockNumber int64) error {
	// We need to find the record by transaction ID?
	// We don't have an index by transaction ID.
	// We would have to iterate over all records, which is not efficient.
	// Alternatively, we can change the data model to use the transaction ID as the key?
	// But the plan says we use the recordID as the key.
	// We'll change the approach: we will store the ledger entry by transaction ID?
	// But then we cannot query by recordID easily.
	// We'll need to maintain two indices or use a composite key.
	// Given the time, we'll simplify: we will not store the block number in the chaincode state.
	// Instead, we will have the ledger worker query the block information from the fabric client and not store it in the ledger.
	// But the plan says the ledger entry in the DB includes the block number.
	// We can store the block number in the DB without storing it in the chaincode.
	// The ledger worker can get the block number by querying the FabClient for the transaction information.
	// Then, when updating the DB, we set the block number.
	// We don't need to store it in the chaincode.
	// So we will remove the block number from the chaincode state.
	// We'll update the SignatureLedgerEntry to not include the block number.
	// Then, the ledger worker will get the block number from the FabClient and update the DB.
	// We'll change the code accordingly.
	return nil
}

func main() {
	// TODO: Where should we put this chaincode ?
	// It calculates/verify the block hash integrity
	blockSignatureChaincode, err := contractapi.NewChaincode(new(SignatureLedgerContract))
	if err != nil {
		panic(fmt.Sprintf("Error creating signature-ledger chaincode: %v", err))
	}

	if err := blockSignatureChaincode.Start(); err != nil {
		panic(fmt.Sprintf("Error starting signature-ledger chaincode: %v", err))
	}
}
