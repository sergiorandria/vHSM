package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SignatureLedger records HSM-generated signatures on the Fabric ledger so that
// every C_Sign operation performed through the vHSM PKCS#11 module is durably
// auditable. It is the on-chain counterpart of the C++ LedgerClient
// (src/ledger/ledger_client.cpp), which submits to the "signature_ledger"
// contract on the "signaturechannel" network.
type SignatureLedger struct {
	contractapi.Contract
}

// SignatureRecord is the on-chain representation of one signed payload. JSON
// tags are intentionally snake_case to match the exact field names the C++
// client parses in LedgerClient::get_record (nlohmann json::parse).
type SignatureRecord struct {
	RecordID       string `json:"record_id"`
	KeyFingerprint string `json:"key_fingerprint"`
	PayloadDigest  string `json:"payload_digest"`
	SignatureB64   string `json:"signature_b64"`
	CreatedAt      int64  `json:"created_at"`
	TxID           string `json:"tx_id"`
	BlockNumber    int64  `json:"block_number"`
	// Submitter is the authenticated client identity (mTLS cert) of the
	// transaction that anchored this signature. It makes the on-chain record
	// attributable to a real actor instead of an unverified claim.
	Submitter string `json:"submitter,omitempty"`
}

// RecordSignature persists one signature record. The argument order and count
// are FIXED by the C++ caller (LedgerClient::submit_record): record_id,
// key_fingerprint, payload_digest, signature_b64, created_at (unix seconds as a
// decimal string).
func (c *SignatureLedger) RecordSignature(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	keyFingerprint string,
	payloadDigest string,
	signatureB64 string,
	createdAt string,
) error {
	exists, err := c.recordExists(ctx, recordID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("signature record '%s' already exists", recordID)
	}

	var created int64
	if _, err := fmt.Sscanf(createdAt, "%d", &created); err != nil {
		// Fall back to the transaction timestamp if the caller supplied an
		// empty/non-numeric created_at.
		if ts, terr := ctx.GetStub().GetTxTimestamp(); terr == nil {
			created = ts.Seconds
		}
	}

	rec := SignatureRecord{
		RecordID:       recordID,
		KeyFingerprint: keyFingerprint,
		PayloadDigest:  payloadDigest,
		SignatureB64:   signatureB64,
		CreatedAt:      created,
		// The block number is assigned by the orderer at commit time; the C++
		// client uses the committed block number from the transaction result,
		// so storing 0 here is fine and is overwritten on the read path only
		// when no commit metadata is available.
		TxID:        ctx.GetStub().GetTxID(),
		BlockNumber: 0,
	}

	// Record the authenticated submitter (mTLS identity) for auditability.
	if submitter, serr := ctx.GetClientIdentity().GetID(); serr == nil && submitter != "" {
		rec.Submitter = submitter
	}

	recJSON, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal signature record: %w", err)
	}

	return ctx.GetStub().PutState(recordID, recJSON)
}

// GetRecord returns the stored signature record for recordID. The returned
// struct is marshaled to JSON by contractapi and becomes the transaction
// payload the C++ client parses.
func (c *SignatureLedger) GetRecord(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) (*SignatureRecord, error) {
	return c.getRecord(ctx, recordID)
}

func (c *SignatureLedger) recordExists(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) (bool, error) {
	data, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return false, fmt.Errorf("failed to read signature record: %w", err)
	}
	return data != nil, nil
}

func (c *SignatureLedger) getRecord(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) (*SignatureRecord, error) {
	data, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature record: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("signature record '%s' does not exist", recordID)
	}
	var rec SignatureRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature record: %w", err)
	}
	return &rec, nil
}
