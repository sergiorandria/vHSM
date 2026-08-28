package main

import (
	"encoding/json"
	"fmt"
	"strconv"

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
	// Post-quantum / hybrid companion signature. When a Dilithium/SPHINCS+ key
	// is paired with the classical signing key, both signatures are anchored so
	// the record stays verifiable against a quantum adversary.
	PqcAlgo          string `json:"pqc_algo,omitempty"`
	SignaturePqcB64  string `json:"signature_pqc_b64,omitempty"`
	KeyFingerprintPqc string `json:"key_fingerprint_pqc,omitempty"`
}

// RecordSignature persists one signature record. The argument order and count
// are FIXED by the C++ caller (LedgerClient::submit_record): record_id,
// key_fingerprint, payload_digest, signature_b64, created_at (unix seconds as a
// decimal string), pqc_algo, signature_pqc_b64, key_fingerprint_pqc.
//
// Idempotent: the record_id is the ledger key, so re-submitting the same
// record (e.g. after a retry or crash) overwrites rather than erroring — this
// is the chaincode half of exactly-once anchoring (see LedgerWorker's in-flight
// set + PROCESSING state).
func (c *SignatureLedger) RecordSignature(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	keyFingerprint string,
	payloadDigest string,
	signatureB64 string,
	createdAt string,
	pqcAlgo string,
	signaturePqcB64 string,
	keyFingerprintPqc string,
) error {
	var created int64
	if _, err := fmt.Sscanf(createdAt, "%d", &created); err != nil {
		// Fall back to the transaction timestamp if the caller supplied an
		// empty/non-numeric created_at.
		if ts, terr := ctx.GetStub().GetTxTimestamp(); terr == nil {
			created = ts.Seconds
		}
	}

	// Preserve the original created_at when upserting an existing record.
	if existing, _ := c.getRecord(ctx, recordID); existing != nil {
		if existing.CreatedAt != 0 {
			created = existing.CreatedAt
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

	// Hybrid post-quantum companion signature (empty when PQC is unavailable).
	rec.PqcAlgo = pqcAlgo
	rec.SignaturePqcB64 = signaturePqcB64
	rec.KeyFingerprintPqc = keyFingerprintPqc

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

// --- Audit tail anchoring -----------------------------------------------------
//
// The append-only audit log is a hash chain whose tail (latest HMAC) can be
// forged by an attacker with file access alone (classic truncation
// undetectability). To close that gap we periodically anchor the audit tail on
// the ledger: every published tail hash is externally verifiable, so any
// tampering or truncation of the local audit file becomes detectable.

// AuditTail is one anchored tail hash of the local audit hash-chain.
type AuditTail struct {
	Seq       int64  `json:"seq"`
	TailHash  string `json:"tail_hash"`
	Timestamp string `json:"timestamp"`
	Submitter string `json:"submitter,omitempty"`
}

func auditTailLatestKey() string { return "audittail:latest" }
func auditTailSeqKey(seq int64) string {
	return "audittail:seq:" + strconv.FormatInt(seq, 10)
}

// RecordAuditTail anchors the current audit hash-chain tail on the ledger. It is
// idempotent per (seq): re-anchoring the same sequence number overwrites rather
// than duplicating.
func (c *SignatureLedger) RecordAuditTail(
	ctx contractapi.TransactionContextInterface,
	tailHash string,
	seq string,
	timestamp string,
) error {
	submitter, _ := clientID(ctx)
	var s int64
	if _, err := fmt.Sscanf(seq, "%d", &s); err != nil {
		s = 0
	}
	tail := AuditTail{
		Seq:       s,
		TailHash:  tailHash,
		Timestamp: timestamp,
		Submitter: submitter,
	}
	b, err := json.Marshal(tail)
	if err != nil {
		return fmt.Errorf("failed to marshal audit tail: %w", err)
	}
	if err := ctx.GetStub().PutState(auditTailSeqKey(s), b); err != nil {
		return err
	}
	return ctx.GetStub().PutState(auditTailLatestKey(), b)
}

// GetLatestAuditTail returns the most recently anchored audit tail (the external
// proof anchor), or an error if none has been anchored yet.
func (c *SignatureLedger) GetLatestAuditTail(
	ctx contractapi.TransactionContextInterface,
) (*AuditTail, error) {
	data, err := ctx.GetStub().GetState(auditTailLatestKey())
	if err != nil {
		return nil, fmt.Errorf("failed to read audit tail: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("no audit tail has been anchored yet")
	}
	var tail AuditTail
	if err := json.Unmarshal(data, &tail); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit tail: %w", err)
	}
	return &tail, nil
}

// --- Policy / attestation engine -------------------------------------------------
//
// Keys may carry a KeyPolicy (published on-chain via PublishKey) that gates who
// may sign, when, with which mechanism, and how many attestations are required
// (quorum). Attestations are submitted by authenticated signers via
// SubmitAttestation; VerifyPolicy evaluates the published policy against the
// on-chain attestation registry so the HSM sign path can fail closed on quorum.

// KeyPolicy mirrors domain/signing/key_policy.h.
type KeyPolicy struct {
	AllowedMechanisms []string `json:"allowed_mechanisms"`
	NotBeforeMs       int64    `json:"not_before_ms"`
	NotAfterMs        int64    `json:"not_after_ms"`
	AllowedSigners    []string `json:"allowed_signers"`
	MinAttestations   int      `json:"min_attestations"`
}

// Attestation is one signer's attestation over a key, recorded on chain.
type Attestation struct {
	KeyID           string `json:"key_id"`
	Signer          string `json:"signer"`  // authenticated client identity
	AttestationType string `json:"attestation_type"`
	Signature       string `json:"signature"`
	SubmittedAt     int64  `json:"submitted_at"`
}

// Policy/attestation methods are attached to SignatureLedger (same contract
// name) so the vHSM C++ LedgerClient can invoke them through the existing
// "signature_ledger" contract handle.

func policyKey(keyID string) string { return "policy:" + keyID }
func attsKey(keyID string) string   { return "atts:" + keyID }

// clientID returns the authenticated submitter identity derived from the
// transaction's x509 certificate (Fabric mTLS). It fails the transaction when
// the client identity is unavailable so on-chain claims are always attributable.
func clientID(ctx contractapi.TransactionContextInterface) (string, error) {
	id, err := ctx.GetClientIdentity().GetID()
	if err != nil || id == "" {
		return "", fmt.Errorf("client identity unavailable: transaction must be submitted over an authenticated channel: %w", err)
	}
	return id, nil
}

func (c *SignatureLedger) getPolicy(ctx contractapi.TransactionContextInterface, keyID string) (*KeyPolicy, error) {
	data, err := ctx.GetStub().GetState(policyKey(keyID))
	if err != nil {
		return nil, fmt.Errorf("failed to read policy: %w", err)
	}
	if data == nil {
		return nil, nil
	}
	var p KeyPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}
	return &p, nil
}

// PublishKey stores the KeyPolicy for keyID. The policy document is supplied as
// a JSON string matching the KeyPolicy struct above.
func (c *SignatureLedger) PublishKey(
	ctx contractapi.TransactionContextInterface,
	keyID string,
	policyJSON string,
) error {
	if _, err := clientID(ctx); err != nil {
		return err
	}
	var p KeyPolicy
	if err := json.Unmarshal([]byte(policyJSON), &p); err != nil {
		return fmt.Errorf("invalid policy JSON: %w", err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}
	return ctx.GetStub().PutState(policyKey(keyID), b)
}

// SubmitAttestation records one signer's attestation for keyID. The signer must
// be an authenticated client (mTLS) and, when the policy restricts
// allowed_signers, must be listed there. Idempotent per (keyID, signer, type).
func (c *SignatureLedger) SubmitAttestation(
	ctx contractapi.TransactionContextInterface,
	keyID string,
	attestationType string,
	signature string,
) error {
	signer, err := clientID(ctx)
	if err != nil {
		return err
	}
	p, err := c.getPolicy(ctx, keyID)
	if err != nil {
		return err
	}
	if p != nil && len(p.AllowedSigners) > 0 {
		allowed := false
		for _, s := range p.AllowedSigners {
			if s == signer {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("signer %s is not authorized to attest key %s", signer, keyID)
		}
	}

	atts, _ := c.getAttestations(ctx, keyID)
	for _, a := range atts {
		if a.Signer == signer && a.AttestationType == attestationType {
			// Idempotent: refresh the signature/timestamp rather than duplicate.
			a.Signature = signature
			if ts, terr := ctx.GetStub().GetTxTimestamp(); terr == nil {
				a.SubmittedAt = ts.Seconds
			}
			return c.putAttestations(ctx, keyID, atts)
		}
	}

	ts := int64(0)
	if t, terr := ctx.GetStub().GetTxTimestamp(); terr == nil {
		ts = t.Seconds
	}
	atts = append(atts, Attestation{
		KeyID:           keyID,
		Signer:          signer,
		AttestationType: attestationType,
		Signature:       signature,
		SubmittedAt:     ts,
	})
	return c.putAttestations(ctx, keyID, atts)
}

func (c *SignatureLedger) getAttestations(ctx contractapi.TransactionContextInterface, keyID string) ([]Attestation, error) {
	data, err := ctx.GetStub().GetState(attsKey(keyID))
	if err != nil {
		return nil, fmt.Errorf("failed to read attestations: %w", err)
	}
	if data == nil {
		return nil, nil
	}
	var atts []Attestation
	if err := json.Unmarshal(data, &atts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestations: %w", err)
	}
	return atts, nil
}

func (c *SignatureLedger) putAttestations(ctx contractapi.TransactionContextInterface, keyID string, atts []Attestation) error {
	b, err := json.Marshal(atts)
	if err != nil {
		return fmt.Errorf("failed to marshal attestations: %w", err)
	}
	return ctx.GetStub().PutState(attsKey(keyID), b)
}

// AttestationsFor returns the attestations collected for keyID.
func (c *SignatureLedger) AttestationsFor(
	ctx contractapi.TransactionContextInterface,
	keyID string,
) ([]Attestation, error) {
	return c.getAttestations(ctx, keyID)
}

// VerifyPolicy evaluates the published policy for keyID against the supplied
// actor/mechanism/now and the on-chain attestation count. Returns a JSON
// document {"ok":bool,"reason":string} so the HSM sign path can fail closed.
func (c *SignatureLedger) VerifyPolicy(
	ctx contractapi.TransactionContextInterface,
	keyID string,
	actor string,
	mechanism string,
	nowMs string,
) (string, error) {
	p, err := c.getPolicy(ctx, keyID)
	if err != nil {
		return "", err
	}
	var ok bool
	var reason string
	if p == nil {
		// No policy published: nothing to enforce.
		ok = true
		reason = "no policy published"
	} else {
		atts, _ := c.getAttestations(ctx, keyID)
		ok, reason = evaluatePolicy(*p, actor, mechanism, nowMs, len(atts))
	}
	out, err := json.Marshal(map[string]interface{}{"ok": ok, "reason": reason})
	if err != nil {
		return "", fmt.Errorf("failed to marshal verification: %w", err)
	}
	return string(out), nil
}

func evaluatePolicy(p KeyPolicy, actor, mechanism, nowMsStr string, attCount int) (bool, string) {
	var nowMs int64
	if _, err := fmt.Sscanf(nowMsStr, "%d", &nowMs); err != nil {
		nowMs = 0
	}
	if p.NotBeforeMs != 0 && nowMs < p.NotBeforeMs {
		return false, "signing not yet active"
	}
	if p.NotAfterMs != 0 && nowMs > p.NotAfterMs {
		return false, "signing window expired"
	}
	if len(p.AllowedMechanisms) > 0 {
		found := false
		for _, m := range p.AllowedMechanisms {
			if m == mechanism {
				found = true
				break
			}
		}
		if !found {
			return false, "mechanism " + mechanism + " not permitted"
		}
	}
	if len(p.AllowedSigners) > 0 {
		found := false
		for _, s := range p.AllowedSigners {
			if s == actor {
				found = true
				break
			}
		}
		if !found {
			return false, "actor " + actor + " not authorized"
		}
	}
	if attCount < p.MinAttestations {
		return false, fmt.Sprintf("insufficient attestations (%d < %d required)", attCount, p.MinAttestations)
	}
	return true, "ok"
}
