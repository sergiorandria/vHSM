package internal

import (
	"electronic_signature/rest_api/gateway_sdk"
)

type NotaryService struct {
	client *gateway_sdk.GatewayClient
	hsm    *HSMService
}

func NewNotaryService(client *gateway_sdk.GatewayClient, hsm *HSMService) *NotaryService {
	return &NotaryService{client: client, hsm: hsm}
}

// CreateThesis creates a new thesis record on the ledger. It is called by a
// superadmin at the time the thesis is registered, before any defense has
// taken place: initialDataJSON carries the Student, Administrative and
// Metadata fields only — no grade. The grade is appended later, once the
// defense happens, via SubmitGrade.
func (n *NotaryService) CreateThesis(thesisID, studentID, initialDataJSON, createdBy string) error {
	return n.client.ExecuteTransaction("CreateThesis", thesisID, studentID, initialDataJSON, createdBy)
}

// SubmitGrade appends the grade to an existing thesis record once the
// defense has taken place, moving its status from DRAFT to DEFENDED.
func (n *NotaryService) SubmitGrade(thesisID string, grade string) error {
	return n.client.ExecuteTransaction("SubmitGrade", thesisID, grade)
}

// SubmitJuryGrade records an individual juror's grade evaluation and comments.
// It invokes the 'SubmitJuryGrade' smart contract function.
func (n *NotaryService) SubmitJuryGrade(thesisID string, jurorID string, grade string, comment string) error {
	return n.client.ExecuteTransaction("SubmitJuryGrade", thesisID, jurorID, grade, comment)
}

// SignPv attaches an individual juror's cryptographic signature over the established
// Procès-Verbal hash on the ledger.
func (n *NotaryService) SignPv(thesisID string, jurorID string, hashHex string, sigHex string) error {
	return n.client.ExecuteTransaction("SignPv", thesisID, jurorID, hashHex, sigHex)
}

// NotarizeDocument attaches the hash and HSM signature of the thesis PDF
// itself to an existing thesis record.
func (n *NotaryService) NotarizeDocument(thesisID string, hash string, signature string) error {
	return n.client.ExecuteTransaction("NotarizeDocument", thesisID, hash, signature)
}

// NotarizePv attaches the hash and HSM signature of the defense
// procès-verbal (PV) to an existing thesis record. Once both the document
// and the PV are notarized, the chaincode moves the thesis to NOTARIZED.
func (n *NotaryService) NotarizePv(thesisID string, hashPv string, signaturePv string) error {
	return n.client.ExecuteTransaction("NotarizePv", thesisID, hashPv, signaturePv)
}

// GetThesis evaluates a transaction to read a single thesis payload.
func (n *NotaryService) GetThesis(thesisID string) ([]byte, error) {
	return n.client.EvaluateTransaction("ReadThesis", thesisID)
}

// GetJuryStatus queries the current validation and signing progress from the ledger.
func (n *NotaryService) GetJuryStatus(thesisID string) ([]byte, error) {
	return n.client.EvaluateTransaction("GetJuryStatus", thesisID)
}

// GetAllTheses evaluates a transaction to return all thesis records on the ledger.
func (n *NotaryService) GetAllTheses() ([]byte, error) {
	return n.client.EvaluateTransaction("GetAllTheses")
}
