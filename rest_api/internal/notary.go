package internal

import (
	"electronic_signature/rest_api/gateway_sdk"
)

type NotaryService struct {
	client      *gateway_sdk.GatewayClient
	hsm         *HSMService
	channelName string
}

func NewNotaryService(client *gateway_sdk.GatewayClient, hsm *HSMService, channelName string) *NotaryService {
	return &NotaryService{client: client, hsm: hsm, channelName: channelName}
}

// CreateThesis creates a new thesis record on the ledger. It is called by a
// superadmin at the time the thesis is registered, before any defense has
// taken place: initialDataJSON carries the Student, Administrative and
// Metadata fields only — no grade. The grade is appended later, once the
// defense happens, one juror at a time, via SubmitJuryGrade.
func (n *NotaryService) CreateThesis(thesisID, studentID, initialDataJSON, createdBy string) error {
	return n.client.ExecuteTransaction("CreateThesis", thesisID, studentID, initialDataJSON, createdBy)
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

// GetThesisHistory returns the full change history of a thesis record —
// one entry per committed transaction that touched it, each carrying the
// txId, the block timestamp, whether that transaction was a delete, and
// the record's value as of that transaction. This is genuinely different
// from GetThesis/ReadThesis, which only returns the *current* state: this
// walks the ledger's per-key history, so the API/frontend can show how a
// thesis moved through DRAFT -> DEFENDED -> NOTARIZED over time, with the
// txId of each step. It invokes the 'GetThesisHistory' chaincode function.
func (n *NotaryService) GetThesisHistory(thesisID string) ([]byte, error) {
	return n.client.EvaluateTransaction("GetThesisHistory", thesisID)
}

// GetTransactionByID looks up a single transaction's details directly via
// QSCC (the system chaincode deployed on every peer), given a txId — e.g.
// one returned by GetThesisHistory above.
//
// NOTE: this is not currently wired up to any HTTP route. QSCC is a
// separate system chaincode from the one this NotaryService's client is
// bound to (cfg.ChaincodeName), and gateway_sdk.GatewayClient as used
// elsewhere in this file always evaluates against that single bound
// chaincode. Passing "qscc" as the transaction name below does NOT target
// the QSCC contract — it would just ask the bound chaincode for a
// function literally named "qscc", which doesn't exist and will fail.
// Querying QSCC properly requires a gateway_sdk client (or a second one)
// constructed against the "qscc" chaincode name specifically. Left here,
// disabled by omission from main.go's routes, until gateway_sdk supports
// that.
func (n *NotaryService) GetTransactionByID(txID string) ([]byte, error) {
	return n.client.EvaluateTransaction("qscc", "GetTransactionByID", n.channelName, txID)
}
