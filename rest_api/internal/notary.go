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

// CreateThesis creates a new thesis record on the ledger and returns the
// auto-generated thesisID (produced by the chaincode via GetTxID()).
func (n *NotaryService) CreateThesis(grade string, title string, date string) (string, error) {
	result, err := n.client.ExecuteTransaction("CreateThesis", grade, title, date)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// Notarize attaches a document hash and HSM signature to an existing thesis record.
func (n *NotaryService) Notarize(thesisID string, hash string, signature string) error {
	_, err := n.client.ExecuteTransaction("NotarizeThesis", thesisID, hash, signature)
	return err
}

func (n *NotaryService) GetThesis(thesisID string) ([]byte, error) {
	return n.client.EvaluateTransaction("ReadThesis", thesisID)
}

func (n *NotaryService) GetAllTheses() ([]byte, error) {
	return n.client.EvaluateTransaction("GetAllTheses")
}
