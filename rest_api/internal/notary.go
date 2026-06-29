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

func (n *NotaryService) Notarize(thesisID string, hash string, signature string) error {
	// Use of the gateway client to call chaincode
	return n.client.ExecuteTransaction("NotarizeThesis", thesisID, hash, signature)
}
