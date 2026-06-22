package notary

import (
	"electronic_signature/rest_api/gateway_sdk"
	"electronic_signature/rest_api/internal/hsm"

)

type NotaryService struct {
	client *gateway_sdk.GatewayClient
	hsm    *hsm.HSMService
}

func NewNotaryService(client *gateway_sdk.GatewayClient, hsm *hsm.HSMService) *NotaryService {
	return &NotaryService{client: client, hsm: hsm}
}

func (n *NotaryService) Notarize(thesisID string, hash string, signature string) error {
	// Utilisation de votre GatewayClient générique pour appeler le Chaincode
	return n.client.ExecuteTransaction("NotarizeThesis", thesisID, hash, signature)
}
