package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sergiorandria/go-rest-api/gateway_sdk" 

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	mspID         = "Org1MSP"
	channelName   = "mychannel"
	chaincodeName = "jurychaincode"

	// CORRECTION : Utilisation de chemins absolus (/home/lika/...)
	cryptoPath      = "/home/lika/project/Fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath        = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem"
	keyPath         = cryptoPath + "/users/User1@org1.example.com/msp/keystore"
	tlsCertPath     = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint    = "127.0.0.1:7051"
	gatewayPeerName = "peer0.org1.example.com"
)

type ThesisMetadata struct {
	ThesisTitle string `json:"thesisTitle"`
	DefenseDate string `json:"DefenseDate"`
}

type ThesisPayload struct {
	ThesisID string         `json:"thesisId"`
	Grade    float64        `json:"grade"`
	Metadata ThesisMetadata `json:"metadata"`
}

func main() {
	fmt.Println("Starting Gateway Client Execution...")

	payload := ThesisPayload{
		ThesisID: "T123",
		Grade:    16.5,
		Metadata: ThesisMetadata{
			ThesisTitle: "Distributed Ledger Integrity Verification",
			DefenseDate: "2026-06-16",
		},
	}

	thesisID := payload.ThesisID
	gradeStr := fmt.Sprintf("%.1f", payload.Grade)

	metadataBytes, err := json.Marshal(payload.Metadata)
	if err != nil {
		fmt.Printf("failed to marshal metadata: %s\n", err)
		return
	}
	metadataJSONStr := string(metadataBytes)

	clientConn, err := newGrpcConnection()
	if err != nil {
		fmt.Printf("failed to create gRPC connection: %s\n", err)
		return
	}
	defer clientConn.Close()

	id, err := newIdentity()
	if err != nil {
		fmt.Printf("failed to create identity: %s\n", err)
		return
	}

	sign, err := newSign()
	if err != nil {
		fmt.Printf("failed to create signing function: %s\n", err)
		return
	}

	client, err := gateway_sdk.NewGatewayClient(clientConn, channelName, chaincodeName, id, sign)
	if err != nil {
		fmt.Printf("failed to initialize gateway client: %s\n", err)
		return
	}
	defer client.Close()

	fmt.Printf("Executing state-changing transaction via SDK wrapper for key [%s]...\n", thesisID)
	err = client.ExecuteTransaction("CreateThesisRecord", thesisID, metadataJSONStr, gradeStr)
	if err != nil {
		fmt.Printf("transaction execution failed: %s\n", err)
		return
	}

	fmt.Println("Transaction successfully committed to the ledger!")
}


// REMARQUE: Shouldn't those function be on a separated file or those are juste for the simulaion?

func newGrpcConnection() (*grpc.ClientConn, error) {
	certPEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS cert: %w", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("failed to add TLS cert to pool")
	}
	transportCreds := credentials.NewClientTLSFromCert(certPool, gatewayPeerName)
	return grpc.NewClient(peerEndpoint, grpc.WithTransportCredentials(transportCreds))
}

func newIdentity() (*identity.X509Identity, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return identity.NewX509Identity(mspID, cert)
}

func newSign() (identity.Sign, error) {
	files, err := os.ReadDir(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore directory: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no private key found in keystore directory %s", keyPath)
	}
	keyPEM, err := os.ReadFile(filepath.Join(keyPath, files[0].Name()))
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	privateKey, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return identity.NewPrivateKeySign(privateKey)
}