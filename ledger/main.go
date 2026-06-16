package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	mspID         = "Org1MSP"
	channelName   = "mychannel"
	chaincodeName = "jurychaincode"

	// Adjust these to match your actual test-network crypto material layout.
	cryptoPath      = "../../test-network/organizations/peerOrganizations/org1.example.com"
	certPath        = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyPath         = cryptoPath + "/users/User1@org1.example.com/msp/keystore"
	tlsCertPath     = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint    = "localhost:7051"
	gatewayPeerName = "peer0.org1.example.com"
)

func main() {
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

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConn),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		fmt.Printf("failed to connect gateway: %s\n", err)
		return
	}
	defer gw.Close()

	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	// Evaluate: read-only query, no endorsement/ordering needed.
	result, err := contract.EvaluateTransaction("GetThesisRecord", "T123")
	if err != nil {
		fmt.Printf("failed to evaluate transaction: %s\n", err)
	} else {
		fmt.Printf("query result: %s\n", result)
	}

	// Submit: writes to the ledger, goes through endorsement + ordering.
	submitResult, err := contract.SubmitTransaction(
		"CreateThesisRecord",
		"T123",
		"docHashPlaceholder",
		"16.5",
	)
	if err != nil {
		fmt.Printf("failed to submit transaction: %s\n", err)
		return
	}
	fmt.Printf("submit result: %s\n", submitResult)
}

// newGrpcConnection creates a gRPC connection to the Gateway peer using TLS.
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

	connection, err := grpc.NewClient(peerEndpoint, grpc.WithTransportCredentials(transportCreds))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}
	return connection, nil
}

// newIdentity creates an X.509 identity from the org1 user's MSP cert.
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

// newSign creates a signing function using the org1 user's private key.
// This reads the key from the local filesystem MSP keystore. To route
// signing through SoftHSM/PKCS#11 instead, replace this with a Sign
// function backed by your HSM signer (see signHash in the REST API).
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

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing function: %w", err)
	}
	return sign, nil
}
