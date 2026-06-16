package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	// Local module import pointing to your generic gateway SDK
	"github.com/sergiorandria/go-rest-api/gateway_sdk"
)

const (
	mspID         = "Org1MSP"
	channelName   = "mychannel"
	chaincodeName = "jurychaincode"

	// Absolute cryptographic asset paths matching your local infrastructure
	cryptoPath      = "/home/lika/project/Fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath        = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem"
	keyPath         = cryptoPath + "/users/User1@org1.example.com/msp/keystore"
	tlsCertPath     = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint    = "127.0.0.1:7051"
	gatewayPeerName = "peer0.org1.example.com"
)

func main() {
	log.Println("Starting standalone execution test for GatewayClient...")

	// 1. Prepare asset payload parameters
	mockThesisID := "T124"

	// 2. Initialize the low-level TLS secure gRPC channel link
	clientConn, err := newGrpcConnection()
	if err != nil {
		log.Fatalf("gRPC connection initialization failed: %v", err)
	}
	defer clientConn.Close()

	// 3. Generate the required organizational identity structures
	id, err := newIdentity()
	if err != nil {
		log.Fatalf("Failed to establish target identity context: %v", err)
	}

	sign, err := newSign()
	if err != nil {
		log.Fatalf("Failed to instantiate signing keystore link: %v", err)
	}

	// 4. Construct your agnostic GatewayClient layer
	fabricClient, err := gateway_sdk.NewGatewayClient(clientConn, channelName, chaincodeName, id, sign)
	if err != nil {
		log.Fatalf("Initialization of custom GatewayClient failed: %v", err)
	}
	defer fabricClient.Close()

	// 5. Invoke the modular transaction mapping execution layer
	// Running 'CreateAsset' to match your current active asset-transfer-basic container image setup
	log.Printf("Invoking transaction dynamically for key [%s]...", mockThesisID)
	err = fabricClient.ExecuteTransaction(
		"CreateAsset",
		mockThesisID,       // Asset ID (param1)
		"Yellow",           // Color (param2)
		"18",               // Size (param3)
		"Lika",             // Owner (param4)
		"100",              // AppraisedValue (param5) -> Expected integer string
	)
	if err != nil {
		log.Fatalf("Ledger transaction submission failed: %v", err)
	}

	log.Println("Test execution complete: Transaction committed successfully to the ledger!")
}

// --- Cryptographic and Infrastructure Credential Parsers ---

func newGrpcConnection() (*grpc.ClientConn, error) {
	certPEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS CA certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("failed to append TLS CA certificate to pool")
	}

	transportCreds := credentials.NewClientTLSFromCert(certPool, gatewayPeerName)
	return grpc.NewClient(peerEndpoint, grpc.WithTransportCredentials(transportCreds))
}

func newIdentity() (*identity.X509Identity, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read user signing certificate: %w", err)
	}

	docCert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate structural properties: %w", err)
	}

	return identity.NewX509Identity(mspID, docCert)
}

func newSign() (identity.Sign, error) {
	files, err := os.ReadDir(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to scan keystore directory layout: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no valid private key found under target directory route %s", keyPath)
	}

	keyPEM, err := os.ReadFile(filepath.Join(keyPath, files[0].Name()))
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore asset file: %w", err)
	}

	privateKey, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA/RSA private key configurations: %w", err)
	}

	return identity.NewPrivateKeySign(privateKey)
}


// go mod tidy
// cd to the vHSM/rest_api directory
// run : go run -a ../tests/rest_api/test_gateway.go
