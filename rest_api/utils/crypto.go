package utils // Declared as a utility package

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Centralized infrastructure constants using absolute paths
const (
	MspID         = "Org1MSP"
	ChannelName   = "mychannel"
	ChaincodeName = "jurychaincode"

	cryptoPath      = "/home/lika/project/Fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath        = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyPath         = cryptoPath + "/users/User1@org1.example.com/msp/keystore"
	tlsCertPath     = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint    = "127.0.0.1:7051"
	gatewayPeerName = "peer0.org1.example.com"
)

// NewGrpcConnection establishes a secure gRPC connection to the Fabric Gateway peer
func NewGrpcConnection() (*grpc.ClientConn, error) {
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

// NewIdentity creates an X509 identity using the user's certificate
func NewIdentity() (*identity.X509Identity, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return identity.NewX509Identity(MspID, cert)
}

// NewSign generates a digital signing function from the private key found in the keystore
func NewSign() (identity.Sign, error) {
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
