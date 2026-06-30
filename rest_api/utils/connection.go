package utils

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const defaultConfigPath = "/etc/vhsmd/default-fabric.conf"

type FabricConfig struct {
	MspID           string
	ChannelName     string
	ChaincodeName   string
	CertPath        string
	KeyPath         string
	TLSCertPath     string
	PeerEndpoint    string
	GatewayPeerName string
}

// LoadConfig reads the .conf file, falling back to env vars, then hardcoded defaults
func LoadConfig() (*FabricConfig, error) {
	raw, err := parseConfFile(defaultConfigPath)
	if err != nil {
		// conf file missing is non-fatal — fall through to env/defaults
		raw = map[string]string{}
	}

	get := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v // env var wins over conf file
		}
		if v, ok := raw[key]; ok && v != "" {
			return v
		}
		return fallback
	}

	cryptoPath := get("CRYPTO_PATH", "/etc/vhsmd/crypto")

	cfg := &FabricConfig{
		MspID:           get("MSP_ID", "Org1MSP"),
		ChannelName:     get("CHANNEL_NAME", "mychannel"),
		ChaincodeName:   get("CHAINCODE_NAME", "jurychaincode"),
		CertPath:        get("CERT_PATH", filepath.Join(cryptoPath, "users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem")),
		KeyPath:         get("KEY_PATH", filepath.Join(cryptoPath, "users/User1@org1.example.com/msp/keystore")),
		TLSCertPath:     get("TLS_CERT_PATH", filepath.Join(cryptoPath, "peers/peer0.org1.example.com/tls/ca.crt")),
		PeerEndpoint:    get("PEER_ENDPOINT", "127.0.0.1:7051"),
		GatewayPeerName: get("GATEWAY_PEER_NAME", "peer0.org1.example.com"),
	}
	return cfg, nil
}

// parseConfFile reads KEY=VALUE lines, ignoring comments and blanks
func parseConfFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return result, scanner.Err()
}

func NewGrpcConnection(cfg *FabricConfig) (*grpc.ClientConn, error) {
	certPEM, err := os.ReadFile(cfg.TLSCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS cert: %w", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("failed to add TLS cert to pool")
	}
	transportCreds := credentials.NewClientTLSFromCert(certPool, cfg.GatewayPeerName)
	return grpc.NewClient(cfg.PeerEndpoint, grpc.WithTransportCredentials(transportCreds))
}

func NewIdentity(cfg *FabricConfig) (*identity.X509Identity, error) {
	certPEM, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return identity.NewX509Identity(cfg.MspID, cert)
}

func NewSign(cfg *FabricConfig) (identity.Sign, error) {
	files, err := os.ReadDir(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore directory: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no private key found in keystore: %s", cfg.KeyPath)
	}
	keyPEM, err := os.ReadFile(filepath.Join(cfg.KeyPath, files[0].Name()))
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	privateKey, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return identity.NewPrivateKeySign(privateKey)
}
