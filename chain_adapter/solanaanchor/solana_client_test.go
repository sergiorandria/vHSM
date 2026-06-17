//go:build integration

// Run with: go test -tags=integration ./solana/...
// Requires: SOLANA_DEVNET_PAYER_KEYFILE env var set to the path of a
// solana-keygen JSON file (e.g. devnet-test.json) for a funded devnet
// account. Generate one with:
//
//	solana-keygen new --outfile devnet-test.json
//	solana airdrop 2 --keypair devnet-test.json --url devnet
package solanaanchor

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestAnchorRoot_Devnet_Live(t *testing.T) {
	keyfile := os.Getenv("SOLANA_DEVNET_PAYER_KEYFILE")
	if keyfile == "" {
		t.Skip("SOLANA_DEVNET_PAYER_KEYFILE not set, skipping live devnet test")
	}

	client, err := NewClient(Config{
		RPCEndpoint:  "https://api.devnet.solana.com",
		PayerKeyfile: keyfile,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	var root [32]byte
	if _, err := rand.Read(root[:]); err != nil {
		t.Fatalf("failed to generate random test root: %v", err)
	}

	batchID := fmt.Sprintf("test-%d", time.Now().Unix())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sig, err := client.AnchorRoot(ctx, root, batchID)
	if err != nil {
		t.Fatalf("AnchorRoot failed: %v", err)
	}
	t.Logf("anchored, signature: %s — view at https://explorer.solana.com/tx/%s?cluster=devnet", sig, sig)

	// Devnet confirmation can take a few seconds; give it a moment before checking.
	time.Sleep(5 * time.Second)

	if err := client.ConfirmTransaction(ctx, sig); err != nil {
		t.Fatalf("transaction did not confirm successfully: %v", err)
	}
}

func TestAnchorRoot_Devnet_InvalidPayer(t *testing.T) {
	// An obviously malformed key should fail at NewClient, not panic.
	_, err := NewClient(Config{
		RPCEndpoint:    "https://api.devnet.solana.com",
		PayerKeyBase58: "not-a-valid-base58-key",
	})
	if err == nil {
		t.Fatal("expected error for invalid payer key, got nil")
	}
}

func TestNewClient_RejectsBothKeyOptions(t *testing.T) {
	_, err := NewClient(Config{
		RPCEndpoint:    "https://api.devnet.solana.com",
		PayerKeyfile:   "somefile.json",
		PayerKeyBase58: "somekey",
	})
	if err == nil {
		t.Fatal("expected error when both PayerKeyfile and PayerKeyBase58 are set, got nil")
	}
}

func TestNewClient_RejectsNeitherKeyOption(t *testing.T) {
	_, err := NewClient(Config{
		RPCEndpoint: "https://api.devnet.solana.com",
	})
	if err == nil {
		t.Fatal("expected error when neither PayerKeyfile nor PayerKeyBase58 is set, got nil")
	}
}
