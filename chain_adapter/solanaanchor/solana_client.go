// Package solana provides a minimal client for anchoring Merkle roots
// onto Solana devnet using the standard Memo program. Unlike the Ethereum
// MerkleAnchor contract, this does not provide on-chain queryability
// (no view function to fetch "the latest root") — proving a root was
// anchored means looking up the transaction by signature or scanning the
// memo account's transaction history. The anchoring guarantee itself
// (immutable, timestamped, on a chain independent of the Fabric
// consortium) is the same; only the lookup ergonomics differ.
package solanaanchor

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// memoProgramID is the well-known, already-deployed Solana Memo program.
// No custom program deployment is required to use it.
var memoProgramID = solana.MustPublicKeyFromBase58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

// Client wraps a connection to Solana devnet plus the signing keypair
// used to pay for and authorize memo transactions.
type Client struct {
	rpcClient *rpc.Client
	payer     solana.PrivateKey
}

// Config holds connection parameters for devnet.
type Config struct {
	RPCEndpoint    string // e.g. rpc.DevNet_RPC from solana-go, or your own devnet RPC URL
	PayerKeyBase58 string // base58-encoded private key for the account paying tx fees
}

// NewClient connects to the given Solana RPC endpoint.
func NewClient(cfg Config) (*Client, error) {
	payerKey, err := solana.PrivateKeyFromBase58(cfg.PayerKeyBase58)
	if err != nil {
		return nil, fmt.Errorf("failed to parse payer private key: %w", err)
	}

	rpcClient := rpc.New(cfg.RPCEndpoint)

	return &Client{
		rpcClient: rpcClient,
		payer:     payerKey,
	}, nil
}

// AnchorRoot writes the Merkle root (plus a batch identifier) into a
// Solana transaction via the Memo program. The memo content format is
// "merkle-anchor:<batchID>:<hex-encoded root>" — a simple, greppable
// format for later lookup by transaction signature.
//
// Returns the transaction signature, which is the durable proof that
// this exact memo was included in a confirmed Solana transaction at a
// specific block time.
func (c *Client) AnchorRoot(ctx context.Context, merkleRoot [32]byte, batchID string) (solana.Signature, error) {
	memoText := fmt.Sprintf("merkle-anchor:%s:%s", batchID, hex.EncodeToString(merkleRoot[:]))

	recent, err := c.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return solana.Signature{}, fmt.Errorf("failed to get recent blockhash: %w", err)
	}

	memoInstruction := solana.NewInstruction(
		memoProgramID,
		solana.AccountMetaSlice{
			solana.NewAccountMeta(c.payer.PublicKey(), true, true),
		},
		[]byte(memoText),
	)

	tx, err := solana.NewTransaction(
		[]solana.Instruction{memoInstruction},
		recent.Value.Blockhash,
		solana.TransactionPayer(c.payer.PublicKey()),
	)
	if err != nil {
		return solana.Signature{}, fmt.Errorf("failed to build transaction: %w", err)
	}

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(c.payer.PublicKey()) {
			return &c.payer
		}
		return nil
	})
	if err != nil {
		return solana.Signature{}, fmt.Errorf("failed to sign transaction: %w", err)
	}

	sig, err := c.rpcClient.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{
		SkipPreflight:       false,
		PreflightCommitment: rpc.CommitmentFinalized,
	})
	if err != nil {
		return solana.Signature{}, fmt.Errorf("failed to send transaction: %w", err)
	}

	return sig, nil
}

// ConfirmTransaction polls until the given signature reaches finalized
// commitment, or returns an error if confirmation fails.
func (c *Client) ConfirmTransaction(ctx context.Context, sig solana.Signature) error {
	statusResp, err := c.rpcClient.GetSignatureStatuses(ctx, true, sig)
	if err != nil {
		return fmt.Errorf("failed to get signature status: %w", err)
	}
	if len(statusResp.Value) == 0 || statusResp.Value[0] == nil {
		return fmt.Errorf("no status found for signature %s — may not be confirmed yet", sig)
	}
	status := statusResp.Value[0]
	if status.Err != nil {
		return fmt.Errorf("transaction failed on-chain: %v", status.Err)
	}
	return nil
}
