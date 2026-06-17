package merkle

import (
	"testing"
)

func mustHash(b byte) [32]byte {
	var h [32]byte
	h[0] = b
	return h
}

func TestBuild_SingleLeaf(t *testing.T) {
	leaf := Leaf{RecordID: "T1", Hash: mustHash(0x01)}
	tree, err := Build([]Leaf{leaf})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With a single leaf, the root should equal the leaf itself (no pairing happens).
	if tree.Root() != leaf.Hash {
		t.Errorf("expected root to equal single leaf hash, got different value")
	}
}

func TestBuild_EmptyLeaves(t *testing.T) {
	_, err := Build(nil)
	if err == nil {
		t.Fatal("expected error for empty leaf set, got nil")
	}
}

func TestBuild_EvenLeaves_RootDeterministic(t *testing.T) {
	leaves := []Leaf{
		{RecordID: "T1", Hash: mustHash(0x01)},
		{RecordID: "T2", Hash: mustHash(0x02)},
		{RecordID: "T3", Hash: mustHash(0x03)},
		{RecordID: "T4", Hash: mustHash(0x04)},
	}

	tree1, err := Build(leaves)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Rebuilding from the same leaves must produce the same root —
	// this is the core determinism guarantee the whole anchoring scheme
	// depends on. If this ever fails, anchoring is unreliable.
	tree2, err := Build(leaves)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tree1.Root() != tree2.Root() {
		t.Errorf("root is not deterministic across identical builds")
	}
}

func TestBuild_OddLeaves_HandlesPadding(t *testing.T) {
	leaves := []Leaf{
		{RecordID: "T1", Hash: mustHash(0x01)},
		{RecordID: "T2", Hash: mustHash(0x02)},
		{RecordID: "T3", Hash: mustHash(0x03)},
	}

	tree, err := Build(leaves)
	if err != nil {
		t.Fatalf("unexpected error building odd-length tree: %v", err)
	}
	if len(tree.Levels[len(tree.Levels)-1]) != 1 {
		t.Errorf("expected exactly one root node, got %d", len(tree.Levels[len(tree.Levels)-1]))
	}
}

func TestProofFor_VerifiesAgainstRoot(t *testing.T) {
	leaves := []Leaf{
		{RecordID: "T1", Hash: mustHash(0x01)},
		{RecordID: "T2", Hash: mustHash(0x02)},
		{RecordID: "T3", Hash: mustHash(0x03)},
		{RecordID: "T4", Hash: mustHash(0x04)},
		{RecordID: "T5", Hash: mustHash(0x05)},
	}

	tree, err := Build(leaves)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	root := tree.Root()

	// Every leaf's proof must verify against the same root — this is the
	// property that matters when proving "this thesis record was included
	// in this specific anchored batch" months or years later.
	for i := range leaves {
		proof, err := tree.ProofFor(i)
		if err != nil {
			t.Fatalf("failed to build proof for leaf %d: %v", i, err)
		}
		if !Verify(proof, root) {
			t.Errorf("proof for leaf %d (%s) failed to verify against root", i, leaves[i].RecordID)
		}
	}
}

func TestProofFor_OutOfRangeIndex(t *testing.T) {
	leaves := []Leaf{{RecordID: "T1", Hash: mustHash(0x01)}}
	tree, err := Build(leaves)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := tree.ProofFor(5); err == nil {
		t.Error("expected error for out-of-range leaf index, got nil")
	}
	if _, err := tree.ProofFor(-1); err == nil {
		t.Error("expected error for negative leaf index, got nil")
	}
}

func TestVerify_TamperedLeafFailsVerification(t *testing.T) {
	leaves := []Leaf{
		{RecordID: "T1", Hash: mustHash(0x01)},
		{RecordID: "T2", Hash: mustHash(0x02)},
		{RecordID: "T3", Hash: mustHash(0x03)},
		{RecordID: "T4", Hash: mustHash(0x04)},
	}

	tree, err := Build(leaves)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	root := tree.Root()

	proof, err := tree.ProofFor(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Simulate tampering: swap in a different leaf hash than what was
	// actually committed. The proof must fail — this is the property
	// that makes the whole anchoring scheme meaningful as tamper evidence.
	proof.Leaf = mustHash(0xFF)

	if Verify(proof, root) {
		t.Error("tampered leaf incorrectly verified against root — proof should have failed")
	}
}

func TestHashPair_SortedConvention(t *testing.T) {
	a := mustHash(0x01)
	b := mustHash(0x02)

	// hashPair must be order-independent: hashPair(a, b) == hashPair(b, a),
	// matching the Solidity contract's sorted-pair comparison in
	// verifyInclusion. If this ever breaks, proofs built here will fail
	// to verify on-chain even though the underlying data is correct.
	if hashPair(a, b) != hashPair(b, a) {
		t.Error("hashPair is not order-independent — will mismatch on-chain verifyInclusion")
	}
}
