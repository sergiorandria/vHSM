// Package merkle builds a Merkle tree over thesis record hashes, using the
// same sorted-pair keccak256 convention as the on-chain MerkleAnchor
// contract's verifyInclusion function. Building the tree the same way on
// both sides is required — a proof generated here must be verifiable by
// the contract without any reordering or different hash function.
package merkle

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Leaf represents one thesis record's contribution to the tree. The Hash
// field should already be the record's content hash (e.g. keccak256 of
// docHash || grade || concatenated signatures) computed by the caller —
// this package only handles combining leaves into a tree, not deriving
// the leaf hash from raw record fields.
type Leaf struct {
	RecordID string // for logging/debugging only, not part of the hash
	Hash     [32]byte
}

// Tree holds all levels of a built Merkle tree, root at the top.
type Tree struct {
	Leaves [][32]byte
	Levels [][][32]byte // Levels[0] = leaves, Levels[len-1] = [root]
}

// Proof is the sibling path from a leaf to the root.
type Proof struct {
	Leaf    [32]byte
	Path    [][32]byte // sibling hashes, leaf to root order
}

func keccak256(data ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hashPair combines two node hashes using the same sorted-pair convention
// as the Solidity contract: the smaller hash (byte-wise) goes first. This
// makes the tree's hashing order-independent for any given pair, matching
// verifyInclusion's comparison logic exactly.
func hashPair(a, b [32]byte) [32]byte {
	if bytes.Compare(a[:], b[:]) <= 0 {
		return keccak256(a[:], b[:])
	}
	return keccak256(b[:], a[:])
}

// Build constructs a Merkle tree from the given leaves. If the number of
// nodes at any level is odd, the last node is paired with itself (a common,
// simple convention — duplicate-leaf padding). Returns an error if leaves
// is empty, since an empty tree has no meaningful root.
func Build(leaves []Leaf) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("cannot build merkle tree from zero leaves")
	}

	leafHashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		leafHashes[i] = l.Hash
	}

	tree := &Tree{
		Leaves: leafHashes,
		Levels: [][][32]byte{leafHashes},
	}

	current := leafHashes
	for len(current) > 1 {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, hashPair(current[i], current[i+1]))
			} else {
				// Odd one out: pair with itself rather than dropping it,
				// so every leaf is still represented in the root.
				next = append(next, hashPair(current[i], current[i]))
			}
		}
		tree.Levels = append(tree.Levels, next)
		current = next
	}

	return tree, nil
}

// Root returns the tree's root hash.
func (t *Tree) Root() [32]byte {
	top := t.Levels[len(t.Levels)-1]
	return top[0]
}

// ProofFor builds an inclusion proof for the leaf at the given index.
// The returned Proof.Path is ordered leaf-to-root, matching what the
// on-chain verifyInclusion function expects.
func (t *Tree) ProofFor(leafIndex int) (*Proof, error) {
	if leafIndex < 0 || leafIndex >= len(t.Leaves) {
		return nil, fmt.Errorf("leaf index %d out of range (have %d leaves)", leafIndex, len(t.Leaves))
	}

	path := make([][32]byte, 0)
	idx := leafIndex

	for level := 0; level < len(t.Levels)-1; level++ {
		levelNodes := t.Levels[level]
		var siblingIdx int
		if idx%2 == 0 {
			siblingIdx = idx + 1
		} else {
			siblingIdx = idx - 1
		}

		if siblingIdx < len(levelNodes) {
			path = append(path, levelNodes[siblingIdx])
		} else {
			// idx was the odd-one-out, paired with itself.
			path = append(path, levelNodes[idx])
		}

		idx = idx / 2
	}

	return &Proof{
		Leaf: t.Leaves[leafIndex],
		Path: path,
	}, nil
}

// Verify checks a proof against a given root, using the same hashing
// convention as Build/hashPair. This is a local sanity-check function —
// the actual security guarantee comes from the on-chain verifyInclusion
// call, but verifying here too is useful for catching mistakes before
// submitting anything on-chain.
func Verify(proof *Proof, root [32]byte) bool {
	computed := proof.Leaf
	for _, sibling := range proof.Path {
		computed = hashPair(computed, sibling)
	}
	return computed == root
}