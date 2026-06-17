// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MerkleAnchor
/// @notice Stores periodic Merkle roots of off-chain (Hyperledger Fabric)
///         thesis records, providing a tamper-evident external trust
///         anchor independent of the Fabric consortium's own peers.
///         This contract does NOT store any thesis data itself — only
///         the root hash, a timestamp, and the submitter's address.
contract MerkleAnchor {
    struct Anchor {
        bytes32 merkleRoot;
        uint256 timestamp;
        address submitter;
        string batchId; // identifies which reconciliation run produced this root
    }

    /// @dev sequential anchor index => Anchor record
    mapping(uint256 => Anchor) public anchors;
    uint256 public anchorCount;

    /// @dev quick lookup: has this exact root ever been anchored?
    mapping(bytes32 => bool) public rootExists;

    address public owner;

    event RootAnchored(
        uint256 indexed anchorIndex,
        bytes32 indexed merkleRoot,
        uint256 timestamp,
        address indexed submitter,
        string batchId
    );

    error NotOwner();
    error RootAlreadyAnchored();
    error EmptyRoot();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Anchor a new Merkle root computed off-chain from the
    ///         current set of Fabric ledger records.
    /// @param merkleRoot The Merkle root hash (32 bytes).
    /// @param batchId A free-form identifier for this reconciliation run
    ///        (e.g. "2026-06-17T00:00:00Z" or an incrementing run number),
    ///        useful for correlating on-chain anchors with off-chain logs.
    function anchorRoot(bytes32 merkleRoot, string calldata batchId) external onlyOwner {
        if (merkleRoot == bytes32(0)) revert EmptyRoot();
        if (rootExists[merkleRoot]) revert RootAlreadyAnchored();

        uint256 index = anchorCount;
        anchors[index] = Anchor({
            merkleRoot: merkleRoot,
            timestamp: block.timestamp,
            submitter: msg.sender,
            batchId: batchId
        });
        rootExists[merkleRoot] = true;
        anchorCount += 1;

        emit RootAnchored(index, merkleRoot, block.timestamp, msg.sender, batchId);
    }

    /// @notice Returns the most recently anchored root, or reverts if none exist.
    function latestAnchor() external view returns (Anchor memory) {
        require(anchorCount > 0, "no anchors yet");
        return anchors[anchorCount - 1];
    }

    /// @notice Verify that a given leaf hash is included in a previously
    ///         anchored Merkle root, using a standard Merkle proof.
    /// @param leaf The leaf hash being verified (e.g. hash of one thesis record).
    /// @param proof Array of sibling hashes from leaf to root.
    /// @param root The anchored root to verify against.
    function verifyInclusion(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) external pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        return computedHash == root;
    }
}
