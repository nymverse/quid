//! Merkle tree implementation for Zero-Knowledge Proofs
//!
//! License: 0BSD

use crate::{ZKPResult, ZKPError};
use serde::{Deserialize, Serialize};
use sha3::{Sha3_256, Digest};
use std::collections::HashMap;

/// Merkle tree structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Tree ID
    pub id: String,
    /// Root hash
    pub root: Vec<u8>,
    /// Tree depth
    pub depth: u32,
    /// Number of leaves
    pub leaf_count: usize,
    /// Internal nodes (layer -> index -> hash)
    pub nodes: HashMap<u32, HashMap<usize, Vec<u8>>>,
    /// Leaf values
    pub leaves: Vec<Vec<u8>>,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Merkle proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Proof ID
    pub id: String,
    /// Leaf index
    pub leaf_index: usize,
    /// Leaf value
    pub leaf_value: Vec<u8>,
    /// Authentication path
    pub auth_path: Vec<MerkleNode>,
    /// Root hash
    pub root: Vec<u8>,
    /// Tree depth
    pub depth: u32,
}

/// Merkle tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    /// Node hash
    pub hash: Vec<u8>,
    /// Direction (Left or Right)
    pub direction: Direction,
    /// Layer in the tree
    pub layer: u32,
    /// Index in the layer
    pub index: usize,
}

/// Direction in authentication path
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Left,
    Right,
}

/// Merkle tree configuration
#[derive(Debug, Clone)]
pub struct MerkleTreeConfig {
    /// Hash function
    pub hash_function: HashFunction,
    /// Minimum tree depth
    pub min_depth: u32,
    /// Maximum tree depth
    pub max_depth: u32,
    /// Enable sparse tree optimization
    pub enable_sparse: bool,
}

/// Hash function types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFunction {
    Sha3_256,
    Blake3,
    Keccak256,
}

impl MerkleTree {
    /// Create new Merkle tree from leaves
    pub fn new(leaves: Vec<Vec<u8>>, config: MerkleTreeConfig) -> ZKPResult<Self> {
        if leaves.is_empty() {
            return Err(ZKPError::InvalidInput("Leaves cannot be empty".to_string()));
        }
        
        let leaf_count = leaves.len();
        let depth = Self::calculate_depth(leaf_count);
        
        if depth < config.min_depth || depth > config.max_depth {
            return Err(ZKPError::InvalidInput(
                format!("Tree depth {} not within bounds [{}, {}]", depth, config.min_depth, config.max_depth)
            ));
        }
        
        let mut tree = Self {
            id: uuid::Uuid::new_v4().to_string(),
            root: Vec::new(),
            depth,
            leaf_count,
            nodes: HashMap::new(),
            leaves: leaves.clone(),
            created_at: chrono::Utc::now(),
        };
        
        tree.build_tree(&config)?;
        Ok(tree)
    }
    
    /// Calculate required tree depth
    fn calculate_depth(leaf_count: usize) -> u32 {
        if leaf_count <= 1 {
            return 1;
        }
        
        let mut depth = 0;
        let mut size = 1;
        
        while size < leaf_count {
            size <<= 1;
            depth += 1;
        }
        
        depth
    }
    
    /// Build the Merkle tree
    fn build_tree(&mut self, config: &MerkleTreeConfig) -> ZKPResult<()> {
        let mut current_layer = self.leaves.clone();
        let mut layer_index = 0u32;
        
        // Store leaf layer
        let mut leaf_nodes = HashMap::new();
        for (i, leaf) in current_layer.iter().enumerate() {
            leaf_nodes.insert(i, Self::hash_data(leaf, config.hash_function)?);
        }
        self.nodes.insert(layer_index, leaf_nodes);
        
        // Build tree bottom-up
        while current_layer.len() > 1 {
            let next_layer = self.build_next_layer(&current_layer, config)?;
            layer_index += 1;
            
            let mut layer_nodes = HashMap::new();
            for (i, hash) in next_layer.iter().enumerate() {
                layer_nodes.insert(i, hash.clone());
            }
            self.nodes.insert(layer_index, layer_nodes);
            
            current_layer = next_layer;
        }
        
        self.root = current_layer[0].clone();
        Ok(())
    }
    
    /// Build next layer of the tree
    fn build_next_layer(&self, current_layer: &[Vec<u8>], config: &MerkleTreeConfig) -> ZKPResult<Vec<Vec<u8>>> {
        let mut next_layer = Vec::new();
        let mut i = 0;
        
        while i < current_layer.len() {
            let left = &current_layer[i];
            let right = if i + 1 < current_layer.len() {
                &current_layer[i + 1]
            } else {
                left // Duplicate last node if odd number of nodes
            };
            
            let combined_hash = Self::hash_pair(left, right, config.hash_function)?;
            next_layer.push(combined_hash);
            
            i += 2;
        }
        
        Ok(next_layer)
    }
    
    /// Hash a single data item
    fn hash_data(data: &[u8], hash_function: HashFunction) -> ZKPResult<Vec<u8>> {
        match hash_function {
            HashFunction::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            HashFunction::Blake3 => {
                // Simplified Blake3 using SHA3-256
                let mut hasher = Sha3_256::new();
                hasher.update(b"blake3:");
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            HashFunction::Keccak256 => {
                // Simplified Keccak256 using SHA3-256
                let mut hasher = Sha3_256::new();
                hasher.update(b"keccak256:");
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
        }
    }
    
    /// Hash a pair of values
    fn hash_pair(left: &[u8], right: &[u8], hash_function: HashFunction) -> ZKPResult<Vec<u8>> {
        match hash_function {
            HashFunction::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(left);
                hasher.update(right);
                Ok(hasher.finalize().to_vec())
            }
            HashFunction::Blake3 => {
                let mut hasher = Sha3_256::new();
                hasher.update(b"blake3:");
                hasher.update(left);
                hasher.update(right);
                Ok(hasher.finalize().to_vec())
            }
            HashFunction::Keccak256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(b"keccak256:");
                hasher.update(left);
                hasher.update(right);
                Ok(hasher.finalize().to_vec())
            }
        }
    }
    
    /// Generate Merkle proof for a leaf
    pub fn generate_proof(&self, leaf_index: usize, config: &MerkleTreeConfig) -> ZKPResult<MerkleProof> {
        if leaf_index >= self.leaf_count {
            return Err(ZKPError::InvalidInput(
                format!("Leaf index {} out of bounds", leaf_index)
            ));
        }
        
        let leaf_value = self.leaves[leaf_index].clone();
        let mut auth_path = Vec::new();
        let mut current_index = leaf_index;
        
        // Build authentication path
        for layer in 0..self.depth {
            let layer_nodes = self.nodes.get(&layer)
                .ok_or_else(|| ZKPError::MerkleTreeConstructionFailed(
                    format!("Layer {} not found", layer)
                ))?;
            
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            let direction = if current_index % 2 == 0 {
                Direction::Right
            } else {
                Direction::Left
            };
            
            let sibling_hash = if let Some(hash) = layer_nodes.get(&sibling_index) {
                hash.clone()
            } else {
                // If sibling doesn't exist, use current node hash
                layer_nodes.get(&current_index).unwrap().clone()
            };
            
            auth_path.push(MerkleNode {
                hash: sibling_hash,
                direction,
                layer,
                index: sibling_index,
            });
            
            current_index /= 2;
        }
        
        Ok(MerkleProof {
            id: uuid::Uuid::new_v4().to_string(),
            leaf_index,
            leaf_value,
            auth_path,
            root: self.root.clone(),
            depth: self.depth,
        })
    }
    
    /// Verify Merkle proof
    pub fn verify_proof(&self, proof: &MerkleProof, config: &MerkleTreeConfig) -> ZKPResult<bool> {
        if proof.root != self.root {
            return Ok(false);
        }
        
        if proof.depth != self.depth {
            return Ok(false);
        }
        
        if proof.leaf_index >= self.leaf_count {
            return Ok(false);
        }
        
        let mut current_hash = Self::hash_data(&proof.leaf_value, config.hash_function)?;
        let mut current_index = proof.leaf_index;
        
        // Verify authentication path
        for node in &proof.auth_path {
            let (left_hash, right_hash) = match node.direction {
                Direction::Left => (&node.hash, &current_hash),
                Direction::Right => (&current_hash, &node.hash),
            };
            
            current_hash = Self::hash_pair(left_hash, right_hash, config.hash_function)?;
            current_index /= 2;
        }
        
        Ok(current_hash == self.root)
    }
    
    /// Update leaf value
    pub fn update_leaf(&mut self, leaf_index: usize, new_value: Vec<u8>, config: &MerkleTreeConfig) -> ZKPResult<()> {
        if leaf_index >= self.leaf_count {
            return Err(ZKPError::InvalidInput(
                format!("Leaf index {} out of bounds", leaf_index)
            ));
        }
        
        // Update leaf value
        self.leaves[leaf_index] = new_value;
        
        // Rebuild tree
        self.build_tree(config)?;
        
        Ok(())
    }
    
    /// Add new leaf to the tree
    pub fn add_leaf(&mut self, value: Vec<u8>, config: &MerkleTreeConfig) -> ZKPResult<()> {
        self.leaves.push(value);
        self.leaf_count += 1;
        
        // Recalculate depth if necessary
        let new_depth = Self::calculate_depth(self.leaf_count);
        if new_depth > config.max_depth {
            return Err(ZKPError::InvalidInput(
                format!("New depth {} exceeds maximum {}", new_depth, config.max_depth)
            ));
        }
        
        self.depth = new_depth;
        
        // Rebuild tree
        self.build_tree(config)?;
        
        Ok(())
    }
    
    /// Get leaf value by index
    pub fn get_leaf(&self, index: usize) -> ZKPResult<&Vec<u8>> {
        self.leaves.get(index).ok_or_else(|| {
            ZKPError::InvalidInput(format!("Leaf index {} out of bounds", index))
        })
    }
    
    /// Get all leaf values
    pub fn get_all_leaves(&self) -> &[Vec<u8>] {
        &self.leaves
    }
    
    /// Get tree size (number of leaves)
    pub fn size(&self) -> usize {
        self.leaf_count
    }
    
    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }
    
    /// Get tree root hash
    pub fn get_root(&self) -> &[u8] {
        &self.root
    }
    
    /// Get tree depth
    pub fn get_depth(&self) -> u32 {
        self.depth
    }
    
    /// Calculate tree hash (commitment to entire tree)
    pub fn calculate_tree_hash(&self, config: &MerkleTreeConfig) -> ZKPResult<Vec<u8>> {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.root);
        hasher.update(&self.depth.to_le_bytes());
        hasher.update(&self.leaf_count.to_le_bytes());
        
        match config.hash_function {
            HashFunction::Sha3_256 => hasher.update(b"sha3_256"),
            HashFunction::Blake3 => hasher.update(b"blake3"),
            HashFunction::Keccak256 => hasher.update(b"keccak256"),
        }
        
        Ok(hasher.finalize().to_vec())
    }
}

impl Default for MerkleTreeConfig {
    fn default() -> Self {
        Self {
            hash_function: HashFunction::Sha3_256,
            min_depth: 1,
            max_depth: 32,
            enable_sparse: false,
        }
    }
}

impl MerkleProof {
    /// Verify proof against a root hash
    pub fn verify_against_root(&self, root: &[u8], config: &MerkleTreeConfig) -> ZKPResult<bool> {
        if self.root != root {
            return Ok(false);
        }
        
        let mut current_hash = MerkleTree::hash_data(&self.leaf_value, config.hash_function)?;
        
        // Verify authentication path
        for node in &self.auth_path {
            let (left_hash, right_hash) = match node.direction {
                Direction::Left => (&node.hash, &current_hash),
                Direction::Right => (&current_hash, &node.hash),
            };
            
            current_hash = MerkleTree::hash_pair(left_hash, right_hash, config.hash_function)?;
        }
        
        Ok(current_hash == root)
    }
    
    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        self.leaf_value.len() + 
        self.auth_path.iter().map(|node| node.hash.len()).sum::<usize>() +
        self.root.len()
    }
    
    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> ZKPResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| ZKPError::SerializationError(e.to_string()))
    }
    
    /// Deserialize proof from bytes
    pub fn from_bytes(data: &[u8]) -> ZKPResult<Self> {
        bincode::deserialize(data)
            .map_err(|e| ZKPError::DeserializationError(e.to_string()))
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::Left => write!(f, "Left"),
            Direction::Right => write!(f, "Right"),
        }
    }
}

impl std::fmt::Display for HashFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashFunction::Sha3_256 => write!(f, "SHA3-256"),
            HashFunction::Blake3 => write!(f, "BLAKE3"),
            HashFunction::Keccak256 => write!(f, "Keccak256"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_merkle_tree_creation() {
        let leaves = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
        ];
        
        let config = MerkleTreeConfig::default();
        let tree = MerkleTree::new(leaves.clone(), config).unwrap();
        
        assert_eq!(tree.leaf_count, 4);
        assert_eq!(tree.depth, 2);
        assert_eq!(tree.leaves, leaves);
        assert!(!tree.root.is_empty());
    }
    
    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaves = vec![vec![1, 2, 3]];
        let config = MerkleTreeConfig::default();
        let tree = MerkleTree::new(leaves, config).unwrap();
        
        assert_eq!(tree.leaf_count, 1);
        assert_eq!(tree.depth, 1);
    }
    
    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let leaves = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
        ];
        
        let config = MerkleTreeConfig::default();
        let tree = MerkleTree::new(leaves, config.clone()).unwrap();
        
        // Generate proof for leaf at index 1
        let proof = tree.generate_proof(1, &config).unwrap();
        assert_eq!(proof.leaf_index, 1);
        assert_eq!(proof.leaf_value, vec![4, 5, 6]);
        assert_eq!(proof.root, tree.root);
        assert_eq!(proof.depth, tree.depth);
        
        // Verify proof
        let is_valid = tree.verify_proof(&proof, &config).unwrap();
        assert!(is_valid);
        
        // Verify proof against root
        let is_valid = proof.verify_against_root(&tree.root, &config).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_merkle_tree_update() {
        let leaves = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
        ];
        
        let config = MerkleTreeConfig::default();
        let mut tree = MerkleTree::new(leaves, config.clone()).unwrap();
        let original_root = tree.root.clone();
        
        // Update leaf at index 1
        tree.update_leaf(1, vec![40, 50, 60], &config).unwrap();
        
        // Root should change
        assert_ne!(tree.root, original_root);
        assert_eq!(tree.leaves[1], vec![40, 50, 60]);
        
        // Generate and verify proof for updated leaf
        let proof = tree.generate_proof(1, &config).unwrap();
        let is_valid = tree.verify_proof(&proof, &config).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_merkle_tree_add_leaf() {
        let leaves = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
        ];
        
        let config = MerkleTreeConfig::default();
        let mut tree = MerkleTree::new(leaves, config.clone()).unwrap();
        let original_count = tree.leaf_count;
        
        // Add new leaf
        tree.add_leaf(vec![7, 8, 9], &config).unwrap();
        
        assert_eq!(tree.leaf_count, original_count + 1);
        assert_eq!(tree.leaves[2], vec![7, 8, 9]);
        
        // Generate and verify proof for new leaf
        let proof = tree.generate_proof(2, &config).unwrap();
        let is_valid = tree.verify_proof(&proof, &config).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_merkle_tree_different_hash_functions() {
        let leaves = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
        ];
        
        let config_sha3 = MerkleTreeConfig {
            hash_function: HashFunction::Sha3_256,
            ..Default::default()
        };
        
        let config_blake3 = MerkleTreeConfig {
            hash_function: HashFunction::Blake3,
            ..Default::default()
        };
        
        let tree_sha3 = MerkleTree::new(leaves.clone(), config_sha3).unwrap();
        let tree_blake3 = MerkleTree::new(leaves, config_blake3).unwrap();
        
        // Different hash functions should produce different roots
        assert_ne!(tree_sha3.root, tree_blake3.root);
    }
    
    #[test]
    fn test_merkle_proof_serialization() {
        let leaves = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
        ];
        
        let config = MerkleTreeConfig::default();
        let tree = MerkleTree::new(leaves, config.clone()).unwrap();
        let proof = tree.generate_proof(0, &config).unwrap();
        
        let serialized = proof.to_bytes().unwrap();
        let deserialized = MerkleProof::from_bytes(&serialized).unwrap();
        
        assert_eq!(proof.leaf_index, deserialized.leaf_index);
        assert_eq!(proof.leaf_value, deserialized.leaf_value);
        assert_eq!(proof.root, deserialized.root);
        assert_eq!(proof.depth, deserialized.depth);
    }
    
    #[test]
    fn test_merkle_tree_properties() {
        let leaves = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
        ];
        
        let config = MerkleTreeConfig::default();
        let tree = MerkleTree::new(leaves, config.clone()).unwrap();
        
        assert_eq!(tree.size(), 3);
        assert!(!tree.is_empty());
        assert_eq!(tree.get_depth(), 2);
        assert_eq!(tree.get_root(), &tree.root);
        assert_eq!(tree.get_leaf(1).unwrap(), &vec![4, 5, 6]);
        assert_eq!(tree.get_all_leaves().len(), 3);
        
        let tree_hash = tree.calculate_tree_hash(&config).unwrap();
        assert_eq!(tree_hash.len(), 32);
    }
    
    #[test]
    fn test_invalid_inputs() {
        let config = MerkleTreeConfig::default();
        
        // Empty leaves
        let result = MerkleTree::new(vec![], config.clone());
        assert!(result.is_err());
        
        // Depth bounds
        let config_restricted = MerkleTreeConfig {
            min_depth: 5,
            max_depth: 10,
            ..config
        };
        
        let result = MerkleTree::new(vec![vec![1, 2, 3]], config_restricted);
        assert!(result.is_err()); // Depth would be 1, less than min_depth 5
        
        // Invalid leaf index
        let tree = MerkleTree::new(vec![vec![1, 2, 3]], config.clone()).unwrap();
        let result = tree.generate_proof(10, &config);
        assert!(result.is_err());
        
        let result = tree.get_leaf(10);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_direction_display() {
        assert_eq!(Direction::Left.to_string(), "Left");
        assert_eq!(Direction::Right.to_string(), "Right");
    }
    
    #[test]
    fn test_hash_function_display() {
        assert_eq!(HashFunction::Sha3_256.to_string(), "SHA3-256");
        assert_eq!(HashFunction::Blake3.to_string(), "BLAKE3");
        assert_eq!(HashFunction::Keccak256.to_string(), "Keccak256");
    }
    
    #[test]
    fn test_proof_properties() {
        let leaves = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
        ];
        
        let config = MerkleTreeConfig::default();
        let tree = MerkleTree::new(leaves, config.clone()).unwrap();
        let proof = tree.generate_proof(0, &config).unwrap();
        
        assert!(proof.size() > 0);
        assert!(!proof.id.is_empty());
        
        // Test proof verification with wrong root
        let wrong_root = vec![0; 32];
        let is_valid = proof.verify_against_root(&wrong_root, &config).unwrap();
        assert!(!is_valid);
    }
}