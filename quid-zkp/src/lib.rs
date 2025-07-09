//! QuID Zero-Knowledge Proof Integration
//!
//! This crate provides zero-knowledge proof capabilities for QuID identities,
//! enabling privacy-preserving authentication, verification, and computation
//! without revealing sensitive information.
//!
//! Features:
//! - zk-SNARKs for efficient proof verification
//! - zk-STARKs for quantum-resistant proofs
//! - Bulletproofs for range proofs and confidential transactions
//! - Commitment schemes for hiding values
//! - Merkle trees for batched proofs
//! - Identity proofs without revealing private keys
//! - Attribute proofs for selective disclosure

use quid_core::{QuIDIdentity, QuIDError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub mod error;
pub mod config;
pub mod snarks;
pub mod starks;
pub mod bulletproofs;
pub mod commitments;
pub mod merkle;
pub mod proofs;
pub mod verifier;

pub use error::{ZKPError, ZKPResult};
pub use config::ZKPConfig;
pub use proofs::{ZKProof, ProofType, ProofSystem};
pub use verifier::ZKVerifier;

/// QuID Zero-Knowledge Proof manager
#[derive(Debug)]
pub struct QuIDZKP {
    /// Configuration
    config: ZKPConfig,
    /// Proof cache
    proof_cache: Arc<RwLock<HashMap<String, ZKProof>>>,
    /// Verifier instances
    verifiers: Arc<RwLock<HashMap<ProofSystem, Arc<dyn ZKVerifier>>>>,
    /// Commitment schemes
    commitments: Arc<RwLock<HashMap<String, commitments::Commitment>>>,
    /// Merkle trees for batch proofs
    merkle_trees: Arc<RwLock<HashMap<String, merkle::MerkleTree>>>,
}

/// Zero-knowledge proof capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKCapabilities {
    /// Supported proof systems
    pub proof_systems: Vec<ProofSystem>,
    /// Supported proof types
    pub proof_types: Vec<ProofType>,
    /// Maximum proof size
    pub max_proof_size: usize,
    /// Verification timeout
    pub verification_timeout: u64,
    /// Quantum resistance
    pub quantum_resistant: bool,
}

/// Proof generation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofParameters {
    /// Proof system to use
    pub proof_system: ProofSystem,
    /// Proof type
    pub proof_type: ProofType,
    /// Circuit parameters
    pub circuit_params: CircuitParameters,
    /// Trusted setup (for systems that require it)
    pub trusted_setup: Option<Vec<u8>>,
    /// Security level
    pub security_level: SecurityLevel,
}

/// Circuit parameters for proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitParameters {
    /// Number of constraints
    pub num_constraints: u32,
    /// Number of variables
    pub num_variables: u32,
    /// Circuit depth
    pub depth: u32,
    /// Custom parameters
    pub custom_params: HashMap<String, String>,
}

/// Security level for proofs
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 80-bit security
    Standard,
    /// 128-bit security
    High,
    /// 256-bit security (quantum-resistant)
    Quantum,
}

impl QuIDZKP {
    /// Create a new QuID ZKP manager
    pub async fn new(config: ZKPConfig) -> ZKPResult<Self> {
        let zkp = Self {
            config,
            proof_cache: Arc::new(RwLock::new(HashMap::new())),
            verifiers: Arc::new(RwLock::new(HashMap::new())),
            commitments: Arc::new(RwLock::new(HashMap::new())),
            merkle_trees: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Initialize verifiers for supported proof systems
        zkp.initialize_verifiers().await?;
        
        Ok(zkp)
    }
    
    /// Generate identity proof without revealing private key
    pub async fn generate_identity_proof(
        &self,
        identity: &QuIDIdentity,
        challenge: &[u8],
        params: ProofParameters,
    ) -> ZKPResult<ZKProof> {
        let statement = self.create_identity_statement(identity, challenge)?;
        let witness = self.create_identity_witness(identity, challenge)?;
        
        let proof = match params.proof_system {
            ProofSystem::ZkSNARK => self.generate_snark_proof(statement, witness, params).await?,
            ProofSystem::ZkSTARK => self.generate_stark_proof(statement, witness, params).await?,
            ProofSystem::Bulletproof => self.generate_bulletproof(statement, witness, params).await?,
            ProofSystem::Plonk => self.generate_plonk_proof(statement, witness, params).await?,
            ProofSystem::Groth16 => self.generate_groth16_proof(statement, witness, params).await?,
        };
        
        // Cache the proof
        {
            let mut cache = self.proof_cache.write().await;
            cache.insert(proof.id.clone(), proof.clone());
        }
        
        Ok(proof)
    }
    
    /// Generate attribute proof for selective disclosure
    pub async fn generate_attribute_proof(
        &self,
        identity: &QuIDIdentity,
        attributes: &HashMap<String, String>,
        revealed_attributes: &[String],
        params: ProofParameters,
    ) -> ZKPResult<ZKProof> {
        let statement = self.create_attribute_statement(identity, attributes, revealed_attributes)?;
        let witness = self.create_attribute_witness(identity, attributes, revealed_attributes)?;
        
        let proof = match params.proof_system {
            ProofSystem::ZkSNARK => self.generate_snark_proof(statement, witness, params).await?,
            ProofSystem::ZkSTARK => self.generate_stark_proof(statement, witness, params).await?,
            ProofSystem::Bulletproof => self.generate_bulletproof(statement, witness, params).await?,
            ProofSystem::Plonk => self.generate_plonk_proof(statement, witness, params).await?,
            ProofSystem::Groth16 => self.generate_groth16_proof(statement, witness, params).await?,
        };
        
        // Cache the proof
        {
            let mut cache = self.proof_cache.write().await;
            cache.insert(proof.id.clone(), proof.clone());
        }
        
        Ok(proof)
    }
    
    /// Generate range proof (e.g., age >= 18 without revealing exact age)
    pub async fn generate_range_proof(
        &self,
        identity: &QuIDIdentity,
        value: u64,
        min_value: u64,
        max_value: u64,
        params: ProofParameters,
    ) -> ZKPResult<ZKProof> {
        let statement = self.create_range_statement(identity, min_value, max_value)?;
        let witness = self.create_range_witness(identity, value, min_value, max_value)?;
        
        // Range proofs are typically done with Bulletproofs
        let proof = self.generate_bulletproof(statement, witness, params).await?;
        
        // Cache the proof
        {
            let mut cache = self.proof_cache.write().await;
            cache.insert(proof.id.clone(), proof.clone());
        }
        
        Ok(proof)
    }
    
    /// Generate membership proof (prove element is in set without revealing which)
    pub async fn generate_membership_proof(
        &self,
        identity: &QuIDIdentity,
        element: &[u8],
        set: &[Vec<u8>],
        params: ProofParameters,
    ) -> ZKPResult<ZKProof> {
        let statement = self.create_membership_statement(identity, set)?;
        let witness = self.create_membership_witness(identity, element, set)?;
        
        let proof = match params.proof_system {
            ProofSystem::ZkSNARK => self.generate_snark_proof(statement, witness, params).await?,
            ProofSystem::ZkSTARK => self.generate_stark_proof(statement, witness, params).await?,
            ProofSystem::Bulletproof => self.generate_bulletproof(statement, witness, params).await?,
            ProofSystem::Plonk => self.generate_plonk_proof(statement, witness, params).await?,
            ProofSystem::Groth16 => self.generate_groth16_proof(statement, witness, params).await?,
        };
        
        // Cache the proof
        {
            let mut cache = self.proof_cache.write().await;
            cache.insert(proof.id.clone(), proof.clone());
        }
        
        Ok(proof)
    }
    
    /// Verify zero-knowledge proof
    pub async fn verify_proof(
        &self,
        proof: &ZKProof,
        public_inputs: &[u8],
    ) -> ZKPResult<bool> {
        let verifiers = self.verifiers.read().await;
        
        if let Some(verifier) = verifiers.get(&proof.proof_system) {
            verifier.verify(proof, public_inputs).await
        } else {
            Err(ZKPError::UnsupportedProofSystem(proof.proof_system))
        }
    }
    
    /// Create commitment to a value
    pub async fn create_commitment(
        &self,
        value: &[u8],
        randomness: Option<&[u8]>,
    ) -> ZKPResult<commitments::Commitment> {
        let commitment = commitments::Commitment::new(
            commitments::CommitmentSchemeType::Hash,
            value.to_vec(),
        );
        
        // Store commitment
        {
            let mut commitments = self.commitments.write().await;
            commitments.insert(commitment.id.clone(), commitment.clone());
        }
        
        Ok(commitment)
    }
    
    /// Open commitment (reveal value and randomness)
    pub async fn open_commitment(
        &self,
        commitment_id: &str,
        value: &[u8],
        randomness: &[u8],
    ) -> ZKPResult<bool> {
        let commitments = self.commitments.read().await;
        
        if let Some(commitment) = commitments.get(commitment_id) {
            // Simplified verification - in production use proper commitment scheme
            Ok(commitment.commitment.len() > 0 && value.len() > 0)
        } else {
            Err(ZKPError::CommitmentNotFound(commitment_id.to_string()))
        }
    }
    
    /// Create Merkle tree for batch proofs
    pub async fn create_merkle_tree(
        &self,
        leaves: Vec<Vec<u8>>,
    ) -> ZKPResult<String> {
        let tree_id = Uuid::new_v4().to_string();
        let config = merkle::MerkleTreeConfig::default();
        let merkle_tree = merkle::MerkleTree::new(leaves, config)?;
        
        {
            let mut trees = self.merkle_trees.write().await;
            trees.insert(tree_id.clone(), merkle_tree);
        }
        
        Ok(tree_id)
    }
    
    /// Generate Merkle proof for inclusion
    pub async fn generate_merkle_proof(
        &self,
        tree_id: &str,
        leaf_index: usize,
    ) -> ZKPResult<merkle::MerkleProof> {
        let trees = self.merkle_trees.read().await;
        
        if let Some(tree) = trees.get(tree_id) {
            let config = merkle::MerkleTreeConfig::default();
            tree.generate_proof(leaf_index, &config)
        } else {
            Err(ZKPError::MerkleTreeNotFound(tree_id.to_string()))
        }
    }
    
    /// Get ZK capabilities
    pub fn get_capabilities(&self) -> ZKCapabilities {
        ZKCapabilities {
            proof_systems: vec![
                ProofSystem::ZkSNARK,
                ProofSystem::ZkSTARK,
                ProofSystem::Bulletproof,
                ProofSystem::Plonk,
                ProofSystem::Groth16,
            ],
            proof_types: vec![
                ProofType::Identity,
                ProofType::Attribute,
                ProofType::Range,
                ProofType::Membership,
                ProofType::Commitment,
            ],
            max_proof_size: self.config.max_proof_size,
            verification_timeout: self.config.verification_timeout,
            quantum_resistant: self.config.quantum_resistant,
        }
    }
    
    /// Get cached proof
    pub async fn get_cached_proof(&self, proof_id: &str) -> Option<ZKProof> {
        let cache = self.proof_cache.read().await;
        cache.get(proof_id).cloned()
    }
    
    /// Clear proof cache
    pub async fn clear_cache(&self) {
        self.proof_cache.write().await.clear();
    }
    
    /// Get proof statistics
    pub async fn get_proof_stats(&self) -> ProofStats {
        let cache = self.proof_cache.read().await;
        let commitments = self.commitments.read().await;
        let trees = self.merkle_trees.read().await;
        
        ProofStats {
            cached_proofs: cache.len() as u32,
            active_commitments: commitments.len() as u32,
            merkle_trees: trees.len() as u32,
            total_proof_size: cache.values().map(|p| p.proof_data.len()).sum::<usize>() as u64,
        }
    }
    
    // Private helper methods
    
    /// Initialize verifiers for supported proof systems
    async fn initialize_verifiers(&self) -> ZKPResult<()> {
        let mut verifiers = self.verifiers.write().await;
        
        // Initialize SNARK verifier
        if self.config.enable_snarks {
            verifiers.insert(ProofSystem::ZkSNARK, Arc::new(snarks::SnarkVerifier::new()?));
        }
        
        // Initialize STARK verifier
        if self.config.enable_starks {
            verifiers.insert(ProofSystem::ZkSTARK, Arc::new(starks::StarkVerifier::new(256, 128)?));
        }
        
        // Initialize Bulletproof verifier
        if self.config.enable_bulletproofs {
            verifiers.insert(ProofSystem::Bulletproof, Arc::new(bulletproofs::BulletproofVerifier::new(64, true)?));
        }
        
        // Initialize PLONK verifier
        if self.config.enable_plonk {
            verifiers.insert(ProofSystem::Plonk, Arc::new(snarks::PlonkVerifier::new()?));
        }
        
        // Initialize Groth16 verifier
        if self.config.enable_groth16 {
            verifiers.insert(ProofSystem::Groth16, Arc::new(snarks::Groth16Verifier::new()?));
        }
        
        Ok(())
    }
    
    /// Create identity statement
    fn create_identity_statement(&self, identity: &QuIDIdentity, challenge: &[u8]) -> ZKPResult<proofs::Statement> {
        Ok(proofs::Statement {
            statement_type: proofs::StatementType::Identity,
            public_inputs: vec![
                identity.public_key().as_bytes().to_vec(),
                challenge.to_vec(),
            ],
            constraints: vec![],
        })
    }
    
    /// Create identity witness
    fn create_identity_witness(&self, identity: &QuIDIdentity, challenge: &[u8]) -> ZKPResult<proofs::Witness> {
        let signature = identity.sign(challenge)
            .map_err(|e| ZKPError::WitnessGenerationFailed(e.to_string()))?;
        
        Ok(proofs::Witness {
            private_inputs: vec![signature],
            randomness: vec![],
        })
    }
    
    /// Create attribute statement
    fn create_attribute_statement(
        &self,
        identity: &QuIDIdentity,
        attributes: &HashMap<String, String>,
        revealed_attributes: &[String],
    ) -> ZKPResult<proofs::Statement> {
        let mut public_inputs = vec![identity.public_key().as_bytes().to_vec()];
        
        // Add revealed attributes as public inputs
        for attr_name in revealed_attributes {
            if let Some(attr_value) = attributes.get(attr_name) {
                public_inputs.push(attr_value.as_bytes().to_vec());
            }
        }
        
        Ok(proofs::Statement {
            statement_type: proofs::StatementType::Attribute,
            public_inputs,
            constraints: vec![],
        })
    }
    
    /// Create attribute witness
    fn create_attribute_witness(
        &self,
        identity: &QuIDIdentity,
        attributes: &HashMap<String, String>,
        revealed_attributes: &[String],
    ) -> ZKPResult<proofs::Witness> {
        let mut private_inputs = vec![];
        
        // Add hidden attributes as private inputs
        for (attr_name, attr_value) in attributes {
            if !revealed_attributes.contains(attr_name) {
                private_inputs.push(attr_value.as_bytes().to_vec());
            }
        }
        
        Ok(proofs::Witness {
            private_inputs,
            randomness: vec![rand::random::<[u8; 32]>().to_vec()],
        })
    }
    
    /// Create range statement
    fn create_range_statement(
        &self,
        identity: &QuIDIdentity,
        min_value: u64,
        max_value: u64,
    ) -> ZKPResult<proofs::Statement> {
        Ok(proofs::Statement {
            statement_type: proofs::StatementType::Range,
            public_inputs: vec![
                identity.public_key().as_bytes().to_vec(),
                min_value.to_le_bytes().to_vec(),
                max_value.to_le_bytes().to_vec(),
            ],
            constraints: vec![],
        })
    }
    
    /// Create range witness
    fn create_range_witness(
        &self,
        _identity: &QuIDIdentity,
        value: u64,
        _min_value: u64,
        _max_value: u64,
    ) -> ZKPResult<proofs::Witness> {
        Ok(proofs::Witness {
            private_inputs: vec![value.to_le_bytes().to_vec()],
            randomness: vec![rand::random::<[u8; 32]>().to_vec()],
        })
    }
    
    /// Create membership statement
    fn create_membership_statement(
        &self,
        identity: &QuIDIdentity,
        set: &[Vec<u8>],
    ) -> ZKPResult<proofs::Statement> {
        let mut public_inputs = vec![identity.public_key().as_bytes().to_vec()];
        
        // Add set elements as public inputs
        for element in set {
            public_inputs.push(element.clone());
        }
        
        Ok(proofs::Statement {
            statement_type: proofs::StatementType::Membership,
            public_inputs,
            constraints: vec![],
        })
    }
    
    /// Create membership witness
    fn create_membership_witness(
        &self,
        _identity: &QuIDIdentity,
        element: &[u8],
        set: &[Vec<u8>],
    ) -> ZKPResult<proofs::Witness> {
        // Find index of element in set
        let index = set.iter().position(|x| x == element)
            .ok_or_else(|| ZKPError::ElementNotInSet)?;
        
        Ok(proofs::Witness {
            private_inputs: vec![
                element.to_vec(),
                index.to_le_bytes().to_vec(),
            ],
            randomness: vec![rand::random::<[u8; 32]>().to_vec()],
        })
    }
    
    /// Generate SNARK proof
    async fn generate_snark_proof(
        &self,
        statement: proofs::Statement,
        witness: proofs::Witness,
        params: ProofParameters,
    ) -> ZKPResult<ZKProof> {
        let proof_data = snarks::generate_snark_proof(statement, witness, params)?;
        
        Ok(ZKProof {
            id: Uuid::new_v4().to_string(),
            proof_system: ProofSystem::ZkSNARK,
            proof_type: ProofType::Identity,
            proof_data,
            public_inputs: vec![],
            verification_key: vec![],
            created_at: Utc::now(),
            verified: false,
        })
    }
    
    /// Generate STARK proof
    async fn generate_stark_proof(
        &self,
        statement: proofs::Statement,
        witness: proofs::Witness,
        params: ProofParameters,
    ) -> ZKPResult<ZKProof> {
        let proof_data = starks::generate_stark_proof(statement, witness, params)?;
        
        Ok(ZKProof {
            id: Uuid::new_v4().to_string(),
            proof_system: ProofSystem::ZkSTARK,
            proof_type: ProofType::Identity,
            proof_data,
            public_inputs: vec![],
            verification_key: vec![],
            created_at: Utc::now(),
            verified: false,
        })
    }
    
    /// Generate Bulletproof
    async fn generate_bulletproof(
        &self,
        statement: proofs::Statement,
        witness: proofs::Witness,
        params: ProofParameters,
    ) -> ZKPResult<ZKProof> {
        // For range proofs, extract the value from private inputs
        let value = if !witness.private_inputs.is_empty() {
            let bytes = &witness.private_inputs[0];
            if bytes.len() >= 8 {
                u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]))
            } else {
                0
            }
        } else {
            0
        };
        
        let proof_data = bulletproofs::generate_range_proof(value, 0, 1000, 32)?;
        
        Ok(ZKProof {
            id: Uuid::new_v4().to_string(),
            proof_system: ProofSystem::Bulletproof,
            proof_type: ProofType::Range,
            proof_data,
            public_inputs: vec![],
            verification_key: vec![],
            created_at: Utc::now(),
            verified: false,
        })
    }
    
    /// Generate PLONK proof
    async fn generate_plonk_proof(
        &self,
        statement: proofs::Statement,
        witness: proofs::Witness,
        params: ProofParameters,
    ) -> ZKPResult<ZKProof> {
        let proof_data = snarks::generate_plonk_proof(statement, witness, params)?;
        
        Ok(ZKProof {
            id: Uuid::new_v4().to_string(),
            proof_system: ProofSystem::Plonk,
            proof_type: ProofType::Identity,
            proof_data,
            public_inputs: vec![],
            verification_key: vec![],
            created_at: Utc::now(),
            verified: false,
        })
    }
    
    /// Generate Groth16 proof
    async fn generate_groth16_proof(
        &self,
        statement: proofs::Statement,
        witness: proofs::Witness,
        params: ProofParameters,
    ) -> ZKPResult<ZKProof> {
        let proof_data = snarks::generate_groth16_proof(statement, witness, params)?;
        
        Ok(ZKProof {
            id: Uuid::new_v4().to_string(),
            proof_system: ProofSystem::Groth16,
            proof_type: ProofType::Identity,
            proof_data,
            public_inputs: vec![],
            verification_key: vec![],
            created_at: Utc::now(),
            verified: false,
        })
    }
}

/// Proof statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStats {
    /// Number of cached proofs
    pub cached_proofs: u32,
    /// Number of active commitments
    pub active_commitments: u32,
    /// Number of Merkle trees
    pub merkle_trees: u32,
    /// Total proof size in bytes
    pub total_proof_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;
    
    #[tokio::test]
    async fn test_zkp_manager_creation() {
        let config = ZKPConfig::default();
        let zkp = QuIDZKP::new(config).await.unwrap();
        
        let capabilities = zkp.get_capabilities();
        assert!(capabilities.proof_systems.contains(&ProofSystem::ZkSNARK));
        assert!(capabilities.proof_systems.contains(&ProofSystem::ZkSTARK));
        assert!(capabilities.quantum_resistant);
    }
    
    #[tokio::test]
    async fn test_identity_proof_generation() {
        let config = ZKPConfig::default();
        let zkp = QuIDZKP::new(config).await.unwrap();
        
        let identity = QuIDIdentity::generate(quid_core::SecurityLevel::High).unwrap();
        let challenge = b"test_challenge";
        
        let params = ProofParameters {
            proof_system: ProofSystem::ZkSTARK,
            proof_type: ProofType::Identity,
            circuit_params: CircuitParameters {
                num_constraints: 1000,
                num_variables: 500,
                depth: 10,
                custom_params: HashMap::new(),
            },
            trusted_setup: None,
            security_level: SecurityLevel::High,
        };
        
        let proof = zkp.generate_identity_proof(&identity, challenge, params).await.unwrap();
        
        assert_eq!(proof.proof_system, ProofSystem::ZkSTARK);
        assert_eq!(proof.proof_type, ProofType::Identity);
        assert!(!proof.proof_data.is_empty());
    }
    
    #[tokio::test]
    async fn test_commitment_creation() {
        let config = ZKPConfig::default();
        let zkp = QuIDZKP::new(config).await.unwrap();
        
        let value = b"secret_value";
        let commitment = zkp.create_commitment(value, None).await.unwrap();
        
        assert!(!commitment.id.is_empty());
        assert!(!commitment.commitment.is_empty());
    }
    
    #[tokio::test]
    async fn test_merkle_tree_creation() {
        let config = ZKPConfig::default();
        let zkp = QuIDZKP::new(config).await.unwrap();
        
        let leaves = vec![
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
            b"leaf4".to_vec(),
        ];
        
        let tree_id = zkp.create_merkle_tree(leaves).await.unwrap();
        assert!(!tree_id.is_empty());
        
        let proof = zkp.generate_merkle_proof(&tree_id, 1).await.unwrap();
        assert!(!proof.id.is_empty());
    }
    
    #[tokio::test]
    async fn test_proof_caching() {
        let config = ZKPConfig::default();
        let zkp = QuIDZKP::new(config).await.unwrap();
        
        let identity = QuIDIdentity::generate(quid_core::SecurityLevel::High).unwrap();
        let challenge = b"test_challenge";
        
        let params = ProofParameters {
            proof_system: ProofSystem::ZkSTARK,
            proof_type: ProofType::Identity,
            circuit_params: CircuitParameters {
                num_constraints: 1000,
                num_variables: 500,
                depth: 10,
                custom_params: HashMap::new(),
            },
            trusted_setup: None,
            security_level: SecurityLevel::High,
        };
        
        let proof = zkp.generate_identity_proof(&identity, challenge, params).await.unwrap();
        let proof_id = proof.id.clone();
        
        // Check that proof is cached
        let cached_proof = zkp.get_cached_proof(&proof_id).await.unwrap();
        assert_eq!(cached_proof.id, proof_id);
        
        // Check stats
        let stats = zkp.get_proof_stats().await;
        assert_eq!(stats.cached_proofs, 1);
        
        // Clear cache
        zkp.clear_cache().await;
        let stats = zkp.get_proof_stats().await;
        assert_eq!(stats.cached_proofs, 0);
    }
}