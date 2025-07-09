//! Zero-knowledge proof types and structures

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::ZKPResult;

/// Zero-knowledge proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProof {
    /// Proof ID
    pub id: String,
    /// Proof system used
    pub proof_system: ProofSystem,
    /// Type of proof
    pub proof_type: ProofType,
    /// Proof data
    pub proof_data: Vec<u8>,
    /// Public inputs
    pub public_inputs: Vec<Vec<u8>>,
    /// Verification key
    pub verification_key: Vec<u8>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Verification status
    pub verified: bool,
}

/// Proof system enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofSystem {
    /// zk-SNARKs (Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge)
    ZkSNARK,
    /// zk-STARKs (Zero-Knowledge Scalable Transparent Arguments of Knowledge)
    ZkSTARK,
    /// Bulletproofs
    Bulletproof,
    /// PLONK (Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge)
    Plonk,
    /// Groth16
    Groth16,
}

/// Proof type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofType {
    /// Identity proof
    Identity,
    /// Attribute proof
    Attribute,
    /// Range proof
    Range,
    /// Membership proof
    Membership,
    /// Commitment proof
    Commitment,
    /// Signature proof
    Signature,
    /// Computation proof
    Computation,
    /// Privacy proof
    Privacy,
}

/// Statement for proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    /// Statement type
    pub statement_type: StatementType,
    /// Public inputs
    pub public_inputs: Vec<Vec<u8>>,
    /// Constraints
    pub constraints: Vec<Constraint>,
}

/// Statement type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum StatementType {
    /// Identity statement
    Identity,
    /// Attribute statement
    Attribute,
    /// Range statement
    Range,
    /// Membership statement
    Membership,
    /// Computation statement
    Computation,
}

/// Witness for proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    /// Private inputs
    pub private_inputs: Vec<Vec<u8>>,
    /// Randomness
    pub randomness: Vec<Vec<u8>>,
}

/// Constraint for circuit definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    /// Constraint type
    pub constraint_type: ConstraintType,
    /// Left input
    pub left: Variable,
    /// Right input
    pub right: Variable,
    /// Output
    pub output: Variable,
}

/// Constraint type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ConstraintType {
    /// Addition constraint
    Add,
    /// Multiplication constraint
    Mul,
    /// Equality constraint
    Eq,
    /// Boolean constraint
    Bool,
    /// Range constraint
    Range,
}

/// Variable in a constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    /// Variable type
    pub var_type: VariableType,
    /// Variable index
    pub index: usize,
    /// Coefficient
    pub coefficient: Vec<u8>,
}

/// Variable type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum VariableType {
    /// Public input
    Public,
    /// Private input
    Private,
    /// Intermediate variable
    Intermediate,
    /// Output variable
    Output,
}

/// Proof verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Verification success
    pub valid: bool,
    /// Error message if verification failed
    pub error: Option<String>,
    /// Verification time in milliseconds
    pub verification_time_ms: u64,
    /// Proof size in bytes
    pub proof_size: usize,
}

/// Proof generation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofGenerationParams {
    /// Security level
    pub security_level: u32,
    /// Enable optimizations
    pub enable_optimizations: bool,
    /// Maximum constraints
    pub max_constraints: u32,
    /// Timeout in seconds
    pub timeout_seconds: u64,
}

/// Proof batch for efficient verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBatch {
    /// Batch ID
    pub id: String,
    /// Proofs in the batch
    pub proofs: Vec<ZKProof>,
    /// Batch proof (aggregated)
    pub batch_proof: Option<Vec<u8>>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

impl ZKProof {
    /// Create a new proof
    pub fn new(
        proof_system: ProofSystem,
        proof_type: ProofType,
        proof_data: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
        verification_key: Vec<u8>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            proof_system,
            proof_type,
            proof_data,
            public_inputs,
            verification_key,
            created_at: Utc::now(),
            verified: false,
        }
    }
    
    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        self.proof_data.len() + 
        self.public_inputs.iter().map(|input| input.len()).sum::<usize>() + 
        self.verification_key.len()
    }
    
    /// Check if proof is expired
    pub fn is_expired(&self, expiry_hours: u64) -> bool {
        let expiry_time = self.created_at + chrono::Duration::hours(expiry_hours as i64);
        Utc::now() > expiry_time
    }
    
    /// Get proof age in seconds
    pub fn age_seconds(&self) -> u64 {
        (Utc::now() - self.created_at).num_seconds() as u64
    }
    
    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> ZKPResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| crate::ZKPError::SerializationError(e.to_string()))
    }
    
    /// Deserialize proof from bytes
    pub fn from_bytes(data: &[u8]) -> ZKPResult<Self> {
        bincode::deserialize(data)
            .map_err(|e| crate::ZKPError::DeserializationError(e.to_string()))
    }
    
    /// Calculate proof hash
    pub fn hash(&self) -> Vec<u8> {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.proof_data);
        hasher.update(&self.verification_key);
        hasher.finalize().to_vec()
    }
}

impl Statement {
    /// Create a new statement
    pub fn new(statement_type: StatementType, public_inputs: Vec<Vec<u8>>) -> Self {
        Self {
            statement_type,
            public_inputs,
            constraints: Vec::new(),
        }
    }
    
    /// Add constraint to statement
    pub fn add_constraint(&mut self, constraint: Constraint) {
        self.constraints.push(constraint);
    }
    
    /// Get number of constraints
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }
    
    /// Get number of public inputs
    pub fn num_public_inputs(&self) -> usize {
        self.public_inputs.len()
    }
}

impl Witness {
    /// Create a new witness
    pub fn new(private_inputs: Vec<Vec<u8>>) -> Self {
        Self {
            private_inputs,
            randomness: Vec::new(),
        }
    }
    
    /// Add randomness to witness
    pub fn add_randomness(&mut self, randomness: Vec<u8>) {
        self.randomness.push(randomness);
    }
    
    /// Get number of private inputs
    pub fn num_private_inputs(&self) -> usize {
        self.private_inputs.len()
    }
}

impl Constraint {
    /// Create addition constraint
    pub fn add(left: Variable, right: Variable, output: Variable) -> Self {
        Self {
            constraint_type: ConstraintType::Add,
            left,
            right,
            output,
        }
    }
    
    /// Create multiplication constraint
    pub fn mul(left: Variable, right: Variable, output: Variable) -> Self {
        Self {
            constraint_type: ConstraintType::Mul,
            left,
            right,
            output,
        }
    }
    
    /// Create equality constraint
    pub fn eq(left: Variable, right: Variable, output: Variable) -> Self {
        Self {
            constraint_type: ConstraintType::Eq,
            left,
            right,
            output,
        }
    }
    
    /// Create boolean constraint
    pub fn bool(var: Variable) -> Self {
        Self {
            constraint_type: ConstraintType::Bool,
            left: var.clone(),
            right: var.clone(),
            output: var,
        }
    }
    
    /// Create range constraint
    pub fn range(var: Variable, min: Variable, max: Variable) -> Self {
        Self {
            constraint_type: ConstraintType::Range,
            left: var,
            right: min,
            output: max,
        }
    }
}

impl Variable {
    /// Create public variable
    pub fn public(index: usize) -> Self {
        Self {
            var_type: VariableType::Public,
            index,
            coefficient: vec![1], // Default coefficient of 1
        }
    }
    
    /// Create private variable
    pub fn private(index: usize) -> Self {
        Self {
            var_type: VariableType::Private,
            index,
            coefficient: vec![1],
        }
    }
    
    /// Create intermediate variable
    pub fn intermediate(index: usize) -> Self {
        Self {
            var_type: VariableType::Intermediate,
            index,
            coefficient: vec![1],
        }
    }
    
    /// Create output variable
    pub fn output(index: usize) -> Self {
        Self {
            var_type: VariableType::Output,
            index,
            coefficient: vec![1],
        }
    }
    
    /// Set coefficient
    pub fn with_coefficient(mut self, coefficient: Vec<u8>) -> Self {
        self.coefficient = coefficient;
        self
    }
}

impl ProofBatch {
    /// Create a new proof batch
    pub fn new(proofs: Vec<ZKProof>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            proofs,
            batch_proof: None,
            created_at: Utc::now(),
        }
    }
    
    /// Add proof to batch
    pub fn add_proof(&mut self, proof: ZKProof) {
        self.proofs.push(proof);
    }
    
    /// Get batch size
    pub fn size(&self) -> usize {
        self.proofs.len()
    }
    
    /// Get total proof data size
    pub fn total_size(&self) -> usize {
        self.proofs.iter().map(|p| p.size()).sum::<usize>() +
        self.batch_proof.as_ref().map_or(0, |p| p.len())
    }
    
    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }
}

impl std::fmt::Display for ProofSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofSystem::ZkSNARK => write!(f, "zk-SNARK"),
            ProofSystem::ZkSTARK => write!(f, "zk-STARK"),
            ProofSystem::Bulletproof => write!(f, "Bulletproof"),
            ProofSystem::Plonk => write!(f, "PLONK"),
            ProofSystem::Groth16 => write!(f, "Groth16"),
        }
    }
}

impl std::fmt::Display for ProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofType::Identity => write!(f, "Identity"),
            ProofType::Attribute => write!(f, "Attribute"),
            ProofType::Range => write!(f, "Range"),
            ProofType::Membership => write!(f, "Membership"),
            ProofType::Commitment => write!(f, "Commitment"),
            ProofType::Signature => write!(f, "Signature"),
            ProofType::Computation => write!(f, "Computation"),
            ProofType::Privacy => write!(f, "Privacy"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proof_creation() {
        let proof = ZKProof::new(
            ProofSystem::ZkSTARK,
            ProofType::Identity,
            vec![1, 2, 3, 4],
            vec![vec![5, 6], vec![7, 8]],
            vec![9, 10, 11, 12],
        );
        
        assert_eq!(proof.proof_system, ProofSystem::ZkSTARK);
        assert_eq!(proof.proof_type, ProofType::Identity);
        assert_eq!(proof.proof_data, vec![1, 2, 3, 4]);
        assert_eq!(proof.public_inputs.len(), 2);
        assert!(!proof.verified);
        assert!(!proof.id.is_empty());
    }
    
    #[test]
    fn test_proof_serialization() {
        let proof = ZKProof::new(
            ProofSystem::ZkSNARK,
            ProofType::Range,
            vec![1, 2, 3],
            vec![vec![4, 5]],
            vec![6, 7, 8],
        );
        
        let serialized = proof.to_bytes().unwrap();
        let deserialized = ZKProof::from_bytes(&serialized).unwrap();
        
        assert_eq!(proof.proof_system, deserialized.proof_system);
        assert_eq!(proof.proof_type, deserialized.proof_type);
        assert_eq!(proof.proof_data, deserialized.proof_data);
    }
    
    #[test]
    fn test_statement_creation() {
        let mut statement = Statement::new(
            StatementType::Identity,
            vec![vec![1, 2, 3], vec![4, 5, 6]],
        );
        
        let constraint = Constraint::add(
            Variable::public(0),
            Variable::private(0),
            Variable::output(0),
        );
        
        statement.add_constraint(constraint);
        
        assert_eq!(statement.statement_type, StatementType::Identity);
        assert_eq!(statement.num_public_inputs(), 2);
        assert_eq!(statement.num_constraints(), 1);
    }
    
    #[test]
    fn test_witness_creation() {
        let mut witness = Witness::new(vec![vec![1, 2], vec![3, 4]]);
        witness.add_randomness(vec![5, 6, 7, 8]);
        
        assert_eq!(witness.num_private_inputs(), 2);
        assert_eq!(witness.randomness.len(), 1);
    }
    
    #[test]
    fn test_constraint_creation() {
        let add_constraint = Constraint::add(
            Variable::public(0),
            Variable::private(1),
            Variable::output(2),
        );
        
        assert_eq!(add_constraint.constraint_type, ConstraintType::Add);
        assert_eq!(add_constraint.left.var_type, VariableType::Public);
        assert_eq!(add_constraint.right.var_type, VariableType::Private);
        assert_eq!(add_constraint.output.var_type, VariableType::Output);
    }
    
    #[test]
    fn test_variable_creation() {
        let var = Variable::public(5).with_coefficient(vec![2, 3, 4]);
        
        assert_eq!(var.var_type, VariableType::Public);
        assert_eq!(var.index, 5);
        assert_eq!(var.coefficient, vec![2, 3, 4]);
    }
    
    #[test]
    fn test_proof_batch() {
        let proof1 = ZKProof::new(
            ProofSystem::ZkSNARK,
            ProofType::Identity,
            vec![1, 2],
            vec![],
            vec![3, 4],
        );
        
        let proof2 = ZKProof::new(
            ProofSystem::ZkSTARK,
            ProofType::Range,
            vec![5, 6],
            vec![],
            vec![7, 8],
        );
        
        let mut batch = ProofBatch::new(vec![proof1]);
        batch.add_proof(proof2);
        
        assert_eq!(batch.size(), 2);
        assert!(!batch.is_empty());
        assert!(batch.total_size() > 0);
    }
    
    #[test]
    fn test_proof_properties() {
        let proof = ZKProof::new(
            ProofSystem::Bulletproof,
            ProofType::Membership,
            vec![1, 2, 3, 4, 5],
            vec![vec![6, 7], vec![8, 9, 10]],
            vec![11, 12],
        );
        
        assert_eq!(proof.size(), 5 + 2 + 3 + 2); // proof_data + public_inputs + verification_key
        assert!(proof.age_seconds() < 1); // Just created
        assert!(!proof.is_expired(24)); // Not expired within 24 hours
        
        let hash = proof.hash();
        assert_eq!(hash.len(), 32); // SHA3-256 hash
    }
    
    #[test]
    fn test_display_formats() {
        assert_eq!(ProofSystem::ZkSNARK.to_string(), "zk-SNARK");
        assert_eq!(ProofSystem::ZkSTARK.to_string(), "zk-STARK");
        assert_eq!(ProofSystem::Bulletproof.to_string(), "Bulletproof");
        assert_eq!(ProofSystem::Plonk.to_string(), "PLONK");
        assert_eq!(ProofSystem::Groth16.to_string(), "Groth16");
        
        assert_eq!(ProofType::Identity.to_string(), "Identity");
        assert_eq!(ProofType::Range.to_string(), "Range");
        assert_eq!(ProofType::Membership.to_string(), "Membership");
    }
}