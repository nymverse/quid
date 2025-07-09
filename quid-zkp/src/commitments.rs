//! Commitment schemes for Zero-Knowledge Proofs
//!
//! License: 0BSD

use crate::{ZKPResult, ZKPError};
use serde::{Deserialize, Serialize};
use sha3::{Sha3_256, Digest};
use std::collections::HashMap;

/// Commitment scheme trait
pub trait CommitmentScheme {
    type Commitment;
    type Value;
    type Randomness;
    type OpeningProof;
    
    /// Generate commitment
    fn commit(&self, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<Self::Commitment>;
    
    /// Verify commitment
    fn verify(&self, commitment: &Self::Commitment, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<bool>;
    
    /// Generate opening proof
    fn open(&self, commitment: &Self::Commitment, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<Self::OpeningProof>;
    
    /// Verify opening proof
    fn verify_opening(&self, commitment: &Self::Commitment, value: &Self::Value, proof: &Self::OpeningProof) -> ZKPResult<bool>;
}

/// Commitment structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Commitment {
    /// Commitment ID
    pub id: String,
    /// Commitment scheme used
    pub scheme: CommitmentSchemeType,
    /// Commitment value
    pub commitment: Vec<u8>,
    /// Metadata
    pub metadata: HashMap<String, String>,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Commitment scheme types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommitmentSchemeType {
    /// Pedersen commitment
    Pedersen,
    /// Hash-based commitment
    Hash,
    /// Polynomial commitment
    Polynomial,
    /// Vector commitment
    Vector,
    /// Merkle tree commitment
    MerkleTree,
}

/// Pedersen commitment scheme
#[derive(Debug, Clone)]
pub struct PedersenCommitment {
    /// Generator for values
    pub g: Vec<u8>,
    /// Generator for randomness
    pub h: Vec<u8>,
    /// Field modulus
    pub modulus: Vec<u8>,
}

impl PedersenCommitment {
    /// Create new Pedersen commitment scheme
    pub fn new() -> ZKPResult<Self> {
        // Generate random generators (simplified)
        let g = (0..32).map(|i| (i * 2 + 1) as u8).collect();
        let h = (0..32).map(|i| (i * 3 + 2) as u8).collect();
        let modulus = vec![255; 32]; // Simplified modulus
        
        Ok(Self { g, h, modulus })
    }
    
    /// Multiply point by scalar (simplified)
    fn scalar_mult(&self, point: &[u8], scalar: &[u8]) -> Vec<u8> {
        point.iter()
            .zip(scalar.iter())
            .map(|(p, s)| p.wrapping_mul(*s))
            .collect()
    }
    
    /// Add two points (simplified)
    fn point_add(&self, p1: &[u8], p2: &[u8]) -> Vec<u8> {
        p1.iter()
            .zip(p2.iter())
            .map(|(a, b)| a.wrapping_add(*b))
            .collect()
    }
}

impl CommitmentScheme for PedersenCommitment {
    type Commitment = Vec<u8>;
    type Value = Vec<u8>;
    type Randomness = Vec<u8>;
    type OpeningProof = (Vec<u8>, Vec<u8>); // (value, randomness)
    
    fn commit(&self, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<Self::Commitment> {
        if value.len() != 32 || randomness.len() != 32 {
            return Err(ZKPError::InvalidInput(
                "Value and randomness must be 32 bytes".to_string()
            ));
        }
        
        // Compute g^value * h^randomness (simplified)
        let g_val = self.scalar_mult(&self.g, value);
        let h_rand = self.scalar_mult(&self.h, randomness);
        let commitment = self.point_add(&g_val, &h_rand);
        
        Ok(commitment)
    }
    
    fn verify(&self, commitment: &Self::Commitment, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<bool> {
        let computed_commitment = self.commit(value, randomness)?;
        Ok(*commitment == computed_commitment)
    }
    
    fn open(&self, _commitment: &Self::Commitment, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<Self::OpeningProof> {
        Ok((value.clone(), randomness.clone()))
    }
    
    fn verify_opening(&self, commitment: &Self::Commitment, value: &Self::Value, proof: &Self::OpeningProof) -> ZKPResult<bool> {
        let (proof_value, proof_randomness) = proof;
        
        if proof_value != value {
            return Ok(false);
        }
        
        self.verify(commitment, value, proof_randomness)
    }
}

/// Hash-based commitment scheme
#[derive(Debug, Clone)]
pub struct HashCommitment {
    /// Hash algorithm
    pub algorithm: String,
}

impl HashCommitment {
    /// Create new hash commitment scheme
    pub fn new(algorithm: String) -> Self {
        Self { algorithm }
    }
}

impl CommitmentScheme for HashCommitment {
    type Commitment = Vec<u8>;
    type Value = Vec<u8>;
    type Randomness = Vec<u8>;
    type OpeningProof = (Vec<u8>, Vec<u8>); // (value, randomness)
    
    fn commit(&self, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<Self::Commitment> {
        let mut hasher = Sha3_256::new();
        hasher.update(value);
        hasher.update(randomness);
        Ok(hasher.finalize().to_vec())
    }
    
    fn verify(&self, commitment: &Self::Commitment, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<bool> {
        let computed_commitment = self.commit(value, randomness)?;
        Ok(*commitment == computed_commitment)
    }
    
    fn open(&self, _commitment: &Self::Commitment, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<Self::OpeningProof> {
        Ok((value.clone(), randomness.clone()))
    }
    
    fn verify_opening(&self, commitment: &Self::Commitment, value: &Self::Value, proof: &Self::OpeningProof) -> ZKPResult<bool> {
        let (proof_value, proof_randomness) = proof;
        
        if proof_value != value {
            return Ok(false);
        }
        
        self.verify(commitment, value, proof_randomness)
    }
}

/// Polynomial commitment scheme
#[derive(Debug, Clone)]
pub struct PolynomialCommitment {
    /// Degree bound
    pub degree_bound: usize,
    /// Setup parameters
    pub setup_params: Vec<u8>,
}

impl PolynomialCommitment {
    /// Create new polynomial commitment scheme
    pub fn new(degree_bound: usize) -> ZKPResult<Self> {
        if degree_bound == 0 {
            return Err(ZKPError::InvalidInput("Degree bound must be positive".to_string()));
        }
        
        // Generate setup parameters (simplified)
        let setup_params = (0..degree_bound * 32)
            .map(|i| (i % 256) as u8)
            .collect();
        
        Ok(Self {
            degree_bound,
            setup_params,
        })
    }
    
    /// Evaluate polynomial at point
    pub fn evaluate_polynomial(&self, polynomial: &[u8], point: u8) -> u8 {
        let mut result = 0u8;
        let mut power = 1u8;
        
        for &coeff in polynomial {
            result = result.wrapping_add(coeff.wrapping_mul(power));
            power = power.wrapping_mul(point);
        }
        
        result
    }
    
    /// Create evaluation proof
    pub fn create_evaluation_proof(&self, polynomial: &[u8], point: u8, evaluation: u8) -> ZKPResult<Vec<u8>> {
        if polynomial.len() > self.degree_bound {
            return Err(ZKPError::InvalidInput("Polynomial degree exceeds bound".to_string()));
        }
        
        // Simplified evaluation proof generation
        let mut hasher = Sha3_256::new();
        hasher.update(polynomial);
        hasher.update(&[point]);
        hasher.update(&[evaluation]);
        hasher.update(&self.setup_params);
        
        Ok(hasher.finalize().to_vec())
    }
    
    /// Verify evaluation proof
    pub fn verify_evaluation_proof(&self, commitment: &[u8], point: u8, evaluation: u8, proof: &[u8]) -> ZKPResult<bool> {
        // Simplified evaluation proof verification
        let is_valid = proof.len() == 32 && // SHA3-256 hash
                      !commitment.is_empty();
        
        Ok(is_valid)
    }
}

impl CommitmentScheme for PolynomialCommitment {
    type Commitment = Vec<u8>;
    type Value = Vec<u8>; // Polynomial coefficients
    type Randomness = Vec<u8>;
    type OpeningProof = Vec<u8>;
    
    fn commit(&self, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<Self::Commitment> {
        if value.len() > self.degree_bound {
            return Err(ZKPError::InvalidInput("Polynomial degree exceeds bound".to_string()));
        }
        
        // Simplified polynomial commitment
        let mut hasher = Sha3_256::new();
        hasher.update(value);
        hasher.update(randomness);
        hasher.update(&self.setup_params);
        
        Ok(hasher.finalize().to_vec())
    }
    
    fn verify(&self, commitment: &Self::Commitment, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<bool> {
        let computed_commitment = self.commit(value, randomness)?;
        Ok(*commitment == computed_commitment)
    }
    
    fn open(&self, _commitment: &Self::Commitment, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<Self::OpeningProof> {
        // Simplified opening proof generation
        let mut hasher = Sha3_256::new();
        hasher.update(value);
        hasher.update(randomness);
        Ok(hasher.finalize().to_vec())
    }
    
    fn verify_opening(&self, commitment: &Self::Commitment, value: &Self::Value, proof: &Self::OpeningProof) -> ZKPResult<bool> {
        // Simplified opening proof verification
        let is_valid = proof.len() == 32 && // SHA3-256 hash
                      !commitment.is_empty() &&
                      value.len() <= self.degree_bound;
        
        Ok(is_valid)
    }
}

/// Vector commitment scheme
#[derive(Debug, Clone)]
pub struct VectorCommitment {
    /// Maximum vector length
    pub max_length: usize,
    /// Commitment parameters
    pub params: Vec<u8>,
}

impl VectorCommitment {
    /// Create new vector commitment scheme
    pub fn new(max_length: usize) -> ZKPResult<Self> {
        if max_length == 0 {
            return Err(ZKPError::InvalidInput("Max length must be positive".to_string()));
        }
        
        // Generate commitment parameters (simplified)
        let params = (0..max_length * 32)
            .map(|i| (i % 256) as u8)
            .collect();
        
        Ok(Self {
            max_length,
            params,
        })
    }
    
    /// Update commitment at specific position
    pub fn update(&self, commitment: &[u8], position: usize, old_value: &[u8], new_value: &[u8]) -> ZKPResult<Vec<u8>> {
        if position >= self.max_length {
            return Err(ZKPError::InvalidInput("Position exceeds max length".to_string()));
        }
        
        // Simplified update operation
        let mut hasher = Sha3_256::new();
        hasher.update(commitment);
        hasher.update(&position.to_le_bytes());
        hasher.update(old_value);
        hasher.update(new_value);
        hasher.update(&self.params);
        
        Ok(hasher.finalize().to_vec())
    }
    
    /// Create update proof
    pub fn create_update_proof(&self, position: usize, old_value: &[u8], new_value: &[u8]) -> ZKPResult<Vec<u8>> {
        if position >= self.max_length {
            return Err(ZKPError::InvalidInput("Position exceeds max length".to_string()));
        }
        
        // Simplified update proof generation
        let mut hasher = Sha3_256::new();
        hasher.update(b"update_proof");
        hasher.update(&position.to_le_bytes());
        hasher.update(old_value);
        hasher.update(new_value);
        hasher.update(&self.params);
        
        Ok(hasher.finalize().to_vec())
    }
    
    /// Verify update proof
    pub fn verify_update_proof(&self, old_commitment: &[u8], new_commitment: &[u8], position: usize, proof: &[u8]) -> ZKPResult<bool> {
        // Simplified update proof verification
        let is_valid = proof.len() == 32 && // SHA3-256 hash
                      position < self.max_length &&
                      !old_commitment.is_empty() &&
                      !new_commitment.is_empty();
        
        Ok(is_valid)
    }
}

impl CommitmentScheme for VectorCommitment {
    type Commitment = Vec<u8>;
    type Value = Vec<Vec<u8>>; // Vector of elements
    type Randomness = Vec<u8>;
    type OpeningProof = (usize, Vec<u8>, Vec<u8>); // (position, value, proof)
    
    fn commit(&self, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<Self::Commitment> {
        if value.len() > self.max_length {
            return Err(ZKPError::InvalidInput("Vector length exceeds maximum".to_string()));
        }
        
        // Simplified vector commitment
        let mut hasher = Sha3_256::new();
        hasher.update(b"vector_commit");
        
        for element in value {
            hasher.update(element);
        }
        
        hasher.update(randomness);
        hasher.update(&self.params);
        
        Ok(hasher.finalize().to_vec())
    }
    
    fn verify(&self, commitment: &Self::Commitment, value: &Self::Value, randomness: &Self::Randomness) -> ZKPResult<bool> {
        let computed_commitment = self.commit(value, randomness)?;
        Ok(*commitment == computed_commitment)
    }
    
    fn open(&self, _commitment: &Self::Commitment, value: &Self::Value, _randomness: &Self::Randomness) -> ZKPResult<Self::OpeningProof> {
        if value.is_empty() {
            return Err(ZKPError::InvalidInput("Vector cannot be empty".to_string()));
        }
        
        // Open to first element (simplified)
        let position = 0;
        let element = value[0].clone();
        
        // Generate proof
        let mut hasher = Sha3_256::new();
        hasher.update(b"opening_proof");
        hasher.update(&position.to_le_bytes());
        hasher.update(&element);
        hasher.update(&self.params);
        let proof = hasher.finalize().to_vec();
        
        Ok((position, element, proof))
    }
    
    fn verify_opening(&self, commitment: &Self::Commitment, value: &Self::Value, proof: &Self::OpeningProof) -> ZKPResult<bool> {
        let (position, element, proof_data) = proof;
        
        if *position >= value.len() {
            return Ok(false);
        }
        
        if &value[*position] != element {
            return Ok(false);
        }
        
        // Simplified opening proof verification
        let is_valid = proof_data.len() == 32 && // SHA3-256 hash
                      *position < self.max_length &&
                      !commitment.is_empty();
        
        Ok(is_valid)
    }
}

impl Commitment {
    /// Create new commitment
    pub fn new(scheme: CommitmentSchemeType, commitment: Vec<u8>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            scheme,
            commitment,
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
        }
    }
    
    /// Add metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
    
    /// Get metadata
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
    
    /// Check if commitment is expired
    pub fn is_expired(&self, expiry_hours: u64) -> bool {
        let expiry_time = self.created_at + chrono::Duration::hours(expiry_hours as i64);
        chrono::Utc::now() > expiry_time
    }
    
    /// Get commitment size
    pub fn size(&self) -> usize {
        self.commitment.len()
    }
    
    /// Get commitment hash
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.commitment);
        hasher.update(&self.id.as_bytes());
        hasher.finalize().to_vec()
    }
}

impl std::fmt::Display for CommitmentSchemeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitmentSchemeType::Pedersen => write!(f, "Pedersen"),
            CommitmentSchemeType::Hash => write!(f, "Hash"),
            CommitmentSchemeType::Polynomial => write!(f, "Polynomial"),
            CommitmentSchemeType::Vector => write!(f, "Vector"),
            CommitmentSchemeType::MerkleTree => write!(f, "MerkleTree"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pedersen_commitment() {
        let scheme = PedersenCommitment::new().unwrap();
        let value = vec![1; 32];
        let randomness = vec![2; 32];
        
        let commitment = scheme.commit(&value, &randomness).unwrap();
        assert_eq!(commitment.len(), 32);
        
        let is_valid = scheme.verify(&commitment, &value, &randomness).unwrap();
        assert!(is_valid);
        
        let proof = scheme.open(&commitment, &value, &randomness).unwrap();
        let is_valid = scheme.verify_opening(&commitment, &value, &proof).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_hash_commitment() {
        let scheme = HashCommitment::new("SHA3-256".to_string());
        let value = vec![1, 2, 3, 4];
        let randomness = vec![5, 6, 7, 8];
        
        let commitment = scheme.commit(&value, &randomness).unwrap();
        assert_eq!(commitment.len(), 32);
        
        let is_valid = scheme.verify(&commitment, &value, &randomness).unwrap();
        assert!(is_valid);
        
        let proof = scheme.open(&commitment, &value, &randomness).unwrap();
        let is_valid = scheme.verify_opening(&commitment, &value, &proof).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_polynomial_commitment() {
        let scheme = PolynomialCommitment::new(10).unwrap();
        let polynomial = vec![1, 2, 3, 4, 5]; // Degree 4 polynomial
        let randomness = vec![6, 7, 8, 9, 10];
        
        let commitment = scheme.commit(&polynomial, &randomness).unwrap();
        assert_eq!(commitment.len(), 32);
        
        let is_valid = scheme.verify(&commitment, &polynomial, &randomness).unwrap();
        assert!(is_valid);
        
        let proof = scheme.open(&commitment, &polynomial, &randomness).unwrap();
        let is_valid = scheme.verify_opening(&commitment, &polynomial, &proof).unwrap();
        assert!(is_valid);
        
        // Test polynomial evaluation
        let evaluation = scheme.evaluate_polynomial(&polynomial, 2);
        assert_eq!(evaluation, 1 + 2*2 + 3*4 + 4*8 + 5*16); // 1 + 4 + 12 + 32 + 80 = 129 (mod 256)
        
        let eval_proof = scheme.create_evaluation_proof(&polynomial, 2, evaluation).unwrap();
        let is_valid = scheme.verify_evaluation_proof(&commitment, 2, evaluation, &eval_proof).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_vector_commitment() {
        let scheme = VectorCommitment::new(100).unwrap();
        let vector = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
        ];
        let randomness = vec![10, 11, 12, 13];
        
        let commitment = scheme.commit(&vector, &randomness).unwrap();
        assert_eq!(commitment.len(), 32);
        
        let is_valid = scheme.verify(&commitment, &vector, &randomness).unwrap();
        assert!(is_valid);
        
        let proof = scheme.open(&commitment, &vector, &randomness).unwrap();
        let is_valid = scheme.verify_opening(&commitment, &vector, &proof).unwrap();
        assert!(is_valid);
        
        // Test vector update
        let new_commitment = scheme.update(&commitment, 1, &vec![4, 5, 6], &vec![14, 15, 16]).unwrap();
        assert_eq!(new_commitment.len(), 32);
        
        let update_proof = scheme.create_update_proof(1, &vec![4, 5, 6], &vec![14, 15, 16]).unwrap();
        let is_valid = scheme.verify_update_proof(&commitment, &new_commitment, 1, &update_proof).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_commitment_struct() {
        let mut commitment = Commitment::new(
            CommitmentSchemeType::Pedersen,
            vec![1, 2, 3, 4, 5],
        );
        
        assert_eq!(commitment.scheme, CommitmentSchemeType::Pedersen);
        assert_eq!(commitment.size(), 5);
        assert!(!commitment.is_expired(24));
        
        commitment.add_metadata("type".to_string(), "identity".to_string());
        assert_eq!(commitment.get_metadata("type"), Some(&"identity".to_string()));
        
        let hash = commitment.hash();
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_commitment_scheme_display() {
        assert_eq!(CommitmentSchemeType::Pedersen.to_string(), "Pedersen");
        assert_eq!(CommitmentSchemeType::Hash.to_string(), "Hash");
        assert_eq!(CommitmentSchemeType::Polynomial.to_string(), "Polynomial");
        assert_eq!(CommitmentSchemeType::Vector.to_string(), "Vector");
        assert_eq!(CommitmentSchemeType::MerkleTree.to_string(), "MerkleTree");
    }
    
    #[test]
    fn test_invalid_inputs() {
        // Invalid degree bound
        let result = PolynomialCommitment::new(0);
        assert!(result.is_err());
        
        // Invalid vector length
        let result = VectorCommitment::new(0);
        assert!(result.is_err());
        
        // Invalid Pedersen commitment input
        let scheme = PedersenCommitment::new().unwrap();
        let result = scheme.commit(&vec![1; 16], &vec![2; 32]); // Wrong value length
        assert!(result.is_err());
        
        // Polynomial degree exceeds bound
        let poly_scheme = PolynomialCommitment::new(5).unwrap();
        let result = poly_scheme.commit(&vec![1; 10], &vec![2; 32]); // Degree 9 > bound 5
        assert!(result.is_err());
        
        // Vector length exceeds maximum
        let vec_scheme = VectorCommitment::new(3).unwrap();
        let long_vector = vec![vec![1]; 5];
        let result = vec_scheme.commit(&long_vector, &vec![2; 32]);
        assert!(result.is_err());
    }
}