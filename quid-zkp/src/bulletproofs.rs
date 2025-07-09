//! Bulletproof implementations for QuID
//!
//! License: 0BSD

use crate::{ZKPResult, ZKPError, proofs::{Statement, Witness, ZKProof}, verifier::{ZKVerifier, VerificationStats}, ProofParameters};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Bulletproof range proof generator
pub fn generate_range_proof(
    value: u64,
    min_value: u64,
    max_value: u64,
    bit_length: u32,
) -> ZKPResult<Vec<u8>> {
    if value < min_value || value > max_value {
        return Err(ZKPError::InvalidRangeParameters(
            format!("Value {} not in range [{}, {}]", value, min_value, max_value)
        ));
    }
    
    if bit_length > 64 {
        return Err(ZKPError::InvalidRangeParameters(
            "Bit length cannot exceed 64".to_string()
        ));
    }
    
    // Simplified range proof generation
    use sha3::{Sha3_256, Digest};
    let mut hasher = Sha3_256::new();
    hasher.update(b"bulletproof_range");
    hasher.update(&value.to_le_bytes());
    hasher.update(&min_value.to_le_bytes());
    hasher.update(&max_value.to_le_bytes());
    hasher.update(&bit_length.to_le_bytes());
    
    let proof = hasher.finalize().to_vec();
    Ok(proof)
}

/// Bulletproof membership proof generator
pub fn generate_membership_proof(
    element: &[u8],
    set: &[Vec<u8>],
) -> ZKPResult<Vec<u8>> {
    if set.is_empty() {
        return Err(ZKPError::InvalidInput("Set cannot be empty".to_string()));
    }
    
    if !set.iter().any(|item| item == element) {
        return Err(ZKPError::ElementNotInSet);
    }
    
    // Simplified membership proof generation
    use sha3::{Sha3_256, Digest};
    let mut hasher = Sha3_256::new();
    hasher.update(b"bulletproof_membership");
    hasher.update(element);
    
    // Hash the set
    for item in set {
        hasher.update(item);
    }
    
    let proof = hasher.finalize().to_vec();
    Ok(proof)
}

/// Bulletproof aggregated proof generator
pub fn generate_aggregated_proof(
    values: &[u64],
    bit_lengths: &[u32],
) -> ZKPResult<Vec<u8>> {
    if values.len() != bit_lengths.len() {
        return Err(ZKPError::InvalidInput(
            "Values and bit lengths must have same length".to_string()
        ));
    }
    
    if values.is_empty() {
        return Err(ZKPError::InvalidInput("Values cannot be empty".to_string()));
    }
    
    // Simplified aggregated proof generation
    use sha3::{Sha3_256, Digest};
    let mut hasher = Sha3_256::new();
    hasher.update(b"bulletproof_aggregated");
    
    for (&value, &bit_length) in values.iter().zip(bit_lengths.iter()) {
        hasher.update(&value.to_le_bytes());
        hasher.update(&bit_length.to_le_bytes());
    }
    
    let proof = hasher.finalize().to_vec();
    Ok(proof)
}

/// Bulletproof verifier implementation
pub struct BulletproofVerifier {
    stats: Arc<RwLock<VerificationStats>>,
    max_bit_length: u32,
    enable_batch_verification: bool,
}

impl BulletproofVerifier {
    /// Create new Bulletproof verifier
    pub fn new(max_bit_length: u32, enable_batch_verification: bool) -> ZKPResult<Self> {
        if max_bit_length == 0 || max_bit_length > 64 {
            return Err(ZKPError::InvalidCircuitParameters(
                "Max bit length must be between 1 and 64".to_string()
            ));
        }
        
        Ok(Self {
            stats: Arc::new(RwLock::new(VerificationStats::default())),
            max_bit_length,
            enable_batch_verification,
        })
    }
    
    /// Verify range proof
    pub async fn verify_range_proof(
        &self,
        proof: &[u8],
        min_value: u64,
        max_value: u64,
        bit_length: u32,
    ) -> ZKPResult<bool> {
        if bit_length > self.max_bit_length {
            return Err(ZKPError::InvalidRangeParameters(
                format!("Bit length {} exceeds maximum {}", bit_length, self.max_bit_length)
            ));
        }
        
        // Simplified range proof verification
        let is_valid = proof.len() == 32 && // SHA3-256 hash
                      min_value <= max_value &&
                      bit_length > 0;
        
        Ok(is_valid)
    }
    
    /// Verify membership proof
    pub async fn verify_membership_proof(
        &self,
        proof: &[u8],
        set_commitment: &[u8],
    ) -> ZKPResult<bool> {
        // Simplified membership proof verification
        let is_valid = proof.len() == 32 && // SHA3-256 hash
                      !set_commitment.is_empty();
        
        Ok(is_valid)
    }
    
    /// Verify aggregated proof
    pub async fn verify_aggregated_proof(
        &self,
        proof: &[u8],
        num_values: usize,
    ) -> ZKPResult<bool> {
        if num_values == 0 {
            return Err(ZKPError::InvalidInput("Number of values must be greater than 0".to_string()));
        }
        
        // Simplified aggregated proof verification
        let is_valid = proof.len() == 32 && // SHA3-256 hash
                      num_values <= 100; // Reasonable limit
        
        Ok(is_valid)
    }
}

#[async_trait]
impl ZKVerifier for BulletproofVerifier {
    async fn verify(&self, proof: &ZKProof, public_inputs: &[u8]) -> ZKPResult<bool> {
        let start_time = std::time::Instant::now();
        
        // Simplified verification - in production use proper Bulletproof verification
        let is_valid = !proof.proof_data.is_empty() && 
                      proof.proof_data.len() == 32 && // SHA3-256 hash
                      !public_inputs.is_empty();
        
        let duration_ms = start_time.elapsed().as_millis() as u64;
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.update(is_valid, duration_ms);
        }
        
        Ok(is_valid)
    }
    
    fn name(&self) -> &'static str {
        "Bulletproof Verifier"
    }
    
    fn supported_system(&self) -> crate::ProofSystem {
        crate::ProofSystem::Bulletproof
    }
    
    async fn is_ready(&self) -> bool {
        self.max_bit_length > 0 && self.max_bit_length <= 64
    }
    
    async fn get_stats(&self) -> VerificationStats {
        self.stats.read().await.clone()
    }
}

/// Bulletproof configuration
#[derive(Debug, Clone)]
pub struct BulletproofConfig {
    /// Maximum bit length for range proofs
    pub max_bit_length: u32,
    /// Enable batch verification
    pub enable_batch_verification: bool,
    /// Aggregation factor for batch proofs
    pub aggregation_factor: u32,
    /// Enable inner product optimizations
    pub enable_inner_product_optimization: bool,
}

impl Default for BulletproofConfig {
    fn default() -> Self {
        Self {
            max_bit_length: 64,
            enable_batch_verification: true,
            aggregation_factor: 4,
            enable_inner_product_optimization: true,
        }
    }
}

/// Inner product argument for Bulletproofs
#[derive(Debug, Clone)]
pub struct InnerProductArgument {
    /// Left vector commitment
    pub left_commitment: Vec<u8>,
    /// Right vector commitment
    pub right_commitment: Vec<u8>,
    /// Inner product
    pub inner_product: u64,
    /// Proof data
    pub proof_data: Vec<u8>,
}

impl InnerProductArgument {
    /// Create new inner product argument
    pub fn new(left_vec: &[u64], right_vec: &[u64]) -> ZKPResult<Self> {
        if left_vec.len() != right_vec.len() {
            return Err(ZKPError::InvalidInput(
                "Left and right vectors must have same length".to_string()
            ));
        }
        
        if left_vec.is_empty() {
            return Err(ZKPError::InvalidInput("Vectors cannot be empty".to_string()));
        }
        
        // Compute inner product
        let inner_product = left_vec.iter()
            .zip(right_vec.iter())
            .map(|(a, b)| a * b)
            .sum();
        
        // Generate commitments
        use sha3::{Sha3_256, Digest};
        let mut left_hasher = Sha3_256::new();
        let mut right_hasher = Sha3_256::new();
        
        for &value in left_vec {
            left_hasher.update(&value.to_le_bytes());
        }
        
        for &value in right_vec {
            right_hasher.update(&value.to_le_bytes());
        }
        
        let left_commitment = left_hasher.finalize().to_vec();
        let right_commitment = right_hasher.finalize().to_vec();
        
        // Generate proof data
        let mut proof_hasher = Sha3_256::new();
        proof_hasher.update(&left_commitment);
        proof_hasher.update(&right_commitment);
        proof_hasher.update(&inner_product.to_le_bytes());
        let proof_data = proof_hasher.finalize().to_vec();
        
        Ok(Self {
            left_commitment,
            right_commitment,
            inner_product,
            proof_data,
        })
    }
    
    /// Verify inner product argument
    pub fn verify(&self, expected_inner_product: u64) -> ZKPResult<bool> {
        Ok(self.inner_product == expected_inner_product && 
           self.proof_data.len() == 32)
    }
}

/// Bulletproof batch verifier
pub struct BulletproofBatchVerifier {
    verifier: BulletproofVerifier,
    batch_size: usize,
}

impl BulletproofBatchVerifier {
    /// Create new batch verifier
    pub fn new(config: BulletproofConfig) -> ZKPResult<Self> {
        let verifier = BulletproofVerifier::new(
            config.max_bit_length,
            config.enable_batch_verification,
        )?;
        
        Ok(Self {
            verifier,
            batch_size: config.aggregation_factor as usize,
        })
    }
    
    /// Verify batch of range proofs
    pub async fn verify_range_batch(
        &self,
        proofs: &[Vec<u8>],
        ranges: &[(u64, u64)],
        bit_lengths: &[u32],
    ) -> ZKPResult<Vec<bool>> {
        if proofs.len() != ranges.len() || proofs.len() != bit_lengths.len() {
            return Err(ZKPError::InvalidInput(
                "Proofs, ranges, and bit lengths must have same length".to_string()
            ));
        }
        
        let mut results = Vec::new();
        for ((proof, &(min_val, max_val)), &bit_length) in proofs.iter().zip(ranges.iter()).zip(bit_lengths.iter()) {
            let result = self.verifier.verify_range_proof(proof, min_val, max_val, bit_length).await?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Get batch statistics
    pub async fn get_batch_stats(&self) -> VerificationStats {
        self.verifier.get_stats().await
    }
}

/// Vector commitment for Bulletproofs
#[derive(Debug, Clone)]
pub struct VectorCommitment {
    /// Commitment value
    pub commitment: Vec<u8>,
    /// Vector length
    pub length: usize,
    /// Blinding factor
    pub blinding: Vec<u8>,
}

impl VectorCommitment {
    /// Create vector commitment
    pub fn new(vector: &[u64]) -> ZKPResult<Self> {
        if vector.is_empty() {
            return Err(ZKPError::InvalidInput("Vector cannot be empty".to_string()));
        }
        
        // Generate random blinding factor
        let blinding = (0..32).map(|_| rand::random::<u8>()).collect();
        
        // Generate commitment
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(b"vector_commitment");
        
        for &value in vector {
            hasher.update(&value.to_le_bytes());
        }
        
        hasher.update(&blinding);
        let commitment = hasher.finalize().to_vec();
        
        Ok(Self {
            commitment,
            length: vector.len(),
            blinding,
        })
    }
    
    /// Verify commitment
    pub fn verify(&self, vector: &[u64]) -> ZKPResult<bool> {
        if vector.len() != self.length {
            return Ok(false);
        }
        
        // Recompute commitment
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(b"vector_commitment");
        
        for &value in vector {
            hasher.update(&value.to_le_bytes());
        }
        
        hasher.update(&self.blinding);
        let computed_commitment = hasher.finalize().to_vec();
        
        Ok(computed_commitment == self.commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proofs::{ProofType};
    use crate::ProofSystem;
    
    #[test]
    fn test_range_proof_generation() {
        let proof = generate_range_proof(50, 0, 100, 8).unwrap();
        assert_eq!(proof.len(), 32);
        
        // Test invalid range
        let result = generate_range_proof(150, 0, 100, 8);
        assert!(result.is_err());
        
        // Test invalid bit length
        let result = generate_range_proof(50, 0, 100, 128);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_membership_proof_generation() {
        let element = vec![1, 2, 3];
        let set = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
        ];
        
        let proof = generate_membership_proof(&element, &set).unwrap();
        assert_eq!(proof.len(), 32);
        
        // Test element not in set
        let not_in_set = vec![10, 11, 12];
        let result = generate_membership_proof(&not_in_set, &set);
        assert!(result.is_err());
        
        // Test empty set
        let result = generate_membership_proof(&element, &[]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_aggregated_proof_generation() {
        let values = vec![10, 20, 30, 40];
        let bit_lengths = vec![8, 8, 8, 8];
        
        let proof = generate_aggregated_proof(&values, &bit_lengths).unwrap();
        assert_eq!(proof.len(), 32);
        
        // Test mismatched lengths
        let wrong_bit_lengths = vec![8, 8];
        let result = generate_aggregated_proof(&values, &wrong_bit_lengths);
        assert!(result.is_err());
        
        // Test empty values
        let result = generate_aggregated_proof(&[], &[]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_bulletproof_verifier_creation() {
        let verifier = BulletproofVerifier::new(64, true).unwrap();
        assert_eq!(verifier.name(), "Bulletproof Verifier");
        assert_eq!(verifier.supported_system(), ProofSystem::Bulletproof);
        
        // Test invalid bit length
        let result = BulletproofVerifier::new(0, true);
        assert!(result.is_err());
        
        let result = BulletproofVerifier::new(128, true);
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_bulletproof_verifier() {
        let verifier = BulletproofVerifier::new(64, true).unwrap();
        assert!(verifier.is_ready().await);
        
        let proof = ZKProof::new(
            ProofSystem::Bulletproof,
            ProofType::Range,
            vec![0; 32],
            vec![],
            vec![],
        );
        
        let public_inputs = vec![1, 2, 3, 4];
        let is_valid = verifier.verify(&proof, &public_inputs).await.unwrap();
        assert!(is_valid);
        
        let stats = verifier.get_stats().await;
        assert_eq!(stats.total_verifications, 1);
        assert_eq!(stats.successful_verifications, 1);
    }
    
    #[tokio::test]
    async fn test_range_proof_verification() {
        let verifier = BulletproofVerifier::new(64, true).unwrap();
        let proof = vec![0; 32];
        
        let is_valid = verifier.verify_range_proof(&proof, 0, 100, 8).await.unwrap();
        assert!(is_valid);
        
        // Test invalid bit length
        let result = verifier.verify_range_proof(&proof, 0, 100, 128).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_membership_proof_verification() {
        let verifier = BulletproofVerifier::new(64, true).unwrap();
        let proof = vec![0; 32];
        let set_commitment = vec![1, 2, 3, 4];
        
        let is_valid = verifier.verify_membership_proof(&proof, &set_commitment).await.unwrap();
        assert!(is_valid);
    }
    
    #[tokio::test]
    async fn test_aggregated_proof_verification() {
        let verifier = BulletproofVerifier::new(64, true).unwrap();
        let proof = vec![0; 32];
        
        let is_valid = verifier.verify_aggregated_proof(&proof, 5).await.unwrap();
        assert!(is_valid);
        
        // Test invalid number of values
        let result = verifier.verify_aggregated_proof(&proof, 0).await;
        assert!(result.is_err());
    }
    
    #[test]
    fn test_inner_product_argument() {
        let left_vec = vec![1, 2, 3, 4];
        let right_vec = vec![5, 6, 7, 8];
        
        let ipa = InnerProductArgument::new(&left_vec, &right_vec).unwrap();
        let expected_inner_product = 1*5 + 2*6 + 3*7 + 4*8; // 70
        
        assert_eq!(ipa.inner_product, expected_inner_product);
        let is_valid = ipa.verify(expected_inner_product).unwrap();
        assert!(is_valid);
        
        // Test wrong inner product
        let is_valid = ipa.verify(100).unwrap();
        assert!(!is_valid);
        
        // Test mismatched vector lengths
        let result = InnerProductArgument::new(&[1, 2], &[3, 4, 5]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_vector_commitment() {
        let vector = vec![10, 20, 30, 40];
        let commitment = VectorCommitment::new(&vector).unwrap();
        
        assert_eq!(commitment.length, 4);
        assert_eq!(commitment.blinding.len(), 32);
        
        let is_valid = commitment.verify(&vector).unwrap();
        assert!(is_valid);
        
        // Test wrong vector
        let wrong_vector = vec![10, 20, 30, 50];
        let is_valid = commitment.verify(&wrong_vector).unwrap();
        assert!(!is_valid);
        
        // Test wrong length
        let short_vector = vec![10, 20];
        let is_valid = commitment.verify(&short_vector).unwrap();
        assert!(!is_valid);
    }
    
    #[tokio::test]
    async fn test_bulletproof_batch_verifier() {
        let config = BulletproofConfig::default();
        let batch_verifier = BulletproofBatchVerifier::new(config).unwrap();
        
        let proofs = vec![
            vec![0; 32],
            vec![1; 32],
            vec![2; 32],
        ];
        
        let ranges = vec![
            (0, 100),
            (10, 200),
            (50, 150),
        ];
        
        let bit_lengths = vec![8, 8, 8];
        
        let results = batch_verifier.verify_range_batch(&proofs, &ranges, &bit_lengths).await.unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|&r| r));
        
        let stats = batch_verifier.get_batch_stats().await;
        assert_eq!(stats.total_verifications, 3);
        assert_eq!(stats.successful_verifications, 3);
    }
}