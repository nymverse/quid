//! Zero-knowledge proof verifier trait and implementations

use crate::{ZKPResult, ZKPError, proofs::ZKProof};
use async_trait::async_trait;

/// Trait for zero-knowledge proof verifiers
#[async_trait]
pub trait ZKVerifier: Send + Sync {
    /// Verify a zero-knowledge proof
    async fn verify(&self, proof: &ZKProof, public_inputs: &[u8]) -> ZKPResult<bool>;
    
    /// Get verifier name
    fn name(&self) -> &'static str;
    
    /// Get supported proof system
    fn supported_system(&self) -> crate::ProofSystem;
    
    /// Check if verifier is ready
    async fn is_ready(&self) -> bool;
    
    /// Get verification statistics
    async fn get_stats(&self) -> VerificationStats;
}

/// Verification statistics
#[derive(Debug, Clone)]
pub struct VerificationStats {
    /// Total verifications performed
    pub total_verifications: u64,
    /// Successful verifications
    pub successful_verifications: u64,
    /// Failed verifications
    pub failed_verifications: u64,
    /// Average verification time (ms)
    pub avg_verification_time_ms: f64,
    /// Total verification time (ms)
    pub total_verification_time_ms: u64,
}

impl Default for VerificationStats {
    fn default() -> Self {
        Self {
            total_verifications: 0,
            successful_verifications: 0,
            failed_verifications: 0,
            avg_verification_time_ms: 0.0,
            total_verification_time_ms: 0,
        }
    }
}

impl VerificationStats {
    /// Update statistics with new verification
    pub fn update(&mut self, success: bool, duration_ms: u64) {
        self.total_verifications += 1;
        self.total_verification_time_ms += duration_ms;
        
        if success {
            self.successful_verifications += 1;
        } else {
            self.failed_verifications += 1;
        }
        
        self.avg_verification_time_ms = 
            self.total_verification_time_ms as f64 / self.total_verifications as f64;
    }
    
    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_verifications == 0 {
            0.0
        } else {
            self.successful_verifications as f64 / self.total_verifications as f64
        }
    }
    
    /// Get failure rate
    pub fn failure_rate(&self) -> f64 {
        if self.total_verifications == 0 {
            0.0
        } else {
            self.failed_verifications as f64 / self.total_verifications as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_verification_stats() {
        let mut stats = VerificationStats::default();
        
        // Update with successful verification
        stats.update(true, 100);
        assert_eq!(stats.total_verifications, 1);
        assert_eq!(stats.successful_verifications, 1);
        assert_eq!(stats.failed_verifications, 0);
        assert_eq!(stats.avg_verification_time_ms, 100.0);
        assert_eq!(stats.success_rate(), 1.0);
        assert_eq!(stats.failure_rate(), 0.0);
        
        // Update with failed verification
        stats.update(false, 50);
        assert_eq!(stats.total_verifications, 2);
        assert_eq!(stats.successful_verifications, 1);
        assert_eq!(stats.failed_verifications, 1);
        assert_eq!(stats.avg_verification_time_ms, 75.0);
        assert_eq!(stats.success_rate(), 0.5);
        assert_eq!(stats.failure_rate(), 0.5);
        
        // Update with another successful verification
        stats.update(true, 200);
        assert_eq!(stats.total_verifications, 3);
        assert_eq!(stats.successful_verifications, 2);
        assert_eq!(stats.failed_verifications, 1);
        assert_eq!(stats.avg_verification_time_ms, 350.0 / 3.0);
        assert!((stats.success_rate() - 2.0/3.0).abs() < 0.001);
        assert!((stats.failure_rate() - 1.0/3.0).abs() < 0.001);
    }
    
    #[test]
    fn test_empty_stats() {
        let stats = VerificationStats::default();
        assert_eq!(stats.success_rate(), 0.0);
        assert_eq!(stats.failure_rate(), 0.0);
        assert_eq!(stats.avg_verification_time_ms, 0.0);
    }
}