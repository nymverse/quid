//! Security hardening utilities for QuID
//! 
//! This module provides additional security measures beyond basic cryptography.

use std::time::Instant;
use zeroize::Zeroize;

/// Constant-time comparison to prevent timing attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Memory protection utilities
pub struct SecureMemory;

impl SecureMemory {
    /// Verify memory has been properly zeroized (for testing)
    pub fn verify_zeroized(memory: &[u8]) -> bool {
        memory.iter().all(|&byte| byte == 0)
    }
    
    /// Force memory clearing with compiler barrier
    pub fn secure_clear(data: &mut [u8]) {
        data.zeroize();
        // Add compiler barrier to prevent optimization
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Timing attack resistance utilities
pub struct TimingResistance;

impl TimingResistance {
    /// Add random delay to mask operation timing
    pub fn random_delay() {
        let delay_nanos = (rand::random::<u16>() % 1000) as u64;
        std::thread::sleep(std::time::Duration::from_nanos(delay_nanos));
    }
    
    /// Measure operation timing for analysis
    pub fn measure_operation<F, R>(operation: F) -> (R, std::time::Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed();
        (result, duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";
        
        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, b"hell")); // Different lengths
    }

    #[test]
    fn test_secure_memory_clear() {
        let mut data = vec![0x42u8; 100];
        assert!(!SecureMemory::verify_zeroized(&data));
        
        SecureMemory::secure_clear(&mut data);
        assert!(SecureMemory::verify_zeroized(&data));
    }
}
