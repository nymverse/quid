//! QuID Core - Quantum-resistant Identity Protocol
//! 
//! This crate provides the core functionality for creating and managing
//! quantum-resistant digital identities.

use serde::{Deserialize, Serialize};

pub mod crypto;
pub mod error;
pub mod identity;
pub mod recovery;
pub mod security;
pub mod storage;
pub mod network;

pub use error::QuIDError;
pub use identity::{QuIDIdentity, Extension};
pub use recovery::{RecoveryCoordinator, RecoveryShare, GuardianInfo};
pub use security::{SecureMemory, TimingResistance};
pub use storage::{IdentityStorage, StorageConfig, EncryptedIdentity};
pub use network::{NetworkPrivacyManager, NetworkPrivacyConfig, PrivacyLevel};

/// Result type for QuID operations
pub type Result<T> = std::result::Result<T, QuIDError>;

/// QuID result type alias
pub type QuIDResult<T> = std::result::Result<T, QuIDError>;

/// Security levels corresponding to NIST categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 128 bits of quantum security
    Level1,
    /// 192 bits of quantum security  
    Level3,
    /// 256 bits of quantum security
    Level5,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Level1
    }
}

/// QuID protocol version
pub const QUID_VERSION: &str = "0.1.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_levels() {
        assert_eq!(SecurityLevel::default(), SecurityLevel::Level1);
    }

    #[test]
    fn test_version_constant() {
        assert!(!QUID_VERSION.is_empty());
    }
}