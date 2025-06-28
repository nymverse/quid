//! QuID Consensus Layer - Minimal blockchain for NYM tokens
//! 
//! This module implements a lightweight consensus system specifically for preventing
//! double spending of NYM tokens while keeping the content layer (DHT) fully decentralized.

pub mod transaction;
pub mod chain;
pub mod validator;
pub mod consensus;
pub mod error;

pub use transaction::{NymTransaction, TransactionType, TransactionPool};
pub use chain::{Block, Blockchain, BlockHeader};
pub use validator::{Validator, ValidatorSet};
pub use consensus::{ConsensusEngine, ConsensusState};
pub use error::ConsensusError;

use quid_core::QuIDIdentity;
use serde::{Deserialize, Serialize};

/// Result type for consensus operations
pub type Result<T> = std::result::Result<T, ConsensusError>;

/// NYM token amount (using u64 for simplicity)
pub type NymAmount = u64;

/// Block height in the consensus chain
pub type BlockHeight = u64;

/// Consensus protocol version
pub const CONSENSUS_VERSION: &str = "0.1.0";

/// Genesis block configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub initial_validators: Vec<QuIDIdentity>,
    pub initial_token_distribution: Vec<(QuIDIdentity, NymAmount)>,
    pub domain_registry_fee: NymAmount,
    pub validator_reward: NymAmount,
    pub dev_fund_address: QuIDIdentity,
}

/// Network configuration constants
pub mod constants {
    use super::NymAmount;
    
    /// Domain registration base fee
    pub const DOMAIN_REGISTRATION_FEE: NymAmount = 10;
    
    /// Domain transfer fee
    pub const DOMAIN_TRANSFER_FEE: NymAmount = 5;
    
    /// Minimum validator stake
    pub const MIN_VALIDATOR_STAKE: NymAmount = 1000;
    
    /// Block time target (in seconds)
    pub const BLOCK_TIME: u64 = 30;
    
    /// Maximum transactions per block
    pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 1000;
    
    /// Fee distribution percentages
    pub const DEV_FUND_PERCENTAGE: u8 = 40;
    pub const VALIDATOR_PERCENTAGE: u8 = 30;
    pub const ECOSYSTEM_PERCENTAGE: u8 = 30;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_constant() {
        assert!(!CONSENSUS_VERSION.is_empty());
    }

    #[test]
    fn test_fee_percentages_sum_to_100() {
        use constants::*;
        assert_eq!(
            DEV_FUND_PERCENTAGE + VALIDATOR_PERCENTAGE + ECOSYSTEM_PERCENTAGE,
            100
        );
    }
}
