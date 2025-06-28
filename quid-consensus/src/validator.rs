//! Validator management for NYM consensus

use crate::{NymAmount, BlockHeight, Result, ConsensusError, Block, Blockchain};
use quid_core::{QuIDIdentity, crypto::KeyPair};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Information about a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// Validator's QuID identity
    pub identity: QuIDIdentity,
    
    /// Amount staked by this validator
    pub stake: NymAmount,
    
    /// When this validator joined the set
    pub joined_at: BlockHeight,
    
    /// Validator's voting power (derived from stake)
    pub voting_power: u64,
    
    /// Performance metrics
    pub metrics: ValidatorMetrics,
    
    /// Status of the validator
    pub status: ValidatorStatus,
}

/// Validator performance metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidatorMetrics {
    /// Total blocks proposed
    pub blocks_proposed: u64,
    
    /// Total blocks signed
    pub blocks_signed: u64,
    
    /// Total blocks missed
    pub blocks_missed: u64,
    
    /// Last time validator was active
    pub last_active: u64,
    
    /// Reputation score (0-100)
    pub reputation: u8,
}

/// Validator status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidatorStatus {
    /// Active and participating in consensus
    Active,
    
    /// Temporarily inactive (missed too many blocks)
    Inactive,
    
    /// Slashed for malicious behavior
    Slashed,
    
    /// Voluntarily left the validator set
    Unstaked,
}

/// Set of active validators
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    /// Active validators (QuID ID -> Validator)
    validators: HashMap<Vec<u8>, Validator>,
    
    /// Total stake across all validators
    total_stake: NymAmount,
    
    /// Current proposer index for round-robin
    proposer_index: usize,
    
    /// Block height when this set was last updated
    last_updated: BlockHeight,
    
    /// Maximum number of validators
    max_validators: usize,
}

impl ValidatorSet {
    /// Create a new validator set
    pub fn new(max_validators: usize) -> Self {
        Self {
            validators: HashMap::new(),
            total_stake: 0,
            proposer_index: 0,
            last_updated: 0,
            max_validators,
        }
    }
    
    /// Initialize validator set from genesis
    pub fn from_genesis(initial_validators: Vec<QuIDIdentity>, max_validators: usize) -> Self {
        let mut validator_set = Self::new(max_validators);
        
        for identity in initial_validators {
            let validator = Validator {
                identity: identity.clone(),
                stake: crate::constants::MIN_VALIDATOR_STAKE,
                joined_at: 0,
                voting_power: 1, // Equal voting power initially
                metrics: ValidatorMetrics::default(),
                status: ValidatorStatus::Active,
            };
            
            validator_set.total_stake += validator.stake;
            validator_set.validators.insert(identity.id.clone(), validator);
        }
        
        validator_set.update_voting_power();
        validator_set
    }
    
    /// Add a new validator to the set
    pub fn add_validator(&mut self, identity: QuIDIdentity, stake: NymAmount, height: BlockHeight) -> Result<()> {
        if self.validators.len() >= self.max_validators {
            return Err(ConsensusError::ValidatorError(
                "Validator set is full".to_string()
            ));
        }
        
        if stake < crate::constants::MIN_VALIDATOR_STAKE {
            return Err(ConsensusError::ValidatorError(
                format!("Stake {} below minimum {}", stake, crate::constants::MIN_VALIDATOR_STAKE)
            ));
        }
        
        if self.validators.contains_key(&identity.id) {
            return Err(ConsensusError::ValidatorError(
                "Validator already exists".to_string()
            ));
        }
        
        let validator = Validator {
            identity: identity.clone(),
            stake,
            joined_at: height,
            voting_power: 0, // Will be calculated
            metrics: ValidatorMetrics::default(),
            status: ValidatorStatus::Active,
        };
        
        self.total_stake += stake;
        self.validators.insert(identity.id.clone(), validator);
        self.update_voting_power();
        self.last_updated = height;
        
        Ok(())
    }
    
    /// Remove a validator from the set
    pub fn remove_validator(&mut self, quid_id: &[u8], height: BlockHeight) -> Result<()> {
        if let Some(validator) = self.validators.remove(quid_id) {
            self.total_stake -= validator.stake;
            self.update_voting_power();
            self.last_updated = height;
            Ok(())
        } else {
            Err(ConsensusError::ValidatorError(
                "Validator not found".to_string()
            ))
        }
    }
    
    /// Update validator stake
    pub fn update_stake(&mut self, quid_id: &[u8], new_stake: NymAmount, height: BlockHeight) -> Result<()> {
        if let Some(validator) = self.validators.get_mut(quid_id) {
            self.total_stake = self.total_stake - validator.stake + new_stake;
            validator.stake = new_stake;
            
            // Check if stake is below minimum
            if new_stake < crate::constants::MIN_VALIDATOR_STAKE {
                validator.status = ValidatorStatus::Unstaked;
            }
            
            self.update_voting_power();
            self.last_updated = height;
            Ok(())
        } else {
            Err(ConsensusError::ValidatorError(
                "Validator not found".to_string()
            ))
        }
    }
    
    /// Get the current block proposer
    pub fn get_current_proposer(&self) -> Option<&Validator> {
        let active_validators: Vec<_> = self.validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .collect();
        
        if active_validators.is_empty() {
            return None;
        }
        
        let index = self.proposer_index % active_validators.len();
        active_validators.get(index).copied()
    }
    
    /// Rotate to next proposer
    pub fn next_proposer(&mut self) {
        self.proposer_index = (self.proposer_index + 1) % self.validators.len().max(1);
    }
    
    /// Get validator by QuID ID
    pub fn get_validator(&self, quid_id: &[u8]) -> Option<&Validator> {
        self.validators.get(quid_id)
    }
    
    /// Get all active validators
    pub fn get_active_validators(&self) -> Vec<&Validator> {
        self.validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .collect()
    }
    
    /// Get total number of validators
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }
    
    /// Get active validator count
    pub fn active_validator_count(&self) -> usize {
        self.validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .count()
    }
    
    /// Calculate required signatures for consensus (2/3+ majority)
    pub fn required_signatures(&self) -> usize {
        let active_count = self.active_validator_count();
        (active_count * 2) / 3 + 1
    }
    
    /// Check if we have enough signatures for consensus
    pub fn has_consensus(&self, signatures: &HashMap<Vec<u8>, Vec<u8>>) -> bool {
        let valid_signatures = signatures
            .keys()
            .filter(|quid_id| {
                self.validators
                    .get(*quid_id)
                    .map_or(false, |v| v.status == ValidatorStatus::Active)
            })
            .count();
        
        valid_signatures >= self.required_signatures()
    }
    
    /// Update voting power based on stakes
    fn update_voting_power(&mut self) {
        if self.total_stake == 0 {
            return;
        }
        
        for validator in self.validators.values_mut() {
            // Voting power is proportional to stake
            validator.voting_power = (validator.stake * 1000) / self.total_stake;
        }
    }
    
    /// Update validator metrics after block processing
    pub fn update_metrics(&mut self, block: &Block, signatures: &HashMap<Vec<u8>, Vec<u8>>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Update proposer metrics
        if let Some(proposer) = self.validators.get_mut(&block.header.proposer) {
            proposer.metrics.blocks_proposed += 1;
            proposer.metrics.last_active = now;
        }
        

        // To this:
        let validator_ids: Vec<Vec<u8>> = self.validators.keys().cloned().collect();
        for validator_id in validator_ids {
            if let Some(validator) = self.validators.get_mut(&validator_id) {
                // Update metrics first
                if signatures.contains_key(&validator.identity.id) {
                    validator.metrics.blocks_signed += 1;
                    validator.metrics.last_active = now;
                } else if validator.status == ValidatorStatus::Active {
                    validator.metrics.blocks_missed += 1;
                    
                    // Check if validator should be marked inactive
                    let total_blocks = validator.metrics.blocks_signed + validator.metrics.blocks_missed;
                    if total_blocks > 100 {
                        let miss_rate = (validator.metrics.blocks_missed * 100) / total_blocks;
                        if miss_rate > 20 { // More than 20% miss rate
                            validator.status = ValidatorStatus::Inactive;
                        }
                    }
                }
            }
        }

        for validator in self.validators.values_mut() {
            Self::update_reputation_static(validator);
        }
    }
    
    /// Update validator reputation based on performance
    
    fn update_reputation_static(validator: &mut Validator) {
        let total_blocks = validator.metrics.blocks_signed + validator.metrics.blocks_missed;
        if total_blocks == 0 {
            validator.metrics.reputation = 100;
            return;
        }
        
        let sign_rate = (validator.metrics.blocks_signed * 100) / total_blocks;
        
        // Reputation is based on signing rate
        validator.metrics.reputation = match sign_rate {
            95..=100 => 100,
            90..=94 => 90,
            80..=89 => 80,
            70..=79 => 70,
            60..=69 => 60,
            50..=59 => 50,
            _ => 30,
        };
    }

    /// Select validators for the next epoch (stake-weighted)
    pub fn select_next_epoch(&self, blockchain: &Blockchain) -> Result<ValidatorSet> {
        // Get all potential validators (those with sufficient stake)
        let mut candidates = Vec::new();
        
        // Current validators
        for validator in self.validators.values() {
            let current_stake = blockchain.get_validator_stake(&validator.identity.id);
            if current_stake >= crate::constants::MIN_VALIDATOR_STAKE {
                candidates.push((validator.identity.clone(), current_stake, validator.metrics.reputation));
            }
        }
        
        // Sort by stake (descending) and reputation
        candidates.sort_by(|a, b| {
            match b.1.cmp(&a.1) { // Sort by stake first
                std::cmp::Ordering::Equal => b.2.cmp(&a.2), // Then by reputation
                other => other,
            }
        });
        
        // Select top validators up to max_validators
        let selected_count = candidates.len().min(self.max_validators);
        let mut next_set = ValidatorSet::new(self.max_validators);
        
        for (identity, stake, _reputation) in candidates.into_iter().take(selected_count) {
            let validator = Validator {
                identity: identity.clone(),
                stake,
                joined_at: blockchain.height(),
                voting_power: 0, // Will be calculated
                metrics: ValidatorMetrics::default(),
                status: ValidatorStatus::Active,
            };
            
            next_set.total_stake += stake;
            next_set.validators.insert(identity.id.clone(), validator);
        }
        
        next_set.update_voting_power();
        next_set.last_updated = blockchain.height();
        
        Ok(next_set)
    }
}

/// Validator operations and utilities
pub struct ValidatorOps;

impl ValidatorOps {
    /// Sign a block as a validator
    pub fn sign_block(block: &Block, keypair: &KeyPair) -> Result<Vec<u8>> {
        let block_hash = block.hash()?;
        keypair.sign(&block_hash)
            .map_err(|e| ConsensusError::CryptoError(format!("Block signing failed: {}", e)))
    }
    
    /// Verify a block signature
    pub fn verify_block_signature(
        block: &Block,
        signature: &[u8],
        validator: &Validator,
    ) -> Result<bool> {
        let block_hash = block.hash()?;
        
        // Create a keypair from validator's public key for verification
        let keypair = quid_core::crypto::KeyPair {
            public_key: validator.identity.public_key.clone(),
            private_key: secrecy::Secret::new(vec![]), // Empty for verification
            security_level: validator.identity.security_level,
        };
        
        keypair.verify(&block_hash, signature)
            .map_err(|e| ConsensusError::CryptoError(format!("Signature verification failed: {}", e)))
    }
    
    /// Calculate validator selection seed for deterministic proposer rotation
    pub fn calculate_selection_seed(block_height: BlockHeight, round: u32) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"quid-validator-selection");
        hasher.update(&block_height.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        hasher.finalize().to_vec()
    }
    
    /// Select proposer deterministically based on stake and seed
    pub fn select_proposer(
        validator_set: &ValidatorSet,
        block_height: BlockHeight,
        round: u32,
    ) -> Option<Vec<u8>> {
        let active_validators = validator_set.get_active_validators();
        if active_validators.is_empty() {
            return None;
        }
        
        let seed = Self::calculate_selection_seed(block_height, round);
        let mut seed_hash = Sha3_256::new();
        seed_hash.update(&seed);
        let hash_bytes = seed_hash.finalize();
        
        // Convert first 8 bytes to u64 for selection
        let mut selection_bytes = [0u8; 8];
        selection_bytes.copy_from_slice(&hash_bytes[..8]);
        let selection_value = u64::from_le_bytes(selection_bytes);
        
        // Weighted selection based on voting power
        let total_voting_power: u64 = active_validators
            .iter()
            .map(|v| v.voting_power)
            .sum();
        
        if total_voting_power == 0 {
            return None;
        }
        
        let target = selection_value % total_voting_power;
        let mut cumulative = 0;
        

        for validator in &active_validators {
            cumulative += validator.voting_power;
            if cumulative > target {
                return Some(validator.identity.id.clone());
            }
        }
        
        // Fallback to first validator
        active_validators.first().map(|v| v.identity.id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;

    #[test]
    fn test_validator_set_creation() {
        let (identity1, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let (identity2, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let validators = vec![identity1.clone(), identity2.clone()];
        let validator_set = ValidatorSet::from_genesis(validators, 10);
        
        assert_eq!(validator_set.validator_count(), 2);
        assert_eq!(validator_set.active_validator_count(), 2);
        assert!(validator_set.get_validator(&identity1.id).is_some());
        assert!(validator_set.get_validator(&identity2.id).is_some());
    }

    #[test]
    fn test_validator_consensus_requirements() {
        let (identity1, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let (identity2, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let (identity3, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let validators = vec![identity1.clone(), identity2.clone(), identity3.clone()];
        let validator_set = ValidatorSet::from_genesis(validators, 10);
        
        // Need 2 out of 3 for consensus (2/3 + 1)
        assert_eq!(validator_set.required_signatures(), 3);
        
        // Test with signatures
        let mut signatures = HashMap::new();
        assert!(!validator_set.has_consensus(&signatures));
        
        signatures.insert(identity1.id.clone(), vec![1, 2, 3]);
        signatures.insert(identity2.id.clone(), vec![4, 5, 6]);
        assert!(!validator_set.has_consensus(&signatures));
        
        signatures.insert(identity3.id.clone(), vec![7, 8, 9]);
        assert!(validator_set.has_consensus(&signatures));
    }

    #[test]
    fn test_proposer_selection() {
        let (identity1, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let (identity2, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let validators = vec![identity1.clone(), identity2.clone()];
        let validator_set = ValidatorSet::from_genesis(validators, 10);
        
        // Should select deterministically
        let proposer1 = ValidatorOps::select_proposer(&validator_set, 1, 0);
        let proposer2 = ValidatorOps::select_proposer(&validator_set, 1, 0);
        assert_eq!(proposer1, proposer2);
        
        // Different height should potentially select different proposer
        let proposer3 = ValidatorOps::select_proposer(&validator_set, 2, 0);
        // Note: might be same due to randomness, but algorithm is deterministic
        
        assert!(proposer1.is_some());
        assert!(proposer3.is_some());
    }

    #[test]
    fn test_voting_power_calculation() {
        let (identity1, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let (identity2, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let mut validator_set = ValidatorSet::new(10);
        
        validator_set.add_validator(identity1.clone(), 1000, 0).unwrap();
        validator_set.add_validator(identity2.clone(), 2000, 0).unwrap();
        
        let val1 = validator_set.get_validator(&identity1.id).unwrap();
        let val2 = validator_set.get_validator(&identity2.id).unwrap();
        
        // val2 should have twice the voting power of val1
        assert_eq!(val2.voting_power, val1.voting_power * 2);
    }
}
