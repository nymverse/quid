//! Blockchain data structures for NYM token consensus

use crate::{NymTransaction, NymAmount, BlockHeight, Result, ConsensusError};
use quid_core::QuIDIdentity;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Block header containing metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]  // Add PartialEq here
pub struct BlockHeader {
    /// Block height (0 for genesis block)
    pub height: BlockHeight,
    
    /// Hash of previous block
    pub previous_hash: Vec<u8>,
    
    /// Merkle root of transactions in this block
    pub merkle_root: Vec<u8>,
    
    /// Block timestamp
    pub timestamp: u64,
    
    /// Number of transactions in block
    pub transaction_count: u32,
    
    /// Total fees collected in this block
    pub total_fees: NymAmount,
    
    /// Validator who proposed this block
    pub proposer: Vec<u8>, // QuID ID
    
    /// Protocol version
    pub version: String,
}

/// A block in the NYM blockchain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    
    /// Transactions in this block
    pub transactions: Vec<NymTransaction>,
    
    /// Validator signatures approving this block
    pub validator_signatures: HashMap<Vec<u8>, Vec<u8>>, // QuID ID -> Signature
}

impl Block {
    /// Create a new block
    pub fn new(
        height: BlockHeight,
        previous_hash: Vec<u8>,
        transactions: Vec<NymTransaction>,
        proposer: Vec<u8>,
    ) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::InvalidBlock(format!("Time error: {}", e)))?
            .as_secs();
        
        let merkle_root = Self::calculate_merkle_root(&transactions)?;
        let total_fees = transactions.iter().map(|tx| tx.fee).sum();
        
        let header = BlockHeader {
            height,
            previous_hash,
            merkle_root,
            timestamp,
            transaction_count: transactions.len() as u32,
            total_fees,
            proposer,
            version: crate::CONSENSUS_VERSION.to_string(),
        };
        
        Ok(Block {
            header,
            transactions,
            validator_signatures: HashMap::new(),
        })
    }
    
    /// Create the genesis block
    pub fn genesis(initial_distribution: Vec<(QuIDIdentity, NymAmount)>) -> Result<Self> {
        // Create genesis transactions for initial token distribution
        let mut genesis_transactions = Vec::new();
        
        for (identity, amount) in initial_distribution {
            let tx = NymTransaction {
                tx_type: crate::transaction::TransactionType::Transfer {
                    to: identity.id.clone(),
                    amount,
                },
                from: vec![0; 32], // Genesis has no sender
                nonce: 0,
                fee: 0,
                timestamp: 0,
                signature: Vec::new(), // Genesis transactions don't need signatures
                version: crate::CONSENSUS_VERSION.to_string(),
            };
            genesis_transactions.push(tx);
        }
        
        let genesis_block = Block::new(
            0, // Height 0
            vec![0; 32], // No previous block
            genesis_transactions,
            vec![0; 32], // Genesis proposer
        )?;
        
        Ok(genesis_block)
    }
    
    /// Calculate the hash of this block
    pub fn hash(&self) -> Result<Vec<u8>> {
        let header_bytes = serde_json::to_vec(&self.header)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(&header_bytes);
        Ok(hasher.finalize().to_vec())
    }
    
    /// Validate this block's structure and transactions
    pub fn validate(&self, previous_block: Option<&Block>) -> Result<()> {
        // Validate header consistency
        if self.header.transaction_count != self.transactions.len() as u32 {
            return Err(ConsensusError::BlockValidation(
                "Transaction count mismatch".to_string()
            ));
        }
        
        // Validate merkle root
        let calculated_root = Self::calculate_merkle_root(&self.transactions)?;
        if self.header.merkle_root != calculated_root {
            return Err(ConsensusError::BlockValidation(
                "Invalid merkle root".to_string()
            ));
        }
        
        // Validate block height and previous hash
        if let Some(prev) = previous_block {
            if self.header.height != prev.header.height + 1 {
                return Err(ConsensusError::BlockValidation(
                    format!("Invalid height: expected {}, got {}", 
                        prev.header.height + 1, self.header.height)
                ));
            }
            
            let prev_hash = prev.hash()?;
            if self.header.previous_hash != prev_hash {
                return Err(ConsensusError::BlockValidation(
                    "Invalid previous hash".to_string()
                ));
            }
        } else {
            // Genesis block validation
            if self.header.height != 0 {
                return Err(ConsensusError::BlockValidation(
                    "Genesis block must have height 0".to_string()
                ));
            }
        }
        
        // Validate timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if self.header.timestamp > now + 300 { // 5 minute future tolerance
            return Err(ConsensusError::BlockValidation(
                "Block timestamp too far in future".to_string()
            ));
        }
        
        // Validate total fees
        let calculated_fees: NymAmount = self.transactions.iter().map(|tx| tx.fee).sum();
        if self.header.total_fees != calculated_fees {
            return Err(ConsensusError::BlockValidation(
                "Fee calculation mismatch".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Calculate merkle root of transactions
    fn calculate_merkle_root(transactions: &[NymTransaction]) -> Result<Vec<u8>> {
        if transactions.is_empty() {
            return Ok(vec![0; 32]);
        }
        
        // Get transaction hashes
        let mut hashes: Vec<Vec<u8>> = transactions
            .iter()
            .map(|tx| tx.hash())
            .collect::<Result<Vec<_>>>()?;
        
        // Build merkle tree bottom-up
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha3_256::new();
                hasher.update(&chunk[0]);
                
                // Handle odd number of hashes by duplicating last hash
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]);
                }
                
                next_level.push(hasher.finalize().to_vec());
            }
            
            hashes = next_level;
        }
        
        Ok(hashes.into_iter().next().unwrap_or_else(|| vec![0; 32]))
    }
}

/// The blockchain state and operations
#[derive(Debug, Clone)]
pub struct Blockchain {
    /// All blocks in order
    blocks: Vec<Block>,
    
    /// Account balances (QuID ID -> balance)
    balances: HashMap<Vec<u8>, NymAmount>,
    
    /// Account nonces (QuID ID -> nonce)
    nonces: HashMap<Vec<u8>, u64>,
    
    /// Domain registry (domain -> owner QuID ID)
    domains: HashMap<String, Vec<u8>>,
    
    /// Validator stakes (QuID ID -> staked amount)
    validator_stakes: HashMap<Vec<u8>, NymAmount>,
}

impl Blockchain {
    /// Create a new blockchain with genesis block
    pub fn new(genesis_block: Block) -> Result<Self> {
        let mut blockchain = Blockchain {
            blocks: Vec::new(),
            balances: HashMap::new(),
            nonces: HashMap::new(),
            domains: HashMap::new(),
            validator_stakes: HashMap::new(),
        };
        
        blockchain.add_block(genesis_block)?;
        Ok(blockchain)
    }
    
    /// Add a new block to the chain
    pub fn add_block(&mut self, block: Block) -> Result<()> {
        // Validate block
        let previous_block = self.blocks.last();
        block.validate(previous_block)?;
        
        // Apply block transactions to state
        for transaction in &block.transactions {
            self.apply_transaction(transaction)?;
        }
        
        // Distribute block fees
        self.distribute_fees(&block)?;
        
        // Add block to chain
        self.blocks.push(block);
        
        Ok(())
    }
    
    /// Get current block height
    pub fn height(&self) -> BlockHeight {
        if self.blocks.is_empty() {
            0
        } else {
            self.blocks.len() as BlockHeight - 1
        }
    }
    
    /// Get block by height
    pub fn get_block(&self, height: BlockHeight) -> Option<&Block> {
        self.blocks.get(height as usize)
    }
    
    /// Get latest block
    pub fn latest_block(&self) -> Option<&Block> {
        self.blocks.last()
    }
    
    /// Get account balance
    pub fn get_balance(&self, quid_id: &[u8]) -> NymAmount {
        self.balances.get(quid_id).copied().unwrap_or(0)
    }
    
    /// Get account nonce
    pub fn get_nonce(&self, quid_id: &[u8]) -> u64 {
        self.nonces.get(quid_id).copied().unwrap_or(0)
    }
    
    /// Get domain owner
    pub fn get_domain_owner(&self, domain: &str) -> Option<&[u8]> {
        self.domains.get(domain).map(|v| v.as_slice())
    }
    
    /// Check if domain is available
    pub fn is_domain_available(&self, domain: &str) -> bool {
        !self.domains.contains_key(domain)
    }
    
    /// Get validator stake
    pub fn get_validator_stake(&self, quid_id: &[u8]) -> NymAmount {
        self.validator_stakes.get(quid_id).copied().unwrap_or(0)
    }
    
    /// Apply a transaction to the blockchain state
    fn apply_transaction(&mut self, tx: &NymTransaction) -> Result<()> {
        use crate::transaction::TransactionType;
        
        // Skip genesis transactions
        if tx.from == vec![0; 32] {
            // Genesis transaction - just credit the recipient
            if let TransactionType::Transfer { to, amount } = &tx.tx_type {
                let current_balance = self.balances.get(to).copied().unwrap_or(0);
                self.balances.insert(to.clone(), current_balance + amount);
            }
            return Ok(());
        }
        
        // Validate nonce
        let expected_nonce = self.get_nonce(&tx.from) + 1;
        if tx.nonce != expected_nonce {
            return Err(ConsensusError::InvalidNonce {
                expected: expected_nonce,
                got: tx.nonce,
            });
        }
        
        // Check and deduct fees
        let sender_balance = self.get_balance(&tx.from);
        if sender_balance < tx.fee {
            return Err(ConsensusError::InsufficientBalance {
                needed: tx.fee,
                available: sender_balance,
            });
        }
        
        // Apply transaction based on type
        match &tx.tx_type {
            TransactionType::Transfer { to, amount } => {
                let total_needed = amount + tx.fee;
                if sender_balance < total_needed {
                    return Err(ConsensusError::InsufficientBalance {
                        needed: total_needed,
                        available: sender_balance,
                    });
                }
                
                // Deduct from sender
                self.balances.insert(tx.from.clone(), sender_balance - total_needed);
                
                // Credit recipient
                let recipient_balance = self.get_balance(to);
                self.balances.insert(to.clone(), recipient_balance + amount);
            }
            
            TransactionType::DomainRegistration { domain, fee } => {
                if !self.is_domain_available(domain) {
                    return Err(ConsensusError::InvalidTransaction(
                        format!("Domain {} already registered", domain)
                    ));
                }
                
                let total_needed = fee + tx.fee;
                if sender_balance < total_needed {
                    return Err(ConsensusError::InsufficientBalance {
                        needed: total_needed,
                        available: sender_balance,
                    });
                }
                
                // Deduct payment
                self.balances.insert(tx.from.clone(), sender_balance - total_needed);
                
                // Register domain
                self.domains.insert(domain.clone(), tx.from.clone());
            }
            
            TransactionType::DomainTransfer { domain, to, fee } => {
                if self.get_domain_owner(domain) != Some(&tx.from) {
                    return Err(ConsensusError::InvalidTransaction(
                        format!("Sender does not own domain {}", domain)
                    ));
                }
                
                let total_needed = fee + tx.fee;
                if sender_balance < total_needed {
                    return Err(ConsensusError::InsufficientBalance {
                        needed: total_needed,
                        available: sender_balance,
                    });
                }
                
                // Deduct payment
                self.balances.insert(tx.from.clone(), sender_balance - total_needed);
                
                // Transfer domain
                self.domains.insert(domain.clone(), to.clone());
            }
            
            TransactionType::ValidatorStake { amount } => {
                let total_needed = amount + tx.fee;
                if sender_balance < total_needed {
                    return Err(ConsensusError::InsufficientBalance {
                        needed: total_needed,
                        available: sender_balance,
                    });
                }
                
                // Deduct stake + fee
                self.balances.insert(tx.from.clone(), sender_balance - total_needed);
                
                // Add to validator stakes
                let current_stake = self.get_validator_stake(&tx.from);
                self.validator_stakes.insert(tx.from.clone(), current_stake + amount);
            }
            
            TransactionType::ValidatorUnstake { amount } => {
                let current_stake = self.get_validator_stake(&tx.from);
                if current_stake < *amount {
                    return Err(ConsensusError::InsufficientBalance {
                        needed: *amount,
                        available: current_stake,
                    });
                }
                
                if sender_balance < tx.fee {
                    return Err(ConsensusError::InsufficientBalance {
                        needed: tx.fee,
                        available: sender_balance,
                    });
                }
                
                // Deduct fee
                self.balances.insert(tx.from.clone(), sender_balance - tx.fee);
                
                // Return stake to balance
                let new_balance = sender_balance - tx.fee + amount;
                self.balances.insert(tx.from.clone(), new_balance);
                
                // Reduce validator stake
                self.validator_stakes.insert(tx.from.clone(), current_stake - amount);
            }
        }
        
        // Update nonce
        self.nonces.insert(tx.from.clone(), tx.nonce);
        
        Ok(())
    }
    
    /// Distribute block fees according to tokenomics
    fn distribute_fees(&mut self, block: &Block) -> Result<()> {
        if block.header.total_fees == 0 {
            return Ok(());
        }
        
        let total_fees = block.header.total_fees;
        
        // Calculate distributions based on constants
        let dev_fund_amount = (total_fees * crate::constants::DEV_FUND_PERCENTAGE as u64) / 100;
        let validator_amount = (total_fees * crate::constants::VALIDATOR_PERCENTAGE as u64) / 100;
        let ecosystem_amount = total_fees - dev_fund_amount - validator_amount; // Remainder
        
        // TODO: Implement actual distribution logic
        // For now, fees just disappear (burned)
        // In production, you'd distribute to:
        // - Dev fund address
        // - Active validators
        // - Ecosystem fund
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;

    #[test]
    fn test_genesis_block_creation() {
        let (identity1, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let (identity2, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let initial_distribution = vec![
            (identity1, 1000),
            (identity2, 500),
        ];
        
        let genesis = Block::genesis(initial_distribution).unwrap();
        
        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.transactions.len(), 2);
        assert!(genesis.validate(None).is_ok());
    }

    #[test]
    fn test_blockchain_creation_and_balances() {
        let (identity1, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let (identity2, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let initial_distribution = vec![
            (identity1.clone(), 1000),
            (identity2.clone(), 500),
        ];
        
        let genesis = Block::genesis(initial_distribution).unwrap();
        let blockchain = Blockchain::new(genesis).unwrap();
        
        assert_eq!(blockchain.get_balance(&identity1.id), 1000);
        assert_eq!(blockchain.get_balance(&identity2.id), 500);
        assert_eq!(blockchain.height(), 0);
    }

    #[test]
    fn test_merkle_root_calculation() {
        // Empty transactions
        let root = Block::calculate_merkle_root(&[]).unwrap();
        assert_eq!(root, vec![0; 32]);
        
        // Single transaction
        let tx = NymTransaction::new(
            crate::transaction::TransactionType::Transfer {
                to: vec![1, 2, 3, 4],
                amount: 100,
            },
            vec![5, 6, 7, 8],
            1,
            10,
        );
        
        let root = Block::calculate_merkle_root(&[tx]).unwrap();
        assert_eq!(root.len(), 32);
        assert_ne!(root, vec![0; 32]);
    }
}
