//! NYM token transactions and transaction pool

use crate::{NymAmount, Result, ConsensusError};
use quid_core::crypto::KeyPair;
use quid_core::QuIDIdentity;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Different types of transactions in the NYM system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    /// Transfer NYM tokens between QuID identities
    Transfer {
        to: Vec<u8>,    // Recipient QuID ID
        amount: NymAmount,
    },
    /// Register a new domain
    DomainRegistration {
        domain: String,  // e.g., "alice.quid"
        fee: NymAmount,
    },
    /// Transfer domain ownership
    DomainTransfer {
        domain: String,
        to: Vec<u8>,    // New owner QuID ID
        fee: NymAmount,
    },
    /// Validator staking
    ValidatorStake {
        amount: NymAmount,
    },
    /// Validator unstaking
    ValidatorUnstake {
        amount: NymAmount,
    },
}

/// A transaction in the NYM consensus system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NymTransaction {
    /// Transaction type and parameters
    pub tx_type: TransactionType,
    
    /// Sender's QuID identity ID
    pub from: Vec<u8>,
    
    /// Transaction nonce (prevents replay attacks)
    pub nonce: u64,
    
    /// Transaction fee
    pub fee: NymAmount,
    
    /// Timestamp when transaction was created
    pub timestamp: u64,
    
    /// Transaction signature (signed by sender's QuID)
    pub signature: Vec<u8>,
    
    /// Protocol version
    pub version: String,
}

impl NymTransaction {
    /// Create a new transaction (without signature)
    pub fn new(
        tx_type: TransactionType,
        from: Vec<u8>,
        nonce: u64,
        fee: NymAmount,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            tx_type,
            from,
            nonce,
            fee,
            timestamp,
            signature: Vec::new(),
            version: crate::CONSENSUS_VERSION.to_string(),
        }
    }
    
    /// Sign the transaction with a QuID keypair
    pub fn sign(&mut self, keypair: &KeyPair) -> Result<()> {
        let signing_data = self.signing_data()?;
        self.signature = keypair.sign(&signing_data)
            .map_err(|e| ConsensusError::CryptoError(format!("Signing failed: {}", e)))?;
        Ok(())
    }
    
    /// Verify the transaction signature
    pub fn verify_signature(&self, keypair: &KeyPair) -> Result<bool> {
        let signing_data = self.signing_data()?;
        keypair.verify(&signing_data, &self.signature)
            .map_err(|e| ConsensusError::CryptoError(format!("Verification failed: {}", e)))
    }
    
    /// Get the transaction hash
    pub fn hash(&self) -> Result<Vec<u8>> {
        let tx_bytes = serde_json::to_vec(self)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(&tx_bytes);
        Ok(hasher.finalize().to_vec())
    }
    
    /// Get data that should be signed (excludes signature field)
    fn signing_data(&self) -> Result<Vec<u8>> {
        let signing_tx = SignableTx {
            tx_type: &self.tx_type,
            from: &self.from,
            nonce: self.nonce,
            fee: self.fee,
            timestamp: self.timestamp,
            version: &self.version,
        };
        
        serde_json::to_vec(&signing_tx)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))
    }
}

/// Transaction data for signing (excludes signature to avoid recursion)
#[derive(Serialize)]
struct SignableTx<'a> {
    tx_type: &'a TransactionType,
    from: &'a [u8],
    nonce: u64,
    fee: NymAmount,
    timestamp: u64,
    version: &'a str,
}

/// Transaction pool for managing pending transactions
#[derive(Debug, Default)]
pub struct TransactionPool {
    /// Pending transactions by sender (QuID ID)
    pending: HashMap<Vec<u8>, VecDeque<NymTransaction>>,
    
    /// Transaction hashes to prevent duplicates
    known_hashes: HashMap<Vec<u8>, ()>,
    
    /// Maximum transactions per sender
    max_per_sender: usize,
}

impl TransactionPool {
    /// Create a new transaction pool
    pub fn new(max_per_sender: usize) -> Self {
        Self {
            pending: HashMap::new(),
            known_hashes: HashMap::new(),
            max_per_sender,
        }
    }
    
    /// Add a transaction to the pool
    pub fn add_transaction(&mut self, tx: NymTransaction) -> Result<()> {
        // Check if we already have this transaction
        let tx_hash = tx.hash()?;
        if self.known_hashes.contains_key(&tx_hash) {
            return Err(ConsensusError::DuplicateTransaction);
        }
        
        // Get sender's queue
        let sender_queue = self.pending.entry(tx.from.clone()).or_insert_with(VecDeque::new);
        
        // Check sender queue limit
        if sender_queue.len() >= self.max_per_sender {
            return Err(ConsensusError::TransactionPoolFull);
        }
        
        // Validate nonce ordering
        if let Some(last_tx) = sender_queue.back() {
            if tx.nonce <= last_tx.nonce {
                return Err(ConsensusError::InvalidNonce {
                    expected: last_tx.nonce + 1,
                    got: tx.nonce,
                });
            }
        }
        
        // Add transaction
        sender_queue.push_back(tx);
        self.known_hashes.insert(tx_hash, ());
        
        Ok(())
    }
    
    /// Get next transactions for a block (up to limit)
    pub fn get_next_transactions(&mut self, limit: usize) -> Vec<NymTransaction> {
        let mut transactions = Vec::new();
        let mut senders_to_remove = Vec::new();
        
        // Collect transactions from all senders
        for (sender, queue) in &mut self.pending {
            if transactions.len() >= limit {
                break;
            }
            
            if let Some(tx) = queue.pop_front() {
                // Remove from known hashes
                if let Ok(hash) = tx.hash() {
                    self.known_hashes.remove(&hash);
                }
                transactions.push(tx);
            }
            
            if queue.is_empty() {
                senders_to_remove.push(sender.clone());
            }
        }
        
        // Clean up empty queues
        for sender in senders_to_remove {
            self.pending.remove(&sender);
        }
        
        transactions
    }
    
    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        self.pending.values().map(|queue| queue.len()).sum()
    }
    
    /// Remove transactions from pool (e.g., after block confirmation)
    pub fn remove_transactions(&mut self, tx_hashes: &[Vec<u8>]) {
        for hash in tx_hashes {
            self.known_hashes.remove(hash);
        }
        
        // Remove from pending queues (this is simplified - production would be more efficient)
        let mut senders_to_remove = Vec::new();
        for (sender, queue) in &mut self.pending {
            queue.retain(|tx| {
                if let Ok(tx_hash) = tx.hash() {
                    !tx_hashes.contains(&tx_hash)
                } else {
                    true // Keep if we can't hash
                }
            });
            
            if queue.is_empty() {
                senders_to_remove.push(sender.clone());
            }
        }
        
        for sender in senders_to_remove {
            self.pending.remove(&sender);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;

    #[test]
    fn test_transaction_creation() {
        let tx_type = TransactionType::Transfer {
            to: vec![1, 2, 3, 4],
            amount: 100,
        };
        
        let tx = NymTransaction::new(
            tx_type,
            vec![5, 6, 7, 8],
            1,
            10,
        );
        
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.fee, 10);
        assert!(tx.signature.is_empty()); // Not signed yet
    }

    #[test]
    fn test_transaction_signing_and_verification() {
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let tx_type = TransactionType::Transfer {
            to: vec![1, 2, 3, 4],
            amount: 100,
        };
        
        let mut tx = NymTransaction::new(
            tx_type,
            identity.id.clone(),
            1,
            10,
        );
        
        // Sign transaction
        tx.sign(&keypair).unwrap();
        assert!(!tx.signature.is_empty());
        
        // Verify signature
        assert!(tx.verify_signature(&keypair).unwrap());
    }

    #[test]
    fn test_transaction_pool() {
        let mut pool = TransactionPool::new(10);
        
        let tx = NymTransaction::new(
            TransactionType::Transfer {
                to: vec![1, 2, 3, 4],
                amount: 100,
            },
            vec![5, 6, 7, 8],
            1,
            10,
        );
        
        pool.add_transaction(tx).unwrap();
        assert_eq!(pool.pending_count(), 1);
        
        let next_txs = pool.get_next_transactions(5);
        assert_eq!(next_txs.len(), 1);
        assert_eq!(pool.pending_count(), 0);
    }
}
