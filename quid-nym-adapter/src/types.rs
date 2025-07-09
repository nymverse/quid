//! Type definitions for Nym adapter

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::PrivacyLevel;

/// Nym transaction structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NymTransaction {
    /// Transaction ID
    pub id: String,
    /// Sender address
    pub from: String,
    /// Recipient address
    pub to: String,
    /// Transaction amount
    pub amount: u128,
    /// Transaction fee
    pub fee: u128,
    /// Privacy level
    pub privacy_level: PrivacyLevel,
    /// Transaction nonce
    pub nonce: u64,
    /// Transaction data
    pub data: Vec<u8>,
    /// Privacy proof (for shielded/anonymous transactions)
    pub privacy_proof: Option<PrivacyProof>,
    /// Mixnet routing info (for mixnet transactions)
    pub mixnet_routing: Option<MixnetRouting>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Privacy proof for shielded transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyProof {
    /// Proof type
    pub proof_type: ProofType,
    /// Proof data
    pub proof_data: Vec<u8>,
    /// Nullifiers (for double-spend prevention)
    pub nullifiers: Vec<Vec<u8>>,
    /// Commitments
    pub commitments: Vec<Vec<u8>>,
}

/// Proof type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ProofType {
    /// Zero-knowledge STARK proof
    ZkStark,
    /// Bulletproof range proof
    Bulletproof,
    /// Groth16 zkSNARK
    Groth16,
    /// PLONK proof
    Plonk,
}

/// Mixnet routing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetRouting {
    /// Entry gateway
    pub entry_gateway: String,
    /// Mix nodes path
    pub mix_path: Vec<String>,
    /// Exit gateway
    pub exit_gateway: String,
    /// Routing metadata
    pub metadata: Vec<u8>,
    /// Delay parameters
    pub delays: Vec<u32>,
}

/// Nym smart contract call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NymContractCall {
    /// Contract address
    pub contract_address: String,
    /// Method name
    pub method: String,
    /// Method parameters
    pub params: Vec<u8>,
    /// Privacy level for the call
    pub privacy_level: PrivacyLevel,
    /// Gas limit
    pub gas_limit: u64,
}

/// Nym contract response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NymContractResponse {
    /// Success status
    pub success: bool,
    /// Return data
    pub data: Vec<u8>,
    /// Gas used
    pub gas_used: u64,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Shielded pool information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedPool {
    /// Pool ID
    pub pool_id: String,
    /// Total shielded value
    pub total_value: u128,
    /// Number of notes
    pub note_count: u64,
    /// Merkle tree root
    pub merkle_root: Vec<u8>,
    /// Last update
    pub last_update: DateTime<Utc>,
}

/// Anonymous note for private transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousNote {
    /// Note commitment
    pub commitment: Vec<u8>,
    /// Encrypted value
    pub encrypted_value: Vec<u8>,
    /// Encrypted recipient
    pub encrypted_recipient: Vec<u8>,
    /// Nullifier (spent indicator)
    pub nullifier: Option<Vec<u8>>,
}

/// Nym network statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NymNetworkStats {
    /// Current block height
    pub block_height: u64,
    /// Active validators
    pub validator_count: u32,
    /// Total staked amount
    pub total_staked: u128,
    /// Network TPS
    pub transactions_per_second: f64,
    /// Mixnet nodes count
    pub mixnet_nodes: u32,
    /// Active gateways
    pub gateway_count: u32,
}

/// Address type for Nym
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum NymAddressType {
    /// Standard public address
    Standard,
    /// Shielded address
    Shielded,
    /// Anonymous address (one-time use)
    Anonymous,
    /// Smart contract address
    Contract,
}

/// Transaction fee structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NymFeeStructure {
    /// Base transaction fee
    pub base_fee: u128,
    /// Privacy premium for shielded transactions
    pub privacy_premium: u128,
    /// Mixnet routing fee
    pub mixnet_fee: u128,
    /// Smart contract execution fee per gas
    pub gas_price: u128,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_privacy_level_serialization() {
        let level = PrivacyLevel::Anonymous;
        let serialized = serde_json::to_string(&level).unwrap();
        let deserialized: PrivacyLevel = serde_json::from_str(&serialized).unwrap();
        assert_eq!(level, deserialized);
    }
    
    #[test]
    fn test_proof_type_serialization() {
        let proof_type = ProofType::ZkStark;
        let serialized = serde_json::to_string(&proof_type).unwrap();
        let deserialized: ProofType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(proof_type, deserialized);
    }
    
    #[test]
    fn test_nym_transaction_creation() {
        let tx = NymTransaction {
            id: "tx123".to_string(),
            from: "nym1sender...".to_string(),
            to: "nym1recipient...".to_string(),
            amount: 1000,
            fee: 10,
            privacy_level: PrivacyLevel::Shielded,
            nonce: 1,
            data: vec![],
            privacy_proof: None,
            mixnet_routing: None,
            timestamp: Utc::now(),
        };
        
        assert_eq!(tx.id, "tx123");
        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.privacy_level, PrivacyLevel::Shielded);
    }
}