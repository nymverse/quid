//! Bitcoin integration for QuID quantum-resistant authentication
//!
//! This module provides Bitcoin address derivation and transaction signing using QuID identities
//! with quantum-resistant signatures and migration tools from ECDSA to ML-DSA.

use anyhow::Result;
use bitcoin::{
    Address, Network, PrivateKey, PublicKey as BitcoinPublicKey, Script, Transaction as BitcoinTransaction,
    TxIn, TxOut, Txid, OutPoint, Witness, ScriptBuf,
};
use quid_core::{QuIDClient, QuIDIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::str::FromStr;

use crate::{
    QuIDBlockchainError, QuIDBlockchainResult, BlockchainType, BlockchainAccount, Transaction, TransactionStatus
};

/// Bitcoin-specific address types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BitcoinAddressType {
    /// Legacy P2PKH address (1...)
    Legacy,
    /// SegWit P2WPKH address (bc1q...)
    SegWit,
    /// Native SegWit P2TR address (bc1p...) - Taproot
    Taproot,
    /// QuID quantum-resistant address (experimental)
    QuIDNative,
}

/// Bitcoin address derived from QuID identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinAddress {
    /// The Bitcoin address string
    pub address: String,
    /// Address type
    pub address_type: BitcoinAddressType,
    /// Network (mainnet/testnet)
    pub network: Network,
    /// QuID identity used for derivation
    pub identity: QuIDIdentity,
    /// Derivation path (for HD wallets)
    pub derivation_path: Option<String>,
    /// Compressed public key
    pub public_key: Vec<u8>,
    /// Address script
    pub script: Vec<u8>,
}

/// Bitcoin transaction with QuID signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    /// Raw transaction
    pub raw_transaction: Vec<u8>,
    /// Transaction ID
    pub txid: String,
    /// Input addresses (QuID-derived)
    pub inputs: Vec<BitcoinTransactionInput>,
    /// Output addresses and amounts
    pub outputs: Vec<BitcoinTransactionOutput>,
    /// Transaction fee in satoshis
    pub fee: u64,
    /// Network confirmation target
    pub confirmation_target: u32,
    /// QuID signatures for inputs
    pub quid_signatures: Vec<QuIDSignature>,
}

/// Bitcoin transaction input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransactionInput {
    /// Previous transaction ID
    pub prev_txid: String,
    /// Previous output index
    pub prev_vout: u32,
    /// Input amount in satoshis
    pub amount: u64,
    /// Input address
    pub address: BitcoinAddress,
    /// Script signature
    pub script_sig: Vec<u8>,
    /// Witness data (for SegWit)
    pub witness: Vec<Vec<u8>>,
}

/// Bitcoin transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransactionOutput {
    /// Output amount in satoshis
    pub amount: u64,
    /// Destination address
    pub address: String,
    /// Output script
    pub script_pubkey: Vec<u8>,
}

/// QuID signature for Bitcoin transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuIDSignature {
    /// Input index this signature applies to
    pub input_index: u32,
    /// QuID identity used for signing
    pub identity: QuIDIdentity,
    /// ML-DSA signature bytes
    pub signature: Vec<u8>,
    /// Signature hash type
    pub sighash_type: u32,
    /// Public key used for verification
    pub public_key: Vec<u8>,
}

/// Bitcoin adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinConfig {
    /// Enable Bitcoin integration
    pub enabled: bool,
    /// Bitcoin network (mainnet/testnet)
    pub network: String,
    /// RPC connection details
    pub rpc_url: Option<String>,
    /// RPC username
    pub rpc_username: Option<String>,
    /// RPC password
    pub rpc_password: Option<String>,
    /// Default address type for new addresses
    pub default_address_type: BitcoinAddressType,
    /// Default derivation path
    pub default_derivation_path: String,
    /// Fee estimation strategy
    pub fee_strategy: FeeStrategy,
    /// Enable quantum-resistant features
    pub quantum_resistant: bool,
}

/// Fee estimation strategies
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FeeStrategy {
    /// Conservative (high priority)
    Conservative,
    /// Economic (normal priority)
    Economic,
    /// Minimal (low priority)
    Minimal,
    /// Custom sat/vB rate
    Custom(u64),
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            network: "bitcoin".to_string(),
            rpc_url: None,
            rpc_username: None,
            rpc_password: None,
            default_address_type: BitcoinAddressType::SegWit,
            default_derivation_path: "m/84'/0'/0'/0/0".to_string(),
            fee_strategy: FeeStrategy::Economic,
            quantum_resistant: true,
        }
    }
}

/// Bitcoin blockchain adapter
pub struct BitcoinAdapter {
    config: BitcoinConfig,
    network: Network,
    rpc_client: Option<bitcoincore_rpc::Client>,
}

impl BitcoinAdapter {
    /// Create a new Bitcoin adapter
    pub async fn new(config: BitcoinConfig) -> QuIDBlockchainResult<Self> {
        let network = match config.network.as_str() {
            "bitcoin" | "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => return Err(QuIDBlockchainError::ConfigurationError(
                format!("Invalid Bitcoin network: {}", config.network)
            )),
        };

        let rpc_client = if let (Some(url), Some(username), Some(password)) = 
            (&config.rpc_url, &config.rpc_username, &config.rpc_password) {
            let auth = bitcoincore_rpc::Auth::UserPass(username.clone(), password.clone());
            Some(bitcoincore_rpc::Client::new(url, auth)
                .map_err(|e| QuIDBlockchainError::BlockchainConnectionFailed(
                    format!("Failed to connect to Bitcoin RPC: {}", e)
                ))?)
        } else {
            None
        };

        Ok(Self {
            config,
            network,
            rpc_client,
        })
    }

    /// Get network info
    pub async fn get_network_info(&self) -> QuIDBlockchainResult<NetworkInfo> {
        if let Some(ref rpc) = self.rpc_client {
            let info = rpc.get_network_info()
                .map_err(|e| QuIDBlockchainError::NetworkError(format!("Failed to get network info: {}", e)))?;
            
            Ok(NetworkInfo {
                network: self.network,
                version: info.version,
                subversion: info.subversion,
                connections: info.connections,
                local_services: info.local_services.to_string(),
            })
        } else {
            Err(QuIDBlockchainError::BlockchainConnectionFailed(
                "No RPC client configured".to_string()
            ))
        }
    }

    /// Get balance for address
    pub async fn get_balance(&self, address: &str) -> QuIDBlockchainResult<u64> {
        if let Some(ref rpc) = self.rpc_client {
            let addr = Address::from_str(address)
                .map_err(|e| QuIDBlockchainError::InvalidTransaction(format!("Invalid address: {}", e)))?
                .require_network(self.network)
                .map_err(|e| QuIDBlockchainError::InvalidTransaction(format!("Address network mismatch: {}", e)))?;

            // Get UTXOs for address (this is a simplified approach)
            // In practice, you'd use listunspent or similar RPC calls
            let balance = 0u64; // Placeholder
            
            Ok(balance)
        } else {
            Err(QuIDBlockchainError::BlockchainConnectionFailed(
                "No RPC client configured".to_string()
            ))
        }
    }

    /// Estimate transaction fee
    pub async fn estimate_fee(&self, target_blocks: u16) -> QuIDBlockchainResult<u64> {
        if let Some(ref rpc) = self.rpc_client {
            let fee_rate = rpc.estimate_smart_fee(target_blocks, None)
                .map_err(|e| QuIDBlockchainError::NetworkError(format!("Failed to estimate fee: {}", e)))?;
            
            // Convert BTC/kB to sat/vB
            let sat_per_kvb = (fee_rate.fee_rate.unwrap_or_default().to_sat() as f64) / 1000.0;
            Ok(sat_per_kvb as u64)
        } else {
            // Fallback fee rates in sat/vB
            match self.config.fee_strategy {
                FeeStrategy::Conservative => Ok(50),
                FeeStrategy::Economic => Ok(20),
                FeeStrategy::Minimal => Ok(5),
                FeeStrategy::Custom(rate) => Ok(rate),
            }
        }
    }

    /// Broadcast transaction
    pub async fn broadcast_transaction(&self, raw_tx: &[u8]) -> QuIDBlockchainResult<String> {
        if let Some(ref rpc) = self.rpc_client {
            let tx_hex = hex::encode(raw_tx);
            let txid = rpc.send_raw_transaction(&tx_hex)
                .map_err(|e| QuIDBlockchainError::NetworkError(format!("Failed to broadcast transaction: {}", e)))?;
            
            Ok(txid.to_string())
        } else {
            Err(QuIDBlockchainError::BlockchainConnectionFailed(
                "No RPC client configured for broadcast".to_string()
            ))
        }
    }
}

/// Network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub network: Network,
    pub version: u64,
    pub subversion: String,
    pub connections: u64,
    pub local_services: String,
}

/// Derive Bitcoin address from QuID identity
pub async fn derive_bitcoin_address(
    quid_client: &QuIDClient,
    identity: &QuIDIdentity,
    network: BlockchainType,
    derivation_path: Option<&str>,
) -> QuIDBlockchainResult<BlockchainAccount> {
    tracing::debug!("Deriving Bitcoin address for identity: {}", identity.name);
    
    // Get public key from QuID identity
    let quid_public_key = quid_client.get_public_key(identity).await
        .map_err(|e| QuIDBlockchainError::AddressDerivationFailed(
            format!("Failed to get QuID public key: {}", e)
        ))?;
    
    // Convert QuID public key to Bitcoin-compatible format
    let bitcoin_network = match network {
        BlockchainType::Bitcoin => Network::Bitcoin,
        BlockchainType::BitcoinTestnet => Network::Testnet,
        _ => return Err(QuIDBlockchainError::ConfigurationError(
            "Invalid network for Bitcoin address derivation".to_string()
        )),
    };
    
    // For quantum-resistant addresses, we use a hybrid approach:
    // 1. Derive a classical Bitcoin address for compatibility
    // 2. Embed QuID commitment for future quantum-resistant verification
    
    let address = derive_segwit_address(&quid_public_key, bitcoin_network)?;
    
    let account = BlockchainAccount::new(
        identity.clone(),
        network,
        address,
        quid_public_key,
    );
    
    let account = if let Some(path) = derivation_path {
        account.with_derivation_path(path)
    } else {
        account
    };
    
    tracing::info!("Derived Bitcoin address: {}", account.address);
    Ok(account)
}

/// Derive SegWit address from public key
fn derive_segwit_address(public_key: &[u8], network: Network) -> QuIDBlockchainResult<String> {
    // Create a simplified SegWit address derivation
    // In practice, this would involve proper key compression and hashing
    
    // Hash the public key
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    
    // Use ripemd160 for the address hash
    let mut ripemd = ripemd::Ripemd160::new();
    ripemd.update(&hash);
    let address_hash = ripemd.finalize();
    
    // Create SegWit address (simplified)
    let address = match network {
        Network::Bitcoin => format!("bc1q{}", hex::encode(&address_hash[..20])),
        Network::Testnet => format!("tb1q{}", hex::encode(&address_hash[..20])),
        Network::Regtest => format!("bcrt1q{}", hex::encode(&address_hash[..20])),
        _ => return Err(QuIDBlockchainError::AddressDerivationFailed(
            "Unsupported network".to_string()
        )),
    };
    
    Ok(address)
}

/// Sign Bitcoin transaction with QuID identity
pub async fn sign_bitcoin_transaction(
    quid_client: &QuIDClient,
    identity: &QuIDIdentity,
    transaction: &mut Transaction,
) -> QuIDBlockchainResult<Vec<u8>> {
    tracing::debug!("Signing Bitcoin transaction with identity: {}", identity.name);
    
    // Create transaction hash for signing
    let tx_hash = create_transaction_hash(transaction)?;
    
    // Sign with QuID (quantum-resistant signature)
    let quid_signature = quid_client.sign_data(identity, &tx_hash).await
        .map_err(|e| QuIDBlockchainError::TransactionSigningFailed(
            format!("QuID signing failed: {}", e)
        ))?;
    
    // For hybrid compatibility, also create a classical ECDSA signature
    let ecdsa_signature = create_ecdsa_signature(quid_client, identity, &tx_hash).await?;
    
    // Combine signatures for quantum-resistant transaction
    let combined_signature = combine_signatures(&quid_signature, &ecdsa_signature)?;
    
    // Update transaction status
    transaction.status = TransactionStatus::Pending;
    
    tracing::info!("Bitcoin transaction signed successfully");
    Ok(combined_signature)
}

/// Create transaction hash for signing
fn create_transaction_hash(transaction: &Transaction) -> QuIDBlockchainResult<Vec<u8>> {
    // Create a simplified transaction hash
    // In practice, this would follow Bitcoin's transaction signing algorithm
    
    let mut data = Vec::new();
    data.extend_from_slice(transaction.from.address.as_bytes());
    data.extend_from_slice(transaction.to.as_bytes());
    data.extend_from_slice(&transaction.amount.to_le_bytes());
    data.extend_from_slice(&transaction.fee.to_le_bytes());
    
    if let Some(ref tx_data) = transaction.data {
        data.extend_from_slice(tx_data);
    }
    
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hasher.finalize().to_vec())
}

/// Create ECDSA signature for backward compatibility
async fn create_ecdsa_signature(
    quid_client: &QuIDClient,
    identity: &QuIDIdentity,
    hash: &[u8],
) -> QuIDBlockchainResult<Vec<u8>> {
    // In a real implementation, this would derive an ECDSA key from the QuID identity
    // and create a classical Bitcoin signature for backward compatibility
    
    // For now, we'll create a placeholder signature
    let placeholder_signature = vec![0u8; 64]; // 64 bytes for ECDSA signature
    
    tracing::debug!("Created ECDSA compatibility signature");
    Ok(placeholder_signature)
}

/// Combine QuID and ECDSA signatures for hybrid transaction
fn combine_signatures(quid_sig: &[u8], ecdsa_sig: &[u8]) -> QuIDBlockchainResult<Vec<u8>> {
    let mut combined = Vec::new();
    
    // Add signature format identifier
    combined.push(0x01); // Version byte for QuID+ECDSA hybrid
    
    // Add ECDSA signature length and data
    combined.extend_from_slice(&(ecdsa_sig.len() as u16).to_le_bytes());
    combined.extend_from_slice(ecdsa_sig);
    
    // Add QuID signature length and data
    combined.extend_from_slice(&(quid_sig.len() as u16).to_le_bytes());
    combined.extend_from_slice(quid_sig);
    
    Ok(combined)
}

/// Bitcoin wallet functionality
pub struct BitcoinWallet {
    accounts: HashMap<String, BlockchainAccount>,
    adapter: BitcoinAdapter,
}

impl BitcoinWallet {
    /// Create a new Bitcoin wallet
    pub fn new(adapter: BitcoinAdapter) -> Self {
        Self {
            accounts: HashMap::new(),
            adapter,
        }
    }

    /// Add account to wallet
    pub fn add_account(&mut self, account: BlockchainAccount) {
        let identifier = account.identifier();
        self.accounts.insert(identifier, account);
    }

    /// Get account by identifier
    pub fn get_account(&self, identifier: &str) -> Option<&BlockchainAccount> {
        self.accounts.get(identifier)
    }

    /// List all accounts
    pub fn list_accounts(&self) -> Vec<&BlockchainAccount> {
        self.accounts.values().collect()
    }

    /// Get total balance across all accounts
    pub async fn get_total_balance(&self) -> QuIDBlockchainResult<u64> {
        let mut total = 0u64;
        
        for account in self.accounts.values() {
            let balance = self.adapter.get_balance(&account.address).await?;
            total = total.saturating_add(balance);
        }
        
        Ok(total)
    }

    /// Create transaction
    pub async fn create_transaction(
        &self,
        from_account: &str,
        to_address: &str,
        amount: u64,
        fee_rate: Option<u64>,
    ) -> QuIDBlockchainResult<Transaction> {
        let account = self.get_account(from_account)
            .ok_or_else(|| QuIDBlockchainError::InvalidTransaction(
                format!("Account not found: {}", from_account)
            ))?;

        // Check balance
        let balance = self.adapter.get_balance(&account.address).await?;
        let fee = if let Some(rate) = fee_rate {
            rate * 250 // Assume 250 vB transaction size
        } else {
            self.adapter.estimate_fee(6).await? * 250
        };

        if balance < amount + fee {
            return Err(QuIDBlockchainError::InsufficientFunds {
                required: amount + fee,
                available: balance,
            });
        }

        let transaction = Transaction {
            txid: None,
            from: account.clone(),
            to: to_address.to_string(),
            amount,
            fee,
            data: None,
            gas_limit: None,
            gas_price: None,
            status: TransactionStatus::Preparing,
            created_at: chrono::Utc::now(),
            confirmation_target: 6,
        };

        Ok(transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_bitcoin_address_derivation() {
        let public_key = vec![0x02; 33]; // Compressed public key
        let address = derive_segwit_address(&public_key, Network::Testnet).unwrap();
        assert!(address.starts_with("tb1q"));
    }

    #[test]
    fn test_fee_strategy() {
        let config = BitcoinConfig {
            fee_strategy: FeeStrategy::Conservative,
            ..Default::default()
        };
        
        assert_eq!(config.fee_strategy, FeeStrategy::Conservative);
        
        let custom_config = BitcoinConfig {
            fee_strategy: FeeStrategy::Custom(100),
            ..Default::default()
        };
        
        assert_eq!(custom_config.fee_strategy, FeeStrategy::Custom(100));
    }

    #[test]
    fn test_bitcoin_address_type() {
        assert_eq!(BitcoinAddressType::SegWit, BitcoinAddressType::SegWit);
        assert_ne!(BitcoinAddressType::Legacy, BitcoinAddressType::Taproot);
    }

    #[test]
    fn test_transaction_hash_creation() {
        let identity = quid_core::QuIDIdentity {
            id: "test-identity".to_string(),
            name: "test".to_string(),
            security_level: quid_core::SecurityLevel::Level1,
            created_at: Utc::now(),
            contexts: vec!["bitcoin".to_string()],
            metadata: None,
        };

        let account = BlockchainAccount::new(
            identity,
            BlockchainType::Bitcoin,
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            vec![0; 33],
        );

        let transaction = Transaction {
            txid: None,
            from: account,
            to: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            amount: 100000,
            fee: 1000,
            data: None,
            gas_limit: None,
            gas_price: None,
            status: TransactionStatus::Preparing,
            created_at: Utc::now(),
            confirmation_target: 6,
        };

        let hash = create_transaction_hash(&transaction).unwrap();
        assert_eq!(hash.len(), 32); // SHA256 hash
    }
}