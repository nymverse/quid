//! Universal blockchain adapter framework for QuID integration
//!
//! This module provides a generic framework for integrating any blockchain with QuID
//! quantum-resistant authentication, including custom chains, Layer 2 solutions,
//! and emerging blockchain protocols.

use anyhow::Result;
use quid_core::{QuIDClient, QuIDIdentity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;

use crate::{
    QuIDBlockchainError, QuIDBlockchainResult, BlockchainType, BlockchainAccount, Transaction, TransactionStatus,
    config::{CustomBlockchainConfig, AddressFormat, SignatureAlgorithm, AdapterSettings}
};

/// Universal blockchain network definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainNetwork {
    /// Network identifier
    pub id: String,
    /// Display name
    pub name: String,
    /// Network type/family
    pub network_type: NetworkType,
    /// Chain configuration
    pub config: CustomBlockchainConfig,
    /// Network status
    pub status: NetworkStatus,
    /// Supported features
    pub features: NetworkFeatures,
}

/// Network type categories
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkType {
    /// Bitcoin-like UTXO chains
    UTXO,
    /// Ethereum-like account-based chains
    Account,
    /// DAG-based networks
    DAG,
    /// Substrate-based chains
    Substrate,
    /// Cosmos SDK chains
    Cosmos,
    /// Layer 2 solutions
    Layer2,
    /// Custom/unknown type
    Custom,
}

/// Network operational status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkStatus {
    /// Network is operational
    Active,
    /// Network is temporarily unavailable
    Inactive,
    /// Network is under maintenance
    Maintenance,
    /// Network is deprecated
    Deprecated,
}

/// Network feature capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFeatures {
    /// Supports smart contracts
    pub smart_contracts: bool,
    /// Supports multi-signature
    pub multisig: bool,
    /// Supports privacy features
    pub privacy: bool,
    /// Supports atomic swaps
    pub atomic_swaps: bool,
    /// Supports staking
    pub staking: bool,
    /// Supports governance
    pub governance: bool,
    /// Native quantum resistance
    pub quantum_resistant: bool,
}

/// Universal blockchain transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainTransaction {
    /// Network identifier
    pub network_id: String,
    /// Transaction data
    pub transaction: Transaction,
    /// Network-specific metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Raw transaction bytes
    pub raw_transaction: Option<Vec<u8>>,
    /// Network-specific signature
    pub network_signature: Option<Vec<u8>>,
    /// QuID quantum-resistant signature
    pub quid_signature: Option<Vec<u8>>,
}

/// Generic blockchain adapter trait
#[async_trait]
pub trait BlockchainAdapter: Send + Sync {
    /// Get adapter name
    fn name(&self) -> &str;
    
    /// Get network information
    async fn get_network_info(&self) -> QuIDBlockchainResult<BlockchainNetwork>;
    
    /// Derive address from QuID identity
    async fn derive_address(
        &self,
        quid_client: &QuIDClient,
        identity: &QuIDIdentity,
        derivation_path: Option<&str>,
    ) -> QuIDBlockchainResult<BlockchainAccount>;
    
    /// Get balance for address
    async fn get_balance(&self, address: &str) -> QuIDBlockchainResult<u64>;
    
    /// Estimate transaction fee
    async fn estimate_fee(&self, transaction: &Transaction) -> QuIDBlockchainResult<u64>;
    
    /// Sign transaction
    async fn sign_transaction(
        &self,
        quid_client: &QuIDClient,
        identity: &QuIDIdentity,
        transaction: &mut Transaction,
    ) -> QuIDBlockchainResult<Vec<u8>>;
    
    /// Broadcast transaction
    async fn broadcast_transaction(&self, raw_tx: &[u8]) -> QuIDBlockchainResult<String>;
    
    /// Get transaction status
    async fn get_transaction_status(&self, txid: &str) -> QuIDBlockchainResult<TransactionStatus>;
    
    /// Validate address format
    fn validate_address(&self, address: &str) -> bool;
}

/// Universal blockchain adapter implementation
pub struct UniversalBlockchainAdapter {
    network: BlockchainNetwork,
    settings: AdapterSettings,
    http_client: reqwest::Client,
    address_generator: AddressGenerator,
    signature_provider: SignatureProvider,
}

/// Address generation for different formats
pub struct AddressGenerator {
    format: AddressFormat,
}

/// Signature provider for different algorithms
pub struct SignatureProvider {
    algorithm: SignatureAlgorithm,
}

impl UniversalBlockchainAdapter {
    /// Create a new universal adapter
    pub async fn new(
        network: BlockchainNetwork,
        settings: AdapterSettings,
    ) -> QuIDBlockchainResult<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(settings.connection_timeout))
            .build()
            .map_err(|e| QuIDBlockchainError::BlockchainConnectionFailed(
                format!("Failed to create HTTP client: {}", e)
            ))?;

        let address_generator = AddressGenerator::new(network.config.address_format.clone());
        let signature_provider = SignatureProvider::new(network.config.signature_algorithm.clone());

        Ok(Self {
            network,
            settings,
            http_client,
            address_generator,
            signature_provider,
        })
    }

    /// Get network configuration
    pub fn get_network(&self) -> &BlockchainNetwork {
        &self.network
    }

    /// Update network status
    pub fn update_status(&mut self, status: NetworkStatus) {
        self.network.status = status;
    }

    /// Check if network supports feature
    pub fn supports_feature(&self, feature: &str) -> bool {
        match feature {
            "smart_contracts" => self.network.features.smart_contracts,
            "multisig" => self.network.features.multisig,
            "privacy" => self.network.features.privacy,
            "atomic_swaps" => self.network.features.atomic_swaps,
            "staking" => self.network.features.staking,
            "governance" => self.network.features.governance,
            "quantum_resistant" => self.network.features.quantum_resistant,
            _ => false,
        }
    }

    /// Make RPC call to blockchain
    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> QuIDBlockchainResult<serde_json::Value> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let mut attempt = 0;
        loop {
            let response = self.http_client
                .post(&self.network.config.rpc_url)
                .json(&request_body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let json: serde_json::Value = resp.json().await
                            .map_err(|e| QuIDBlockchainError::NetworkError(
                                format!("Failed to parse RPC response: {}", e)
                            ))?;

                        if let Some(error) = json.get("error") {
                            return Err(QuIDBlockchainError::NetworkError(
                                format!("RPC error: {}", error)
                            ));
                        }

                        return Ok(json["result"].clone());
                    } else {
                        return Err(QuIDBlockchainError::NetworkError(
                            format!("RPC call failed with status: {}", resp.status())
                        ));
                    }
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= self.settings.retry_attempts {
                        return Err(QuIDBlockchainError::NetworkError(
                            format!("RPC call failed after {} attempts: {}", attempt, e)
                        ));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(self.settings.retry_delay)).await;
                }
            }
        }
    }
}

#[async_trait]
impl BlockchainAdapter for UniversalBlockchainAdapter {
    fn name(&self) -> &str {
        &self.network.name
    }

    async fn get_network_info(&self) -> QuIDBlockchainResult<BlockchainNetwork> {
        // Try to get latest network info via RPC
        match self.network.network_type {
            NetworkType::Account => {
                // Ethereum-like chains
                let _chain_id = self.rpc_call("eth_chainId", serde_json::Value::Null).await?;
                let _block_number = self.rpc_call("eth_blockNumber", serde_json::Value::Null).await?;
            }
            NetworkType::UTXO => {
                // Bitcoin-like chains
                let _info = self.rpc_call("getblockchaininfo", serde_json::Value::Null).await?;
            }
            _ => {
                // Other chain types - implement as needed
            }
        }

        Ok(self.network.clone())
    }

    async fn derive_address(
        &self,
        quid_client: &QuIDClient,
        identity: &QuIDIdentity,
        derivation_path: Option<&str>,
    ) -> QuIDBlockchainResult<BlockchainAccount> {
        tracing::debug!("Deriving {} address for identity: {}", self.network.name, identity.name);

        // Get public key from QuID identity
        let quid_public_key = quid_client.get_public_key(identity).await
            .map_err(|e| QuIDBlockchainError::AddressDerivationFailed(
                format!("Failed to get QuID public key: {}", e)
            ))?;

        // Generate address using the appropriate format
        let address = self.address_generator.generate_address(&quid_public_key, &self.network)?;

        let mut account = BlockchainAccount::new(
            identity.clone(),
            BlockchainType::Custom(self.network.id.clone()),
            address,
            quid_public_key,
        );

        if let Some(path) = derivation_path {
            account = account.with_derivation_path(path);
        }

        // Add network-specific metadata
        account = account
            .with_metadata("network_type", &format!("{:?}", self.network.network_type))
            .with_metadata("address_format", &format!("{:?}", self.network.config.address_format))
            .with_metadata("signature_algorithm", &format!("{:?}", self.network.config.signature_algorithm));

        tracing::info!("Derived {} address: {}", self.network.name, account.address);
        Ok(account)
    }

    async fn get_balance(&self, address: &str) -> QuIDBlockchainResult<u64> {
        if !self.validate_address(address) {
            return Err(QuIDBlockchainError::InvalidTransaction(
                format!("Invalid address format: {}", address)
            ));
        }

        match self.network.network_type {
            NetworkType::Account => {
                // Ethereum-like balance query
                let params = serde_json::json!([address, "latest"]);
                let result = self.rpc_call("eth_getBalance", params).await?;
                
                if let Some(balance_hex) = result.as_str() {
                    let balance = u64::from_str_radix(balance_hex.trim_start_matches("0x"), 16)
                        .map_err(|e| QuIDBlockchainError::EncodingError(
                            format!("Failed to parse balance: {}", e)
                        ))?;
                    Ok(balance)
                } else {
                    Err(QuIDBlockchainError::NetworkError("Invalid balance response".to_string()))
                }
            }
            NetworkType::UTXO => {
                // Bitcoin-like UTXO query
                let params = serde_json::json!([address]);
                let result = self.rpc_call("getaddressinfo", params).await?;
                
                // This would typically require scanning UTXOs
                // For now, return a placeholder
                Ok(0)
            }
            _ => {
                // Other network types
                Ok(0)
            }
        }
    }

    async fn estimate_fee(&self, transaction: &Transaction) -> QuIDBlockchainResult<u64> {
        match self.network.network_type {
            NetworkType::Account => {
                // Ethereum-like gas estimation
                let params = serde_json::json!([{
                    "from": transaction.from.address,
                    "to": transaction.to,
                    "value": format!("0x{:x}", transaction.amount),
                    "data": transaction.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_default()
                }]);
                
                let gas_estimate = self.rpc_call("eth_estimateGas", params).await?;
                let gas_price = self.rpc_call("eth_gasPrice", serde_json::Value::Null).await?;
                
                if let (Some(gas_hex), Some(price_hex)) = (gas_estimate.as_str(), gas_price.as_str()) {
                    let gas = u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16)
                        .map_err(|e| QuIDBlockchainError::EncodingError(format!("Failed to parse gas: {}", e)))?;
                    let price = u64::from_str_radix(price_hex.trim_start_matches("0x"), 16)
                        .map_err(|e| QuIDBlockchainError::EncodingError(format!("Failed to parse gas price: {}", e)))?;
                    
                    Ok(gas * price)
                } else {
                    Err(QuIDBlockchainError::NetworkError("Invalid fee estimation response".to_string()))
                }
            }
            NetworkType::UTXO => {
                // Bitcoin-like fee estimation
                let target_blocks = transaction.confirmation_target.max(1);
                let params = serde_json::json!([target_blocks]);
                let result = self.rpc_call("estimatesmartfee", params).await?;
                
                if let Some(fee_rate) = result.get("feerate").and_then(|f| f.as_f64()) {
                    // Estimate transaction size and calculate fee
                    let tx_size = 250; // Estimated transaction size in bytes
                    let fee_btc = fee_rate * (tx_size as f64 / 1000.0);
                    let fee_sat = (fee_btc * 100_000_000.0) as u64;
                    Ok(fee_sat)
                } else {
                    Ok(1000) // Default fee in satoshis
                }
            }
            _ => {
                // Default fee estimation
                Ok(self.network.config.block_time * 1000) // Simple heuristic
            }
        }
    }

    async fn sign_transaction(
        &self,
        quid_client: &QuIDClient,
        identity: &QuIDIdentity,
        transaction: &mut Transaction,
    ) -> QuIDBlockchainResult<Vec<u8>> {
        tracing::debug!("Signing {} transaction with identity: {}", self.network.name, identity.name);

        // Create transaction hash based on network type
        let tx_hash = self.create_transaction_hash(transaction)?;

        // Sign with QuID (quantum-resistant signature)
        let quid_signature = quid_client.sign_data(identity, &tx_hash).await
            .map_err(|e| QuIDBlockchainError::TransactionSigningFailed(
                format!("QuID signing failed: {}", e)
            ))?;

        // Create network-compatible signature if needed
        let network_signature = self.signature_provider.create_network_signature(
            quid_client,
            identity,
            &tx_hash,
            &self.network.config.signature_algorithm,
        ).await?;

        // Create combined signature for quantum resistance
        let combined_signature = self.combine_signatures(&quid_signature, &network_signature)?;

        // Update transaction status
        transaction.status = TransactionStatus::Pending;

        tracing::info!("{} transaction signed successfully", self.network.name);
        Ok(combined_signature)
    }

    async fn broadcast_transaction(&self, raw_tx: &[u8]) -> QuIDBlockchainResult<String> {
        let tx_hex = hex::encode(raw_tx);

        let params = match self.network.network_type {
            NetworkType::Account => {
                // Ethereum-like broadcast
                serde_json::json!([format!("0x{}", tx_hex)])
            }
            NetworkType::UTXO => {
                // Bitcoin-like broadcast
                serde_json::json!([tx_hex])
            }
            _ => {
                // Generic broadcast
                serde_json::json!([tx_hex])
            }
        };

        let method = match self.network.network_type {
            NetworkType::Account => "eth_sendRawTransaction",
            NetworkType::UTXO => "sendrawtransaction",
            _ => "broadcast_transaction",
        };

        let result = self.rpc_call(method, params).await?;
        
        if let Some(txid) = result.as_str() {
            Ok(txid.to_string())
        } else {
            Err(QuIDBlockchainError::NetworkError("Invalid broadcast response".to_string()))
        }
    }

    async fn get_transaction_status(&self, txid: &str) -> QuIDBlockchainResult<TransactionStatus> {
        let params = serde_json::json!([txid]);
        
        let method = match self.network.network_type {
            NetworkType::Account => "eth_getTransactionReceipt",
            NetworkType::UTXO => "gettransaction",
            _ => "get_transaction",
        };

        match self.rpc_call(method, params).await {
            Ok(result) => {
                if result.is_null() {
                    Ok(TransactionStatus::Pending)
                } else if let Some(confirmations) = result.get("confirmations").and_then(|c| c.as_u64()) {
                    Ok(TransactionStatus::Confirmed { confirmations: confirmations as u32 })
                } else if result.get("blockNumber").is_some() {
                    // Ethereum-style confirmation
                    Ok(TransactionStatus::Confirmed { confirmations: 1 })
                } else {
                    Ok(TransactionStatus::Broadcast)
                }
            }
            Err(_) => Ok(TransactionStatus::Pending),
        }
    }

    fn validate_address(&self, address: &str) -> bool {
        self.address_generator.validate_address(address, &self.network.config.address_format)
    }
}

impl UniversalBlockchainAdapter {
    /// Create transaction hash for signing
    fn create_transaction_hash(&self, transaction: &Transaction) -> QuIDBlockchainResult<Vec<u8>> {
        use sha2::{Sha256, Digest};
        
        let mut data = Vec::new();
        
        // Add network identifier
        data.extend_from_slice(self.network.id.as_bytes());
        
        // Add transaction data
        data.extend_from_slice(transaction.from.address.as_bytes());
        data.extend_from_slice(transaction.to.as_bytes());
        data.extend_from_slice(&transaction.amount.to_le_bytes());
        data.extend_from_slice(&transaction.fee.to_le_bytes());
        
        if let Some(ref tx_data) = transaction.data {
            data.extend_from_slice(tx_data);
        }
        
        // Add network-specific fields
        if let Some(gas_limit) = transaction.gas_limit {
            data.extend_from_slice(&gas_limit.to_le_bytes());
        }
        
        if let Some(gas_price) = transaction.gas_price {
            data.extend_from_slice(&gas_price.to_le_bytes());
        }
        
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hasher.finalize().to_vec())
    }

    /// Combine quantum-resistant and network signatures
    fn combine_signatures(
        &self,
        quid_sig: &[u8],
        network_sig: &[u8],
    ) -> QuIDBlockchainResult<Vec<u8>> {
        let mut combined = Vec::new();
        
        // Add signature format identifier
        combined.push(0x02); // Version byte for QuID+Network hybrid
        
        // Add network signature length and data
        combined.extend_from_slice(&(network_sig.len() as u16).to_le_bytes());
        combined.extend_from_slice(network_sig);
        
        // Add QuID signature length and data
        combined.extend_from_slice(&(quid_sig.len() as u16).to_le_bytes());
        combined.extend_from_slice(quid_sig);
        
        Ok(combined)
    }
}

impl AddressGenerator {
    /// Create new address generator
    pub fn new(format: AddressFormat) -> Self {
        Self { format }
    }

    /// Generate address from public key
    pub fn generate_address(
        &self,
        public_key: &[u8],
        network: &BlockchainNetwork,
    ) -> QuIDBlockchainResult<String> {
        match &self.format {
            AddressFormat::Base58Check => self.generate_base58_address(public_key),
            AddressFormat::EthereumHex => self.generate_ethereum_address(public_key),
            AddressFormat::Bech32 => self.generate_bech32_address(public_key, &network.id),
            AddressFormat::Custom(pattern) => self.generate_custom_address(public_key, pattern),
        }
    }

    /// Validate address format
    pub fn validate_address(&self, address: &str, format: &AddressFormat) -> bool {
        match format {
            AddressFormat::Base58Check => self.validate_base58_address(address),
            AddressFormat::EthereumHex => self.validate_ethereum_address(address),
            AddressFormat::Bech32 => self.validate_bech32_address(address),
            AddressFormat::Custom(pattern) => self.validate_custom_address(address, pattern),
        }
    }

    fn generate_base58_address(&self, public_key: &[u8]) -> QuIDBlockchainResult<String> {
        use sha2::{Sha256, Digest};
        use ripemd::Ripemd160;
        
        // Bitcoin-style address generation
        let mut sha256 = Sha256::new();
        sha256.update(public_key);
        let sha256_hash = sha256.finalize();
        
        let mut ripemd = Ripemd160::new();
        ripemd.update(&sha256_hash);
        let ripemd_hash = ripemd.finalize();
        
        // Add version byte (0x00 for mainnet)
        let mut versioned_hash = vec![0x00];
        versioned_hash.extend_from_slice(&ripemd_hash);
        
        // Add checksum
        let mut checksum_sha = Sha256::new();
        checksum_sha.update(&versioned_hash);
        let checksum_hash1 = checksum_sha.finalize();
        
        let mut checksum_sha2 = Sha256::new();
        checksum_sha2.update(&checksum_hash1);
        let checksum_hash2 = checksum_sha2.finalize();
        
        versioned_hash.extend_from_slice(&checksum_hash2[..4]);
        
        Ok(bs58::encode(versioned_hash).into_string())
    }

    fn generate_ethereum_address(&self, public_key: &[u8]) -> QuIDBlockchainResult<String> {
        use sha3::{Keccak256, Digest};
        
        // Ethereum address derivation
        let mut hasher = Keccak256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        // Take last 20 bytes and add 0x prefix
        let address = format!("0x{}", hex::encode(&hash[12..]));
        Ok(address)
    }

    fn generate_bech32_address(&self, public_key: &[u8], hrp: &str) -> QuIDBlockchainResult<String> {
        use sha2::{Sha256, Digest};
        
        // Simplified bech32 address generation
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        // For simplicity, use hex encoding with prefix
        let address = format!("{}{}", hrp, hex::encode(&hash[..20]));
        Ok(address)
    }

    fn generate_custom_address(&self, public_key: &[u8], _pattern: &str) -> QuIDBlockchainResult<String> {
        // Custom address generation based on pattern
        // For now, use a simple hex-based approach
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        Ok(hex::encode(&hash[..20]))
    }

    fn validate_base58_address(&self, address: &str) -> bool {
        bs58::decode(address).into_vec().is_ok() && address.len() >= 26 && address.len() <= 35
    }

    fn validate_ethereum_address(&self, address: &str) -> bool {
        address.starts_with("0x") && address.len() == 42 && address[2..].chars().all(|c| c.is_ascii_hexdigit())
    }

    fn validate_bech32_address(&self, address: &str) -> bool {
        // Simplified bech32 validation
        address.len() > 8 && address.chars().all(|c| c.is_ascii_alphanumeric())
    }

    fn validate_custom_address(&self, address: &str, _pattern: &str) -> bool {
        // Custom validation based on pattern
        // For now, just check if it's valid hex
        address.len() == 40 && address.chars().all(|c| c.is_ascii_hexdigit())
    }
}

impl SignatureProvider {
    /// Create new signature provider
    pub fn new(algorithm: SignatureAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Create network-compatible signature
    pub async fn create_network_signature(
        &self,
        quid_client: &QuIDClient,
        identity: &QuIDIdentity,
        hash: &[u8],
        algorithm: &SignatureAlgorithm,
    ) -> QuIDBlockchainResult<Vec<u8>> {
        match algorithm {
            SignatureAlgorithm::EcdsaSecp256k1 => {
                self.create_ecdsa_signature(quid_client, identity, hash).await
            }
            SignatureAlgorithm::Ed25519 => {
                self.create_ed25519_signature(quid_client, identity, hash).await
            }
            SignatureAlgorithm::Sr25519 => {
                self.create_sr25519_signature(quid_client, identity, hash).await
            }
            SignatureAlgorithm::QuIDQuantumResistant => {
                // Already have QuID signature, return empty
                Ok(Vec::new())
            }
            SignatureAlgorithm::Hybrid => {
                // Create ECDSA for compatibility
                self.create_ecdsa_signature(quid_client, identity, hash).await
            }
        }
    }

    async fn create_ecdsa_signature(
        &self,
        _quid_client: &QuIDClient,
        _identity: &QuIDIdentity,
        _hash: &[u8],
    ) -> QuIDBlockchainResult<Vec<u8>> {
        // In a real implementation, this would derive an ECDSA key and create signature
        Ok(vec![0u8; 64]) // Placeholder signature
    }

    async fn create_ed25519_signature(
        &self,
        _quid_client: &QuIDClient,
        _identity: &QuIDIdentity,
        _hash: &[u8],
    ) -> QuIDBlockchainResult<Vec<u8>> {
        // Ed25519 signature implementation
        Ok(vec![0u8; 64]) // Placeholder signature
    }

    async fn create_sr25519_signature(
        &self,
        _quid_client: &QuIDClient,
        _identity: &QuIDIdentity,
        _hash: &[u8],
    ) -> QuIDBlockchainResult<Vec<u8>> {
        // SR25519 signature implementation
        Ok(vec![0u8; 64]) // Placeholder signature
    }
}

/// Derive custom blockchain address from QuID identity
pub async fn derive_custom_address(
    quid_client: &QuIDClient,
    identity: &QuIDIdentity,
    network_name: &str,
) -> QuIDBlockchainResult<BlockchainAccount> {
    tracing::debug!("Deriving custom {} address for identity: {}", network_name, identity.name);
    
    // Get public key from QuID identity
    let quid_public_key = quid_client.get_public_key(identity).await
        .map_err(|e| QuIDBlockchainError::AddressDerivationFailed(
            format!("Failed to get QuID public key: {}", e)
        ))?;
    
    // Create generic address (simplified)
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"CUSTOM_CHAIN");
    hasher.update(network_name.as_bytes());
    hasher.update(&quid_public_key);
    let address_hash = hasher.finalize();
    
    let address = format!("{}1{}", network_name.chars().take(3).collect::<String>(), hex::encode(&address_hash[..16]));
    
    let account = BlockchainAccount::new(
        identity.clone(),
        BlockchainType::Custom(network_name.to_string()),
        address,
        quid_public_key,
    );
    
    tracing::info!("Derived custom {} address: {}", network_name, account.address);
    Ok(account)
}

/// Sign custom blockchain transaction
pub async fn sign_custom_transaction(
    quid_client: &QuIDClient,
    identity: &QuIDIdentity,
    transaction: &mut Transaction,
    network_name: &str,
) -> QuIDBlockchainResult<Vec<u8>> {
    tracing::debug!("Signing custom {} transaction with identity: {}", network_name, identity.name);
    
    // Create transaction hash
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"CUSTOM_TX");
    hasher.update(network_name.as_bytes());
    hasher.update(transaction.from.address.as_bytes());
    hasher.update(transaction.to.as_bytes());
    hasher.update(&transaction.amount.to_le_bytes());
    let tx_hash = hasher.finalize();
    
    // Sign with QuID
    let quid_signature = quid_client.sign_data(identity, &tx_hash).await
        .map_err(|e| QuIDBlockchainError::TransactionSigningFailed(
            format!("QuID signing failed: {}", e)
        ))?;
    
    // Update transaction status
    transaction.status = TransactionStatus::Pending;
    
    tracing::info!("Custom {} transaction signed successfully", network_name);
    Ok(quid_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_network_features() {
        let features = NetworkFeatures {
            smart_contracts: true,
            multisig: true,
            privacy: false,
            atomic_swaps: true,
            staking: false,
            governance: true,
            quantum_resistant: true,
        };

        assert!(features.smart_contracts);
        assert!(!features.privacy);
    }

    #[test]
    fn test_address_generator() {
        let generator = AddressGenerator::new(AddressFormat::EthereumHex);
        let public_key = vec![0x04; 64]; // Uncompressed public key
        
        let network = BlockchainNetwork {
            id: "test".to_string(),
            name: "Test Network".to_string(),
            network_type: NetworkType::Account,
            config: CustomBlockchainConfig {
                name: "test".to_string(),
                chain_id: Some(1),
                rpc_url: "http://localhost:8545".to_string(),
                ws_url: None,
                native_token: "TEST".to_string(),
                block_time: 15,
                confirmation_blocks: 12,
                address_format: AddressFormat::EthereumHex,
                signature_algorithm: SignatureAlgorithm::EcdsaSecp256k1,
            },
            status: NetworkStatus::Active,
            features: NetworkFeatures {
                smart_contracts: true,
                multisig: true,
                privacy: false,
                atomic_swaps: false,
                staking: false,
                governance: false,
                quantum_resistant: false,
            },
        };
        
        let address = generator.generate_address(&public_key, &network).unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_address_validation() {
        let generator = AddressGenerator::new(AddressFormat::EthereumHex);
        
        assert!(generator.validate_ethereum_address("0x742C3cF9bF1bD96C6d0cC8B2A5d4bbf8b8C8A3F8"));
        assert!(!generator.validate_ethereum_address("742C3cF9bF1bD96C6d0cC8B2A5d4bbf8b8C8A3F8"));
        assert!(!generator.validate_ethereum_address("0x742C3cF9bF1bD96C6d0cC8B2A5d4bbf8b8C8A3F"));
    }

    #[test]
    fn test_network_type_categories() {
        assert_eq!(NetworkType::UTXO, NetworkType::UTXO);
        assert_ne!(NetworkType::Account, NetworkType::DAG);
    }
}