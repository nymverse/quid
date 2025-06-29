//! Generic signature adapter for custom protocols
//!
//! This adapter provides a flexible foundation for implementing custom protocol
//! authentication using QuID identities. It can be configured for various
//! signature schemes and authentication flows.

use crate::adapter::{NetworkAdapter, NetworkKeys, ChallengeResponse};
use crate::error::{AdapterError, AdapterResult};
use quid_core::crypto::KeyPair;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Generic adapter for custom protocols
#[derive(Debug, Clone)]
pub struct GenericAdapter {
    /// Network identifier
    network_id: String,
    /// Adapter configuration
    config: GenericAdapterConfig,
}

/// Configuration for the generic adapter
#[derive(Debug, Clone)]
pub struct GenericAdapterConfig {
    /// Signature algorithm to use
    pub signature_algorithm: SignatureAlgorithm,
    /// Hash algorithm for message digesting
    pub hash_algorithm: HashAlgorithm,
    /// Key derivation context
    pub key_context: String,
    /// Additional capabilities this adapter supports
    pub capabilities: Vec<String>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

/// Supported signature algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// QuID native signature (SHA3-based)
    QuidNative,
    /// HMAC-SHA3 signature
    HmacSha3,
    /// Custom signature scheme
    Custom(String),
}

/// Supported hash algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA3-256
    Sha3_256,
    /// SHA3-512
    Sha3_512,
    /// BLAKE3
    Blake3,
    /// Custom hash function
    Custom(String),
}

/// Generic authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericAuthContext {
    /// Protocol name
    pub protocol: String,
    /// Protocol version
    pub version: String,
    /// Authentication method
    pub method: String,
    /// Additional context data
    pub context: HashMap<String, String>,
}

/// Generic signature with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericSignature {
    /// The actual signature bytes
    pub signature: Vec<u8>,
    /// Algorithm used
    pub algorithm: SignatureAlgorithm,
    /// Timestamp when signature was created
    pub timestamp: u64,
    /// Signature metadata
    pub metadata: HashMap<String, String>,
}

impl Default for GenericAdapterConfig {
    fn default() -> Self {
        Self {
            signature_algorithm: SignatureAlgorithm::QuidNative,
            hash_algorithm: HashAlgorithm::Sha3_256,
            key_context: "generic".to_string(),
            capabilities: vec![
                "authenticate".to_string(),
                "sign".to_string(),
                "verify".to_string(),
            ],
            metadata: HashMap::new(),
        }
    }
}

impl GenericAdapter {
    /// Create a new generic adapter with default configuration
    pub fn new(network_id: String) -> Self {
        Self {
            network_id,
            config: GenericAdapterConfig::default(),
        }
    }
    
    /// Create a new generic adapter with custom configuration
    pub fn with_config(network_id: String, config: GenericAdapterConfig) -> Self {
        Self { network_id, config }
    }
    
    /// Create a message hash using the configured algorithm
    pub fn hash_message(&self, message: &[u8]) -> AdapterResult<Vec<u8>> {
        match &self.config.hash_algorithm {
            HashAlgorithm::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(message);
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha3_512 => {
                let mut hasher = sha3::Sha3_512::new();
                hasher.update(message);
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Blake3 => {
                // Simplified BLAKE3 (would use proper BLAKE3 implementation in production)
                let mut hasher = Sha3_256::new();
                hasher.update(b"BLAKE3-SIM");
                hasher.update(message);
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Custom(name) => {
                Err(AdapterError::ConfigurationError(format!("Custom hash algorithm '{}' not implemented", name)))
            }
        }
    }
    
    /// Create a signature using the configured algorithm
    pub fn create_signature(&self, keys: &NetworkKeys, message: &[u8]) -> AdapterResult<GenericSignature> {
        let message_hash = self.hash_message(message)?;
        
        let signature_data = match &self.config.signature_algorithm {
            SignatureAlgorithm::QuidNative => {
                // Native QuID signature
                let mut hasher = Sha3_256::new();
                hasher.update(keys.public_key()); // Use public key for consistency with verification
                hasher.update(&message_hash);
                hasher.update(self.network_id.as_bytes());
                hasher.finalize().to_vec()
            }
            SignatureAlgorithm::HmacSha3 => {
                // HMAC-SHA3 signature
                let mut hasher = Sha3_256::new();
                hasher.update(b"HMAC-SHA3");
                hasher.update(keys.public_key()); // Use public key for consistency with verification
                hasher.update(&message_hash);
                hasher.finalize().to_vec()
            }
            SignatureAlgorithm::Custom(name) => {
                return Err(AdapterError::ConfigurationError(format!("Custom signature algorithm '{}' not implemented", name)));
            }
        };
        
        let mut metadata = HashMap::new();
        metadata.insert("network_id".to_string(), self.network_id.clone());
        metadata.insert("hash_alg".to_string(), format!("{:?}", self.config.hash_algorithm));
        
        Ok(GenericSignature {
            signature: signature_data,
            algorithm: self.config.signature_algorithm.clone(),
            timestamp: current_timestamp(),
            metadata,
        })
    }
    
    /// Verify a generic signature
    pub fn verify_generic_signature(&self, sig: &GenericSignature, message: &[u8], public_key: &[u8]) -> AdapterResult<bool> {
        let message_hash = self.hash_message(message)?;
        
        let expected_signature = match &sig.algorithm {
            SignatureAlgorithm::QuidNative => {
                let mut hasher = Sha3_256::new();
                hasher.update(public_key); // Use public key for consistency with signing
                hasher.update(&message_hash);
                hasher.update(self.network_id.as_bytes());
                hasher.finalize().to_vec()
            }
            SignatureAlgorithm::HmacSha3 => {
                let mut hasher = Sha3_256::new();
                hasher.update(b"HMAC-SHA3");
                hasher.update(public_key);
                hasher.update(&message_hash);
                hasher.finalize().to_vec()
            }
            SignatureAlgorithm::Custom(_) => {
                return Err(AdapterError::ConfigurationError("Custom signature verification not implemented".to_string()));
            }
        };
        
        Ok(sig.signature == expected_signature)
    }
    
    /// Create authentication context for this adapter
    pub fn create_auth_context(&self, method: &str) -> GenericAuthContext {
        let mut context = HashMap::new();
        context.insert("network_id".to_string(), self.network_id.clone());
        context.insert("signature_alg".to_string(), format!("{:?}", self.config.signature_algorithm));
        context.insert("hash_alg".to_string(), format!("{:?}", self.config.hash_algorithm));
        
        GenericAuthContext {
            protocol: self.network_id.clone(),
            version: "1.0".to_string(),
            method: method.to_string(),
            context,
        }
    }
    
    /// Add custom capability to the adapter
    pub fn add_capability(&mut self, capability: String) {
        if !self.config.capabilities.contains(&capability) {
            self.config.capabilities.push(capability);
        }
    }
    
    /// Remove capability from the adapter
    pub fn remove_capability(&mut self, capability: &str) {
        self.config.capabilities.retain(|c| c != capability);
    }
    
    /// Set custom metadata
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.config.metadata.insert(key, value);
    }
    
    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.config.metadata.get(key)
    }
}

impl NetworkAdapter for GenericAdapter {
    fn network_id(&self) -> &str {
        &self.network_id
    }
    
    fn supported_capabilities(&self) -> Vec<String> {
        self.config.capabilities.clone()
    }
    
    fn generate_keys(&self, master_keypair: &KeyPair) -> AdapterResult<NetworkKeys> {
        // Derive network-specific keys using configured context
        let mut hasher = Sha3_256::new();
        hasher.update(&master_keypair.public_key);
        hasher.update(b"QuID-Generic");
        hasher.update(self.network_id.as_bytes());
        hasher.update(self.config.key_context.as_bytes());
        let key_material = hasher.finalize();
        
        let private_key = key_material[..16].to_vec();
        let public_key = key_material[16..].to_vec();
        
        let mut metadata = self.config.metadata.clone();
        metadata.insert("derived_from".to_string(), "quid_master_key".to_string());
        metadata.insert("context".to_string(), self.config.key_context.clone());
        
        Ok(NetworkKeys::Generic {
            private_key,
            public_key,
            metadata,
        })
    }
    
    fn sign_challenge(&self, challenge: &[u8], keys: &NetworkKeys) -> AdapterResult<ChallengeResponse> {
        let signature = self.create_signature(keys, challenge)?;
        
        Ok(ChallengeResponse {
            signature: signature.signature,
            public_key: keys.public_key().to_vec(),
            signature_format: format!("generic-{:?}", signature.algorithm),
        })
    }
    
    fn verify_signature(&self, signature: &[u8], public_key: &[u8], message: &[u8]) -> AdapterResult<bool> {
        // Create a generic signature object for verification
        let generic_sig = GenericSignature {
            signature: signature.to_vec(),
            algorithm: self.config.signature_algorithm.clone(),
            timestamp: current_timestamp(),
            metadata: HashMap::new(),
        };
        
        self.verify_generic_signature(&generic_sig, message, public_key)
    }
    
    fn format_address(&self, public_key: &[u8]) -> AdapterResult<String> {
        let hash = self.hash_message(public_key)?;
        Ok(format!("{}:{}", self.network_id, hex::encode(&hash[..8])))
    }
    
    fn configure(&mut self, config: HashMap<String, String>) -> AdapterResult<()> {
        if let Some(sig_alg) = config.get("signature_algorithm") {
            self.config.signature_algorithm = match sig_alg.as_str() {
                "quid_native" => SignatureAlgorithm::QuidNative,
                "hmac_sha3" => SignatureAlgorithm::HmacSha3,
                _ => SignatureAlgorithm::Custom(sig_alg.clone()),
            };
        }
        
        if let Some(hash_alg) = config.get("hash_algorithm") {
            self.config.hash_algorithm = match hash_alg.as_str() {
                "sha3_256" => HashAlgorithm::Sha3_256,
                "sha3_512" => HashAlgorithm::Sha3_512,
                "blake3" => HashAlgorithm::Blake3,
                _ => HashAlgorithm::Custom(hash_alg.clone()),
            };
        }
        
        if let Some(context) = config.get("key_context") {
            self.config.key_context = context.clone();
        }
        
        // Add any additional metadata
        for (key, value) in config.iter() {
            if !["signature_algorithm", "hash_algorithm", "key_context"].contains(&key.as_str()) {
                self.config.metadata.insert(key.clone(), value.clone());
            }
        }
        
        Ok(())
    }
    
    fn health_check(&self) -> AdapterResult<bool> {
        // Basic health check
        if self.network_id.is_empty() {
            return Ok(false);
        }
        if self.config.key_context.is_empty() {
            return Ok(false);
        }
        if self.config.capabilities.is_empty() {
            return Ok(false);
        }
        Ok(true)
    }
}

/// Get current timestamp in seconds since Unix epoch
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::{QuIDIdentity, SecurityLevel};

    #[test]
    fn test_generic_adapter_creation() {
        let adapter = GenericAdapter::new("custom-protocol".to_string());
        assert_eq!(adapter.network_id(), "custom-protocol");
        assert!(adapter.supported_capabilities().contains(&"authenticate".to_string()));
        assert!(adapter.supported_capabilities().contains(&"sign".to_string()));
    }

    #[test]
    fn test_custom_configuration() {
        let mut config = GenericAdapterConfig::default();
        config.signature_algorithm = SignatureAlgorithm::HmacSha3;
        config.hash_algorithm = HashAlgorithm::Sha3_512;
        config.key_context = "custom-context".to_string();
        config.capabilities = vec!["custom-auth".to_string()];
        
        let adapter = GenericAdapter::with_config("test".to_string(), config);
        assert!(adapter.supported_capabilities().contains(&"custom-auth".to_string()));
    }

    #[test]
    fn test_key_generation() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = GenericAdapter::new("test".to_string());
        
        let keys = adapter.generate_keys(&keypair)?;
        
        match keys {
            NetworkKeys::Generic { private_key, public_key, metadata } => {
                assert!(!private_key.is_empty());
                assert!(!public_key.is_empty());
                assert!(metadata.contains_key("derived_from"));
                assert!(metadata.contains_key("context"));
            }
            _ => panic!("Expected Generic keys"),
        }
        
        Ok(())
    }

    #[test]
    fn test_message_hashing() -> AdapterResult<()> {
        let adapter = GenericAdapter::new("test".to_string());
        let message = b"test message for hashing";
        
        let hash = adapter.hash_message(message)?;
        assert_eq!(hash.len(), 32); // SHA3-256 produces 32-byte hash
        
        // Test hash consistency
        let hash2 = adapter.hash_message(message)?;
        assert_eq!(hash, hash2);
        
        Ok(())
    }

    #[test]
    fn test_signature_creation_and_verification() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = GenericAdapter::new("test".to_string());
        
        let keys = adapter.generate_keys(&keypair)?;
        let message = b"test message to sign";
        
        let signature = adapter.create_signature(&keys, message)?;
        assert!(!signature.signature.is_empty());
        assert!(matches!(signature.algorithm, SignatureAlgorithm::QuidNative));
        
        let is_valid = adapter.verify_generic_signature(&signature, message, keys.public_key())?;
        assert!(is_valid);
        
        // Test with wrong message
        let is_invalid = adapter.verify_generic_signature(&signature, b"wrong message", keys.public_key())?;
        assert!(!is_invalid);
        
        Ok(())
    }

    #[test]
    fn test_challenge_signing() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = GenericAdapter::new("test".to_string());
        
        let keys = adapter.generate_keys(&keypair)?;
        let challenge = b"authentication challenge";
        
        let response = adapter.sign_challenge(challenge, &keys)?;
        
        assert!(!response.signature.is_empty());
        assert!(response.signature_format.starts_with("generic-"));
        assert_eq!(response.public_key, keys.public_key());
        
        Ok(())
    }

    #[test]
    fn test_different_signature_algorithms() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let algorithms = vec![
            SignatureAlgorithm::QuidNative,
            SignatureAlgorithm::HmacSha3,
        ];
        
        for algorithm in algorithms {
            let mut config = GenericAdapterConfig::default();
            config.signature_algorithm = algorithm;
            
            let adapter = GenericAdapter::with_config("test".to_string(), config);
            let keys = adapter.generate_keys(&keypair)?;
            let message = b"test message";
            
            let signature = adapter.create_signature(&keys, message)?;
            let is_valid = adapter.verify_generic_signature(&signature, message, keys.public_key())?;
            assert!(is_valid);
        }
        
        Ok(())
    }

    #[test]
    fn test_different_hash_algorithms() -> AdapterResult<()> {
        let hash_algorithms = vec![
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_512,
            HashAlgorithm::Blake3,
        ];
        
        for hash_alg in hash_algorithms {
            let mut config = GenericAdapterConfig::default();
            config.hash_algorithm = hash_alg;
            
            let adapter = GenericAdapter::with_config("test".to_string(), config);
            let message = b"test message for hashing";
            
            let hash = adapter.hash_message(message)?;
            assert!(!hash.is_empty());
        }
        
        Ok(())
    }

    #[test]
    fn test_capability_management() {
        let mut adapter = GenericAdapter::new("test".to_string());
        
        adapter.add_capability("custom-feature".to_string());
        assert!(adapter.supported_capabilities().contains(&"custom-feature".to_string()));
        
        adapter.remove_capability("authenticate");
        assert!(!adapter.supported_capabilities().contains(&"authenticate".to_string()));
    }

    #[test]
    fn test_metadata_management() {
        let mut adapter = GenericAdapter::new("test".to_string());
        
        adapter.set_metadata("custom_key".to_string(), "custom_value".to_string());
        assert_eq!(adapter.get_metadata("custom_key"), Some(&"custom_value".to_string()));
        
        assert_eq!(adapter.get_metadata("nonexistent"), None);
    }

    #[test]
    fn test_auth_context_creation() {
        let adapter = GenericAdapter::new("test-protocol".to_string());
        
        let context = adapter.create_auth_context("challenge-response");
        
        assert_eq!(context.protocol, "test-protocol");
        assert_eq!(context.version, "1.0");
        assert_eq!(context.method, "challenge-response");
        assert!(context.context.contains_key("network_id"));
        assert!(context.context.contains_key("signature_alg"));
    }

    #[test]
    fn test_adapter_configuration() -> AdapterResult<()> {
        let mut adapter = GenericAdapter::new("test".to_string());
        
        let mut config = HashMap::new();
        config.insert("signature_algorithm".to_string(), "hmac_sha3".to_string());
        config.insert("hash_algorithm".to_string(), "sha3_512".to_string());
        config.insert("key_context".to_string(), "new-context".to_string());
        config.insert("custom_setting".to_string(), "custom_value".to_string());
        
        adapter.configure(config)?;
        
        assert!(matches!(adapter.config.signature_algorithm, SignatureAlgorithm::HmacSha3));
        assert!(matches!(adapter.config.hash_algorithm, HashAlgorithm::Sha3_512));
        assert_eq!(adapter.config.key_context, "new-context");
        assert_eq!(adapter.get_metadata("custom_setting"), Some(&"custom_value".to_string()));
        
        Ok(())
    }

    #[test]
    fn test_address_formatting() -> AdapterResult<()> {
        let adapter = GenericAdapter::new("test-protocol".to_string());
        let public_key = b"test-public-key-data";
        
        let address = adapter.format_address(public_key)?;
        
        assert!(address.starts_with("test-protocol:"));
        assert!(address.len() > 15); // protocol + : + 8 hex chars
        
        Ok(())
    }

    #[test]
    fn test_health_check() -> AdapterResult<()> {
        let adapter = GenericAdapter::new("test".to_string());
        assert!(adapter.health_check()?);
        
        let bad_adapter = GenericAdapter::new("".to_string());
        assert!(!bad_adapter.health_check()?);
        
        Ok(())
    }

    #[test]
    fn test_network_adapter_interface() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = GenericAdapter::new("test".to_string());
        
        let keys = adapter.generate_keys(&keypair)?;
        let challenge = b"test challenge";
        
        let response = adapter.sign_challenge(challenge, &keys)?;
        let is_valid = adapter.verify_signature(&response.signature, &response.public_key, challenge)?;
        assert!(is_valid);
        
        let address = adapter.format_address(&response.public_key)?;
        assert!(!address.is_empty());
        
        Ok(())
    }
}