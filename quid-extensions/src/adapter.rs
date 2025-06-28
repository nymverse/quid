//! Network adapter trait and core types

use crate::error::{AdapterError, AdapterResult};
// use crate::key_derivation::{DerivedKeys, KeyDerivation};
use quid_core::crypto::KeyPair;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authentication request from an application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    /// Unique challenge for this authentication attempt
    pub challenge: Vec<u8>,
    /// Authentication context
    pub context: AuthContext,
    /// Timestamp when request was created
    pub timestamp: u64,
    /// Optional request metadata
    pub metadata: HashMap<String, String>,
}

/// Authentication context providing details about the request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Network type (bitcoin, ethereum, nym, web, ssh, etc.)
    pub network_type: String,
    /// Application or service identifier
    pub application_id: String,
    /// Required capabilities for this authentication
    pub required_capabilities: Vec<String>,
    /// Optional context-specific data
    pub context_data: HashMap<String, String>,
}

/// Authentication response from QuID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    /// Identity proof containing public information
    pub identity_proof: IdentityProof,
    /// Challenge response with signature
    pub challenge_response: ChallengeResponse,
    /// Capability proofs demonstrating what the identity can do
    pub capabilities: Vec<CapabilityProof>,
    /// Response timestamp
    pub timestamp: u64,
    /// Network-specific additional data
    pub network_data: HashMap<String, String>,
}

/// Proof of identity ownership
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProof {
    /// QuID identity ID
    pub identity_id: Vec<u8>,
    /// Master public key
    pub public_key: Vec<u8>,
    /// Signature over identity with master key
    pub identity_signature: Vec<u8>,
}

/// Response to authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Signature over the challenge
    pub signature: Vec<u8>,
    /// Network-specific public key used for signing
    pub public_key: Vec<u8>,
    /// Signature format/algorithm identifier
    pub signature_format: String,
}

/// Proof of specific capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProof {
    /// Capability name (e.g., "sign_transaction", "authenticate")
    pub capability: String,
    /// Proof data demonstrating the capability
    pub proof_data: Vec<u8>,
    /// Expiration timestamp (0 = no expiration)
    pub expires_at: u64,
}

/// Container for network-specific keys
#[derive(Debug, Clone)]
pub enum NetworkKeys {
    /// Bitcoin-style keys
    Bitcoin {
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        address: String,
    },
    /// Ethereum-style keys
    Ethereum {
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        address: String,
    },
    /// Nym blockchain keys with privacy support
    Nym {
        signing_key: Vec<u8>,
        privacy_key: Vec<u8>,
        public_key: Vec<u8>,
        address: String,
    },
    /// NomadNet social platform keys
    NomadNet {
        content_signing_key: Vec<u8>,
        domain_control_key: Vec<u8>,
        public_key: Vec<u8>,
        domain: String,
    },
    /// SSH authentication keys
    SSH {
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        key_format: String,
    },
    /// Web authentication keys
    Web {
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        credential_id: Vec<u8>,
    },
    /// Generic network keys
    Generic {
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        metadata: HashMap<String, String>,
    },
}

impl NetworkKeys {
    /// Get the public key regardless of network type
    pub fn public_key(&self) -> &[u8] {
        match self {
            NetworkKeys::Bitcoin { public_key, .. } => public_key,
            NetworkKeys::Ethereum { public_key, .. } => public_key,
            NetworkKeys::Nym { public_key, .. } => public_key,
            NetworkKeys::NomadNet { public_key, .. } => public_key,
            NetworkKeys::SSH { public_key, .. } => public_key,
            NetworkKeys::Web { public_key, .. } => public_key,
            NetworkKeys::Generic { public_key, .. } => public_key,
        }
    }
    
    /// Get the private key regardless of network type
    pub fn private_key(&self) -> &[u8] {
        match self {
            NetworkKeys::Bitcoin { private_key, .. } => private_key,
            NetworkKeys::Ethereum { private_key, .. } => private_key,
            NetworkKeys::Nym { signing_key, .. } => signing_key,
            NetworkKeys::NomadNet { content_signing_key, .. } => content_signing_key,
            NetworkKeys::SSH { private_key, .. } => private_key,
            NetworkKeys::Web { private_key, .. } => private_key,
            NetworkKeys::Generic { private_key, .. } => private_key,
        }
    }
    
    /// Get network-specific address or identifier
    pub fn address(&self) -> Option<&str> {
        match self {
            NetworkKeys::Bitcoin { address, .. } => Some(address),
            NetworkKeys::Ethereum { address, .. } => Some(address),
            NetworkKeys::Nym { address, .. } => Some(address),
            NetworkKeys::NomadNet { domain, .. } => Some(domain),
            _ => None,
        }
    }
}

/// Core trait that all network adapters must implement
pub trait NetworkAdapter: Send + Sync {
    /// Get the network identifier for this adapter
    fn network_id(&self) -> &str;
    
    /// Get supported capabilities for this network
    fn supported_capabilities(&self) -> Vec<String>;
    
    /// Generate network-specific keys from master identity
    fn generate_keys(&self, master_keypair: &KeyPair) -> AdapterResult<NetworkKeys>;
    
    /// Sign an authentication challenge
    fn sign_challenge(&self, challenge: &[u8], keys: &NetworkKeys) -> AdapterResult<ChallengeResponse>;
    
    /// Verify a signature
    fn verify_signature(&self, signature: &[u8], public_key: &[u8], message: &[u8]) -> AdapterResult<bool>;
    
    /// Format network-specific address from public key
    fn format_address(&self, public_key: &[u8]) -> AdapterResult<String>;
    
    /// Handle complete authentication request
    fn authenticate(&self, request: &AuthenticationRequest, master_keypair: &KeyPair) -> AdapterResult<AuthenticationResponse> {
        // Default implementation using other trait methods
        let keys = self.generate_keys(master_keypair)?;
        let challenge_response = self.sign_challenge(&request.challenge, &keys)?;
        
        // Generate identity proof
        let identity_proof = IdentityProof {
            identity_id: self.derive_identity_id(master_keypair)?,
            public_key: master_keypair.public_key.clone(),
            identity_signature: self.sign_identity_proof(master_keypair)?,
        };
        
        // Generate capability proofs
        let capabilities = self.generate_capability_proofs(&request.context, &keys)?;
        
        Ok(AuthenticationResponse {
            identity_proof,
            challenge_response,
            capabilities,
            timestamp: current_timestamp(),
            network_data: self.get_network_metadata(&keys)?,
        })
    }
    
    /// Optional: Custom network-specific configuration
    fn configure(&mut self, _config: HashMap<String, String>) -> AdapterResult<()> {
        Ok(())
    }
    
    /// Optional: Network-specific health check
    fn health_check(&self) -> AdapterResult<bool> {
        Ok(true)
    }
    
    // Helper methods with default implementations
    
    /// Derive identity ID from master keypair
    fn derive_identity_id(&self, master_keypair: &KeyPair) -> AdapterResult<Vec<u8>> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&master_keypair.public_key);
        hasher.update(b"QuID-Identity-v1");
        Ok(hasher.finalize().to_vec())
    }
    
    /// Sign identity proof
    fn sign_identity_proof(&self, master_keypair: &KeyPair) -> AdapterResult<Vec<u8>> {
        let identity_data = format!("QuID-Identity-{}", self.network_id());
        master_keypair.sign(identity_data.as_bytes())
            .map_err(|e| AdapterError::SignatureFailed(e.to_string()))
    }
    
    /// Generate capability proofs
    fn generate_capability_proofs(&self, context: &AuthContext, _keys: &NetworkKeys) -> AdapterResult<Vec<CapabilityProof>> {
        let mut proofs = Vec::new();
        
        for capability in &context.required_capabilities {
            if self.supported_capabilities().contains(capability) {
                let proof_data = format!("QuID-Capability-{}-{}", self.network_id(), capability);
                proofs.push(CapabilityProof {
                    capability: capability.clone(),
                    proof_data: proof_data.into_bytes(),
                    expires_at: 0, // No expiration by default
                });
            }
        }
        
        Ok(proofs)
    }
    
    /// Get network-specific metadata
    fn get_network_metadata(&self, keys: &NetworkKeys) -> AdapterResult<HashMap<String, String>> {
        let mut metadata = HashMap::new();
        metadata.insert("network_id".to_string(), self.network_id().to_string());
        
        if let Some(address) = keys.address() {
            metadata.insert("address".to_string(), address.to_string());
        }
        
        Ok(metadata)
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

    // Mock adapter for testing
    struct MockAdapter {
        network_id: String,
        capabilities: Vec<String>,
    }

    impl MockAdapter {
        fn new(network_id: &str) -> Self {
            Self {
                network_id: network_id.to_string(),
                capabilities: vec!["authenticate".to_string(), "sign".to_string()],
            }
        }
    }

    impl NetworkAdapter for MockAdapter {
        fn network_id(&self) -> &str {
            &self.network_id
        }
        
        fn supported_capabilities(&self) -> Vec<String> {
            self.capabilities.clone()
        }
        
        fn generate_keys(&self, master_keypair: &KeyPair) -> AdapterResult<NetworkKeys> {
            // Simple mock key generation
            use sha3::{Digest, Sha3_256};
            let mut hasher = Sha3_256::new();
            hasher.update(&master_keypair.public_key);
            hasher.update(self.network_id.as_bytes());
            let key_material = hasher.finalize();
            
            Ok(NetworkKeys::Generic {
                private_key: key_material[..16].to_vec(),
                public_key: key_material[16..].to_vec(),
                metadata: HashMap::new(),
            })
        }
        
        fn sign_challenge(&self, challenge: &[u8], keys: &NetworkKeys) -> AdapterResult<ChallengeResponse> {
            // Mock signature
            use sha3::{Digest, Sha3_256};
            let mut hasher = Sha3_256::new();
            hasher.update(keys.private_key());
            hasher.update(challenge);
            let signature = hasher.finalize().to_vec();
            
            Ok(ChallengeResponse {
                signature,
                public_key: keys.public_key().to_vec(),
                signature_format: "mock-sha3".to_string(),
            })
        }
        
        fn verify_signature(&self, _signature: &[u8], _public_key: &[u8], _message: &[u8]) -> AdapterResult<bool> {
            Ok(true) // Mock verification always passes
        }
        
        fn format_address(&self, public_key: &[u8]) -> AdapterResult<String> {
            Ok(format!("{}:{}", self.network_id, hex::encode(&public_key[..8])))
        }
    }

    #[test]
    fn test_network_keys_accessors() {
        let keys = NetworkKeys::Generic {
            private_key: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
            metadata: HashMap::new(),
        };
        
        assert_eq!(keys.private_key(), &[1, 2, 3]);
        assert_eq!(keys.public_key(), &[4, 5, 6]);
        assert_eq!(keys.address(), None);
    }

    #[test]
    fn test_bitcoin_keys_address() {
        let keys = NetworkKeys::Bitcoin {
            private_key: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
        };
        
        assert_eq!(keys.address(), Some("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
    }

    #[test]
    fn test_mock_adapter() -> AdapterResult<()> {
        let adapter = MockAdapter::new("test");
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        assert_eq!(adapter.network_id(), "test");
        assert_eq!(adapter.supported_capabilities(), vec!["authenticate", "sign"]);
        
        let keys = adapter.generate_keys(&keypair)?;
        assert!(!keys.public_key().is_empty());
        assert!(!keys.private_key().is_empty());
        
        Ok(())
    }

    #[test]
    fn test_authentication_flow() -> AdapterResult<()> {
        let adapter = MockAdapter::new("test");
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let request = AuthenticationRequest {
            challenge: vec![1, 2, 3, 4, 5],
            context: AuthContext {
                network_type: "test".to_string(),
                application_id: "test_app".to_string(),
                required_capabilities: vec!["authenticate".to_string()],
                context_data: HashMap::new(),
            },
            timestamp: current_timestamp(),
            metadata: HashMap::new(),
        };
        
        let response = adapter.authenticate(&request, &keypair)?;
        
        assert!(!response.identity_proof.identity_id.is_empty());
        assert!(!response.challenge_response.signature.is_empty());
        assert_eq!(response.capabilities.len(), 1);
        assert_eq!(response.capabilities[0].capability, "authenticate");
        
        Ok(())
    }

    #[test]
    fn test_challenge_response() -> AdapterResult<()> {
        let adapter = MockAdapter::new("test");
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let keys = adapter.generate_keys(&keypair)?;
        let challenge = vec![1, 2, 3, 4, 5];
        
        let response = adapter.sign_challenge(&challenge, &keys)?;
        
        assert!(!response.signature.is_empty());
        assert_eq!(response.public_key, keys.public_key());
        assert_eq!(response.signature_format, "mock-sha3");
        
        Ok(())
    }
}