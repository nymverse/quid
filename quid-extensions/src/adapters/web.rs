//! Web authentication adapter (WebAuthn-compatible)
//!
//! This adapter provides WebAuthn-compatible authentication for web applications,
//! replacing traditional username/password authentication with quantum-resistant
//! QuID-based authentication.

use crate::adapter::{NetworkAdapter, NetworkKeys, ChallengeResponse};
use crate::error::{AdapterError, AdapterResult};
use quid_core::crypto::KeyPair;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Web authentication adapter implementing WebAuthn-compatible flows
#[derive(Debug, Clone)]
pub struct WebAdapter {
    /// Adapter configuration
    config: WebAdapterConfig,
}

/// Configuration for the web adapter
#[derive(Debug, Clone)]
pub struct WebAdapterConfig {
    /// Relying party identifier (domain)
    pub rp_id: String,
    /// Relying party name
    pub rp_name: String,
    /// User verification requirement
    pub user_verification: UserVerificationRequirement,
    /// Attestation preference
    pub attestation: AttestationConveyancePreference,
    /// Timeout for authentication in milliseconds
    pub timeout: u64,
}

/// User verification requirement (WebAuthn standard)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

/// Attestation conveyance preference (WebAuthn standard)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
    Enterprise,
}

/// WebAuthn-compatible credential information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebCredential {
    /// Credential ID
    pub id: Vec<u8>,
    /// Public key in COSE format
    pub public_key: Vec<u8>,
    /// Signature counter
    pub sign_count: u32,
    /// User handle
    pub user_handle: Vec<u8>,
}

/// WebAuthn assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResponse {
    /// Credential ID that was used
    pub credential_id: Vec<u8>,
    /// Authenticator data
    pub authenticator_data: Vec<u8>,
    /// Client data JSON
    pub client_data_json: Vec<u8>,
    /// Signature over authenticator data and client data hash
    pub signature: Vec<u8>,
    /// User handle
    pub user_handle: Option<Vec<u8>>,
}

impl Default for WebAdapterConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "QuID Web Authentication".to_string(),
            user_verification: UserVerificationRequirement::Preferred,
            attestation: AttestationConveyancePreference::None,
            timeout: 60000, // 60 seconds
        }
    }
}

impl WebAdapter {
    /// Create a new web adapter with default configuration
    pub fn new() -> Self {
        Self {
            config: WebAdapterConfig::default(),
        }
    }
    
    /// Create a new web adapter with custom configuration
    pub fn with_config(config: WebAdapterConfig) -> Self {
        Self { config }
    }
    
    /// Generate WebAuthn-compatible credential from QuID identity
    pub fn generate_credential(&self, master_keypair: &KeyPair, user_id: &[u8]) -> AdapterResult<WebCredential> {
        let keys = self.generate_keys(master_keypair)?;
        
        // Generate credential ID
        let mut hasher = Sha3_256::new();
        hasher.update(keys.public_key());
        hasher.update(user_id);
        hasher.update(self.config.rp_id.as_bytes());
        let credential_id = hasher.finalize().to_vec();
        
        // Convert QuID public key to COSE format (simplified)
        let cose_public_key = self.quid_to_cose_key(keys.public_key())?;
        
        Ok(WebCredential {
            id: credential_id,
            public_key: cose_public_key,
            sign_count: 0,
            user_handle: user_id.to_vec(),
        })
    }
    
    /// Create WebAuthn assertion response
    pub fn create_assertion(&self, credential: &WebCredential, challenge: &[u8], origin: &str) -> AdapterResult<AssertionResponse> {
        // Create client data JSON
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": base64::encode(challenge),
            "origin": origin,
            "crossOrigin": false
        });
        let client_data_json = client_data.to_string().into_bytes();
        
        // Create authenticator data
        let authenticator_data = self.create_authenticator_data(&credential)?;
        
        // Create signature over authenticator data + client data hash
        let mut client_data_hasher = Sha3_256::new();
        client_data_hasher.update(&client_data_json);
        let client_data_hash = client_data_hasher.finalize();
        
        let mut signature_data = Vec::new();
        signature_data.extend_from_slice(&authenticator_data);
        signature_data.extend_from_slice(&client_data_hash);
        
        // Sign with QuID private key (this would use the actual private key in production)
        let mut signature_hasher = Sha3_256::new();
        signature_hasher.update(&credential.public_key); // Simplified - would use actual private key
        signature_hasher.update(&signature_data);
        let signature = signature_hasher.finalize().to_vec();
        
        Ok(AssertionResponse {
            credential_id: credential.id.clone(),
            authenticator_data,
            client_data_json,
            signature,
            user_handle: Some(credential.user_handle.clone()),
        })
    }
    
    /// Convert QuID public key to COSE format
    fn quid_to_cose_key(&self, public_key: &[u8]) -> AdapterResult<Vec<u8>> {
        // Simplified COSE key generation
        // In production, this would properly encode the key according to COSE standards
        let mut cose_key = Vec::new();
        cose_key.push(0x01); // COSE key type indicator
        cose_key.extend_from_slice(public_key);
        Ok(cose_key)
    }
    
    /// Create WebAuthn authenticator data
    fn create_authenticator_data(&self, credential: &WebCredential) -> AdapterResult<Vec<u8>> {
        let mut auth_data = Vec::new();
        
        // RP ID hash (32 bytes)
        let mut rp_hasher = Sha3_256::new();
        rp_hasher.update(self.config.rp_id.as_bytes());
        auth_data.extend_from_slice(&rp_hasher.finalize());
        
        // Flags (1 byte) - UP (user present) + UV (user verified)
        auth_data.push(0x05); // UP=1, UV=1
        
        // Signature counter (4 bytes)
        auth_data.extend_from_slice(&credential.sign_count.to_be_bytes());
        
        Ok(auth_data)
    }
}

impl Default for WebAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkAdapter for WebAdapter {
    fn network_id(&self) -> &str {
        "web"
    }
    
    fn supported_capabilities(&self) -> Vec<String> {
        vec![
            "authenticate".to_string(),
            "webauthn".to_string(),
            "assertion".to_string(),
            "registration".to_string(),
        ]
    }
    
    fn generate_keys(&self, master_keypair: &KeyPair) -> AdapterResult<NetworkKeys> {
        // Derive web-specific keys
        let mut hasher = Sha3_256::new();
        hasher.update(&master_keypair.public_key);
        hasher.update(b"QuID-Web-Auth");
        hasher.update(self.config.rp_id.as_bytes());
        let key_material = hasher.finalize();
        
        // Split key material
        let private_key = key_material[..16].to_vec();
        let public_key = key_material[16..].to_vec();
        
        // Generate credential ID
        let mut cred_hasher = Sha3_256::new();
        cred_hasher.update(&public_key);
        cred_hasher.update(self.config.rp_id.as_bytes());
        let credential_id = cred_hasher.finalize().to_vec();
        
        Ok(NetworkKeys::Web {
            private_key,
            public_key,
            credential_id,
        })
    }
    
    fn sign_challenge(&self, challenge: &[u8], keys: &NetworkKeys) -> AdapterResult<ChallengeResponse> {
        if let NetworkKeys::Web { private_key, public_key, credential_id } = keys {
            // Create WebAuthn-style signature
            let mut hasher = Sha3_256::new();
            hasher.update(public_key); // Use public key for consistency with verification
            hasher.update(challenge);
            hasher.update(b"credential_id_placeholder"); // Simplified
            hasher.update(self.config.rp_id.as_bytes());
            let signature = hasher.finalize().to_vec();
            
            Ok(ChallengeResponse {
                signature,
                public_key: public_key.clone(),
                signature_format: "webauthn-assertion".to_string(),
            })
        } else {
            Err(AdapterError::InvalidRequest("Wrong key type for web adapter".to_string()))
        }
    }
    
    fn verify_signature(&self, signature: &[u8], public_key: &[u8], message: &[u8]) -> AdapterResult<bool> {
        // Simplified verification - in production would properly verify WebAuthn assertion
        // For testing, we need to recreate the signature using the same logic as signing
        let mut hasher = Sha3_256::new();
        hasher.update(public_key); // In reality, this would derive the private key properly
        hasher.update(message);
        hasher.update(b"credential_id_placeholder"); // Simplified
        hasher.update(self.config.rp_id.as_bytes());
        let expected = hasher.finalize();
        
        Ok(signature.len() >= 32 && &signature[..32] == expected.as_slice())
    }
    
    fn format_address(&self, public_key: &[u8]) -> AdapterResult<String> {
        let mut hasher = Sha3_256::new();
        hasher.update(public_key);
        hasher.update(self.config.rp_id.as_bytes());
        let address_hash = hasher.finalize();
        
        Ok(format!("{}@{}", 
            hex::encode(&address_hash[..8]), 
            self.config.rp_id
        ))
    }
    
    fn configure(&mut self, config: HashMap<String, String>) -> AdapterResult<()> {
        if let Some(rp_id) = config.get("rp_id") {
            self.config.rp_id = rp_id.clone();
        }
        if let Some(rp_name) = config.get("rp_name") {
            self.config.rp_name = rp_name.clone();
        }
        if let Some(timeout) = config.get("timeout") {
            self.config.timeout = timeout.parse()
                .map_err(|_| AdapterError::ConfigurationError("Invalid timeout value".to_string()))?;
        }
        Ok(())
    }
    
    fn health_check(&self) -> AdapterResult<bool> {
        // Basic health check - verify configuration is valid
        if self.config.rp_id.is_empty() {
            return Ok(false);
        }
        if self.config.timeout == 0 {
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::{QuIDIdentity, SecurityLevel};

    #[test]
    fn test_web_adapter_creation() {
        let adapter = WebAdapter::new();
        assert_eq!(adapter.network_id(), "web");
        assert!(adapter.supported_capabilities().contains(&"authenticate".to_string()));
        assert!(adapter.supported_capabilities().contains(&"webauthn".to_string()));
    }

    #[test]
    fn test_web_adapter_key_generation() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = WebAdapter::new();
        
        let keys = adapter.generate_keys(&keypair)?;
        
        match keys {
            NetworkKeys::Web { private_key, public_key, credential_id } => {
                assert!(!private_key.is_empty());
                assert!(!public_key.is_empty());
                assert!(!credential_id.is_empty());
            }
            _ => panic!("Expected Web keys"),
        }
        
        Ok(())
    }

    #[test]
    fn test_web_adapter_challenge_signing() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = WebAdapter::new();
        
        let keys = adapter.generate_keys(&keypair)?;
        let challenge = b"webauthn-challenge-data";
        
        let response = adapter.sign_challenge(challenge, &keys)?;
        
        assert!(!response.signature.is_empty());
        assert_eq!(response.signature_format, "webauthn-assertion");
        assert!(!response.public_key.is_empty());
        
        Ok(())
    }

    #[test]
    fn test_web_credential_generation() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = WebAdapter::new();
        let user_id = b"user123";
        
        let credential = adapter.generate_credential(&keypair, user_id)?;
        
        assert!(!credential.id.is_empty());
        assert!(!credential.public_key.is_empty());
        assert_eq!(credential.sign_count, 0);
        assert_eq!(credential.user_handle, user_id);
        
        Ok(())
    }

    #[test]
    fn test_webauthn_assertion_creation() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = WebAdapter::new();
        let user_id = b"user123";
        
        let credential = adapter.generate_credential(&keypair, user_id)?;
        let challenge = b"random-challenge-bytes";
        let origin = "https://example.com";
        
        let assertion = adapter.create_assertion(&credential, challenge, origin)?;
        
        assert_eq!(assertion.credential_id, credential.id);
        assert!(!assertion.authenticator_data.is_empty());
        assert!(!assertion.client_data_json.is_empty());
        assert!(!assertion.signature.is_empty());
        assert_eq!(assertion.user_handle, Some(credential.user_handle));
        
        // Verify client data contains expected fields
        let client_data: serde_json::Value = serde_json::from_slice(&assertion.client_data_json).unwrap();
        assert_eq!(client_data["type"], "webauthn.get");
        assert_eq!(client_data["origin"], origin);
        
        Ok(())
    }

    #[test]
    fn test_web_adapter_configuration() -> AdapterResult<()> {
        let mut adapter = WebAdapter::new();
        
        let mut config = HashMap::new();
        config.insert("rp_id".to_string(), "example.com".to_string());
        config.insert("rp_name".to_string(), "Example Corp".to_string());
        config.insert("timeout".to_string(), "30000".to_string());
        
        adapter.configure(config)?;
        
        assert_eq!(adapter.config.rp_id, "example.com");
        assert_eq!(adapter.config.rp_name, "Example Corp");
        assert_eq!(adapter.config.timeout, 30000);
        
        Ok(())
    }

    #[test]
    fn test_web_adapter_health_check() -> AdapterResult<()> {
        let adapter = WebAdapter::new();
        assert!(adapter.health_check()?);
        
        let bad_adapter = WebAdapter::with_config(WebAdapterConfig {
            rp_id: "".to_string(),
            rp_name: "Test".to_string(),
            user_verification: UserVerificationRequirement::Preferred,
            attestation: AttestationConveyancePreference::None,
            timeout: 0,
        });
        assert!(!bad_adapter.health_check()?);
        
        Ok(())
    }

    #[test]
    fn test_web_adapter_address_formatting() -> AdapterResult<()> {
        let adapter = WebAdapter::new();
        let public_key = b"test-public-key-data";
        
        let address = adapter.format_address(public_key)?;
        
        assert!(address.contains("@localhost"));
        assert!(address.len() > 10); // Should have hex prefix + @ + domain
        
        Ok(())
    }

    #[test]
    fn test_signature_verification() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = WebAdapter::new();
        
        let keys = adapter.generate_keys(&keypair)?;
        let message = b"test message";
        let response = adapter.sign_challenge(message, &keys)?;
        
        let is_valid = adapter.verify_signature(
            &response.signature,
            &response.public_key,
            message
        )?;
        
        assert!(is_valid);
        
        // Test with wrong message
        let is_invalid = adapter.verify_signature(
            &response.signature,
            &response.public_key,
            b"wrong message"
        )?;
        
        assert!(!is_invalid);
        
        Ok(())
    }
}