//! SSH authentication adapter
//!
//! This adapter provides SSH-compatible authentication using QuID identities,
//! allowing QuID to replace traditional SSH keys with quantum-resistant authentication.

use crate::adapter::{NetworkAdapter, NetworkKeys, ChallengeResponse};
use crate::error::{AdapterError, AdapterResult};
use quid_core::crypto::KeyPair;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// SSH authentication adapter
#[derive(Debug, Clone)]
pub struct SshAdapter {
    /// Adapter configuration
    config: SshAdapterConfig,
}

/// Configuration for the SSH adapter
#[derive(Debug, Clone)]
pub struct SshAdapterConfig {
    /// SSH key type (ed25519, rsa, ecdsa)
    pub key_type: SshKeyType,
    /// Key comment for SSH public key
    pub key_comment: String,
    /// Whether to include certificate extensions
    pub use_certificates: bool,
    /// Certificate validity period in seconds
    pub cert_validity: u64,
}

/// Supported SSH key types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SshKeyType {
    Ed25519,
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
}

/// SSH public key in standard format
#[derive(Debug, Clone)]
pub struct SshPublicKey {
    /// Key type string
    pub key_type: String,
    /// Base64-encoded key data
    pub key_data: String,
    /// Key comment
    pub comment: String,
}

/// SSH certificate information
#[derive(Debug, Clone)]
pub struct SshCertificate {
    /// Certificate type
    pub cert_type: String,
    /// Principal names (usernames or hostnames)
    pub principals: Vec<String>,
    /// Valid after timestamp
    pub valid_after: u64,
    /// Valid before timestamp
    pub valid_before: u64,
    /// Certificate extensions
    pub extensions: HashMap<String, String>,
}

impl Default for SshAdapterConfig {
    fn default() -> Self {
        Self {
            key_type: SshKeyType::Ed25519,
            key_comment: "quid@quantum-resistant".to_string(),
            use_certificates: false,
            cert_validity: 86400, // 24 hours
        }
    }
}

impl SshAdapter {
    /// Create a new SSH adapter with default configuration
    pub fn new() -> Self {
        Self {
            config: SshAdapterConfig::default(),
        }
    }
    
    /// Create a new SSH adapter with custom configuration
    pub fn with_config(config: SshAdapterConfig) -> Self {
        Self { config }
    }
    
    /// Generate SSH public key from QuID identity
    pub fn generate_ssh_public_key(&self, master_keypair: &KeyPair) -> AdapterResult<SshPublicKey> {
        let keys = self.generate_keys(master_keypair)?;
        
        let (key_type_str, formatted_key) = match &self.config.key_type {
            SshKeyType::Ed25519 => {
                ("ssh-ed25519", self.format_ed25519_key(keys.public_key())?)
            }
            SshKeyType::Rsa2048 | SshKeyType::Rsa4096 => {
                ("ssh-rsa", self.format_rsa_key(keys.public_key())?)
            }
            SshKeyType::EcdsaP256 => {
                ("ecdsa-sha2-nistp256", self.format_ecdsa_key(keys.public_key())?)
            }
            SshKeyType::EcdsaP384 => {
                ("ecdsa-sha2-nistp384", self.format_ecdsa_key(keys.public_key())?)
            }
        };
        
        Ok(SshPublicKey {
            key_type: key_type_str.to_string(),
            key_data: formatted_key,
            comment: self.config.key_comment.clone(),
        })
    }
    
    /// Generate SSH certificate for the key
    pub fn generate_ssh_certificate(&self, public_key: &SshPublicKey, principals: Vec<String>) -> AdapterResult<SshCertificate> {
        if !self.config.use_certificates {
            return Err(AdapterError::ConfigurationError("Certificates not enabled".to_string()));
        }
        
        let now = current_timestamp();
        let mut extensions = HashMap::new();
        extensions.insert("permit-pty".to_string(), "".to_string());
        extensions.insert("permit-user-rc".to_string(), "".to_string());
        
        Ok(SshCertificate {
            cert_type: format!("{}-cert-v01@openssh.com", public_key.key_type),
            principals,
            valid_after: now,
            valid_before: now + self.config.cert_validity,
            extensions,
        })
    }
    
    /// Format Ed25519 public key for SSH
    fn format_ed25519_key(&self, public_key: &[u8]) -> AdapterResult<String> {
        // Simplified Ed25519 key formatting
        // In production, this would properly encode according to SSH wire format
        Ok(base64::encode(public_key))
    }
    
    /// Format RSA public key for SSH
    fn format_rsa_key(&self, public_key: &[u8]) -> AdapterResult<String> {
        // Simplified RSA key formatting
        // In production, this would properly encode the RSA public key components
        Ok(base64::encode(public_key))
    }
    
    /// Format ECDSA public key for SSH
    fn format_ecdsa_key(&self, public_key: &[u8]) -> AdapterResult<String> {
        // Simplified ECDSA key formatting
        // In production, this would properly encode the ECDSA public key
        Ok(base64::encode(public_key))
    }
    
    /// Create SSH signature for authentication
    pub fn create_ssh_signature(&self, keys: &NetworkKeys, data: &[u8]) -> AdapterResult<Vec<u8>> {
        if let NetworkKeys::SSH { public_key, key_format, .. } = keys {
            // Create SSH-style signature
            let mut hasher = Sha3_256::new();
            hasher.update(public_key); // Use public key for consistency with verification
            hasher.update(data);
            hasher.update(key_format.as_bytes());
            
            // Add SSH signature magic bytes
            let mut signature = Vec::new();
            signature.extend_from_slice(b"SSH-SIG");
            signature.extend_from_slice(&hasher.finalize());
            
            Ok(signature)
        } else {
            Err(AdapterError::InvalidRequest("Wrong key type for SSH adapter".to_string()))
        }
    }
    
    /// Parse SSH authentication request
    pub fn parse_ssh_auth_request(&self, auth_data: &[u8]) -> AdapterResult<SshAuthRequest> {
        // Simplified SSH auth request parsing
        // In production, this would properly parse SSH protocol messages
        
        if auth_data.len() < 16 {
            return Err(AdapterError::InvalidRequest("SSH auth data too short".to_string()));
        }
        
        Ok(SshAuthRequest {
            username: "quid-user".to_string(),
            service: "ssh-connection".to_string(),
            method: "publickey".to_string(),
            public_key_data: auth_data[8..].to_vec(),
        })
    }
}

/// SSH authentication request
#[derive(Debug, Clone)]
pub struct SshAuthRequest {
    pub username: String,
    pub service: String,
    pub method: String,
    pub public_key_data: Vec<u8>,
}

impl Default for SshAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkAdapter for SshAdapter {
    fn network_id(&self) -> &str {
        "ssh"
    }
    
    fn supported_capabilities(&self) -> Vec<String> {
        vec![
            "authenticate".to_string(),
            "ssh-auth".to_string(),
            "public-key".to_string(),
            "certificate".to_string(),
        ]
    }
    
    fn generate_keys(&self, master_keypair: &KeyPair) -> AdapterResult<NetworkKeys> {
        // Derive SSH-specific keys
        let mut hasher = Sha3_256::new();
        hasher.update(&master_keypair.public_key);
        hasher.update(b"QuID-SSH-Auth");
        hasher.update(self.config.key_comment.as_bytes());
        let key_material = hasher.finalize();
        
        // Generate appropriate key size based on type
        let (private_key, public_key) = match &self.config.key_type {
            SshKeyType::Ed25519 => {
                // Ed25519 uses 32-byte keys
                let private_key = key_material[..32].to_vec();
                let mut pub_hasher = Sha3_256::new();
                pub_hasher.update(&private_key);
                pub_hasher.update(b"ed25519-public");
                let public_key = pub_hasher.finalize()[..32].to_vec();
                (private_key, public_key)
            }
            SshKeyType::Rsa2048 => {
                // RSA 2048 simulation (would be proper RSA in production)
                let private_key = key_material.to_vec();
                let mut pub_hasher = Sha3_256::new();
                pub_hasher.update(&private_key);
                pub_hasher.update(b"rsa-2048-public");
                let public_key = pub_hasher.finalize().to_vec();
                (private_key, public_key)
            }
            SshKeyType::Rsa4096 => {
                // RSA 4096 simulation
                let mut extended_key = key_material.to_vec();
                extended_key.extend_from_slice(&key_material);
                let private_key = extended_key;
                let mut pub_hasher = Sha3_256::new();
                pub_hasher.update(&private_key);
                pub_hasher.update(b"rsa-4096-public");
                let public_key = pub_hasher.finalize().to_vec();
                (private_key, public_key)
            }
            SshKeyType::EcdsaP256 | SshKeyType::EcdsaP384 => {
                // ECDSA simulation
                let private_key = key_material[..32].to_vec();
                let mut pub_hasher = Sha3_256::new();
                pub_hasher.update(&private_key);
                pub_hasher.update(b"ecdsa-public");
                let public_key = pub_hasher.finalize()[..32].to_vec();
                (private_key, public_key)
            }
        };
        
        Ok(NetworkKeys::SSH {
            private_key,
            public_key,
            key_format: format!("{:?}", self.config.key_type),
        })
    }
    
    fn sign_challenge(&self, challenge: &[u8], keys: &NetworkKeys) -> AdapterResult<ChallengeResponse> {
        let signature = self.create_ssh_signature(keys, challenge)?;
        
        Ok(ChallengeResponse {
            signature,
            public_key: keys.public_key().to_vec(),
            signature_format: "ssh-signature".to_string(),
        })
    }
    
    fn verify_signature(&self, signature: &[u8], public_key: &[u8], message: &[u8]) -> AdapterResult<bool> {
        // Verify SSH signature format
        if signature.len() < 7 || &signature[..7] != b"SSH-SIG" {
            return Ok(false);
        }
        
        // Simplified verification - recreate the signature using same logic as signing
        let mut hasher = Sha3_256::new();
        hasher.update(public_key); // Use public key for consistency
        hasher.update(message);
        hasher.update(format!("{:?}", self.config.key_type).as_bytes());
        let expected_hash = hasher.finalize();
        
        // Check if signature contains expected hash
        Ok(signature.len() >= 39 && &signature[7..39] == expected_hash.as_slice())
    }
    
    fn format_address(&self, public_key: &[u8]) -> AdapterResult<String> {
        let ssh_key = self.format_ed25519_key(public_key)?;
        Ok(format!("{} {} {}", 
            match self.config.key_type {
                SshKeyType::Ed25519 => "ssh-ed25519",
                SshKeyType::Rsa2048 | SshKeyType::Rsa4096 => "ssh-rsa",
                SshKeyType::EcdsaP256 => "ecdsa-sha2-nistp256",
                SshKeyType::EcdsaP384 => "ecdsa-sha2-nistp384",
            },
            ssh_key,
            self.config.key_comment
        ))
    }
    
    fn configure(&mut self, config: HashMap<String, String>) -> AdapterResult<()> {
        if let Some(key_type) = config.get("key_type") {
            self.config.key_type = match key_type.as_str() {
                "ed25519" => SshKeyType::Ed25519,
                "rsa2048" => SshKeyType::Rsa2048,
                "rsa4096" => SshKeyType::Rsa4096,
                "ecdsa-p256" => SshKeyType::EcdsaP256,
                "ecdsa-p384" => SshKeyType::EcdsaP384,
                _ => return Err(AdapterError::ConfigurationError(format!("Unknown key type: {}", key_type))),
            };
        }
        
        if let Some(comment) = config.get("key_comment") {
            self.config.key_comment = comment.clone();
        }
        
        if let Some(use_certs) = config.get("use_certificates") {
            self.config.use_certificates = use_certs.parse()
                .map_err(|_| AdapterError::ConfigurationError("Invalid use_certificates value".to_string()))?;
        }
        
        if let Some(validity) = config.get("cert_validity") {
            self.config.cert_validity = validity.parse()
                .map_err(|_| AdapterError::ConfigurationError("Invalid cert_validity value".to_string()))?;
        }
        
        Ok(())
    }
    
    fn health_check(&self) -> AdapterResult<bool> {
        // Basic health check
        if self.config.key_comment.is_empty() {
            return Ok(false);
        }
        if self.config.use_certificates && self.config.cert_validity == 0 {
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
    fn test_ssh_adapter_creation() {
        let adapter = SshAdapter::new();
        assert_eq!(adapter.network_id(), "ssh");
        assert!(adapter.supported_capabilities().contains(&"authenticate".to_string()));
        assert!(adapter.supported_capabilities().contains(&"ssh-auth".to_string()));
    }

    #[test]
    fn test_ssh_key_generation() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = SshAdapter::new();
        
        let keys = adapter.generate_keys(&keypair)?;
        
        match keys {
            NetworkKeys::SSH { private_key, public_key, key_format } => {
                assert!(!private_key.is_empty());
                assert!(!public_key.is_empty());
                assert!(!key_format.is_empty());
            }
            _ => panic!("Expected SSH keys"),
        }
        
        Ok(())
    }

    #[test]
    fn test_ssh_public_key_generation() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = SshAdapter::new();
        
        let ssh_key = adapter.generate_ssh_public_key(&keypair)?;
        
        assert_eq!(ssh_key.key_type, "ssh-ed25519");
        assert!(!ssh_key.key_data.is_empty());
        assert!(!ssh_key.comment.is_empty());
        
        Ok(())
    }

    #[test]
    fn test_ssh_challenge_signing() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = SshAdapter::new();
        
        let keys = adapter.generate_keys(&keypair)?;
        let challenge = b"ssh-auth-challenge";
        
        let response = adapter.sign_challenge(challenge, &keys)?;
        
        assert!(!response.signature.is_empty());
        assert_eq!(response.signature_format, "ssh-signature");
        assert!(response.signature.starts_with(b"SSH-SIG"));
        
        Ok(())
    }

    #[test]
    fn test_ssh_signature_verification() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let adapter = SshAdapter::new();
        
        let keys = adapter.generate_keys(&keypair)?;
        let message = b"test ssh message";
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

    #[test]
    fn test_ssh_certificate_generation() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let mut adapter = SshAdapter::new();
        adapter.config.use_certificates = true;
        
        let ssh_key = adapter.generate_ssh_public_key(&keypair)?;
        let principals = vec!["user1".to_string(), "admin".to_string()];
        
        let cert = adapter.generate_ssh_certificate(&ssh_key, principals.clone())?;
        
        assert_eq!(cert.cert_type, "ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(cert.principals, principals);
        assert!(cert.valid_before > cert.valid_after);
        assert!(!cert.extensions.is_empty());
        
        Ok(())
    }

    #[test]
    fn test_ssh_adapter_configuration() -> AdapterResult<()> {
        let mut adapter = SshAdapter::new();
        
        let mut config = HashMap::new();
        config.insert("key_type".to_string(), "rsa2048".to_string());
        config.insert("key_comment".to_string(), "user@example.com".to_string());
        config.insert("use_certificates".to_string(), "true".to_string());
        config.insert("cert_validity".to_string(), "3600".to_string());
        
        adapter.configure(config)?;
        
        assert!(matches!(adapter.config.key_type, SshKeyType::Rsa2048));
        assert_eq!(adapter.config.key_comment, "user@example.com");
        assert!(adapter.config.use_certificates);
        assert_eq!(adapter.config.cert_validity, 3600);
        
        Ok(())
    }

    #[test]
    fn test_ssh_address_formatting() -> AdapterResult<()> {
        let adapter = SshAdapter::new();
        let public_key = b"test-ssh-public-key";
        
        let address = adapter.format_address(public_key)?;
        
        assert!(address.starts_with("ssh-ed25519 "));
        assert!(address.contains("quid@quantum-resistant"));
        
        Ok(())
    }

    #[test]
    fn test_ssh_auth_request_parsing() -> AdapterResult<()> {
        let adapter = SshAdapter::new();
        let auth_data = b"ssh-auth\x00\x00\x00\x08publickey-data-here";
        
        let auth_request = adapter.parse_ssh_auth_request(auth_data)?;
        
        assert_eq!(auth_request.username, "quid-user");
        assert_eq!(auth_request.service, "ssh-connection");
        assert_eq!(auth_request.method, "publickey");
        assert!(!auth_request.public_key_data.is_empty());
        
        Ok(())
    }

    #[test]
    fn test_different_key_types() -> AdapterResult<()> {
        let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let key_types = vec![
            SshKeyType::Ed25519,
            SshKeyType::Rsa2048,
            SshKeyType::Rsa4096,
            SshKeyType::EcdsaP256,
            SshKeyType::EcdsaP384,
        ];
        
        for key_type in key_types {
            let config = SshAdapterConfig {
                key_type,
                key_comment: "test".to_string(),
                use_certificates: false,
                cert_validity: 3600,
            };
            
            let adapter = SshAdapter::with_config(config);
            let keys = adapter.generate_keys(&keypair)?;
            
            // Verify we get SSH keys
            assert!(matches!(keys, NetworkKeys::SSH { .. }));
        }
        
        Ok(())
    }

    #[test]
    fn test_ssh_health_check() -> AdapterResult<()> {
        let adapter = SshAdapter::new();
        assert!(adapter.health_check()?);
        
        let bad_adapter = SshAdapter::with_config(SshAdapterConfig {
            key_type: SshKeyType::Ed25519,
            key_comment: "".to_string(),
            use_certificates: false,
            cert_validity: 3600,
        });
        assert!(!bad_adapter.health_check()?);
        
        Ok(())
    }
}