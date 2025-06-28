//! Generic key derivation for network adapters

use crate::error::AdapterResult;
use quid_core::crypto::KeyPair;
use sha3::{Digest, Sha3_256};
use secrecy::{ExposeSecret, Secret};

/// Key derivation trait for network-specific key generation
pub trait KeyDerivation {
    /// Derive network-specific keys from a master QuID keypair
    fn derive_keys(&self, master_keypair: &KeyPair, network_id: &str) -> AdapterResult<DerivedKeys>;
    
    /// Derive a single key with custom context
    fn derive_key_with_context(&self, master_keypair: &KeyPair, context: &[u8]) -> AdapterResult<Vec<u8>>;
}

/// Container for derived network keys
pub struct DerivedKeys {
    /// Network identifier
    pub network_id: String,
    /// Primary derived key
    pub primary_key: Secret<Vec<u8>>,
    /// Public key derived from primary key
    pub public_key: Vec<u8>,
    /// Optional secondary keys for specific networks
    pub secondary_keys: std::collections::HashMap<String, Secret<Vec<u8>>>,
    /// Network-specific metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKeys")
            .field("network_id", &self.network_id)
            .field("primary_key", &"[REDACTED]")
            .field("public_key", &hex::encode(&self.public_key))
            .field("secondary_keys", &format!("{} keys", self.secondary_keys.len()))
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl Clone for DerivedKeys {
    fn clone(&self) -> Self {
        let mut secondary_keys = std::collections::HashMap::new();
        for (key, secret) in &self.secondary_keys {
            secondary_keys.insert(key.clone(), Secret::new(secret.expose_secret().clone()));
        }
        
        Self {
            network_id: self.network_id.clone(),
            primary_key: Secret::new(self.primary_key.expose_secret().clone()),
            public_key: self.public_key.clone(),
            secondary_keys,
            metadata: self.metadata.clone(),
        }
    }
}

impl DerivedKeys {
    /// Create new derived keys
    pub fn new(network_id: String, primary_key: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            network_id,
            primary_key: Secret::new(primary_key),
            public_key,
            secondary_keys: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
        }
    }
    
    /// Add a secondary key
    pub fn add_secondary_key(&mut self, name: String, key: Vec<u8>) {
        self.secondary_keys.insert(name, Secret::new(key));
    }
    
    /// Add metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
    
    /// Get secondary key by name
    pub fn get_secondary_key(&self, name: &str) -> Option<&Secret<Vec<u8>>> {
        self.secondary_keys.get(name)
    }
}

/// Default HMAC-based key derivation implementation
pub struct HmacKeyDerivation;

impl KeyDerivation for HmacKeyDerivation {
    fn derive_keys(&self, master_keypair: &KeyPair, network_id: &str) -> AdapterResult<DerivedKeys> {
        // Derive primary key using master private key + network ID
        let primary_context = format!("QuID-Network-{}", network_id);
        let primary_key = self.derive_key_with_context(master_keypair, primary_context.as_bytes())?;
        
        // Derive public key from primary key (simplified - in production use proper crypto)
        let mut public_hasher = Sha3_256::new();
        public_hasher.update(&primary_key);
        public_hasher.update(b"QuID-Public");
        let public_key = public_hasher.finalize().to_vec();
        
        let mut derived = DerivedKeys::new(network_id.to_string(), primary_key, public_key);
        
        // Add network-specific secondary keys based on network type
        match network_id {
            "bitcoin" => {
                let signing_key = self.derive_key_with_context(master_keypair, b"QuID-Bitcoin-Signing")?;
                derived.add_secondary_key("signing".to_string(), signing_key);
                derived.add_metadata("address_format".to_string(), "p2pkh".to_string());
            }
            "ethereum" => {
                let signing_key = self.derive_key_with_context(master_keypair, b"QuID-Ethereum-Signing")?;
                derived.add_secondary_key("signing".to_string(), signing_key);
                derived.add_metadata("address_format".to_string(), "ethereum".to_string());
            }
            "nym" => {
                let privacy_key = self.derive_key_with_context(master_keypair, b"QuID-Nym-Privacy")?;
                let signing_key = self.derive_key_with_context(master_keypair, b"QuID-Nym-Signing")?;
                derived.add_secondary_key("privacy".to_string(), privacy_key);
                derived.add_secondary_key("signing".to_string(), signing_key);
                derived.add_metadata("privacy_enabled".to_string(), "true".to_string());
            }
            "nomadnet" => {
                let content_key = self.derive_key_with_context(master_keypair, b"QuID-NomadNet-Content")?;
                let domain_key = self.derive_key_with_context(master_keypair, b"QuID-NomadNet-Domain")?;
                derived.add_secondary_key("content".to_string(), content_key);
                derived.add_secondary_key("domain".to_string(), domain_key);
                derived.add_metadata("domain_suffix".to_string(), "nomad".to_string());
            }
            "ssh" => {
                let auth_key = self.derive_key_with_context(master_keypair, b"QuID-SSH-Auth")?;
                derived.add_secondary_key("auth".to_string(), auth_key);
                derived.add_metadata("key_type".to_string(), "ed25519".to_string());
            }
            _ => {
                // Generic network - just primary key
                derived.add_metadata("type".to_string(), "generic".to_string());
            }
        }
        
        Ok(derived)
    }
    
    fn derive_key_with_context(&self, master_keypair: &KeyPair, context: &[u8]) -> AdapterResult<Vec<u8>> {
        let mut hasher = Sha3_256::new();
        hasher.update(master_keypair.private_key.expose_secret());
        hasher.update(&master_keypair.public_key);
        hasher.update(context);
        hasher.update(b"QuID-KeyDerivation-v1");
        
        Ok(hasher.finalize().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::{QuIDIdentity, SecurityLevel};

    #[test]
    fn test_derived_keys_creation() {
        let keys = DerivedKeys::new(
            "test".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
        );
        
        assert_eq!(keys.network_id, "test");
        assert_eq!(keys.public_key, vec![4, 5, 6]);
    }

    #[test]
    fn test_secondary_keys() {
        let mut keys = DerivedKeys::new(
            "test".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
        );
        
        keys.add_secondary_key("signing".to_string(), vec![7, 8, 9]);
        let secondary = keys.get_secondary_key("signing").unwrap();
        assert_eq!(secondary.expose_secret(), &vec![7, 8, 9]);
    }

    #[test]
    fn test_hmac_key_derivation() -> AdapterResult<()> {
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let derivation = HmacKeyDerivation;
        
        let keys = derivation.derive_keys(&keypair, "bitcoin")?;
        
        assert_eq!(keys.network_id, "bitcoin");
        assert!(!keys.primary_key.expose_secret().is_empty());
        assert!(!keys.public_key.is_empty());
        assert!(keys.get_secondary_key("signing").is_some());
        assert_eq!(keys.metadata.get("address_format"), Some(&"p2pkh".to_string()));
        
        Ok(())
    }

    #[test]
    fn test_nym_key_derivation() -> AdapterResult<()> {
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let derivation = HmacKeyDerivation;
        
        let keys = derivation.derive_keys(&keypair, "nym")?;
        
        assert_eq!(keys.network_id, "nym");
        assert!(keys.get_secondary_key("privacy").is_some());
        assert!(keys.get_secondary_key("signing").is_some());
        assert_eq!(keys.metadata.get("privacy_enabled"), Some(&"true".to_string()));
        
        Ok(())
    }

    #[test]
    fn test_key_derivation_reproducible() -> AdapterResult<()> {
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let derivation = HmacKeyDerivation;
        
        let keys1 = derivation.derive_keys(&keypair, "ethereum")?;
        let keys2 = derivation.derive_keys(&keypair, "ethereum")?;
        
        assert_eq!(keys1.primary_key.expose_secret(), keys2.primary_key.expose_secret());
        assert_eq!(keys1.public_key, keys2.public_key);
        
        Ok(())
    }

    #[test]
    fn test_different_networks_different_keys() -> AdapterResult<()> {
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let derivation = HmacKeyDerivation;
        
        let bitcoin_keys = derivation.derive_keys(&keypair, "bitcoin")?;
        let ethereum_keys = derivation.derive_keys(&keypair, "ethereum")?;
        
        assert_ne!(bitcoin_keys.primary_key.expose_secret(), ethereum_keys.primary_key.expose_secret());
        assert_ne!(bitcoin_keys.public_key, ethereum_keys.public_key);
        
        Ok(())
    }
}