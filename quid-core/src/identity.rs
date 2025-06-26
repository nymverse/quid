//! Core identity structures and operations

use crate::{crypto::KeyPair, QuIDError, Result, SecurityLevel, QUID_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Core QuID identity structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuIDIdentity {
    pub id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub creation_timestamp: u64,
    pub version: String,
    pub security_level: SecurityLevel,
    pub metadata: HashMap<String, Vec<u8>>,
    pub extensions: HashMap<String, Extension>,
}

/// Extension attached to an identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    pub extension_type: String,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub version: String,
    pub metadata: HashMap<String, Vec<u8>>,
}

impl QuIDIdentity {
    /// Create a new QuID identity
    pub fn new(security_level: SecurityLevel) -> Result<(Self, KeyPair)> {
        let keypair = KeyPair::generate(security_level)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| QuIDError::CryptoError(format!("Time error: {}", e)))?
            .as_secs();
        
        let id = crate::crypto::generate_id(&keypair.public_key, timestamp);
        
        let identity = QuIDIdentity {
            id,
            public_key: keypair.public_key.clone(),
            creation_timestamp: timestamp,
            version: QUID_VERSION.to_string(),
            security_level,
            metadata: HashMap::new(),
            extensions: HashMap::new(),
        };
        
        Ok((identity, keypair))
    }
    
    /// Add an extension to the identity
    pub fn add_extension(
        &mut self,
        keypair: &KeyPair,
        extension_type: String,
        data: Vec<u8>,
    ) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| QuIDError::CryptoError(format!("Time error: {}", e)))?
            .as_secs();
        
        // Create signature over extension data
        let signature = keypair.sign(&data)?;
        
        let extension = Extension {
            extension_type: extension_type.clone(),
            data,
            signature,
            timestamp,
            version: QUID_VERSION.to_string(),
            metadata: HashMap::new(),
        };
        
        self.extensions.insert(extension_type, extension);
        Ok(())
    }
    
    /// Verify all extensions in the identity
    pub fn verify_extensions(&self, keypair: &KeyPair) -> Result<bool> {
        for extension in self.extensions.values() {
            if !keypair.verify(&extension.data, &extension.signature)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_creation() {
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        assert!(!identity.id.is_empty());
        assert_eq!(identity.public_key, keypair.public_key);
        assert_eq!(identity.version, QUID_VERSION);
        assert_eq!(identity.security_level, SecurityLevel::Level1);
    }

    #[test]
    fn test_extension_management() {
        let (mut identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        // Add an extension
        let extension_data = b"test extension data".to_vec();
        identity.add_extension(&keypair, "test".to_string(), extension_data.clone()).unwrap();
        
        // Verify extension was added
        assert!(identity.extensions.contains_key("test"));
        
        // Verify extensions
        assert!(identity.verify_extensions(&keypair).unwrap());
    }
}