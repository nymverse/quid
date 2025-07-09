//! Address derivation for Nym blockchain

use quid_core::QuIDIdentity;
use sha3::{Sha3_256, Digest};
// use ed25519_dalek::PublicKey; // Temporarily disabled
use crate::{NymAdapterResult, NymAdapterError, PrivacyLevel, config::AddressConfig};

/// Nym address generator
#[derive(Debug, Clone)]
pub struct NymAddressGenerator {
    config: AddressConfig,
}

impl NymAddressGenerator {
    /// Create new address generator
    pub fn new(config: &AddressConfig) -> NymAdapterResult<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Derive Nym address from QuID identity
    pub async fn derive_address(
        &self,
        identity: &QuIDIdentity,
        privacy_level: PrivacyLevel,
    ) -> NymAdapterResult<String> {
        let public_key_bytes = identity.public_key().as_bytes();
        
        match privacy_level {
            PrivacyLevel::Public => self.derive_public_address(public_key_bytes),
            PrivacyLevel::Shielded => self.derive_shielded_address(public_key_bytes),
            PrivacyLevel::Anonymous => self.derive_anonymous_address(public_key_bytes),
            PrivacyLevel::Mixnet => self.derive_mixnet_address(public_key_bytes),
        }
    }

    /// Derive public address
    fn derive_public_address(&self, public_key: &[u8]) -> NymAdapterResult<String> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"nym_public_address");
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        let address = self.encode_address(&hash[0..20])?;
        Ok(address)
    }

    /// Derive shielded address
    fn derive_shielded_address(&self, public_key: &[u8]) -> NymAdapterResult<String> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"nym_shielded_address");
        hasher.update(public_key);
        hasher.update(&self.config.derivation_path.as_bytes());
        let hash = hasher.finalize();
        
        let address = self.encode_shielded_address(&hash[0..32])?;
        Ok(address)
    }

    /// Derive anonymous address (one-time use)
    fn derive_anonymous_address(&self, public_key: &[u8]) -> NymAdapterResult<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_bytes: [u8; 32] = rng.gen();
        
        let mut hasher = Sha3_256::new();
        hasher.update(b"nym_anonymous_address");
        hasher.update(public_key);
        hasher.update(&random_bytes);
        let hash = hasher.finalize();
        
        let address = self.encode_anonymous_address(&hash[0..32])?;
        Ok(address)
    }

    /// Derive mixnet address
    fn derive_mixnet_address(&self, public_key: &[u8]) -> NymAdapterResult<String> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"nym_mixnet_address");
        hasher.update(public_key);
        hasher.update(b"mixnet_routing");
        let hash = hasher.finalize();
        
        let address = self.encode_mixnet_address(&hash[0..32])?;
        Ok(address)
    }

    /// Encode standard address with bech32
    fn encode_address(&self, hash: &[u8]) -> NymAdapterResult<String> {
        // Simplified bech32 encoding (in production, use proper bech32 library)
        let encoded = format!("{}1{}", self.config.prefix, hex::encode(hash));
        Ok(encoded)
    }

    /// Encode shielded address
    fn encode_shielded_address(&self, hash: &[u8]) -> NymAdapterResult<String> {
        let encoded = format!("{}s1{}", self.config.prefix, hex::encode(hash));
        Ok(encoded)
    }

    /// Encode anonymous address
    fn encode_anonymous_address(&self, hash: &[u8]) -> NymAdapterResult<String> {
        let encoded = format!("{}a1{}", self.config.prefix, hex::encode(hash));
        Ok(encoded)
    }

    /// Encode mixnet address
    fn encode_mixnet_address(&self, hash: &[u8]) -> NymAdapterResult<String> {
        let encoded = format!("{}m1{}", self.config.prefix, hex::encode(hash));
        Ok(encoded)
    }

    /// Validate address format
    pub fn validate_address(&self, address: &str) -> bool {
        if !address.starts_with(&self.config.prefix) {
            return false;
        }

        // Check for valid address types
        let valid_prefixes = [
            format!("{}1", self.config.prefix),      // Public
            format!("{}s1", self.config.prefix),     // Shielded
            format!("{}a1", self.config.prefix),     // Anonymous
            format!("{}m1", self.config.prefix),     // Mixnet
        ];

        valid_prefixes.iter().any(|prefix| address.starts_with(prefix))
    }

    /// Get address type from address string
    pub fn get_address_type(&self, address: &str) -> Option<PrivacyLevel> {
        if address.starts_with(&format!("{}1", self.config.prefix)) {
            Some(PrivacyLevel::Public)
        } else if address.starts_with(&format!("{}s1", self.config.prefix)) {
            Some(PrivacyLevel::Shielded)
        } else if address.starts_with(&format!("{}a1", self.config.prefix)) {
            Some(PrivacyLevel::Anonymous)
        } else if address.starts_with(&format!("{}m1", self.config.prefix)) {
            Some(PrivacyLevel::Mixnet)
        } else {
            None
        }
    }

    /// Derive viewing key for shielded addresses
    pub fn derive_viewing_key(&self, identity: &QuIDIdentity) -> NymAdapterResult<Vec<u8>> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"nym_viewing_key");
        hasher.update(identity.public_key().as_bytes());
        let hash = hasher.finalize();
        
        Ok(hash.to_vec())
    }

    /// Derive spending key for shielded addresses
    pub fn derive_spending_key(&self, identity: &QuIDIdentity) -> NymAdapterResult<Vec<u8>> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"nym_spending_key");
        hasher.update(identity.public_key().as_bytes());
        let hash = hasher.finalize();
        
        Ok(hash.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;

    #[test]
    fn test_address_generator_creation() {
        let config = AddressConfig::default();
        let generator = NymAddressGenerator::new(&config).unwrap();
        assert_eq!(generator.config.prefix, "nym");
    }

    #[tokio::test]
    async fn test_public_address_derivation() {
        let config = AddressConfig::default();
        let generator = NymAddressGenerator::new(&config).unwrap();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        let address = generator.derive_address(&identity, PrivacyLevel::Public).await.unwrap();
        assert!(address.starts_with("nym1"));
        assert!(generator.validate_address(&address));
    }

    #[tokio::test]
    async fn test_shielded_address_derivation() {
        let config = AddressConfig::default();
        let generator = NymAddressGenerator::new(&config).unwrap();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        let address = generator.derive_address(&identity, PrivacyLevel::Shielded).await.unwrap();
        assert!(address.starts_with("nyms1"));
        assert!(generator.validate_address(&address));
    }

    #[tokio::test]
    async fn test_anonymous_address_derivation() {
        let config = AddressConfig::default();
        let generator = NymAddressGenerator::new(&config).unwrap();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        let address1 = generator.derive_address(&identity, PrivacyLevel::Anonymous).await.unwrap();
        let address2 = generator.derive_address(&identity, PrivacyLevel::Anonymous).await.unwrap();
        
        assert!(address1.starts_with("nyma1"));
        assert!(address2.starts_with("nyma1"));
        assert_ne!(address1, address2); // Anonymous addresses should be different each time
        assert!(generator.validate_address(&address1));
        assert!(generator.validate_address(&address2));
    }

    #[tokio::test]
    async fn test_mixnet_address_derivation() {
        let config = AddressConfig::default();
        let generator = NymAddressGenerator::new(&config).unwrap();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        let address = generator.derive_address(&identity, PrivacyLevel::Mixnet).await.unwrap();
        assert!(address.starts_with("nymm1"));
        assert!(generator.validate_address(&address));
    }

    #[test]
    fn test_address_type_detection() {
        let config = AddressConfig::default();
        let generator = NymAddressGenerator::new(&config).unwrap();
        
        assert_eq!(generator.get_address_type("nym1abcdef"), Some(PrivacyLevel::Public));
        assert_eq!(generator.get_address_type("nyms1abcdef"), Some(PrivacyLevel::Shielded));
        assert_eq!(generator.get_address_type("nyma1abcdef"), Some(PrivacyLevel::Anonymous));
        assert_eq!(generator.get_address_type("nymm1abcdef"), Some(PrivacyLevel::Mixnet));
        assert_eq!(generator.get_address_type("invalid"), None);
    }

    #[test]
    fn test_address_validation() {
        let config = AddressConfig::default();
        let generator = NymAddressGenerator::new(&config).unwrap();
        
        assert!(generator.validate_address("nym1abcdef"));
        assert!(generator.validate_address("nyms1abcdef"));
        assert!(generator.validate_address("nyma1abcdef"));
        assert!(generator.validate_address("nymm1abcdef"));
        assert!(!generator.validate_address("invalid"));
        assert!(!generator.validate_address("btc1abcdef"));
    }

    #[test]
    fn test_key_derivation() {
        let config = AddressConfig::default();
        let generator = NymAddressGenerator::new(&config).unwrap();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        let viewing_key = generator.derive_viewing_key(&identity).unwrap();
        let spending_key = generator.derive_spending_key(&identity).unwrap();
        
        assert_eq!(viewing_key.len(), 32);
        assert_eq!(spending_key.len(), 32);
        assert_ne!(viewing_key, spending_key);
    }

    #[tokio::test]
    async fn test_deterministic_addresses() {
        let config = AddressConfig::default();
        let generator = NymAddressGenerator::new(&config).unwrap();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        // Public and shielded addresses should be deterministic
        let public1 = generator.derive_address(&identity, PrivacyLevel::Public).await.unwrap();
        let public2 = generator.derive_address(&identity, PrivacyLevel::Public).await.unwrap();
        assert_eq!(public1, public2);
        
        let shielded1 = generator.derive_address(&identity, PrivacyLevel::Shielded).await.unwrap();
        let shielded2 = generator.derive_address(&identity, PrivacyLevel::Shielded).await.unwrap();
        assert_eq!(shielded1, shielded2);
    }
}