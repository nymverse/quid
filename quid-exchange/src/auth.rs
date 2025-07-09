//! Authentication and API key management for QuID exchange integration

use quid_core::{QuIDIdentity, SecurityLevel};
use secrecy::{SecretString, ExposeSecret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use base64::{Engine as _, engine::general_purpose};

use crate::{ExchangeError, ExchangeResult, ExchangeType, types::APICredentials};

/// API key manager for secure key derivation and management
#[derive(Debug)]
pub struct APIKeyManager {
    /// QuID identity for key derivation
    identity: QuIDIdentity,
    /// Cached API keys by exchange
    api_keys: Arc<RwLock<HashMap<ExchangeType, DerivedAPIKey>>>,
    /// Key derivation settings
    derivation_settings: KeyDerivationSettings,
}

/// Derived API key with metadata
#[derive(Debug, Clone)]
pub struct DerivedAPIKey {
    /// API key
    pub api_key: SecretString,
    /// API secret
    pub api_secret: SecretString,
    /// Optional passphrase
    pub passphrase: Option<SecretString>,
    /// Exchange type
    pub exchange_type: ExchangeType,
    /// Derivation path
    pub derivation_path: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Expiry timestamp
    pub expires_at: Option<DateTime<Utc>>,
    /// Usage count
    pub usage_count: u64,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
}

/// Key derivation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationSettings {
    /// Key length in bytes
    pub key_length: usize,
    /// Salt for key derivation
    pub salt: String,
    /// Number of iterations for PBKDF2
    pub iterations: u32,
    /// Key rotation interval in seconds
    pub rotation_interval: u64,
    /// Enable key caching
    pub enable_caching: bool,
}

/// API signature generator
#[derive(Debug)]
pub struct APISignatureGenerator {
    /// API key manager
    key_manager: Arc<APIKeyManager>,
}

/// API request signature
#[derive(Debug, Clone)]
pub struct APISignature {
    /// Signature value
    pub signature: String,
    /// Timestamp used for signature
    pub timestamp: DateTime<Utc>,
    /// Nonce used for signature
    pub nonce: String,
    /// Algorithm used
    pub algorithm: String,
}

/// Exchange-specific authentication handler
#[async_trait::async_trait]
pub trait ExchangeAuthHandler: Send + Sync {
    /// Generate authentication headers
    async fn generate_auth_headers(
        &self,
        method: &str,
        path: &str,
        query_params: &HashMap<String, String>,
        body: &str,
        timestamp: DateTime<Utc>,
    ) -> ExchangeResult<HashMap<String, String>>;
    
    /// Validate API credentials
    async fn validate_credentials(&self, credentials: &APICredentials) -> ExchangeResult<bool>;
    
    /// Get required permissions for operation
    fn get_required_permissions(&self, operation: &str) -> Vec<String>;
}

impl APIKeyManager {
    /// Create new API key manager
    pub async fn new(identity: QuIDIdentity) -> ExchangeResult<Self> {
        let api_keys = Arc::new(RwLock::new(HashMap::new()));
        let derivation_settings = KeyDerivationSettings::default();
        
        Ok(Self {
            identity,
            api_keys,
            derivation_settings,
        })
    }
    
    /// Derive API key for exchange
    pub async fn derive_api_key(&self, exchange_type: ExchangeType, custom_path: Option<&str>) -> ExchangeResult<DerivedAPIKey> {
        // Check if we already have a cached key
        if self.derivation_settings.enable_caching {
            let api_keys = self.api_keys.read().await;
            if let Some(cached_key) = api_keys.get(&exchange_type) {
                if !self.is_key_expired(cached_key) {
                    return Ok(cached_key.clone());
                }
            }
        }
        
        // Generate new API key
        let derivation_path = custom_path.unwrap_or(&format!("quid-exchange/{}", exchange_type.to_string()));
        
        let (api_key, api_secret, passphrase) = self.generate_key_pair(exchange_type, derivation_path).await?;
        
        let derived_key = DerivedAPIKey {
            api_key,
            api_secret,
            passphrase,
            exchange_type,
            derivation_path: derivation_path.to_string(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::seconds(self.derivation_settings.rotation_interval as i64)),
            usage_count: 0,
            last_used: None,
        };
        
        // Cache the key
        if self.derivation_settings.enable_caching {
            let mut api_keys = self.api_keys.write().await;
            api_keys.insert(exchange_type, derived_key.clone());
        }
        
        tracing::info!("Derived API key for exchange: {}", exchange_type.to_string());
        
        Ok(derived_key)
    }
    
    /// Get API key for exchange
    pub async fn get_api_key(&self, exchange_type: ExchangeType) -> ExchangeResult<DerivedAPIKey> {
        let api_keys = self.api_keys.read().await;
        if let Some(cached_key) = api_keys.get(&exchange_type) {
            if !self.is_key_expired(cached_key) {
                return Ok(cached_key.clone());
            }
        }
        drop(api_keys);
        
        // Generate new key if not cached or expired
        self.derive_api_key(exchange_type, None).await
    }
    
    /// Rotate API key for exchange
    pub async fn rotate_api_key(&self, exchange_type: ExchangeType) -> ExchangeResult<DerivedAPIKey> {
        // Remove old key from cache
        {
            let mut api_keys = self.api_keys.write().await;
            api_keys.remove(&exchange_type);
        }
        
        // Generate new key
        self.derive_api_key(exchange_type, None).await
    }
    
    /// Update key usage statistics
    pub async fn update_key_usage(&self, exchange_type: ExchangeType) -> ExchangeResult<()> {
        let mut api_keys = self.api_keys.write().await;
        if let Some(key) = api_keys.get_mut(&exchange_type) {
            key.usage_count += 1;
            key.last_used = Some(Utc::now());
        }
        Ok(())
    }
    
    /// Check if key is expired
    fn is_key_expired(&self, key: &DerivedAPIKey) -> bool {
        if let Some(expires_at) = key.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }
    
    /// Generate key pair using QuID identity
    async fn generate_key_pair(
        &self,
        exchange_type: ExchangeType,
        derivation_path: &str,
    ) -> ExchangeResult<(SecretString, SecretString, Option<SecretString>)> {
        // Use QuID identity to derive exchange-specific keys
        let identity_bytes = self.identity.public_key().as_bytes();
        let path_bytes = derivation_path.as_bytes();
        let exchange_bytes = exchange_type.to_string().as_bytes();
        
        // Create key derivation input
        let mut input = Vec::new();
        input.extend_from_slice(identity_bytes);
        input.extend_from_slice(path_bytes);
        input.extend_from_slice(exchange_bytes);
        input.extend_from_slice(self.derivation_settings.salt.as_bytes());
        
        // Generate API key
        let api_key = self.derive_key(&input, b"api_key")?;
        let api_key_str = general_purpose::STANDARD.encode(&api_key);
        
        // Generate API secret
        let api_secret = self.derive_key(&input, b"api_secret")?;
        let api_secret_str = general_purpose::STANDARD.encode(&api_secret);
        
        // Generate passphrase for exchanges that require it
        let passphrase = if self.requires_passphrase(exchange_type) {
            let passphrase_bytes = self.derive_key(&input, b"passphrase")?;
            let passphrase_str = general_purpose::STANDARD.encode(&passphrase_bytes);
            Some(SecretString::new(passphrase_str))
        } else {
            None
        };
        
        Ok((
            SecretString::new(api_key_str),
            SecretString::new(api_secret_str),
            passphrase,
        ))
    }
    
    /// Derive key using PBKDF2
    fn derive_key(&self, input: &[u8], info: &[u8]) -> ExchangeResult<Vec<u8>> {
        use sha2::Sha256;
        
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.update(info);
        let hash = hasher.finalize();
        
        // Simple key derivation (in production, use proper PBKDF2 or HKDF)
        let mut derived_key = vec![0u8; self.derivation_settings.key_length];
        let hash_bytes = hash.as_slice();
        
        for i in 0..self.derivation_settings.key_length {
            derived_key[i] = hash_bytes[i % hash_bytes.len()];
        }
        
        Ok(derived_key)
    }
    
    /// Check if exchange requires passphrase
    fn requires_passphrase(&self, exchange_type: ExchangeType) -> bool {
        match exchange_type {
            ExchangeType::Coinbase | ExchangeType::OKX => true,
            _ => false,
        }
    }
    
    /// Get key derivation settings
    pub fn get_derivation_settings(&self) -> &KeyDerivationSettings {
        &self.derivation_settings
    }
    
    /// Update key derivation settings
    pub fn update_derivation_settings(&mut self, settings: KeyDerivationSettings) {
        self.derivation_settings = settings;
    }
}

impl APISignatureGenerator {
    /// Create new API signature generator
    pub fn new(key_manager: Arc<APIKeyManager>) -> Self {
        Self { key_manager }
    }
    
    /// Generate API signature for request
    pub async fn generate_signature(
        &self,
        exchange_type: ExchangeType,
        method: &str,
        path: &str,
        query_params: &HashMap<String, String>,
        body: &str,
        timestamp: DateTime<Utc>,
    ) -> ExchangeResult<APISignature> {
        let api_key = self.key_manager.get_api_key(exchange_type).await?;
        
        // Generate nonce
        let nonce = uuid::Uuid::new_v4().to_string();
        
        // Create signature payload
        let payload = self.create_signature_payload(
            method,
            path,
            query_params,
            body,
            timestamp,
            &nonce,
        )?;
        
        // Generate HMAC signature
        let signature = self.sign_payload(&payload, &api_key.api_secret)?;
        
        // Update usage statistics
        self.key_manager.update_key_usage(exchange_type).await?;
        
        Ok(APISignature {
            signature,
            timestamp,
            nonce,
            algorithm: "HMAC-SHA256".to_string(),
        })
    }
    
    /// Create signature payload
    fn create_signature_payload(
        &self,
        method: &str,
        path: &str,
        query_params: &HashMap<String, String>,
        body: &str,
        timestamp: DateTime<Utc>,
        nonce: &str,
    ) -> ExchangeResult<String> {
        let mut payload = String::new();
        
        // Add timestamp
        payload.push_str(&timestamp.timestamp().to_string());
        
        // Add nonce
        payload.push_str(nonce);
        
        // Add method
        payload.push_str(method);
        
        // Add path
        payload.push_str(path);
        
        // Add query parameters (sorted)
        if !query_params.is_empty() {
            let mut sorted_params: Vec<_> = query_params.iter().collect();
            sorted_params.sort_by_key(|(k, _)| *k);
            
            payload.push('?');
            for (i, (key, value)) in sorted_params.iter().enumerate() {
                if i > 0 {
                    payload.push('&');
                }
                payload.push_str(key);
                payload.push('=');
                payload.push_str(value);
            }
        }
        
        // Add body
        payload.push_str(body);
        
        Ok(payload)
    }
    
    /// Sign payload with HMAC-SHA256
    fn sign_payload(&self, payload: &str, secret: &SecretString) -> ExchangeResult<String> {
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
            .map_err(|e| ExchangeError::SignatureVerificationFailed(e.to_string()))?;
        
        mac.update(payload.as_bytes());
        let result = mac.finalize();
        let signature = general_purpose::STANDARD.encode(result.into_bytes());
        
        Ok(signature)
    }
}

impl Default for KeyDerivationSettings {
    fn default() -> Self {
        Self {
            key_length: 32,
            salt: "quid-exchange-salt".to_string(),
            iterations: 100_000,
            rotation_interval: 86400, // 24 hours
            enable_caching: true,
        }
    }
}

/// Generic exchange authentication handler
#[derive(Debug)]
pub struct GenericExchangeAuthHandler {
    /// API key manager
    key_manager: Arc<APIKeyManager>,
    /// Signature generator
    signature_generator: APISignatureGenerator,
}

impl GenericExchangeAuthHandler {
    /// Create new generic exchange auth handler
    pub fn new(key_manager: Arc<APIKeyManager>) -> Self {
        let signature_generator = APISignatureGenerator::new(key_manager.clone());
        
        Self {
            key_manager,
            signature_generator,
        }
    }
}

#[async_trait::async_trait]
impl ExchangeAuthHandler for GenericExchangeAuthHandler {
    async fn generate_auth_headers(
        &self,
        method: &str,
        path: &str,
        query_params: &HashMap<String, String>,
        body: &str,
        timestamp: DateTime<Utc>,
    ) -> ExchangeResult<HashMap<String, String>> {
        let mut headers = HashMap::new();
        
        // Add timestamp
        headers.insert("X-Timestamp".to_string(), timestamp.timestamp().to_string());
        
        // Add content type
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        
        // Add user agent
        headers.insert("User-Agent".to_string(), "QuID-Exchange/1.0".to_string());
        
        Ok(headers)
    }
    
    async fn validate_credentials(&self, credentials: &APICredentials) -> ExchangeResult<bool> {
        // Basic validation - check if credentials are not empty
        if credentials.api_key.is_empty() || credentials.api_secret.is_empty() {
            return Ok(false);
        }
        
        // Additional validation can be added here
        
        Ok(true)
    }
    
    fn get_required_permissions(&self, operation: &str) -> Vec<String> {
        match operation {
            "get_balance" | "get_account_info" => vec!["read".to_string()],
            "place_order" | "cancel_order" => vec!["trade".to_string()],
            "withdraw" => vec!["withdraw".to_string()],
            _ => vec!["read".to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;
    
    #[tokio::test]
    async fn test_api_key_manager_creation() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let manager = APIKeyManager::new(identity).await.unwrap();
        
        assert!(manager.derivation_settings.enable_caching);
        assert_eq!(manager.derivation_settings.key_length, 32);
    }
    
    #[tokio::test]
    async fn test_api_key_derivation() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let manager = APIKeyManager::new(identity).await.unwrap();
        
        let derived_key = manager.derive_api_key(ExchangeType::Binance, None).await.unwrap();
        
        assert_eq!(derived_key.exchange_type, ExchangeType::Binance);
        assert!(!derived_key.api_key.expose_secret().is_empty());
        assert!(!derived_key.api_secret.expose_secret().is_empty());
        assert_eq!(derived_key.usage_count, 0);
    }
    
    #[tokio::test]
    async fn test_api_key_caching() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let manager = APIKeyManager::new(identity).await.unwrap();
        
        let key1 = manager.derive_api_key(ExchangeType::Binance, None).await.unwrap();
        let key2 = manager.get_api_key(ExchangeType::Binance).await.unwrap();
        
        // Should be the same key (cached)
        assert_eq!(key1.created_at, key2.created_at);
        assert_eq!(key1.api_key.expose_secret(), key2.api_key.expose_secret());
    }
    
    #[tokio::test]
    async fn test_signature_generation() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let manager = Arc::new(APIKeyManager::new(identity).await.unwrap());
        let generator = APISignatureGenerator::new(manager);
        
        let signature = generator.generate_signature(
            ExchangeType::Binance,
            "GET",
            "/api/v3/account",
            &HashMap::new(),
            "",
            Utc::now(),
        ).await.unwrap();
        
        assert!(!signature.signature.is_empty());
        assert_eq!(signature.algorithm, "HMAC-SHA256");
        assert!(!signature.nonce.is_empty());
    }
    
    #[tokio::test]
    async fn test_passphrase_requirement() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let manager = APIKeyManager::new(identity).await.unwrap();
        
        let binance_key = manager.derive_api_key(ExchangeType::Binance, None).await.unwrap();
        assert!(binance_key.passphrase.is_none());
        
        let coinbase_key = manager.derive_api_key(ExchangeType::Coinbase, None).await.unwrap();
        assert!(coinbase_key.passphrase.is_some());
    }
    
    #[tokio::test]
    async fn test_key_rotation() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let manager = APIKeyManager::new(identity).await.unwrap();
        
        let original_key = manager.derive_api_key(ExchangeType::Binance, None).await.unwrap();
        let rotated_key = manager.rotate_api_key(ExchangeType::Binance).await.unwrap();
        
        // Should be different keys
        assert_ne!(original_key.created_at, rotated_key.created_at);
        assert_ne!(original_key.api_key.expose_secret(), rotated_key.api_key.expose_secret());
    }
}