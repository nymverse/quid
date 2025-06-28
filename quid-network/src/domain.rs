//! Domain resolution system for QuID network
//! 
//! Maps human-readable domain names (alice.quid) to content stored in the DHT

use crate::{DHT, DHTKey, DHTValue, Result, NetworkError, consistent_hash};
use quid_core::{QuIDIdentity, crypto::KeyPair};
use quid_consensus::{Blockchain, NymAmount};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// A domain record stored in the DHT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecord {
    /// Domain name (e.g., "alice.quid")
    pub domain: String,
    
    /// Owner's QuID identity ID
    pub owner: Vec<u8>,
    
    /// Content hash that this domain points to
    pub content_hash: Vec<u8>,
    
    /// Domain metadata
    pub metadata: DomainMetadata,
    
    /// When this record was created/updated
    pub timestamp: u64,
    
    /// Record version (for updates)
    pub version: u64,
    
    /// Owner's signature of this record
    pub signature: Vec<u8>,
}

/// Domain metadata and configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainMetadata {
    /// Domain title/description
    pub title: String,
    
    /// Domain category
    pub category: String,
    
    /// Content type (website, social, marketplace, etc.)
    pub content_type: String,
    
    /// When domain registration expires
    pub expires_at: u64,
    
    /// Domain tags for discovery
    pub tags: Vec<String>,
    
    /// Public metadata (visible to all)
    pub public_data: HashMap<String, String>,
    
    /// Domain configuration
    pub config: DomainConfig,
}

/// Domain configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    /// Allow subdomain creation
    pub allow_subdomains: bool,
    
    /// Cache TTL for this domain (seconds)
    pub cache_ttl: u64,
    
    /// Whether domain content can be cached by others
    pub allow_caching: bool,
    
    /// Access control settings
    pub access_control: AccessControl,
    
    /// Redirect settings
    pub redirect: Option<String>,
}

/// Access control for domain content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControl {
    /// Is domain publicly accessible
    pub public: bool,
    
    /// List of QuID identities with access
    pub allowed_users: Vec<Vec<u8>>,
    
    /// Require payment to access
    pub payment_required: Option<NymAmount>,
    
    /// Rate limiting (requests per minute)
    pub rate_limit: Option<u32>,
}

impl Default for AccessControl {
    fn default() -> Self {
        Self {
            public: true,
            allowed_users: Vec::new(),
            payment_required: None,
            rate_limit: None,
        }
    }
}

impl Default for DomainConfig {
    fn default() -> Self {
        Self {
            allow_subdomains: false,
            cache_ttl: 3600, // 1 hour
            allow_caching: true,
            access_control: AccessControl::default(),
            redirect: None,
        }
    }
}

impl DomainRecord {
    /// Create a new domain record
    pub fn new(
        domain: String,
        owner: Vec<u8>,
        content_hash: Vec<u8>,
        title: String,
        category: String,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let metadata = DomainMetadata {
            title,
            category,
            content_type: "website".to_string(),
            expires_at: timestamp + (365 * 24 * 3600), // 1 year from now
            tags: Vec::new(),
            public_data: HashMap::new(),
            config: DomainConfig::default(),
        };
        
        Self {
            domain,
            owner,
            content_hash,
            metadata,
            timestamp,
            version: 1,
            signature: Vec::new(),
        }
    }
    
    /// Sign this domain record
    pub fn sign(&mut self, keypair: &KeyPair) -> Result<()> {
        let signing_data = self.signing_data()?;
        self.signature = keypair.sign(&signing_data)
            .map_err(|e| NetworkError::DHTError(format!("Signing failed: {}", e)))?;
        Ok(())
    }
    
    /// Verify the signature on this domain record
    pub fn verify_signature(&self, keypair: &KeyPair) -> Result<bool> {
        let signing_data = self.signing_data()?;
        keypair.verify(&signing_data, &self.signature)
            .map_err(|e| NetworkError::DHTError(format!("Verification failed: {}", e)))
    }
    
    /// Check if this domain record has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now > self.metadata.expires_at
    }
    
    /// Update content hash (creates new version)
    pub fn update_content(&mut self, new_content_hash: Vec<u8>) {
        self.content_hash = new_content_hash;
        self.version += 1;
        self.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    /// Get data that should be signed
    fn signing_data(&self) -> Result<Vec<u8>> {
        let signable = SignableDomainRecord {
            domain: &self.domain,
            owner: &self.owner,
            content_hash: &self.content_hash,
            metadata: &self.metadata,
            timestamp: self.timestamp,
            version: self.version,
        };
        
        serde_json::to_vec(&signable)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))
    }
}

/// Domain record data for signing (excludes signature)
#[derive(Serialize)]
struct SignableDomainRecord<'a> {
    domain: &'a str,
    owner: &'a [u8],
    content_hash: &'a [u8],
    metadata: &'a DomainMetadata,
    timestamp: u64,
    version: u64,
}

/// Domain resolution query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainResolution {
    /// The domain record
    pub record: DomainRecord,
    
    /// The actual content (if available locally)
    pub content: Option<Vec<u8>>,
    
    /// Where this resolution came from
    pub source: ResolutionSource,
    
    /// Time when this was resolved
    pub resolved_at: u64,
}

/// Source of domain resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResolutionSource {
    /// Local cache
    LocalCache,
    
    /// DHT lookup
    DHT,
    
    /// Blockchain registry
    Blockchain,
    
    /// Peer provided
    Peer(Vec<u8>), // Peer QuID ID
}

/// Domain resolver that integrates with DHT and blockchain
pub struct DomainResolver {
    /// DHT for content storage
    dht: DHT,
    
    /// Blockchain for domain ownership verification
    blockchain: Option<Blockchain>,
    
    /// Local domain cache
    cache: tokio::sync::RwLock<HashMap<String, DomainResolution>>,
    
    /// Cache TTL (seconds)
    cache_ttl: u64,
}

impl DomainResolver {
    /// Create a new domain resolver
    pub fn new(dht: DHT, blockchain: Option<Blockchain>) -> Self {
        Self {
            dht,
            blockchain,
            cache: tokio::sync::RwLock::new(HashMap::new()),
            cache_ttl: 300, // 5 minutes default cache
        }
    }
    
    /// Register a new domain
    pub async fn register_domain(
        &mut self,
        domain: String,
        owner_identity: &QuIDIdentity,
        owner_keypair: &KeyPair,
        content_hash: Vec<u8>,
        title: String,
        category: String,
    ) -> Result<()> {
        // Validate domain name
        self.validate_domain_name(&domain)?;
        
        // Check if domain already exists
        if self.domain_exists(&domain).await? {
            return Err(NetworkError::InvalidContent(
                format!("Domain {} already exists", domain)
            ));
        }
        
        // Create domain record
        let mut record = DomainRecord::new(
            domain.clone(),
            owner_identity.id.clone(),
            content_hash,
            title,
            category,
        );
        
        // Sign the record
        record.sign(owner_keypair)?;
        
        // Store in DHT
        let domain_key = self.domain_to_key(&domain);
        let dht_value = DHTValue::new(
            serde_json::to_vec(&record)
                .map_err(|e| NetworkError::SerializationError(e.to_string()))?,
            "application/quid-domain".to_string(),
            owner_identity.id.clone(),
            record.signature.clone(),
            365 * 24 * 3600, // 1 year TTL
            record.version,
        );
        
        self.dht.store(domain_key, dht_value).await?;
        
        // Update cache
        let resolution = DomainResolution {
            record,
            content: None,
            source: ResolutionSource::LocalCache,
            resolved_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let mut cache = self.cache.write().await;
        cache.insert(domain, resolution);
        
        Ok(())
    }
    
    /// Resolve a domain name to its content
    pub async fn resolve(&self, domain: &str) -> Result<Option<DomainResolution>> {
        // Check cache first
        if let Some(cached) = self.get_from_cache(domain).await {
            return Ok(Some(cached));
        }
        
        // Look up in DHT
        let domain_key = self.domain_to_key(domain);
        
        if let Some(dht_value) = self.dht.get(&domain_key).await? {
            // Parse domain record
            let record: DomainRecord = serde_json::from_slice(&dht_value.data)
                .map_err(|e| NetworkError::SerializationError(e.to_string()))?;
            
            // Verify record hasn't expired
            if record.is_expired() {
                return Ok(None);
            }
            
            // Try to fetch content
            let content = self.dht.get(&record.content_hash).await?
                .map(|v| v.data);
            
            let resolution = DomainResolution {
                record,
                content,
                source: ResolutionSource::DHT,
                resolved_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            
            // Cache the result
            self.update_cache(domain.to_string(), resolution.clone()).await;
            
            return Ok(Some(resolution));
        }
        
        Ok(None)
    }
    
    /// Update domain content
    pub async fn update_domain(
        &mut self,
        domain: &str,
        owner_keypair: &KeyPair,
        new_content_hash: Vec<u8>,
    ) -> Result<()> {
        // Get current domain record
        let mut resolution = self.resolve(domain).await?
            .ok_or_else(|| NetworkError::ContentNotFound(format!("Domain {} not found", domain)))?;
        
        // Update content hash and version
        resolution.record.update_content(new_content_hash);
        
        // Re-sign the record
        resolution.record.sign(owner_keypair)?;
        
        // Store updated record in DHT
        let domain_key = self.domain_to_key(domain);
        let dht_value = DHTValue::new(
            serde_json::to_vec(&resolution.record)
                .map_err(|e| NetworkError::SerializationError(e.to_string()))?,
            "application/quid-domain".to_string(),
            resolution.record.owner.clone(),
            resolution.record.signature.clone(),
            365 * 24 * 3600, // 1 year TTL
            resolution.record.version,
        );
        
        self.dht.update(domain_key, dht_value).await?;
        
        // Update cache
        resolution.resolved_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.update_cache(domain.to_string(), resolution).await;
        
        Ok(())
    }
    
    /// Delete a domain (only by owner)
    pub async fn delete_domain(
        &mut self,
        domain: &str,
        owner_quid_id: &[u8],
    ) -> Result<bool> {
        // Verify ownership
        if let Some(resolution) = self.resolve(domain).await? {
            if resolution.record.owner != owner_quid_id {
                return Err(NetworkError::PermissionDenied(
                    "Only domain owner can delete domain".to_string()
                ));
            }
        } else {
            return Ok(false); // Domain doesn't exist
        }
        
        // Delete from DHT
        let domain_key = self.domain_to_key(domain);
        let deleted = self.dht.delete(&domain_key, owner_quid_id).await?;
        
        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(domain);
        
        Ok(deleted)
    }
    
    /// List domains by category
    pub async fn list_by_category(&self, category: &str) -> Result<Vec<DomainRecord>> {
        // This would require a secondary index in a production system
        // For now, return empty list
        // TODO: Implement category indexing in DHT
        Ok(Vec::new())
    }
    
    /// Search domains by tags or keywords
    pub async fn search(&self, query: &str) -> Result<Vec<DomainRecord>> {
        // This would require full-text search indexing in a production system
        // For now, return empty list
        // TODO: Implement search indexing
        Ok(Vec::new())
    }
    
    /// Get domain statistics
    pub async fn get_domain_stats(&self, domain: &str) -> Result<DomainStats> {
        let resolution = self.resolve(domain).await?
            .ok_or_else(|| NetworkError::ContentNotFound(format!("Domain {} not found", domain)))?;
        
        let content_size = if let Some(content) = &resolution.content {
            content.len()
        } else {
            0
        };
        
        Ok(DomainStats {
            domain: domain.to_string(),
            owner: resolution.record.owner,
            created_at: resolution.record.timestamp,
            last_updated: resolution.record.timestamp,
            version: resolution.record.version,
            content_size,
            expires_at: resolution.record.metadata.expires_at,
        })
    }
    
    /// Convert domain name to DHT key
    fn domain_to_key(&self, domain: &str) -> DHTKey {
        let domain_bytes = format!("quid-domain:{}", domain.to_lowercase());
        consistent_hash(domain_bytes.as_bytes())
    }
    
    /// Validate domain name format
    fn validate_domain_name(&self, domain: &str) -> Result<()> {
        // Basic validation
        if domain.is_empty() {
            return Err(NetworkError::InvalidContent("Domain name cannot be empty".to_string()));
        }
        
        if domain.len() > 253 {
            return Err(NetworkError::InvalidContent("Domain name too long".to_string()));
        }
        
        if !domain.ends_with(".quid") {
            return Err(NetworkError::InvalidContent("Domain must end with .quid".to_string()));
        }
        
        // Check for valid characters
        let name_part = &domain[..domain.len() - 5]; // Remove ".quid"
        if !name_part.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '.') {
            return Err(NetworkError::InvalidContent(
                "Domain name contains invalid characters".to_string()
            ));
        }
        
        // No consecutive dots or hyphens
        if name_part.contains("..") || name_part.contains("--") {
            return Err(NetworkError::InvalidContent(
                "Domain name cannot contain consecutive dots or hyphens".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Check if domain already exists
    async fn domain_exists(&self, domain: &str) -> Result<bool> {
        Ok(self.resolve(domain).await?.is_some())
    }
    
    /// Get domain from cache
    async fn get_from_cache(&self, domain: &str) -> Option<DomainResolution> {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(domain) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            if now - cached.resolved_at < self.cache_ttl {
                return Some(cached.clone());
            }
        }
        None
    }
    
    /// Update cache
    async fn update_cache(&self, domain: String, resolution: DomainResolution) {
        let mut cache = self.cache.write().await;
        cache.insert(domain, resolution);
    }
    
    /// Clear expired cache entries
    pub async fn cleanup_cache(&self) {
        let mut cache = self.cache.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        cache.retain(|_, resolution| now - resolution.resolved_at < self.cache_ttl);
    }
}

/// Domain statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStats {
    pub domain: String,
    pub owner: Vec<u8>,
    pub created_at: u64,
    pub last_updated: u64,
    pub version: u64,
    pub content_size: usize,
    pub expires_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;

    #[test]
    fn test_domain_validation() {
        let (identity, _) = quid_core::QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let dht = DHT::new(identity, "127.0.0.1:8080".to_string(), 3);
        let resolver = DomainResolver::new(dht, None);
        
        // Valid domains
        assert!(resolver.validate_domain_name("alice.quid").is_ok());
        assert!(resolver.validate_domain_name("my-shop.quid").is_ok());
        assert!(resolver.validate_domain_name("sub.domain.quid").is_ok());
        
        // Invalid domains
        assert!(resolver.validate_domain_name("").is_err());
        assert!(resolver.validate_domain_name("alice").is_err()); // No .quid
        assert!(resolver.validate_domain_name("alice..quid").is_err()); // Double dot
        assert!(resolver.validate_domain_name("alice@quid").is_err()); // Invalid char
    }

    #[tokio::test]
    async fn test_domain_registration() {
        let (identity, keypair) = quid_core::QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let dht = DHT::new(identity.clone(), "127.0.0.1:8080".to_string(), 3);
        let mut resolver = DomainResolver::new(dht, None);
        
        let content_hash = consistent_hash(b"my website content");
        
        // Register domain
        resolver.register_domain(
            "alice.quid".to_string(),
            &identity,
            &keypair,
            content_hash.clone(),
            "Alice's Personal Site".to_string(),
            "personal".to_string(),
        ).await.unwrap();
        
        // Resolve domain
        let resolution = resolver.resolve("alice.quid").await.unwrap();
        assert!(resolution.is_some());
        
        let record = resolution.unwrap().record;
        assert_eq!(record.domain, "alice.quid");
        assert_eq!(record.owner, identity.id);
        assert_eq!(record.content_hash, content_hash);
    }

    #[test]
    fn test_domain_record_signing() {
        let (identity, keypair) = quid_core::QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let mut record = DomainRecord::new(
            "test.quid".to_string(),
            identity.id.clone(),
            vec![1, 2, 3, 4],
            "Test Domain".to_string(),
            "test".to_string(),
        );
        
        // Sign record
        record.sign(&keypair).unwrap();
        assert!(!record.signature.is_empty());
        
        // Verify signature
        assert!(record.verify_signature(&keypair).unwrap());
    }

    #[tokio::test]
    async fn test_domain_update() {
        let (identity, keypair) = quid_core::QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let dht = DHT::new(identity.clone(), "127.0.0.1:8080".to_string(), 3);
        let mut resolver = DomainResolver::new(dht, None);
        
        let original_content = consistent_hash(b"original content");
        let updated_content = consistent_hash(b"updated content");
        
        // Register domain
        resolver.register_domain(
            "alice.quid".to_string(),
            &identity,
            &keypair,
            original_content,
            "Alice's Site".to_string(),
            "personal".to_string(),
        ).await.unwrap();
        
        // Update domain
        resolver.update_domain("alice.quid", &keypair, updated_content.clone()).await.unwrap();
        
        // Verify update
        let resolution = resolver.resolve("alice.quid").await.unwrap().unwrap();
        assert_eq!(resolution.record.content_hash, updated_content);
        assert_eq!(resolution.record.version, 2); // Should be incremented
    }
}
