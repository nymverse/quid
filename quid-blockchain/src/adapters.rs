//! Blockchain adapter registry and management
//!
//! This module provides a high-performance centralized registry for managing different 
//! blockchain adapters, enabling dynamic discovery and instantiation of blockchain integrations.
//! 
//! Optimizations include:
//! - Arc-based adapter sharing for memory efficiency
//! - Cached health checks to reduce lock contention
//! - Batch operations for improved performance
//! - Lazy initialization and cleanup

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use crate::{
    QuIDBlockchainError, QuIDBlockchainResult,
    universal::{BlockchainAdapter, BlockchainNetwork, UniversalBlockchainAdapter},
    config::{CustomBlockchainConfig, AdapterSettings},
};

/// Adapter registry error types
#[derive(thiserror::Error, Debug)]
pub enum AdapterError {
    #[error("Adapter not found: {0}")]
    NotFound(String),
    
    #[error("Adapter already registered: {0}")]
    AlreadyExists(String),
    
    #[error("Adapter initialization failed: {0}")]
    InitializationFailed(String),
    
    #[error("Adapter operation failed: {0}")]
    OperationFailed(String),
}

/// Cached health check result
#[derive(Debug, Clone)]
struct HealthCheckCache {
    status: AdapterStatus,
    last_check: Instant,
    check_duration: Duration,
}

impl HealthCheckCache {
    fn new(status: AdapterStatus) -> Self {
        Self {
            status,
            last_check: Instant::now(),
            check_duration: Duration::from_millis(0),
        }
    }
    
    fn is_expired(&self, ttl: Duration) -> bool {
        self.last_check.elapsed() > ttl
    }
    
    fn update(&mut self, status: AdapterStatus, duration: Duration) {
        self.status = status;
        self.last_check = Instant::now();
        self.check_duration = duration;
    }
}

/// Adapter metadata with performance tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterMetadata {
    /// Adapter name
    pub name: String,
    /// Adapter version
    pub version: String,
    /// Description
    pub description: String,
    /// Supported networks
    pub supported_networks: Vec<String>,
    /// Required features
    pub required_features: Vec<String>,
    /// Adapter status
    pub status: AdapterStatus,
    /// Registration timestamp
    pub registered_at: chrono::DateTime<chrono::Utc>,
    /// Performance metrics
    pub metrics: AdapterMetrics,
}

/// Performance metrics for adapters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdapterMetrics {
    /// Total number of operations performed
    pub total_operations: u64,
    /// Total number of errors
    pub total_errors: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Last health check duration
    pub last_health_check_ms: Option<u64>,
    /// Total uptime since registration
    pub uptime_percentage: f64,
}

/// Adapter status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AdapterStatus {
    /// Adapter is active and available
    Active,
    /// Adapter is temporarily inactive
    Inactive,
    /// Adapter initialization is in progress
    Initializing,
    /// Adapter has failed
    Failed(String),
}

/// Adapter factory trait for dynamic creation
#[async_trait]
pub trait AdapterFactory: Send + Sync {
    /// Create a new adapter instance
    async fn create_adapter(
        &self,
        config: CustomBlockchainConfig,
        settings: AdapterSettings,
    ) -> QuIDBlockchainResult<Box<dyn BlockchainAdapter>>;
    
    /// Get factory metadata
    fn get_metadata(&self) -> AdapterMetadata;
    
    /// Validate configuration
    fn validate_config(&self, config: &CustomBlockchainConfig) -> QuIDBlockchainResult<()>;
}

/// Central adapter registry with optimized performance
pub struct AdapterRegistry {
    /// Registered adapters (Arc for efficient sharing)
    adapters: RwLock<HashMap<String, Arc<dyn BlockchainAdapter>>>,
    /// Adapter factories
    factories: RwLock<HashMap<String, Box<dyn AdapterFactory>>>,
    /// Adapter metadata
    metadata: RwLock<HashMap<String, AdapterMetadata>>,
    /// Health check cache
    health_cache: RwLock<HashMap<String, HealthCheckCache>>,
    /// Registry configuration
    config: RegistryConfig,
}

/// Batch operations for improved performance
#[derive(Debug)]
pub struct BatchOperationResult {
    pub successful: Vec<String>,
    pub failed: Vec<(String, String)>, // (name, error)
    pub total_processed: usize,
    pub processing_time: Duration,
}

/// Registry configuration with performance tuning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Enable auto-discovery of adapters
    pub auto_discovery: bool,
    /// Maximum number of adapters
    pub max_adapters: usize,
    /// Health check interval in seconds
    pub health_check_interval: u64,
    /// Enable adapter caching
    pub enable_caching: bool,
    /// Health check cache TTL in seconds
    pub health_cache_ttl: u64,
    /// Batch operation timeout in seconds
    pub batch_timeout: u64,
    /// Enable performance metrics collection
    pub enable_metrics: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            auto_discovery: true,
            max_adapters: 100,
            health_check_interval: 300, // 5 minutes
            enable_caching: true,
            health_cache_ttl: 60, // 1 minute
            batch_timeout: 30, // 30 seconds
            enable_metrics: true,
        }
    }
}

impl AdapterRegistry {
    /// Create a new adapter registry
    pub fn new() -> Self {
        Self::with_config(RegistryConfig::default())
    }

    /// Create registry with custom configuration
    pub fn with_config(config: RegistryConfig) -> Self {
        Self {
            adapters: RwLock::new(HashMap::new()),
            factories: RwLock::new(HashMap::new()),
            metadata: RwLock::new(HashMap::new()),
            health_cache: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Register a blockchain adapter with performance optimization
    pub async fn register(
        &self,
        name: &str,
        adapter: Box<dyn BlockchainAdapter>,
    ) -> QuIDBlockchainResult<()> {
        let mut adapters = self.adapters.write().await;
        let mut metadata = self.metadata.write().await;
        let mut health_cache = self.health_cache.write().await;

        if adapters.contains_key(name) {
            return Err(QuIDBlockchainError::AdapterError(
                AdapterError::AlreadyExists(name.to_string()).to_string()
            ));
        }

        if adapters.len() >= self.config.max_adapters {
            return Err(QuIDBlockchainError::AdapterError(
                "Maximum number of adapters reached".to_string()
            ));
        }

        // Create metadata with metrics
        let adapter_metadata = AdapterMetadata {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: format!("{} blockchain adapter", adapter.name()),
            supported_networks: vec![name.to_string()],
            required_features: Vec::new(),
            status: AdapterStatus::Active,
            registered_at: chrono::Utc::now(),
            metrics: AdapterMetrics::default(),
        };

        // Convert to Arc for efficient sharing
        let adapter_arc = Arc::from(adapter);
        
        adapters.insert(name.to_string(), adapter_arc);
        metadata.insert(name.to_string(), adapter_metadata);
        
        // Initialize health cache
        if self.config.enable_caching {
            health_cache.insert(name.to_string(), HealthCheckCache::new(AdapterStatus::Active));
        }

        tracing::info!("Registered blockchain adapter: {}", name);
        Ok(())
    }

    /// Register an adapter factory
    pub async fn register_factory(
        &self,
        name: &str,
        factory: Box<dyn AdapterFactory>,
    ) -> QuIDBlockchainResult<()> {
        let mut factories = self.factories.write().await;
        let mut metadata = self.metadata.write().await;

        if factories.contains_key(name) {
            return Err(QuIDBlockchainError::AdapterError(
                AdapterError::AlreadyExists(name.to_string()).to_string()
            ));
        }

        let factory_metadata = factory.get_metadata();
        factories.insert(name.to_string(), factory);
        metadata.insert(name.to_string(), factory_metadata);

        tracing::info!("Registered adapter factory: {}", name);
        Ok(())
    }

    /// Get adapter by name (returns Arc for efficient sharing)
    pub async fn get_adapter(&self, name: &str) -> QuIDBlockchainResult<Arc<dyn BlockchainAdapter>> {
        let adapters = self.adapters.read().await;
        adapters.get(name)
            .cloned()
            .ok_or_else(|| QuIDBlockchainError::AdapterError(
                AdapterError::NotFound(name.to_string()).to_string()
            ))
    }

    /// Create adapter from factory
    pub async fn create_adapter(
        &self,
        factory_name: &str,
        adapter_name: &str,
        config: CustomBlockchainConfig,
        settings: AdapterSettings,
    ) -> QuIDBlockchainResult<()> {
        let factories = self.factories.read().await;
        let factory = factories.get(factory_name)
            .ok_or_else(|| QuIDBlockchainError::AdapterError(
                AdapterError::NotFound(factory_name.to_string()).to_string()
            ))?;

        // Validate configuration
        factory.validate_config(&config)?;

        // Create adapter
        let adapter = factory.create_adapter(config, settings).await?;

        // Release factory lock before acquiring adapter lock
        drop(factories);

        // Register the created adapter
        self.register(adapter_name, adapter).await?;

        Ok(())
    }

    /// Unregister adapter
    pub async fn unregister(&self, name: &str) -> QuIDBlockchainResult<()> {
        let mut adapters = self.adapters.write().await;
        let mut metadata = self.metadata.write().await;

        adapters.remove(name)
            .ok_or_else(|| QuIDBlockchainError::AdapterError(
                AdapterError::NotFound(name.to_string()).to_string()
            ))?;

        metadata.remove(name);

        tracing::info!("Unregistered blockchain adapter: {}", name);
        Ok(())
    }

    /// List all registered adapters
    pub async fn list_adapters(&self) -> Vec<String> {
        let adapters = self.adapters.read().await;
        adapters.keys().cloned().collect()
    }

    /// List all registered factories
    pub async fn list_factories(&self) -> Vec<String> {
        let factories = self.factories.read().await;
        factories.keys().cloned().collect()
    }

    /// Get adapter metadata
    pub async fn get_metadata(&self, name: &str) -> Option<AdapterMetadata> {
        let metadata = self.metadata.read().await;
        metadata.get(name).cloned()
    }

    /// Get all adapter metadata
    pub async fn get_all_metadata(&self) -> Vec<AdapterMetadata> {
        let metadata = self.metadata.read().await;
        metadata.values().cloned().collect()
    }

    /// Count registered adapters
    pub async fn count(&self) -> usize {
        let adapters = self.adapters.read().await;
        adapters.len()
    }

    /// Check if adapter exists
    pub async fn exists(&self, name: &str) -> bool {
        let adapters = self.adapters.read().await;
        adapters.contains_key(name)
    }

    /// Batch register adapters for improved performance
    pub async fn batch_register(
        &self,
        adapters: Vec<(String, Box<dyn BlockchainAdapter>)>,
    ) -> BatchOperationResult {
        let start_time = Instant::now();
        let mut successful = Vec::new();
        let mut failed = Vec::new();
        
        for (name, adapter) in adapters {
            match self.register(&name, adapter).await {
                Ok(_) => successful.push(name),
                Err(e) => failed.push((name, e.to_string())),
            }
        }
        
        let processing_time = start_time.elapsed();
        let total_processed = successful.len() + failed.len();
        
        BatchOperationResult {
            successful,
            failed,
            total_processed,
            processing_time,
        }
    }
    
    /// Perform health check on all adapters with caching
    pub async fn health_check(&self) -> HashMap<String, AdapterStatus> {
        let adapters = self.adapters.read().await;
        let mut results = HashMap::new();
        let cache_ttl = Duration::from_secs(self.config.health_cache_ttl);
        
        // Check cache first if enabled
        if self.config.enable_caching {
            let health_cache = self.health_cache.read().await;
            
            for (name, adapter) in adapters.iter() {
                if let Some(cached) = health_cache.get(name) {
                    if !cached.is_expired(cache_ttl) {
                        results.insert(name.clone(), cached.status.clone());
                        continue;
                    }
                }
                
                // Need to perform actual health check
                let check_start = Instant::now();
                let status = match adapter.get_network_info().await {
                    Ok(_) => AdapterStatus::Active,
                    Err(e) => AdapterStatus::Failed(e.to_string()),
                };
                let check_duration = check_start.elapsed();
                
                results.insert(name.clone(), status.clone());
                
                // Update cache without blocking (spawn task)
                let name_clone = name.clone();
                let health_cache_clone = self.health_cache.clone();
                tokio::spawn(async move {
                    let mut cache = health_cache_clone.write().await;
                    cache.entry(name_clone)
                        .and_modify(|entry| entry.update(status.clone(), check_duration))
                        .or_insert_with(|| {
                            let mut new_cache = HealthCheckCache::new(status);
                            new_cache.check_duration = check_duration;
                            new_cache
                        });
                });
            }
        } else {
            // No caching, perform direct health checks
            for (name, adapter) in adapters.iter() {
                let status = match adapter.get_network_info().await {
                    Ok(_) => AdapterStatus::Active,
                    Err(e) => AdapterStatus::Failed(e.to_string()),
                };
                results.insert(name.clone(), status);
            }
        }
        
        results
    }

    /// Update adapter status
    pub async fn update_status(&self, name: &str, status: AdapterStatus) {
        let mut metadata = self.metadata.write().await;
        if let Some(meta) = metadata.get_mut(name) {
            meta.status = status;
        }
    }

    /// Auto-discover and register adapters
    pub async fn auto_discover(&self) -> QuIDBlockchainResult<Vec<String>> {
        if !self.config.auto_discovery {
            return Ok(Vec::new());
        }

        let mut discovered = Vec::new();

        // Register built-in universal adapter factory
        if !self.exists("universal").await {
            let universal_factory = UniversalAdapterFactory::new();
            self.register_factory("universal", Box::new(universal_factory)).await?;
            discovered.push("universal".to_string());
        }

        tracing::info!("Auto-discovered {} adapter factories", discovered.len());
        Ok(discovered)
    }

    /// Start background health monitoring
    pub async fn start_health_monitoring(&self) -> tokio::task::JoinHandle<()> {
        let registry = Arc::new(self);
        let interval = self.config.health_check_interval;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(
                std::time::Duration::from_secs(interval)
            );

            loop {
                interval_timer.tick().await;

                let health_results = registry.health_check().await;
                for (name, status) in health_results {
                    registry.update_status(&name, status).await;
                }

                tracing::debug!("Completed health check for {} adapters", registry.count().await);
            }
        })
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Universal adapter factory implementation
pub struct UniversalAdapterFactory {
    metadata: AdapterMetadata,
}

impl UniversalAdapterFactory {
    /// Create new universal adapter factory
    pub fn new() -> Self {
        let metadata = AdapterMetadata {
            name: "universal".to_string(),
            version: "1.0.0".to_string(),
            description: "Universal blockchain adapter factory".to_string(),
            supported_networks: vec!["*".to_string()],
            required_features: vec![
                "rpc".to_string(),
                "address_generation".to_string(),
                "transaction_signing".to_string(),
            ],
            status: AdapterStatus::Active,
            registered_at: chrono::Utc::now(),
        };

        Self { metadata }
    }
}

#[async_trait]
impl AdapterFactory for UniversalAdapterFactory {
    async fn create_adapter(
        &self,
        config: CustomBlockchainConfig,
        settings: AdapterSettings,
    ) -> QuIDBlockchainResult<Box<dyn BlockchainAdapter>> {
        // Create blockchain network from config
        let network = BlockchainNetwork {
            id: config.name.clone(),
            name: config.name.clone(),
            network_type: crate::universal::NetworkType::Custom,
            config: config.clone(),
            status: crate::universal::NetworkStatus::Active,
            features: crate::universal::NetworkFeatures {
                smart_contracts: false,
                multisig: false,
                privacy: false,
                atomic_swaps: false,
                staking: false,
                governance: false,
                quantum_resistant: true,
            },
        };

        let adapter = UniversalBlockchainAdapter::new(network, settings).await?;
        Ok(Box::new(adapter))
    }

    fn get_metadata(&self) -> AdapterMetadata {
        self.metadata.clone()
    }

    fn validate_config(&self, config: &CustomBlockchainConfig) -> QuIDBlockchainResult<()> {
        config.validate()?;

        // Additional universal adapter validations
        if config.rpc_url.is_empty() {
            return Err(QuIDBlockchainError::ConfigurationError(
                "RPC URL is required for universal adapter".to_string()
            ));
        }

        Ok(())
    }
}

impl Default for UniversalAdapterFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Adapter discovery service
pub struct AdapterDiscovery {
    registry: Arc<AdapterRegistry>,
}

impl AdapterDiscovery {
    /// Create new discovery service
    pub fn new(registry: Arc<AdapterRegistry>) -> Self {
        Self { registry }
    }

    /// Discover adapters from configuration
    pub async fn discover_from_config(
        &self,
        configs: Vec<CustomBlockchainConfig>,
        settings: AdapterSettings,
    ) -> QuIDBlockchainResult<Vec<String>> {
        let mut discovered = Vec::new();

        for config in configs {
            let adapter_name = format!("custom-{}", config.name);
            
            // Try to create adapter using universal factory
            match self.registry.create_adapter(
                "universal",
                &adapter_name,
                config.clone(),
                settings.clone(),
            ).await {
                Ok(_) => {
                    discovered.push(adapter_name);
                    tracing::info!("Discovered and created adapter for: {}", config.name);
                }
                Err(e) => {
                    tracing::warn!("Failed to create adapter for {}: {}", config.name, e);
                }
            }
        }

        Ok(discovered)
    }

    /// Discover adapters from network scan
    pub async fn discover_from_network(&self) -> QuIDBlockchainResult<Vec<String>> {
        // In a real implementation, this would scan for available blockchain networks
        // For now, return empty list
        Ok(Vec::new())
    }
}

/// Registry builder for easy configuration
pub struct RegistryBuilder {
    config: RegistryConfig,
}

impl RegistryBuilder {
    /// Create new registry builder
    pub fn new() -> Self {
        Self {
            config: RegistryConfig::default(),
        }
    }

    /// Enable/disable auto-discovery
    pub fn auto_discovery(mut self, enabled: bool) -> Self {
        self.config.auto_discovery = enabled;
        self
    }

    /// Set maximum adapters
    pub fn max_adapters(mut self, max: usize) -> Self {
        self.config.max_adapters = max;
        self
    }

    /// Set health check interval
    pub fn health_check_interval(mut self, seconds: u64) -> Self {
        self.config.health_check_interval = seconds;
        self
    }

    /// Enable/disable caching
    pub fn enable_caching(mut self, enabled: bool) -> Self {
        self.config.enable_caching = enabled;
        self
    }
    
    /// Set health cache TTL
    pub fn health_cache_ttl(mut self, seconds: u64) -> Self {
        self.config.health_cache_ttl = seconds;
        self
    }
    
    /// Set batch operation timeout
    pub fn batch_timeout(mut self, seconds: u64) -> Self {
        self.config.batch_timeout = seconds;
        self
    }
    
    /// Enable/disable metrics collection
    pub fn enable_metrics(mut self, enabled: bool) -> Self {
        self.config.enable_metrics = enabled;
        self
    }

    /// Build the registry
    pub fn build(self) -> AdapterRegistry {
        AdapterRegistry::with_config(self.config)
    }
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AddressFormat, SignatureAlgorithm};

    #[tokio::test]
    async fn test_registry_creation() {
        let registry = AdapterRegistry::new();
        assert_eq!(registry.count().await, 0);
        assert!(registry.list_adapters().await.is_empty());
    }

    #[tokio::test]
    async fn test_factory_registration() {
        let registry = AdapterRegistry::new();
        let factory = UniversalAdapterFactory::new();
        
        registry.register_factory("universal", Box::new(factory)).await.unwrap();
        
        let factories = registry.list_factories().await;
        assert_eq!(factories.len(), 1);
        assert!(factories.contains(&"universal".to_string()));
    }

    #[tokio::test]
    async fn test_adapter_creation_from_factory() {
        let registry = AdapterRegistry::new();
        let factory = UniversalAdapterFactory::new();
        
        registry.register_factory("universal", Box::new(factory)).await.unwrap();
        
        let config = CustomBlockchainConfig {
            name: "test-chain".to_string(),
            chain_id: Some(12345),
            rpc_url: "https://test-rpc.example.com".to_string(),
            ws_url: None,
            native_token: "TEST".to_string(),
            block_time: 15,
            confirmation_blocks: 12,
            address_format: AddressFormat::EthereumHex,
            signature_algorithm: SignatureAlgorithm::EcdsaSecp256k1,
        };
        
        let settings = AdapterSettings::default();
        
        registry.create_adapter("universal", "test-adapter", config, settings).await.unwrap();
        
        assert_eq!(registry.count().await, 1);
        assert!(registry.exists("test-adapter").await);
    }

    #[test]
    fn test_adapter_metadata() {
        let metadata = AdapterMetadata {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "Test adapter".to_string(),
            supported_networks: vec!["testnet".to_string()],
            required_features: vec!["rpc".to_string()],
            status: AdapterStatus::Active,
            registered_at: chrono::Utc::now(),
            metrics: AdapterMetrics::default(),
        };

        assert_eq!(metadata.name, "test");
        assert_eq!(metadata.status, AdapterStatus::Active);
        assert_eq!(metadata.metrics.total_operations, 0);
    }

    #[test]
    fn test_registry_builder() {
        let registry = RegistryBuilder::new()
            .auto_discovery(false)
            .max_adapters(50)
            .health_check_interval(600)
            .enable_caching(false)
            .health_cache_ttl(120)
            .batch_timeout(60)
            .enable_metrics(true)
            .build();

        assert!(!registry.config.auto_discovery);
        assert_eq!(registry.config.max_adapters, 50);
        assert_eq!(registry.config.health_check_interval, 600);
        assert!(!registry.config.enable_caching);
        assert_eq!(registry.config.health_cache_ttl, 120);
        assert_eq!(registry.config.batch_timeout, 60);
        assert!(registry.config.enable_metrics);
    }
    
    #[test]
    fn test_health_check_cache() {
        let mut cache = HealthCheckCache::new(AdapterStatus::Active);
        let ttl = Duration::from_secs(60);
        
        // Should not be expired immediately
        assert!(!cache.is_expired(ttl));
        
        // Update the cache
        cache.update(AdapterStatus::Failed("Test error".to_string()), Duration::from_millis(100));
        
        // Should still not be expired
        assert!(!cache.is_expired(ttl));
        assert_eq!(cache.check_duration, Duration::from_millis(100));
    }
    
    #[test]
    fn test_adapter_metrics() {
        let metrics = AdapterMetrics::default();
        
        assert_eq!(metrics.total_operations, 0);
        assert_eq!(metrics.total_errors, 0);
        assert_eq!(metrics.avg_response_time_ms, 0.0);
        assert_eq!(metrics.uptime_percentage, 0.0);
        assert!(metrics.last_health_check_ms.is_none());
    }
    
    #[test]
    fn test_batch_operation_result() {
        let result = BatchOperationResult {
            successful: vec!["adapter1".to_string(), "adapter2".to_string()],
            failed: vec![("adapter3".to_string(), "Error message".to_string())],
            total_processed: 3,
            processing_time: Duration::from_millis(500),
        };
        
        assert_eq!(result.successful.len(), 2);
        assert_eq!(result.failed.len(), 1);
        assert_eq!(result.total_processed, 3);
        assert_eq!(result.processing_time, Duration::from_millis(500));
    }
}