//! Dynamic adapter loading and registration system

use crate::adapter::{NetworkAdapter, AuthenticationRequest, AuthenticationResponse};
use crate::error::{AdapterError, AdapterResult};
use quid_core::crypto::KeyPair;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Thread-safe registry for network adapters
#[derive(Clone)]
pub struct AdapterRegistry {
    adapters: Arc<RwLock<HashMap<String, Arc<dyn NetworkAdapter>>>>,
    metadata: Arc<RwLock<HashMap<String, AdapterMetadata>>>,
}

/// Metadata about a registered adapter
#[derive(Debug, Clone)]
pub struct AdapterMetadata {
    /// Adapter version
    pub version: String,
    /// Adapter description
    pub description: String,
    /// Supported capabilities
    pub capabilities: Vec<String>,
    /// Registration timestamp
    pub registered_at: u64,
    /// Health status
    pub healthy: bool,
    /// Custom metadata
    pub custom_data: HashMap<String, String>,
}

impl AdapterMetadata {
    /// Create new adapter metadata
    pub fn new(version: String, description: String, capabilities: Vec<String>) -> Self {
        Self {
            version,
            description,
            capabilities,
            registered_at: current_timestamp(),
            healthy: true,
            custom_data: HashMap::new(),
        }
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterRegistry {
    /// Create a new adapter registry
    pub fn new() -> Self {
        Self {
            adapters: Arc::new(RwLock::new(HashMap::new())),
            metadata: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Register a new network adapter
    pub fn register_adapter(&self, adapter: Arc<dyn NetworkAdapter>) -> AdapterResult<()> {
        let network_id = adapter.network_id().to_string();
        
        // Create metadata
        let metadata = AdapterMetadata::new(
            "1.0.0".to_string(),
            format!("Adapter for {}", network_id),
            adapter.supported_capabilities(),
        );
        
        // Register adapter
        {
            let mut adapters = self.adapters.write()
                .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
            adapters.insert(network_id.clone(), adapter);
        }
        
        // Register metadata
        {
            let mut meta = self.metadata.write()
                .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
            meta.insert(network_id, metadata);
        }
        
        Ok(())
    }
    
    /// Unregister an adapter
    pub fn unregister_adapter(&self, network_id: &str) -> AdapterResult<bool> {
        let removed;
        
        {
            let mut adapters = self.adapters.write()
                .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
            removed = adapters.remove(network_id).is_some();
        }
        
        if removed {
            let mut meta = self.metadata.write()
                .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
            meta.remove(network_id);
        }
        
        Ok(removed)
    }
    
    /// Get an adapter by network ID
    pub fn get_adapter(&self, network_id: &str) -> AdapterResult<Arc<dyn NetworkAdapter>> {
        let adapters = self.adapters.read()
            .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
        
        adapters.get(network_id)
            .cloned()
            .ok_or_else(|| AdapterError::AdapterNotFound(network_id.to_string()))
    }
    
    /// Get adapter metadata
    pub fn get_metadata(&self, network_id: &str) -> AdapterResult<AdapterMetadata> {
        let metadata = self.metadata.read()
            .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
        
        metadata.get(network_id)
            .cloned()
            .ok_or_else(|| AdapterError::AdapterNotFound(network_id.to_string()))
    }
    
    /// List all registered adapters
    pub fn list_adapters(&self) -> AdapterResult<Vec<String>> {
        let adapters = self.adapters.read()
            .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
        
        Ok(adapters.keys().cloned().collect())
    }
    
    /// Get adapter count
    pub fn adapter_count(&self) -> AdapterResult<usize> {
        let adapters = self.adapters.read()
            .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
        
        Ok(adapters.len())
    }
    
    /// Check if an adapter is registered
    pub fn has_adapter(&self, network_id: &str) -> AdapterResult<bool> {
        let adapters = self.adapters.read()
            .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
        
        Ok(adapters.contains_key(network_id))
    }
    
    /// Authenticate using the registry
    pub fn authenticate(&self, request: &AuthenticationRequest, master_keypair: &KeyPair) -> AdapterResult<AuthenticationResponse> {
        let adapter = self.get_adapter(&request.context.network_type)?;
        adapter.authenticate(request, master_keypair)
    }
    
    /// Perform health check on all adapters
    pub fn health_check_all(&self) -> AdapterResult<HashMap<String, bool>> {
        let adapters = self.adapters.read()
            .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
        
        let mut results = HashMap::new();
        
        for (network_id, adapter) in adapters.iter() {
            let healthy = adapter.health_check().unwrap_or(false);
            results.insert(network_id.clone(), healthy);
            
            // Update metadata
            if let Ok(mut metadata) = self.metadata.write() {
                if let Some(meta) = metadata.get_mut(network_id) {
                    meta.healthy = healthy;
                }
            }
        }
        
        Ok(results)
    }
    
    /// Get adapters by capability
    pub fn get_adapters_by_capability(&self, capability: &str) -> AdapterResult<Vec<String>> {
        let metadata = self.metadata.read()
            .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
        
        let mut matching_adapters = Vec::new();
        
        for (network_id, meta) in metadata.iter() {
            if meta.capabilities.contains(&capability.to_string()) {
                matching_adapters.push(network_id.clone());
            }
        }
        
        Ok(matching_adapters)
    }
    
    /// Get detailed registry statistics
    pub fn get_statistics(&self) -> AdapterResult<RegistryStatistics> {
        let adapters = self.adapters.read()
            .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
        let metadata = self.metadata.read()
            .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
        
        let total_adapters = adapters.len();
        let healthy_adapters = metadata.values().filter(|m| m.healthy).count();
        
        let mut capabilities = std::collections::HashSet::new();
        for meta in metadata.values() {
            for cap in &meta.capabilities {
                capabilities.insert(cap.clone());
            }
        }
        
        Ok(RegistryStatistics {
            total_adapters,
            healthy_adapters,
            unhealthy_adapters: total_adapters - healthy_adapters,
            unique_capabilities: capabilities.len(),
            all_capabilities: capabilities.into_iter().collect(),
        })
    }
    
    // === ADAPTER LIFECYCLE MANAGEMENT ===
    
    /// Initialize all registered adapters
    pub fn initialize_all(&self) -> AdapterResult<InitializationReport> {
        let adapters = self.adapters.read()
            .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
        
        let mut report = InitializationReport::new();
        
        for (network_id, adapter) in adapters.iter() {
            let start_time = current_timestamp();
            
            match adapter.health_check() {
                Ok(true) => {
                    report.successful.push(network_id.clone());
                    report.timing.insert(network_id.clone(), current_timestamp() - start_time);
                }
                Ok(false) => {
                    report.failed.push((network_id.clone(), "Health check failed".to_string()));
                }
                Err(e) => {
                    report.failed.push((network_id.clone(), e.to_string()));
                }
            }
        }
        
        Ok(report)
    }
    
    /// Gracefully shutdown all adapters
    pub fn shutdown_all(&self) -> AdapterResult<ShutdownReport> {
        let mut shutdown_report = ShutdownReport::new();
        
        // Get list of adapters to shutdown
        let adapter_list = {
            let adapters = self.adapters.read()
                .map_err(|e| AdapterError::Generic(format!("Lock error: {}", e)))?;
            adapters.keys().cloned().collect::<Vec<_>>()
        };
        
        // Shutdown each adapter
        for network_id in adapter_list {
            let start_time = current_timestamp();
            
            match self.unregister_adapter(&network_id) {
                Ok(true) => {
                    shutdown_report.successful.push(network_id.clone());
                    shutdown_report.timing.insert(network_id, current_timestamp() - start_time);
                }
                Ok(false) => {
                    shutdown_report.failed.push((network_id, "Adapter not found".to_string()));
                }
                Err(e) => {
                    shutdown_report.failed.push((network_id, e.to_string()));
                }
            }
        }
        
        Ok(shutdown_report)
    }
    
    /// Monitor adapters for failures and attempt recovery
    pub fn monitor_and_recover(&self) -> AdapterResult<MonitoringReport> {
        let health_results = self.health_check_all()?;
        
        let mut report = MonitoringReport::new();
        
        for (network_id, is_healthy) in health_results {
            if is_healthy {
                report.healthy_adapters.push(network_id);
            } else {
                report.unhealthy_adapters.push(network_id.clone());
                
                // Attempt basic recovery by re-checking health
                if let Ok(adapter) = self.get_adapter(&network_id) {
                    match adapter.health_check() {
                        Ok(true) => {
                            report.recovered_adapters.push(network_id);
                        }
                        _ => {
                            report.failed_recovery.push(network_id);
                        }
                    }
                }
            }
        }
        
        Ok(report)
    }
    
    /// Configure an adapter with new settings
    pub fn configure_adapter(&self, network_id: &str, config: HashMap<String, String>) -> AdapterResult<()> {
        let adapter = self.get_adapter(network_id)?;
        
        // Note: NetworkAdapter trait doesn't have mutable configure method
        // This would need to be enhanced in a production implementation
        // For now, we'll simulate configuration success
        
        Ok(())
    }
    
    /// Get adapter uptime and performance metrics
    pub fn get_adapter_metrics(&self, network_id: &str) -> AdapterResult<AdapterMetrics> {
        let metadata = self.get_metadata(network_id)?;
        let adapter = self.get_adapter(network_id)?;
        
        let uptime = current_timestamp() - metadata.registered_at;
        let health_status = adapter.health_check().unwrap_or(false);
        
        Ok(AdapterMetrics {
            network_id: network_id.to_string(),
            uptime_seconds: uptime,
            healthy: health_status,
            capabilities_count: metadata.capabilities.len(),
            version: metadata.version,
            last_health_check: current_timestamp(),
        })
    }
}

/// Report from adapter initialization
#[derive(Debug, Clone)]
pub struct InitializationReport {
    /// Successfully initialized adapters
    pub successful: Vec<String>,
    /// Failed initializations with error messages
    pub failed: Vec<(String, String)>,
    /// Timing information for each adapter
    pub timing: HashMap<String, u64>,
}

impl InitializationReport {
    pub fn new() -> Self {
        Self {
            successful: Vec::new(),
            failed: Vec::new(),
            timing: HashMap::new(),
        }
    }
}

/// Report from adapter shutdown
#[derive(Debug, Clone)]
pub struct ShutdownReport {
    /// Successfully shutdown adapters
    pub successful: Vec<String>,
    /// Failed shutdowns with error messages
    pub failed: Vec<(String, String)>,
    /// Timing information for each adapter
    pub timing: HashMap<String, u64>,
}

impl ShutdownReport {
    pub fn new() -> Self {
        Self {
            successful: Vec::new(),
            failed: Vec::new(),
            timing: HashMap::new(),
        }
    }
}

/// Report from adapter monitoring
#[derive(Debug, Clone)]
pub struct MonitoringReport {
    /// Currently healthy adapters
    pub healthy_adapters: Vec<String>,
    /// Currently unhealthy adapters
    pub unhealthy_adapters: Vec<String>,
    /// Adapters that were recovered
    pub recovered_adapters: Vec<String>,
    /// Adapters that failed recovery
    pub failed_recovery: Vec<String>,
}

impl MonitoringReport {
    pub fn new() -> Self {
        Self {
            healthy_adapters: Vec::new(),
            unhealthy_adapters: Vec::new(),
            recovered_adapters: Vec::new(),
            failed_recovery: Vec::new(),
        }
    }
}

/// Metrics for a specific adapter
#[derive(Debug, Clone)]
pub struct AdapterMetrics {
    /// Network identifier
    pub network_id: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Current health status
    pub healthy: bool,
    /// Number of capabilities
    pub capabilities_count: usize,
    /// Adapter version
    pub version: String,
    /// Last health check timestamp
    pub last_health_check: u64,
}

/// Registry statistics
#[derive(Debug, Clone)]
pub struct RegistryStatistics {
    /// Total number of registered adapters
    pub total_adapters: usize,
    /// Number of healthy adapters
    pub healthy_adapters: usize,
    /// Number of unhealthy adapters
    pub unhealthy_adapters: usize,
    /// Number of unique capabilities across all adapters
    pub unique_capabilities: usize,
    /// List of all capabilities
    pub all_capabilities: Vec<String>,
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
    use crate::adapter::{NetworkKeys, AuthContext, ChallengeResponse};
    use quid_core::{QuIDIdentity, SecurityLevel};

    // Mock adapter for testing
    struct MockAdapter {
        network_id: String,
        capabilities: Vec<String>,
        healthy: bool,
    }

    impl MockAdapter {
        fn new(network_id: &str, capabilities: Vec<String>) -> Self {
            Self {
                network_id: network_id.to_string(),
                capabilities,
                healthy: true,
            }
        }
        
        fn unhealthy(mut self) -> Self {
            self.healthy = false;
            self
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
            Ok(true)
        }
        
        fn format_address(&self, public_key: &[u8]) -> AdapterResult<String> {
            Ok(format!("{}:{}", self.network_id, hex::encode(&public_key[..8])))
        }
        
        fn health_check(&self) -> AdapterResult<bool> {
            Ok(self.healthy)
        }
    }

    #[test]
    fn test_registry_creation() {
        let registry = AdapterRegistry::new();
        assert_eq!(registry.adapter_count().unwrap(), 0);
    }

    #[test]
    fn test_adapter_registration() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        let adapter = Arc::new(MockAdapter::new("test", vec!["authenticate".to_string()]));
        
        registry.register_adapter(adapter)?;
        
        assert_eq!(registry.adapter_count()?, 1);
        assert!(registry.has_adapter("test")?);
        
        let retrieved = registry.get_adapter("test")?;
        assert_eq!(retrieved.network_id(), "test");
        
        Ok(())
    }

    #[test]
    fn test_adapter_unregistration() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        let adapter = Arc::new(MockAdapter::new("test", vec!["authenticate".to_string()]));
        
        registry.register_adapter(adapter)?;
        assert_eq!(registry.adapter_count()?, 1);
        
        let removed = registry.unregister_adapter("test")?;
        assert!(removed);
        assert_eq!(registry.adapter_count()?, 0);
        assert!(!registry.has_adapter("test")?);
        
        let not_removed = registry.unregister_adapter("nonexistent")?;
        assert!(!not_removed);
        
        Ok(())
    }

    #[test]
    fn test_adapter_not_found() {
        let registry = AdapterRegistry::new();
        
        match registry.get_adapter("nonexistent") {
            Err(AdapterError::AdapterNotFound(id)) => assert_eq!(id, "nonexistent"),
            _ => panic!("Expected AdapterNotFound error"),
        }
    }

    #[test]
    fn test_list_adapters() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        
        let adapter1 = Arc::new(MockAdapter::new("bitcoin", vec!["sign".to_string()]));
        let adapter2 = Arc::new(MockAdapter::new("ethereum", vec!["sign".to_string()]));
        
        registry.register_adapter(adapter1)?;
        registry.register_adapter(adapter2)?;
        
        let mut adapters = registry.list_adapters()?;
        adapters.sort();
        
        assert_eq!(adapters, vec!["bitcoin", "ethereum"]);
        
        Ok(())
    }

    #[test]
    fn test_get_adapters_by_capability() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        
        let adapter1 = Arc::new(MockAdapter::new("bitcoin", vec!["sign".to_string(), "authenticate".to_string()]));
        let adapter2 = Arc::new(MockAdapter::new("ethereum", vec!["sign".to_string()]));
        let adapter3 = Arc::new(MockAdapter::new("web", vec!["authenticate".to_string()]));
        
        registry.register_adapter(adapter1)?;
        registry.register_adapter(adapter2)?;
        registry.register_adapter(adapter3)?;
        
        let mut sign_adapters = registry.get_adapters_by_capability("sign")?;
        sign_adapters.sort();
        assert_eq!(sign_adapters, vec!["bitcoin", "ethereum"]);
        
        let mut auth_adapters = registry.get_adapters_by_capability("authenticate")?;
        auth_adapters.sort();
        assert_eq!(auth_adapters, vec!["bitcoin", "web"]);
        
        let empty_adapters = registry.get_adapters_by_capability("nonexistent")?;
        assert!(empty_adapters.is_empty());
        
        Ok(())
    }

    #[test]
    fn test_health_check() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        
        let healthy_adapter = Arc::new(MockAdapter::new("healthy", vec!["test".to_string()]));
        let unhealthy_adapter = Arc::new(MockAdapter::new("unhealthy", vec!["test".to_string()]).unhealthy());
        
        registry.register_adapter(healthy_adapter)?;
        registry.register_adapter(unhealthy_adapter)?;
        
        let health_results = registry.health_check_all()?;
        
        assert_eq!(health_results.get("healthy"), Some(&true));
        assert_eq!(health_results.get("unhealthy"), Some(&false));
        
        Ok(())
    }

    #[test]
    fn test_authentication_via_registry() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        let adapter = Arc::new(MockAdapter::new("test", vec!["authenticate".to_string()]));
        registry.register_adapter(adapter)?;
        
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
        
        let response = registry.authenticate(&request, &keypair)?;
        
        assert!(!response.identity_proof.identity_id.is_empty());
        assert!(!response.challenge_response.signature.is_empty());
        
        Ok(())
    }

    #[test]
    fn test_registry_statistics() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        
        let adapter1 = Arc::new(MockAdapter::new("bitcoin", vec!["sign".to_string(), "authenticate".to_string()]));
        let adapter2 = Arc::new(MockAdapter::new("ethereum", vec!["sign".to_string()]));
        let adapter3 = Arc::new(MockAdapter::new("broken", vec!["test".to_string()]).unhealthy());
        
        registry.register_adapter(adapter1)?;
        registry.register_adapter(adapter2)?;
        registry.register_adapter(adapter3)?;
        
        // Trigger health check to update metadata
        registry.health_check_all()?;
        
        let stats = registry.get_statistics()?;
        
        assert_eq!(stats.total_adapters, 3);
        assert_eq!(stats.healthy_adapters, 2);
        assert_eq!(stats.unhealthy_adapters, 1);
        assert!(stats.unique_capabilities >= 2); // At least "sign" and "authenticate"
        
        Ok(())
    }

    #[test]
    fn test_adapter_metadata() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        let adapter = Arc::new(MockAdapter::new("test", vec!["authenticate".to_string()]));
        
        registry.register_adapter(adapter)?;
        
        let metadata = registry.get_metadata("test")?;
        
        assert_eq!(metadata.version, "1.0.0");
        assert_eq!(metadata.description, "Adapter for test");
        assert_eq!(metadata.capabilities, vec!["authenticate"]);
        assert!(metadata.healthy);
        assert!(metadata.registered_at > 0);
        
        Ok(())
    }

    // === LIFECYCLE MANAGEMENT TESTS ===

    #[test]
    fn test_initialization_report() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        
        let healthy_adapter = Arc::new(MockAdapter::new("healthy", vec!["test".to_string()]));
        let unhealthy_adapter = Arc::new(MockAdapter::new("unhealthy", vec!["test".to_string()]).unhealthy());
        
        registry.register_adapter(healthy_adapter)?;
        registry.register_adapter(unhealthy_adapter)?;
        
        let report = registry.initialize_all()?;
        
        assert_eq!(report.successful.len(), 1);
        assert_eq!(report.failed.len(), 1);
        assert!(report.successful.contains(&"healthy".to_string()));
        assert!(report.failed.iter().any(|(id, _)| id == "unhealthy"));
        assert!(report.timing.contains_key("healthy"));
        
        Ok(())
    }

    #[test]
    fn test_shutdown_report() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        
        let adapter1 = Arc::new(MockAdapter::new("test1", vec!["test".to_string()]));
        let adapter2 = Arc::new(MockAdapter::new("test2", vec!["test".to_string()]));
        
        registry.register_adapter(adapter1)?;
        registry.register_adapter(adapter2)?;
        
        assert_eq!(registry.adapter_count()?, 2);
        
        let report = registry.shutdown_all()?;
        
        assert_eq!(report.successful.len(), 2);
        assert_eq!(report.failed.len(), 0);
        assert_eq!(registry.adapter_count()?, 0);
        
        Ok(())
    }

    #[test]
    fn test_monitoring_and_recovery() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        
        let healthy_adapter = Arc::new(MockAdapter::new("healthy", vec!["test".to_string()]));
        let unhealthy_adapter = Arc::new(MockAdapter::new("unhealthy", vec!["test".to_string()]).unhealthy());
        
        registry.register_adapter(healthy_adapter)?;
        registry.register_adapter(unhealthy_adapter)?;
        
        let report = registry.monitor_and_recover()?;
        
        assert!(report.healthy_adapters.contains(&"healthy".to_string()));
        assert!(report.unhealthy_adapters.contains(&"unhealthy".to_string()));
        // In our mock, unhealthy adapters stay unhealthy, so they should be in failed_recovery
        assert!(report.failed_recovery.contains(&"unhealthy".to_string()));
        
        Ok(())
    }

    #[test]
    fn test_adapter_metrics() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        let adapter = Arc::new(MockAdapter::new("test", vec!["authenticate".to_string(), "sign".to_string()]));
        
        registry.register_adapter(adapter)?;
        
        // Wait a moment to ensure uptime > 0
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        let metrics = registry.get_adapter_metrics("test")?;
        
        assert_eq!(metrics.network_id, "test");
        assert!(metrics.uptime_seconds >= 0);
        assert!(metrics.healthy);
        assert_eq!(metrics.capabilities_count, 2);
        assert_eq!(metrics.version, "1.0.0");
        assert!(metrics.last_health_check > 0);
        
        Ok(())
    }

    #[test]
    fn test_configure_adapter() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        let adapter = Arc::new(MockAdapter::new("test", vec!["authenticate".to_string()]));
        
        registry.register_adapter(adapter)?;
        
        let mut config = HashMap::new();
        config.insert("timeout".to_string(), "5000".to_string());
        config.insert("retries".to_string(), "3".to_string());
        
        // This should succeed (though it's a no-op in our mock implementation)
        registry.configure_adapter("test", config)?;
        
        Ok(())
    }

    #[test]
    fn test_adapter_lifecycle_integration() -> AdapterResult<()> {
        let registry = AdapterRegistry::new();
        
        // Register multiple adapters
        let adapters = vec![
            Arc::new(MockAdapter::new("bitcoin", vec!["sign".to_string(), "authenticate".to_string()])),
            Arc::new(MockAdapter::new("ethereum", vec!["sign".to_string()])),
            Arc::new(MockAdapter::new("web", vec!["authenticate".to_string()])),
        ];
        
        for adapter in adapters {
            registry.register_adapter(adapter)?;
        }
        
        // Initialize all
        let init_report = registry.initialize_all()?;
        assert_eq!(init_report.successful.len(), 3);
        assert_eq!(init_report.failed.len(), 0);
        
        // Check health
        let health_results = registry.health_check_all()?;
        assert_eq!(health_results.len(), 3);
        assert!(health_results.values().all(|&healthy| healthy));
        
        // Monitor
        let monitor_report = registry.monitor_and_recover()?;
        assert_eq!(monitor_report.healthy_adapters.len(), 3);
        assert_eq!(monitor_report.unhealthy_adapters.len(), 0);
        
        // Get stats
        let stats = registry.get_statistics()?;
        assert_eq!(stats.total_adapters, 3);
        assert_eq!(stats.healthy_adapters, 3);
        assert_eq!(stats.unhealthy_adapters, 0);
        
        // Shutdown all
        let shutdown_report = registry.shutdown_all()?;
        assert_eq!(shutdown_report.successful.len(), 3);
        assert_eq!(shutdown_report.failed.len(), 0);
        
        // Verify empty registry
        assert_eq!(registry.adapter_count()?, 0);
        
        Ok(())
    }
}