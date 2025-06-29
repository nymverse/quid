//! Desktop authentication flows and request handling

use crate::{DesktopConfig, DesktopError, DesktopResult};
use quid_core::{QuIDIdentity, SecurityLevel};
use quid_extensions::AdapterRegistry;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

/// Authentication request from desktop applications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    /// Unique request ID
    pub request_id: String,
    /// Requesting application name
    pub app_name: String,
    /// Service or domain requesting authentication
    pub service: String,
    /// Network type (web, ssh, bitcoin, etc.)
    pub network: String,
    /// Required capabilities
    pub capabilities: Vec<String>,
    /// Challenge data (optional)
    pub challenge: Option<Vec<u8>>,
    /// Request metadata
    pub metadata: HashMap<String, String>,
    /// Request timestamp
    pub timestamp: u64,
    /// Request timeout in seconds
    pub timeout_seconds: Option<u64>,
}

impl AuthenticationRequest {
    /// Create a new authentication request
    pub fn new(app_name: String, service: String, network: String) -> Self {
        Self {
            request_id: format!("auth-{}", rand::random::<u64>()),
            app_name,
            service,
            network,
            capabilities: vec!["authenticate".to_string()],
            challenge: None,
            metadata: HashMap::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            timeout_seconds: Some(300), // 5 minutes default
        }
    }

    /// Add capability requirement
    pub fn with_capability(mut self, capability: String) -> Self {
        self.capabilities.push(capability);
        self
    }

    /// Add challenge data
    pub fn with_challenge(mut self, challenge: Vec<u8>) -> Self {
        self.challenge = Some(challenge);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set request timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = Some(seconds);
        self
    }

    /// Check if request has timed out
    pub fn is_expired(&self) -> bool {
        if let Some(timeout_secs) = self.timeout_seconds {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            now > self.timestamp + timeout_secs
        } else {
            false
        }
    }
}

/// Result of authentication processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResult {
    /// Original request ID
    pub request_id: String,
    /// Whether authentication was successful
    pub success: bool,
    /// Authentication response data
    pub response: Option<AuthenticationResponse>,
    /// Error message if authentication failed
    pub error: Option<String>,
    /// Processing timestamp
    pub timestamp: u64,
}

/// Authentication response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    /// Identity ID that authenticated
    pub identity_id: String,
    /// Signature over challenge/request data
    pub signature: String,
    /// Public key for verification
    pub public_key: String,
    /// Network-specific authentication data
    pub network_data: HashMap<String, String>,
    /// Supported capabilities
    pub capabilities: Vec<String>,
}

/// Authentication context for adapters
#[derive(Debug, Clone)]
pub struct AuthenticationContext {
    pub network: String,
    pub service: String,
    pub challenge: Option<Vec<u8>>,
    pub capabilities: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Desktop authentication flow manager
pub struct AuthenticationFlow {
    config: DesktopConfig,
    adapter_registry: AdapterRegistry,
    pending_requests: HashMap<String, AuthenticationRequest>,
}

impl AuthenticationFlow {
    /// Create new authentication flow
    pub fn new(config: DesktopConfig) -> Self {
        Self {
            config,
            adapter_registry: AdapterRegistry::new(),
            pending_requests: HashMap::new(),
        }
    }

    /// Initialize authentication flow with adapters
    pub async fn initialize(&mut self) -> DesktopResult<()> {
        // Register common adapters using the available registry methods
        use quid_extensions::adapters::{WebAdapter, SshAdapter, GenericAdapter};
        use std::sync::Arc;
        
        self.adapter_registry.register_adapter(Arc::new(WebAdapter::new()))
            .map_err(|e| DesktopError::Authentication(format!("Failed to register web adapter: {}", e)))?;
        
        self.adapter_registry.register_adapter(Arc::new(SshAdapter::new()))
            .map_err(|e| DesktopError::Authentication(format!("Failed to register SSH adapter: {}", e)))?;
        
        self.adapter_registry.register_adapter(Arc::new(GenericAdapter::new("bitcoin".to_string())))
            .map_err(|e| DesktopError::Authentication(format!("Failed to register Bitcoin adapter: {}", e)))?;
        
        self.adapter_registry.register_adapter(Arc::new(GenericAdapter::new("ethereum".to_string())))
            .map_err(|e| DesktopError::Authentication(format!("Failed to register Ethereum adapter: {}", e)))?;
        
        self.adapter_registry.register_adapter(Arc::new(GenericAdapter::new("nym".to_string())))
            .map_err(|e| DesktopError::Authentication(format!("Failed to register Nym adapter: {}", e)))?;

        Ok(())
    }

    /// Process authentication request
    pub async fn process_request(&mut self, request: AuthenticationRequest) -> DesktopResult<AuthenticationResult> {
        // Check if request has expired
        if request.is_expired() {
            return Ok(AuthenticationResult {
                request_id: request.request_id.clone(),
                success: false,
                response: None,
                error: Some("Authentication request has expired".to_string()),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
        }

        // Store pending request
        self.pending_requests.insert(request.request_id.clone(), request.clone());

        // Set up timeout
        let timeout_duration = Duration::from_secs(request.timeout_seconds.unwrap_or(300));
        
        let request_id = request.request_id.clone();
        let result = timeout(timeout_duration, self.handle_authentication_request(request)).await;

        match result {
            Ok(auth_result) => {
                // Remove from pending requests
                self.pending_requests.remove(&auth_result.request_id);
                Ok(auth_result)
            }
            Err(_) => {
                // Timeout occurred
                let timeout_result = AuthenticationResult {
                    request_id: request_id.clone(),
                    success: false,
                    response: None,
                    error: Some("Authentication request timed out".to_string()),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
                
                self.pending_requests.remove(&request_id);
                Ok(timeout_result)
            }
        }
    }

    /// Handle authentication request implementation
    async fn handle_authentication_request(&self, request: AuthenticationRequest) -> AuthenticationResult {
        // For now, simulate user interaction - in a real implementation, 
        // this would show a UI dialog for user confirmation and identity selection
        let (identity, _keypair) = match self.simulate_user_interaction(&request).await {
            Ok(result) => result,
            Err(e) => {
                return AuthenticationResult {
                    request_id: request.request_id,
                    success: false,
                    response: None,
                    error: Some(format!("User interaction failed: {}", e)),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
            }
        };

        // For demonstration, create a simple signature
        let challenge_data = request.challenge.clone()
            .unwrap_or_else(|| format!("{}:{}", request.service, request.network).into_bytes());

        // Use the keypair to create a signature (simplified)
        let signature = sha3::Sha3_256::digest(&challenge_data).to_vec();

        // Create network-specific data
        let mut network_data = HashMap::new();
        network_data.insert("network".to_string(), request.network);
        network_data.insert("service".to_string(), request.service);
        network_data.insert("challenge_hash".to_string(), hex::encode(&challenge_data));

        // Create successful response
        let response = AuthenticationResponse {
            identity_id: hex::encode(&identity.id),
            signature: hex::encode(&signature),
            public_key: hex::encode(&identity.public_key),
            network_data,
            capabilities: request.capabilities,
        };

        AuthenticationResult {
            request_id: request.request_id,
            success: true,
            response: Some(response),
            error: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Simulate user interaction for identity selection
    /// In a real implementation, this would show a native UI dialog
    async fn simulate_user_interaction(&self, request: &AuthenticationRequest) -> DesktopResult<(QuIDIdentity, quid_core::crypto::KeyPair)> {
        // For demonstration, create a temporary identity
        // In production, this would:
        // 1. Show a native dialog listing available identities
        // 2. Allow user to select identity and enter password/biometric auth
        // 3. Load the selected identity from secure storage
        
        println!("🔐 Authentication Request");
        println!("📱 App: {}", request.app_name);
        println!("🌐 Service: {}", request.service);
        println!("📡 Network: {}", request.network);
        println!("🎯 Capabilities: {:?}", request.capabilities);
        
        // Simulate user approval delay
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Create temporary identity for demonstration
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1)
            .map_err(|e| DesktopError::Authentication(format!("Failed to create identity: {}", e)))?;
        
        Ok((identity, keypair))
    }

    /// Get list of pending authentication requests
    pub fn pending_requests(&self) -> Vec<&AuthenticationRequest> {
        self.pending_requests.values().collect()
    }

    /// Cancel pending authentication request
    pub fn cancel_request(&mut self, request_id: &str) -> bool {
        self.pending_requests.remove(request_id).is_some()
    }

    /// Get supported networks
    pub fn supported_networks(&self) -> Vec<String> {
        // Return known supported networks
        vec![
            "web".to_string(),
            "ssh".to_string(),
            "bitcoin".to_string(),
            "ethereum".to_string(),
            "nym".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication_request_creation() {
        let request = AuthenticationRequest::new(
            "Test App".to_string(),
            "example.com".to_string(),
            "web".to_string(),
        );

        assert_eq!(request.app_name, "Test App");
        assert_eq!(request.service, "example.com");
        assert_eq!(request.network, "web");
        assert!(!request.request_id.is_empty());
        assert!(request.capabilities.contains(&"authenticate".to_string()));
    }

    #[test]
    fn test_request_expiration() {
        let mut request = AuthenticationRequest::new(
            "Test App".to_string(),
            "example.com".to_string(),
            "web".to_string(),
        );

        // Set a very short timeout
        request.timeout_seconds = Some(0);
        request.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - 1; // 1 second ago

        assert!(request.is_expired());
    }

    #[test]
    fn test_request_builder_pattern() {
        let request = AuthenticationRequest::new(
            "Test App".to_string(),
            "example.com".to_string(),
            "web".to_string(),
        )
        .with_capability("sign".to_string())
        .with_challenge(b"test challenge".to_vec())
        .with_metadata("key".to_string(), "value".to_string())
        .with_timeout(600);

        assert!(request.capabilities.contains(&"sign".to_string()));
        assert_eq!(request.challenge, Some(b"test challenge".to_vec()));
        assert_eq!(request.metadata.get("key"), Some(&"value".to_string()));
        assert_eq!(request.timeout_seconds, Some(600));
    }

    #[tokio::test]
    async fn test_authentication_flow_creation() {
        let config = DesktopConfig::default();
        let auth_flow = AuthenticationFlow::new(config);
        
        assert!(auth_flow.pending_requests.is_empty());
    }

    #[tokio::test]
    async fn test_authentication_flow_initialization() {
        let config = DesktopConfig::default();
        let mut auth_flow = AuthenticationFlow::new(config);
        
        let result = auth_flow.initialize().await;
        assert!(result.is_ok());
        
        let networks = auth_flow.supported_networks();
        assert!(networks.contains(&"web".to_string()));
        assert!(networks.contains(&"ssh".to_string()));
    }
}