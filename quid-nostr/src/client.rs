//! Nostr client implementation

use crate::{
    NostrResult, NostrError, NostrEvent, EventKind, Filter, 
    config::ClientConfig, event::RelayMessage, event::ClientMessage
};
use quid_core::QuIDIdentity;
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{timeout, Duration};
use url::Url;

/// Nostr client for connecting to relays
#[derive(Debug)]
pub struct NostrClient {
    /// Client configuration
    config: ClientConfig,
    /// QuID identity
    identity: QuIDIdentity,
    /// Connected relays
    relays: Arc<RwLock<HashMap<String, RelayConnection>>>,
    /// Event cache
    event_cache: Arc<RwLock<HashMap<String, NostrEvent>>>,
    /// Active subscriptions
    subscriptions: Arc<RwLock<HashMap<String, SubscriptionInfo>>>,
    /// Event receiver channel
    event_receiver: Arc<RwLock<Option<mpsc::Receiver<NostrEvent>>>>,
    /// Event sender channel
    event_sender: mpsc::Sender<NostrEvent>,
}

/// Relay connection information
#[derive(Debug, Clone)]
pub struct RelayConnection {
    /// Relay URL
    pub url: String,
    /// Connection status
    pub status: ConnectionStatus,
    /// Last ping time
    pub last_ping: Option<chrono::DateTime<chrono::Utc>>,
    /// Connection metrics
    pub metrics: ConnectionMetrics,
}

/// Connection status enumeration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionStatus {
    /// Disconnected
    Disconnected,
    /// Connecting
    Connecting,
    /// Connected
    Connected,
    /// Reconnecting
    Reconnecting,
    /// Error state
    Error,
}

/// Connection metrics
#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    /// Events sent
    pub events_sent: u64,
    /// Events received
    pub events_received: u64,
    /// Connection time
    pub connected_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Last activity
    pub last_activity: Option<chrono::DateTime<chrono::Utc>>,
    /// Reconnection count
    pub reconnection_count: u32,
}

/// Subscription information
#[derive(Debug, Clone)]
pub struct SubscriptionInfo {
    /// Subscription ID
    pub id: String,
    /// Filters
    pub filters: Vec<Filter>,
    /// Relay URLs
    pub relay_urls: Vec<String>,
    /// Created at
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Events received
    pub events_received: u64,
}

/// Event publication result
#[derive(Debug, Clone)]
pub struct PublishResult {
    /// Event ID
    pub event_id: String,
    /// Successful relays
    pub successful_relays: Vec<String>,
    /// Failed relays with errors
    pub failed_relays: Vec<(String, String)>,
}

impl NostrClient {
    /// Create a new Nostr client
    pub async fn new(identity: QuIDIdentity, config: &ClientConfig) -> NostrResult<Self> {
        let (event_sender, event_receiver) = mpsc::channel(1000);
        
        let client = Self {
            config: config.clone(),
            identity,
            relays: Arc::new(RwLock::new(HashMap::new())),
            event_cache: Arc::new(RwLock::new(HashMap::new())),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            event_sender,
        };
        
        // Auto-connect to default relays if enabled
        if config.auto_connect {
            for relay_url in &config.default_relays {
                if let Err(e) = client.connect_relay(relay_url).await {
                    tracing::warn!("Failed to auto-connect to relay {}: {}", relay_url, e);
                }
            }
        }
        
        Ok(client)
    }
    
    /// Connect to a relay
    pub async fn connect_relay(&self, url: &str) -> NostrResult<()> {
        let parsed_url = Url::parse(url)
            .map_err(|e| NostrError::ConnectionFailed(format!("Invalid URL: {}", e)))?;
        
        if !parsed_url.scheme().starts_with("ws") {
            return Err(NostrError::ConnectionFailed("Only WebSocket URLs are supported".to_string()));
        }
        
        let connection = RelayConnection {
            url: url.to_string(),
            status: ConnectionStatus::Connecting,
            last_ping: None,
            metrics: ConnectionMetrics {
                events_sent: 0,
                events_received: 0,
                connected_at: None,
                last_activity: None,
                reconnection_count: 0,
            },
        };
        
        {
            let mut relays = self.relays.write().await;
            relays.insert(url.to_string(), connection);
        }
        
        // Simulate connection process
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Update connection status to connected
        {
            let mut relays = self.relays.write().await;
            if let Some(conn) = relays.get_mut(url) {
                conn.status = ConnectionStatus::Connected;
                conn.metrics.connected_at = Some(chrono::Utc::now());
            }
        }
        
        tracing::info!("Connected to relay: {}", url);
        Ok(())
    }
    
    /// Disconnect from a relay
    pub async fn disconnect_relay(&self, url: &str) -> NostrResult<()> {
        let mut relays = self.relays.write().await;
        if let Some(mut conn) = relays.remove(url) {
            conn.status = ConnectionStatus::Disconnected;
            tracing::info!("Disconnected from relay: {}", url);
        }
        Ok(())
    }
    
    /// Publish an event to connected relays
    pub async fn publish_event(&self, event: &NostrEvent) -> NostrResult<PublishResult> {
        let relays = self.relays.read().await;
        let mut successful_relays = Vec::new();
        let mut failed_relays = Vec::new();
        
        for (url, connection) in relays.iter() {
            if connection.status == ConnectionStatus::Connected {
                match self.send_event_to_relay(url, event).await {
                    Ok(_) => {
                        successful_relays.push(url.clone());
                        tracing::debug!("Published event {} to relay {}", event.id, url);
                    }
                    Err(e) => {
                        failed_relays.push((url.clone(), e.to_string()));
                        tracing::warn!("Failed to publish event {} to relay {}: {}", event.id, url, e);
                    }
                }
            }
        }
        
        if successful_relays.is_empty() {
            return Err(NostrError::PublishFailed("No relays available".to_string()));
        }
        
        // Cache the published event
        {
            let mut cache = self.event_cache.write().await;
            cache.insert(event.id.clone(), event.clone());
            
            // Maintain cache size limit
            if cache.len() > self.config.event_cache_size {
                // Remove oldest events (simplified - in production use proper LRU)
                let keys_to_remove: Vec<String> = cache.keys().take(cache.len() - self.config.event_cache_size).cloned().collect();
                for key in keys_to_remove {
                    cache.remove(&key);
                }
            }
        }
        
        Ok(PublishResult {
            event_id: event.id.clone(),
            successful_relays,
            failed_relays,
        })
    }
    
    /// Subscribe to events with filters
    pub async fn subscribe(&self, filters: Vec<Filter>) -> NostrResult<String> {
        let subscription_id = uuid::Uuid::new_v4().to_string();
        let relays = self.relays.read().await;
        let relay_urls: Vec<String> = relays.keys().cloned().collect();
        
        // Send subscription to all connected relays
        for (url, connection) in relays.iter() {
            if connection.status == ConnectionStatus::Connected {
                if let Err(e) = self.send_subscription_to_relay(url, &subscription_id, &filters).await {
                    tracing::warn!("Failed to send subscription to relay {}: {}", url, e);
                }
            }
        }
        
        // Store subscription info
        let subscription_info = SubscriptionInfo {
            id: subscription_id.clone(),
            filters,
            relay_urls,
            created_at: chrono::Utc::now(),
            events_received: 0,
        };
        
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.insert(subscription_id.clone(), subscription_info);
        }
        
        Ok(subscription_id)
    }
    
    /// Unsubscribe from events
    pub async fn unsubscribe(&self, subscription_id: &str) -> NostrResult<()> {
        let relays = self.relays.read().await;
        
        // Send close message to all connected relays
        for (url, connection) in relays.iter() {
            if connection.status == ConnectionStatus::Connected {
                if let Err(e) = self.send_close_to_relay(url, subscription_id).await {
                    tracing::warn!("Failed to send close to relay {}: {}", url, e);
                }
            }
        }
        
        // Remove subscription info
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.remove(subscription_id);
        }
        
        Ok(())
    }
    
    /// Get cached events
    pub async fn get_cached_events(&self) -> HashMap<String, NostrEvent> {
        self.event_cache.read().await.clone()
    }
    
    /// Get events by filter
    pub async fn get_events(&self, filter: &Filter) -> Vec<NostrEvent> {
        let cache = self.event_cache.read().await;
        cache.values()
            .filter(|event| filter.matches(event))
            .cloned()
            .collect()
    }
    
    /// Get connection status for all relays
    pub async fn get_relay_status(&self) -> HashMap<String, ConnectionStatus> {
        let relays = self.relays.read().await;
        relays.iter()
            .map(|(url, conn)| (url.clone(), conn.status))
            .collect()
    }
    
    /// Get connection metrics
    pub async fn get_metrics(&self) -> ClientMetrics {
        let relays = self.relays.read().await;
        let subscriptions = self.subscriptions.read().await;
        let cache = self.event_cache.read().await;
        
        let total_events_sent = relays.values().map(|c| c.metrics.events_sent).sum();
        let total_events_received = relays.values().map(|c| c.metrics.events_received).sum();
        let connected_relays = relays.values().filter(|c| c.status == ConnectionStatus::Connected).count();
        
        ClientMetrics {
            connected_relays: connected_relays as u32,
            total_relays: relays.len() as u32,
            active_subscriptions: subscriptions.len() as u32,
            cached_events: cache.len() as u32,
            events_sent: total_events_sent,
            events_received: total_events_received,
        }
    }
    
    /// Take the event receiver (can only be called once)
    pub async fn take_event_receiver(&self) -> Option<mpsc::Receiver<NostrEvent>> {
        self.event_receiver.write().await.take()
    }
    
    // Private helper methods
    
    /// Send event to a specific relay
    async fn send_event_to_relay(&self, url: &str, event: &NostrEvent) -> NostrResult<()> {
        // In production, this would send over WebSocket
        // For now, simulate sending
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Update metrics
        {
            let mut relays = self.relays.write().await;
            if let Some(conn) = relays.get_mut(url) {
                conn.metrics.events_sent += 1;
                conn.metrics.last_activity = Some(chrono::Utc::now());
            }
        }
        
        Ok(())
    }
    
    /// Send subscription to a specific relay
    async fn send_subscription_to_relay(&self, url: &str, subscription_id: &str, filters: &[Filter]) -> NostrResult<()> {
        // In production, this would send REQ message over WebSocket
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(())
    }
    
    /// Send close message to a specific relay
    async fn send_close_to_relay(&self, url: &str, subscription_id: &str) -> NostrResult<()> {
        // In production, this would send CLOSE message over WebSocket
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(())
    }
}

/// Client metrics
#[derive(Debug, Clone)]
pub struct ClientMetrics {
    /// Number of connected relays
    pub connected_relays: u32,
    /// Total number of relays
    pub total_relays: u32,
    /// Number of active subscriptions
    pub active_subscriptions: u32,
    /// Number of cached events
    pub cached_events: u32,
    /// Total events sent
    pub events_sent: u64,
    /// Total events received
    pub events_received: u64,
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self {
            events_sent: 0,
            events_received: 0,
            connected_at: None,
            last_activity: None,
            reconnection_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;
    use crate::config::ClientConfig;
    
    #[tokio::test]
    async fn test_client_creation() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let mut config = ClientConfig::default();
        config.auto_connect = false; // Disable auto-connect for testing
        
        let client = NostrClient::new(identity, &config).await.unwrap();
        let metrics = client.get_metrics().await;
        
        assert_eq!(metrics.connected_relays, 0);
        assert_eq!(metrics.total_relays, 0);
    }
    
    #[tokio::test]
    async fn test_relay_connection() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let mut config = ClientConfig::default();
        config.auto_connect = false;
        
        let client = NostrClient::new(identity, &config).await.unwrap();
        
        // Connect to a mock relay
        client.connect_relay("wss://relay.example.com").await.unwrap();
        
        let status = client.get_relay_status().await;
        assert_eq!(status.get("wss://relay.example.com"), Some(&ConnectionStatus::Connected));
        
        let metrics = client.get_metrics().await;
        assert_eq!(metrics.connected_relays, 1);
        assert_eq!(metrics.total_relays, 1);
    }
    
    #[tokio::test]
    async fn test_event_publishing() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let mut config = ClientConfig::default();
        config.auto_connect = false;
        
        let client = NostrClient::new(identity.clone(), &config).await.unwrap();
        client.connect_relay("wss://relay.example.com").await.unwrap();
        
        let event = NostrEvent::new(
            "test_pubkey".to_string(),
            EventKind::TEXT_NOTE,
            "Hello Nostr!".to_string(),
            vec![],
        );
        
        let result = client.publish_event(&event).await.unwrap();
        assert_eq!(result.successful_relays.len(), 1);
        assert_eq!(result.failed_relays.len(), 0);
        
        // Check that event is cached
        let cached_events = client.get_cached_events().await;
        assert!(cached_events.contains_key(&event.id));
    }
    
    #[tokio::test]
    async fn test_subscription() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let mut config = ClientConfig::default();
        config.auto_connect = false;
        
        let client = NostrClient::new(identity, &config).await.unwrap();
        client.connect_relay("wss://relay.example.com").await.unwrap();
        
        let filters = vec![
            Filter::new().kinds(vec![EventKind::TEXT_NOTE]).limit(10)
        ];
        
        let subscription_id = client.subscribe(filters).await.unwrap();
        assert!(!subscription_id.is_empty());
        
        let metrics = client.get_metrics().await;
        assert_eq!(metrics.active_subscriptions, 1);
        
        // Unsubscribe
        client.unsubscribe(&subscription_id).await.unwrap();
        
        let metrics = client.get_metrics().await;
        assert_eq!(metrics.active_subscriptions, 0);
    }
    
    #[tokio::test]
    async fn test_event_filtering() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let mut config = ClientConfig::default();
        config.auto_connect = false;
        
        let client = NostrClient::new(identity, &config).await.unwrap();
        
        // Add some events to cache manually
        {
            let mut cache = client.event_cache.write().await;
            
            let event1 = NostrEvent::new(
                "pubkey1".to_string(),
                EventKind::TEXT_NOTE,
                "Message 1".to_string(),
                vec![],
            );
            
            let event2 = NostrEvent::new(
                "pubkey2".to_string(),
                EventKind::METADATA,
                "Metadata".to_string(),
                vec![],
            );
            
            cache.insert(event1.id.clone(), event1);
            cache.insert(event2.id.clone(), event2);
        }
        
        // Filter for text notes only
        let filter = Filter::new().kinds(vec![EventKind::TEXT_NOTE]);
        let events = client.get_events(&filter).await;
        
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].content, "Message 1");
    }
    
    #[tokio::test]
    async fn test_invalid_relay_url() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let mut config = ClientConfig::default();
        config.auto_connect = false;
        
        let client = NostrClient::new(identity, &config).await.unwrap();
        
        // Try to connect to invalid URL
        let result = client.connect_relay("invalid-url").await;
        assert!(result.is_err());
        
        // Try to connect to non-WebSocket URL
        let result = client.connect_relay("https://example.com").await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_relay_disconnection() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let mut config = ClientConfig::default();
        config.auto_connect = false;
        
        let client = NostrClient::new(identity, &config).await.unwrap();
        
        let relay_url = "wss://relay.example.com";
        client.connect_relay(relay_url).await.unwrap();
        
        let status = client.get_relay_status().await;
        assert_eq!(status.get(relay_url), Some(&ConnectionStatus::Connected));
        
        client.disconnect_relay(relay_url).await.unwrap();
        
        let status = client.get_relay_status().await;
        assert!(!status.contains_key(relay_url));
    }
}