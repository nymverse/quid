//! Nostr relay implementation

use crate::{NostrResult, NostrError, NostrEvent, Filter, config::RelayConfig};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Nostr relay server
#[derive(Debug)]
pub struct NostrRelay {
    /// Relay configuration
    config: RelayConfig,
    /// Stored events
    events: Arc<RwLock<HashMap<String, NostrEvent>>>,
    /// Active subscriptions
    subscriptions: Arc<RwLock<HashMap<String, Vec<Filter>>>>,
    /// Connected clients
    clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
    /// Relay metrics
    metrics: Arc<RwLock<RelayMetrics>>,
}

/// Client information
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// Client ID
    pub id: String,
    /// Connected at
    pub connected_at: chrono::DateTime<chrono::Utc>,
    /// Last activity
    pub last_activity: chrono::DateTime<chrono::Utc>,
    /// Events published
    pub events_published: u64,
    /// Subscriptions count
    pub subscriptions_count: u32,
}

/// Relay metrics
#[derive(Debug, Clone)]
pub struct RelayMetrics {
    /// Total events stored
    pub total_events: u64,
    /// Active connections
    pub active_connections: u32,
    /// Total connections
    pub total_connections: u64,
    /// Events published today
    pub events_today: u64,
    /// Storage size in bytes
    pub storage_size: u64,
    /// Uptime in seconds
    pub uptime: u64,
}

impl NostrRelay {
    /// Connect to a relay (client perspective)
    pub async fn connect(url: &str, config: &RelayConfig) -> NostrResult<Self> {
        Ok(Self {
            config: config.clone(),
            events: Arc::new(RwLock::new(HashMap::new())),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            clients: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(RelayMetrics::default())),
        })
    }
    
    /// Start relay server
    pub async fn start_server(&self) -> NostrResult<()> {
        if !self.config.enable_relay {
            return Err(NostrError::RelayError("Relay functionality is disabled".to_string()));
        }
        
        tracing::info!("Starting Nostr relay on {}:{}", self.config.bind_address, self.config.port);
        
        // In production, this would start the actual WebSocket server
        // For now, just simulate startup
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        Ok(())
    }
    
    /// Publish event to relay
    pub async fn publish_event(&self, event: &NostrEvent) -> NostrResult<()> {
        // Validate event
        event.validate().map_err(|e| NostrError::RelayError(e.to_string()))?;
        
        // Check if event already exists
        {
            let events = self.events.read().await;
            if events.contains_key(&event.id) {
                return Ok(()); // Event already exists, ignore
            }
        }
        
        // Store event
        {
            let mut events = self.events.write().await;
            events.insert(event.id.clone(), event.clone());
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_events += 1;
            metrics.events_today += 1;
        }
        
        // Notify subscribers
        self.notify_subscribers(event).await?;
        
        tracing::debug!("Stored event: {}", event.id);
        Ok(())
    }
    
    /// Subscribe to events
    pub async fn subscribe(&self, subscription_id: &str, filters: Vec<Filter>) -> NostrResult<()> {
        // Store subscription
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.insert(subscription_id.to_string(), filters.clone());
        }
        
        // Send existing matching events
        self.send_stored_events(subscription_id, &filters).await?;
        
        tracing::debug!("Added subscription: {}", subscription_id);
        Ok(())
    }
    
    /// Unsubscribe from events
    pub async fn unsubscribe(&self, subscription_id: &str) -> NostrResult<()> {
        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.remove(subscription_id);
        
        tracing::debug!("Removed subscription: {}", subscription_id);
        Ok(())
    }
    
    /// Get events matching filters
    pub async fn get_events(&self, filters: &[Filter]) -> Vec<NostrEvent> {
        let events = self.events.read().await;
        let mut matching_events = Vec::new();
        
        for event in events.values() {
            for filter in filters {
                if filter.matches(event) {
                    matching_events.push(event.clone());
                    break;
                }
            }
        }
        
        // Sort by created_at descending
        matching_events.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        
        matching_events
    }
    
    /// Get relay metrics
    pub async fn get_metrics(&self) -> RelayMetrics {
        let mut metrics = self.metrics.read().await.clone();
        
        // Update current values
        let events = self.events.read().await;
        let clients = self.clients.read().await;
        let subscriptions = self.subscriptions.read().await;
        
        metrics.total_events = events.len() as u64;
        metrics.active_connections = clients.len() as u32;
        
        // Estimate storage size
        metrics.storage_size = events.values()
            .map(|e| e.content.len() + e.pubkey.len() + e.id.len() + e.sig.len() + 100) // rough estimate
            .sum::<usize>() as u64;
        
        metrics
    }
    
    /// Get supported NIPs
    pub fn get_supported_nips(&self) -> Vec<u16> {
        self.config.supported_nips.clone()
    }
    
    /// Check if NIP is supported
    pub fn supports_nip(&self, nip: u16) -> bool {
        self.config.supported_nips.contains(&nip)
    }
    
    /// Add client connection
    pub async fn add_client(&self, client_id: String) -> NostrResult<()> {
        let client_info = ClientInfo {
            id: client_id.clone(),
            connected_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            events_published: 0,
            subscriptions_count: 0,
        };
        
        {
            let mut clients = self.clients.write().await;
            clients.insert(client_id, client_info);
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_connections += 1;
        }
        
        Ok(())
    }
    
    /// Remove client connection
    pub async fn remove_client(&self, client_id: &str) -> NostrResult<()> {
        let mut clients = self.clients.write().await;
        clients.remove(client_id);
        Ok(())
    }
    
    /// Update client activity
    pub async fn update_client_activity(&self, client_id: &str) -> NostrResult<()> {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(client_id) {
            client.last_activity = chrono::Utc::now();
        }
        Ok(())
    }
    
    /// Cleanup old events based on retention policy
    pub async fn cleanup_events(&self) -> NostrResult<u64> {
        let policy = &self.config.retention_policy;
        let mut removed_count = 0;
        
        {
            let mut events = self.events.write().await;
            let now = chrono::Utc::now();
            
            // Remove by age
            if let Some(max_age_days) = policy.max_age_days {
                let cutoff = now - chrono::Duration::days(max_age_days as i64);
                let cutoff_timestamp = cutoff.timestamp() as u64;
                
                events.retain(|_, event| {
                    let keep = event.created_at >= cutoff_timestamp || 
                               policy.permanent_kinds.contains(&(event.kind.0));
                    if !keep {
                        removed_count += 1;
                    }
                    keep
                });
            }
            
            // Remove by count limit
            if let Some(max_events) = policy.max_events {
                if events.len() > max_events as usize {
                    // Keep newest events, remove oldest
                    let mut event_list: Vec<_> = events.iter().collect();
                    event_list.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at));
                    
                    for (id, _) in event_list.iter().skip(max_events as usize) {
                        events.remove(*id);
                        removed_count += 1;
                    }
                }
            }
        }
        
        if removed_count > 0 {
            tracing::info!("Cleaned up {} old events", removed_count);
        }
        
        Ok(removed_count)
    }
    
    // Private helper methods
    
    /// Notify subscribers of new event
    async fn notify_subscribers(&self, event: &NostrEvent) -> NostrResult<()> {
        let subscriptions = self.subscriptions.read().await;
        
        for (subscription_id, filters) in subscriptions.iter() {
            for filter in filters {
                if filter.matches(event) {
                    // In production, send event to client via WebSocket
                    tracing::debug!("Would notify subscription {} of event {}", subscription_id, event.id);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Send stored events matching filters
    async fn send_stored_events(&self, subscription_id: &str, filters: &[Filter]) -> NostrResult<()> {
        let matching_events = self.get_events(filters).await;
        
        // Apply limit if specified
        let limited_events = if let Some(filter) = filters.first() {
            if let Some(limit) = filter.limit {
                matching_events.into_iter().take(limit as usize).collect()
            } else {
                matching_events
            }
        } else {
            matching_events
        };
        
        // In production, send events to client via WebSocket
        tracing::debug!("Would send {} stored events for subscription {}", limited_events.len(), subscription_id);
        
        Ok(())
    }
}

impl Default for RelayMetrics {
    fn default() -> Self {
        Self {
            total_events: 0,
            active_connections: 0,
            total_connections: 0,
            events_today: 0,
            storage_size: 0,
            uptime: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventKind, event::NostrEvent};
    
    #[tokio::test]
    async fn test_relay_creation() {
        let config = RelayConfig::default();
        let relay = NostrRelay::connect("wss://relay.example.com", &config).await.unwrap();
        
        let metrics = relay.get_metrics().await;
        assert_eq!(metrics.total_events, 0);
        assert_eq!(metrics.active_connections, 0);
    }
    
    #[tokio::test]
    async fn test_event_publishing() {
        let config = RelayConfig::default();
        let relay = NostrRelay::connect("wss://relay.example.com", &config).await.unwrap();
        
        let mut event = NostrEvent::new(
            "0".repeat(64),
            EventKind::TEXT_NOTE,
            "Hello Nostr!".to_string(),
            vec![],
        );
        event.id = "0".repeat(64);
        event.sig = "0".repeat(128);
        
        relay.publish_event(&event).await.unwrap();
        
        let metrics = relay.get_metrics().await;
        assert_eq!(metrics.total_events, 1);
    }
    
    #[tokio::test]
    async fn test_subscription() {
        let config = RelayConfig::default();
        let relay = NostrRelay::connect("wss://relay.example.com", &config).await.unwrap();
        
        let filters = vec![Filter::new().kinds(vec![EventKind::TEXT_NOTE])];
        relay.subscribe("sub123", filters).await.unwrap();
        
        // Add an event
        let mut event = NostrEvent::new(
            "0".repeat(64),
            EventKind::TEXT_NOTE,
            "Hello!".to_string(),
            vec![],
        );
        event.id = "0".repeat(64);
        event.sig = "0".repeat(128);
        
        relay.publish_event(&event).await.unwrap();
        
        // Unsubscribe
        relay.unsubscribe("sub123").await.unwrap();
    }
    
    #[tokio::test]
    async fn test_event_filtering() {
        let config = RelayConfig::default();
        let relay = NostrRelay::connect("wss://relay.example.com", &config).await.unwrap();
        
        // Add different types of events
        let mut text_event = NostrEvent::new(
            "0".repeat(64),
            EventKind::TEXT_NOTE,
            "Text note".to_string(),
            vec![],
        );
        text_event.id = "1".repeat(64);
        text_event.sig = "0".repeat(128);
        
        let mut metadata_event = NostrEvent::new(
            "0".repeat(64),
            EventKind::METADATA,
            "Metadata".to_string(),
            vec![],
        );
        metadata_event.id = "2".repeat(64);
        metadata_event.sig = "0".repeat(128);
        
        relay.publish_event(&text_event).await.unwrap();
        relay.publish_event(&metadata_event).await.unwrap();
        
        // Filter for text notes only
        let filters = vec![Filter::new().kinds(vec![EventKind::TEXT_NOTE])];
        let events = relay.get_events(&filters).await;
        
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].content, "Text note");
    }
    
    #[tokio::test]
    async fn test_client_management() {
        let config = RelayConfig::default();
        let relay = NostrRelay::connect("wss://relay.example.com", &config).await.unwrap();
        
        relay.add_client("client123".to_string()).await.unwrap();
        
        let metrics = relay.get_metrics().await;
        assert_eq!(metrics.active_connections, 1);
        assert_eq!(metrics.total_connections, 1);
        
        relay.update_client_activity("client123").await.unwrap();
        relay.remove_client("client123").await.unwrap();
        
        let metrics = relay.get_metrics().await;
        assert_eq!(metrics.active_connections, 0);
        assert_eq!(metrics.total_connections, 1); // Total doesn't decrease
    }
    
    #[tokio::test]
    async fn test_event_cleanup() {
        let mut config = RelayConfig::default();
        config.retention_policy.max_events = Some(2);
        
        let relay = NostrRelay::connect("wss://relay.example.com", &config).await.unwrap();
        
        // Add 3 events
        for i in 0..3 {
            let mut event = NostrEvent::new(
                "0".repeat(64),
                EventKind::TEXT_NOTE,
                format!("Message {}", i),
                vec![],
            );
            event.id = format!("{}", i).repeat(64);
            event.sig = "0".repeat(128);
            event.created_at = 1000000000 + i; // Different timestamps
            
            relay.publish_event(&event).await.unwrap();
        }
        
        let metrics = relay.get_metrics().await;
        assert_eq!(metrics.total_events, 3);
        
        // Cleanup should remove 1 event (keep newest 2)
        let removed = relay.cleanup_events().await.unwrap();
        assert_eq!(removed, 1);
        
        let metrics = relay.get_metrics().await;
        assert_eq!(metrics.total_events, 2);
    }
    
    #[tokio::test]
    async fn test_nip_support() {
        let mut config = RelayConfig::default();
        config.supported_nips = vec![1, 2, 4];
        
        let relay = NostrRelay::connect("wss://relay.example.com", &config).await.unwrap();
        
        assert!(relay.supports_nip(1));
        assert!(relay.supports_nip(2));
        assert!(relay.supports_nip(4));
        assert!(!relay.supports_nip(50));
        
        let nips = relay.get_supported_nips();
        assert_eq!(nips, vec![1, 2, 4]);
    }
    
    #[tokio::test]
    async fn test_relay_server_start() {
        let mut config = RelayConfig::default();
        config.enable_relay = true;
        
        let relay = NostrRelay::connect("wss://relay.example.com", &config).await.unwrap();
        relay.start_server().await.unwrap();
        
        // Test with disabled relay
        config.enable_relay = false;
        let relay = NostrRelay::connect("wss://relay.example.com", &config).await.unwrap();
        let result = relay.start_server().await;
        assert!(result.is_err());
    }
}