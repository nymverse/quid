//! Nostr event types and utilities

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::{NostrResult, NostrError};

/// Nostr event structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NostrEvent {
    /// Event ID (32-byte hex-encoded sha256)
    pub id: String,
    /// Public key of event creator (32-byte hex)
    pub pubkey: String,
    /// Unix timestamp in seconds
    pub created_at: u64,
    /// Event kind
    pub kind: EventKind,
    /// Tags
    pub tags: Vec<Vec<String>>,
    /// Event content
    pub content: String,
    /// Signature (64-byte hex)
    pub sig: String,
}

/// Nostr event kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventKind(pub u16);

impl EventKind {
    // Standard event kinds (NIP-01)
    pub const METADATA: EventKind = EventKind(0);
    pub const TEXT_NOTE: EventKind = EventKind(1);
    pub const RECOMMEND_RELAY: EventKind = EventKind(2);
    pub const CONTACTS: EventKind = EventKind(3);
    pub const ENCRYPTED_DIRECT_MESSAGE: EventKind = EventKind(4);
    pub const DELETE: EventKind = EventKind(5);
    pub const REPOST: EventKind = EventKind(6);
    pub const REACTION: EventKind = EventKind(7);
    
    // Channel management (NIP-28)
    pub const CHANNEL_CREATION: EventKind = EventKind(40);
    pub const CHANNEL_METADATA: EventKind = EventKind(41);
    pub const CHANNEL_MESSAGE: EventKind = EventKind(42);
    pub const CHANNEL_HIDE_MESSAGE: EventKind = EventKind(43);
    pub const CHANNEL_MUTE_USER: EventKind = EventKind(44);
    
    // Lightning payments (NIP-57)
    pub const ZAP_REQUEST: EventKind = EventKind(9734);
    pub const ZAP_RECEIPT: EventKind = EventKind(9735);
    
    // Replaceable events (NIP-16)
    pub const LONG_FORM_CONTENT: EventKind = EventKind(30023);
    
    // QuID-specific extensions
    pub const QUID_IDENTITY_PROOF: EventKind = EventKind(31000);
    pub const QUID_AUTHENTICATION: EventKind = EventKind(31001);
    pub const QUID_CAPABILITY_ANNOUNCEMENT: EventKind = EventKind(31002);
    
    /// Check if event kind is replaceable
    pub fn is_replaceable(&self) -> bool {
        (self.0 >= 10000 && self.0 < 20000) || (self.0 >= 30000 && self.0 < 40000)
    }
    
    /// Check if event kind is ephemeral
    pub fn is_ephemeral(&self) -> bool {
        self.0 >= 20000 && self.0 < 30000
    }
    
    /// Check if event kind is regular
    pub fn is_regular(&self) -> bool {
        self.0 < 10000
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Event filter for subscriptions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    /// Event IDs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    /// Author public keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    /// Event kinds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<EventKind>>,
    /// Tags (e.g., #e, #p)
    #[serde(flatten)]
    pub tags: std::collections::HashMap<String, Vec<String>>,
    /// Since timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    /// Until timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    /// Limit number of events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

impl Filter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self {
            ids: None,
            authors: None,
            kinds: None,
            tags: std::collections::HashMap::new(),
            since: None,
            until: None,
            limit: None,
        }
    }
    
    /// Filter by event IDs
    pub fn ids(mut self, ids: Vec<String>) -> Self {
        self.ids = Some(ids);
        self
    }
    
    /// Filter by authors
    pub fn authors(mut self, authors: Vec<String>) -> Self {
        self.authors = Some(authors);
        self
    }
    
    /// Filter by event kinds
    pub fn kinds(mut self, kinds: Vec<EventKind>) -> Self {
        self.kinds = Some(kinds);
        self
    }
    
    /// Filter by tags
    pub fn tag(mut self, name: &str, values: Vec<String>) -> Self {
        self.tags.insert(format!("#{}", name), values);
        self
    }
    
    /// Filter by P tags (referenced public keys)
    pub fn p_tags(self, pubkeys: Vec<String>) -> Self {
        self.tag("p", pubkeys)
    }
    
    /// Filter by E tags (referenced event IDs)
    pub fn e_tags(self, event_ids: Vec<String>) -> Self {
        self.tag("e", event_ids)
    }
    
    /// Filter by time range
    pub fn since(mut self, timestamp: u64) -> Self {
        self.since = Some(timestamp);
        self
    }
    
    /// Filter until time
    pub fn until(mut self, timestamp: u64) -> Self {
        self.until = Some(timestamp);
        self
    }
    
    /// Limit number of results
    pub fn limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
    
    /// Check if event matches this filter
    pub fn matches(&self, event: &NostrEvent) -> bool {
        // Check IDs
        if let Some(ref ids) = self.ids {
            if !ids.contains(&event.id) {
                return false;
            }
        }
        
        // Check authors
        if let Some(ref authors) = self.authors {
            if !authors.contains(&event.pubkey) {
                return false;
            }
        }
        
        // Check kinds
        if let Some(ref kinds) = self.kinds {
            if !kinds.contains(&event.kind) {
                return false;
            }
        }
        
        // Check tags
        for (tag_name, tag_values) in &self.tags {
            if tag_name.starts_with('#') {
                let tag_key = &tag_name[1..];
                let mut found = false;
                
                for tag in &event.tags {
                    if !tag.is_empty() && tag[0] == tag_key {
                        if tag.len() > 1 && tag_values.contains(&tag[1]) {
                            found = true;
                            break;
                        }
                    }
                }
                
                if !found {
                    return false;
                }
            }
        }
        
        // Check time range
        if let Some(since) = self.since {
            if event.created_at < since {
                return false;
            }
        }
        
        if let Some(until) = self.until {
            if event.created_at > until {
                return false;
            }
        }
        
        true
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

/// Subscription request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRequest {
    /// Subscription ID
    pub id: String,
    /// Filters
    pub filters: Vec<Filter>,
}

/// Relay message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    /// Event message
    #[serde(rename = "EVENT")]
    Event {
        subscription_id: String,
        event: NostrEvent,
    },
    /// End of stored events
    #[serde(rename = "EOSE")]
    EndOfStoredEvents {
        subscription_id: String,
    },
    /// Notice
    #[serde(rename = "NOTICE")]
    Notice {
        message: String,
    },
    /// OK response
    #[serde(rename = "OK")]
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
}

/// Client message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Publish event
    #[serde(rename = "EVENT")]
    Event(NostrEvent),
    /// Request events
    #[serde(rename = "REQ")]
    Request {
        subscription_id: String,
        filters: Vec<Filter>,
    },
    /// Close subscription
    #[serde(rename = "CLOSE")]
    Close {
        subscription_id: String,
    },
}

impl NostrEvent {
    /// Create a new event
    pub fn new(
        pubkey: String,
        kind: EventKind,
        content: String,
        tags: Vec<Vec<String>>,
    ) -> Self {
        Self {
            id: String::new(), // Will be calculated
            pubkey,
            created_at: Utc::now().timestamp() as u64,
            kind,
            tags,
            content,
            sig: String::new(), // Will be calculated
        }
    }
    
    /// Get age of event in seconds
    pub fn age(&self) -> u64 {
        let now = Utc::now().timestamp() as u64;
        if now >= self.created_at {
            now - self.created_at
        } else {
            0
        }
    }
    
    /// Check if event is recent (less than 1 hour old)
    pub fn is_recent(&self) -> bool {
        self.age() < 3600
    }
    
    /// Get referenced event IDs (e tags)
    pub fn referenced_events(&self) -> Vec<String> {
        self.tags
            .iter()
            .filter(|tag| tag.len() >= 2 && tag[0] == "e")
            .map(|tag| tag[1].clone())
            .collect()
    }
    
    /// Get referenced public keys (p tags)
    pub fn referenced_pubkeys(&self) -> Vec<String> {
        self.tags
            .iter()
            .filter(|tag| tag.len() >= 2 && tag[0] == "p")
            .map(|tag| tag[1].clone())
            .collect()
    }
    
    /// Get tags by name
    pub fn get_tags(&self, name: &str) -> Vec<&Vec<String>> {
        self.tags
            .iter()
            .filter(|tag| !tag.is_empty() && tag[0] == name)
            .collect()
    }
    
    /// Add a tag
    pub fn add_tag(&mut self, tag: Vec<String>) {
        self.tags.push(tag);
    }
    
    /// Add an e tag (event reference)
    pub fn add_e_tag(&mut self, event_id: String, relay_url: Option<String>) {
        let mut tag = vec!["e".to_string(), event_id];
        if let Some(url) = relay_url {
            tag.push(url);
        }
        self.add_tag(tag);
    }
    
    /// Add a p tag (pubkey reference)
    pub fn add_p_tag(&mut self, pubkey: String, relay_url: Option<String>) {
        let mut tag = vec!["p".to_string(), pubkey];
        if let Some(url) = relay_url {
            tag.push(url);
        }
        self.add_tag(tag);
    }
    
    /// Check if event is a reply
    pub fn is_reply(&self) -> bool {
        !self.referenced_events().is_empty()
    }
    
    /// Check if event mentions a pubkey
    pub fn mentions_pubkey(&self, pubkey: &str) -> bool {
        self.referenced_pubkeys().contains(&pubkey.to_string())
    }
    
    /// Validate event structure
    pub fn validate(&self) -> NostrResult<()> {
        // Check ID format
        if self.id.len() != 64 {
            return Err(NostrError::InvalidEventId("Invalid ID length".to_string()));
        }
        
        // Check pubkey format
        if self.pubkey.len() != 64 {
            return Err(NostrError::InvalidPublicKey("Invalid pubkey length".to_string()));
        }
        
        // Check signature format
        if self.sig.len() != 128 {
            return Err(NostrError::InvalidSignature("Invalid signature length".to_string()));
        }
        
        // Validate hex encoding
        hex::decode(&self.id).map_err(|_| NostrError::InvalidEventId("Invalid hex encoding".to_string()))?;
        hex::decode(&self.pubkey).map_err(|_| NostrError::InvalidPublicKey("Invalid hex encoding".to_string()))?;
        hex::decode(&self.sig).map_err(|_| NostrError::InvalidSignature("Invalid hex encoding".to_string()))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_event_creation() {
        let event = NostrEvent::new(
            "test_pubkey".to_string(),
            EventKind::TEXT_NOTE,
            "Hello Nostr!".to_string(),
            vec![],
        );
        
        assert_eq!(event.pubkey, "test_pubkey");
        assert_eq!(event.kind, EventKind::TEXT_NOTE);
        assert_eq!(event.content, "Hello Nostr!");
        assert!(event.is_recent());
    }
    
    #[test]
    fn test_event_kind_classification() {
        assert!(EventKind::TEXT_NOTE.is_regular());
        assert!(!EventKind::TEXT_NOTE.is_replaceable());
        assert!(!EventKind::TEXT_NOTE.is_ephemeral());
        
        assert!(EventKind::METADATA.is_replaceable());
        assert!(!EventKind::METADATA.is_regular());
        assert!(!EventKind::METADATA.is_ephemeral());
        
        let ephemeral_kind = EventKind(25000);
        assert!(ephemeral_kind.is_ephemeral());
        assert!(!ephemeral_kind.is_regular());
        assert!(!ephemeral_kind.is_replaceable());
    }
    
    #[test]
    fn test_filter_matching() {
        let event = NostrEvent {
            id: "test_id".to_string(),
            pubkey: "test_pubkey".to_string(),
            created_at: 1234567890,
            kind: EventKind::TEXT_NOTE,
            tags: vec![
                vec!["p".to_string(), "mentioned_pubkey".to_string()],
                vec!["e".to_string(), "referenced_event".to_string()],
            ],
            content: "Test content".to_string(),
            sig: "test_sig".to_string(),
        };
        
        // Test author filter
        let filter = Filter::new().authors(vec!["test_pubkey".to_string()]);
        assert!(filter.matches(&event));
        
        let filter = Filter::new().authors(vec!["other_pubkey".to_string()]);
        assert!(!filter.matches(&event));
        
        // Test kind filter
        let filter = Filter::new().kinds(vec![EventKind::TEXT_NOTE]);
        assert!(filter.matches(&event));
        
        let filter = Filter::new().kinds(vec![EventKind::METADATA]);
        assert!(!filter.matches(&event));
        
        // Test p tag filter
        let filter = Filter::new().p_tags(vec!["mentioned_pubkey".to_string()]);
        assert!(filter.matches(&event));
        
        let filter = Filter::new().p_tags(vec!["other_pubkey".to_string()]);
        assert!(!filter.matches(&event));
        
        // Test time filter
        let filter = Filter::new().since(1234567889);
        assert!(filter.matches(&event));
        
        let filter = Filter::new().since(1234567891);
        assert!(!filter.matches(&event));
    }
    
    #[test]
    fn test_event_references() {
        let mut event = NostrEvent::new(
            "test_pubkey".to_string(),
            EventKind::TEXT_NOTE,
            "Test content".to_string(),
            vec![],
        );
        
        event.add_e_tag("event123".to_string(), Some("wss://relay.example.com".to_string()));
        event.add_p_tag("pubkey456".to_string(), None);
        
        assert_eq!(event.referenced_events(), vec!["event123"]);
        assert_eq!(event.referenced_pubkeys(), vec!["pubkey456"]);
        assert!(event.is_reply());
        assert!(event.mentions_pubkey("pubkey456"));
        assert!(!event.mentions_pubkey("other_pubkey"));
    }
    
    #[test]
    fn test_event_validation() {
        let mut event = NostrEvent::new(
            "0".repeat(64),
            EventKind::TEXT_NOTE,
            "Test".to_string(),
            vec![],
        );
        event.id = "0".repeat(64);
        event.sig = "0".repeat(128);
        
        assert!(event.validate().is_ok());
        
        // Invalid ID length
        event.id = "invalid".to_string();
        assert!(event.validate().is_err());
    }
    
    #[test]
    fn test_event_serialization() {
        let event = NostrEvent::new(
            "test_pubkey".to_string(),
            EventKind::TEXT_NOTE,
            "Hello Nostr!".to_string(),
            vec![vec!["p".to_string(), "mentioned".to_string()]],
        );
        
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: NostrEvent = serde_json::from_str(&json).unwrap();
        
        assert_eq!(event.pubkey, deserialized.pubkey);
        assert_eq!(event.content, deserialized.content);
        assert_eq!(event.kind, deserialized.kind);
    }
}