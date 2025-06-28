//! Distributed Hash Table implementation for QuID network
//! 
//! Uses Kademlia-inspired design with quantum-resistant hashing

use crate::{Result, NetworkError, consistent_hash, key_distance, is_closer};
use quid_core::QuIDIdentity;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, BTreeMap};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::sync::RwLock;

/// DHT key type (32-byte hash)
pub type DHTKey = Vec<u8>;

/// DHT value with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTValue {
    /// The actual data being stored
    pub data: Vec<u8>,
    
    /// Content type hint
    pub content_type: String,
    
    /// QuID identity that published this data
    pub publisher: Vec<u8>,
    
    /// Signature of the data by the publisher
    pub signature: Vec<u8>,
    
    /// When this value was stored
    pub timestamp: u64,
    
    /// Time-to-live (seconds from timestamp)
    pub ttl: u64,
    
    /// Version number for mutable content
    pub version: u64,
}

impl DHTValue {
    /// Create a new DHT value
    pub fn new(
        data: Vec<u8>,
        content_type: String,
        publisher: Vec<u8>,
        signature: Vec<u8>,
        ttl: u64,
        version: u64,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            data,
            content_type,
            publisher,
            signature,
            timestamp,
            ttl,
            version,
        }
    }
    
    /// Check if this value has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now > self.timestamp + self.ttl
    }
    
    /// Get hash of the data for verification
    pub fn data_hash(&self) -> Vec<u8> {
        consistent_hash(&self.data)
    }
}

/// Information about a DHT node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTNode {
    /// Node's QuID identity
    pub identity: QuIDIdentity,
    
    /// Network address
    pub address: String,
    
    /// Last time we heard from this node
    pub last_seen: u64,
    
    /// Node's position in the DHT key space
    pub node_id: DHTKey,
    
    /// Round-trip time to this node (milliseconds)
    pub rtt: Option<u64>,
    
    /// Number of successful responses
    pub success_count: u64,
    
    /// Number of failed requests
    pub failure_count: u64,
}

impl DHTNode {
    /// Create a new DHT node
    pub fn new(identity: QuIDIdentity, address: String) -> Self {
        let node_id = consistent_hash(&identity.id);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            identity,
            address,
            last_seen: now,
            node_id,
            rtt: None,
            success_count: 0,
            failure_count: 0,
        }
    }
    
    /// Update node metrics after successful interaction
    pub fn record_success(&mut self, rtt_ms: u64) {
        self.success_count += 1;
        self.rtt = Some(rtt_ms);
        self.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    /// Update node metrics after failed interaction
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
    }
    
    /// Calculate node reliability score (0-100)
    pub fn reliability_score(&self) -> u8 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 50; // Unknown
        }
        
        let success_rate = (self.success_count * 100) / total;
        success_rate.min(100) as u8
    }
    
    /// Check if node is considered alive
    pub fn is_alive(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Consider dead if no response for 10 minutes
        now - self.last_seen < 600
    }
}

/// Kademlia-style routing table bucket
#[derive(Debug, Default)]
struct RoutingBucket {
    /// Nodes in this bucket
    nodes: Vec<DHTNode>,
    
    /// Maximum nodes per bucket
    max_size: usize,
    
    /// Last time this bucket was updated
    last_updated: u64,
}

impl RoutingBucket {
    fn new(max_size: usize) -> Self {
        Self {
            nodes: Vec::new(),
            max_size,
            last_updated: 0,
        }
    }
    
    /// Add or update a node in this bucket
    fn add_node(&mut self, node: DHTNode) {
        // Check if node already exists
        if let Some(pos) = self.nodes.iter().position(|n| n.node_id == node.node_id) {
            self.nodes[pos] = node;
            return;
        }
        
        // Add new node if space available
        if self.nodes.len() < self.max_size {
            self.nodes.push(node);
        } else {
            // Bucket is full - replace least reliable node
            if let Some(worst_idx) = self.find_worst_node() {
                if self.nodes[worst_idx].reliability_score() < node.reliability_score() {
                    self.nodes[worst_idx] = node;
                }
            }
        }
        
        self.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    /// Find the least reliable node
    fn find_worst_node(&self) -> Option<usize> {
        self.nodes
            .iter()
            .enumerate()
            .min_by_key(|(_, node)| node.reliability_score())
            .map(|(idx, _)| idx)
    }
    
    /// Get nodes sorted by distance to target
    fn closest_nodes(&self, target: &DHTKey, count: usize) -> Vec<DHTNode> {
        let mut nodes = self.nodes.clone();
        nodes.sort_by(|a, b| {
            let dist_a = key_distance(target, &a.node_id);
            let dist_b = key_distance(target, &b.node_id);
            dist_a.cmp(&dist_b)
        });
        
        nodes.into_iter().take(count).collect()
    }
    
    /// Remove dead nodes
    fn cleanup_dead_nodes(&mut self) {
        self.nodes.retain(|node| node.is_alive());
    }
}

/// Main DHT implementation
pub struct DHT {
    /// Our node information
    our_node: DHTNode,
    
    /// Routing table (bucket index -> bucket)
    routing_table: Vec<RoutingBucket>,
    
    /// Local storage (key -> value)
    storage: RwLock<HashMap<DHTKey, DHTValue>>,
    
    /// Replication factor
    replication_factor: usize,
    
    /// Maximum nodes per bucket
    bucket_size: usize,
}

impl DHT {
    /// Create a new DHT instance
    pub fn new(our_identity: QuIDIdentity, our_address: String, replication_factor: usize) -> Self {
        let our_node = DHTNode::new(our_identity, our_address);
        
        // Create 256 buckets (one for each bit of the 256-bit key space)
        let mut routing_table = Vec::new();
        for _ in 0..256 {
            routing_table.push(RoutingBucket::new(20)); // Max 20 nodes per bucket
        }
        
        Self {
            our_node,
            routing_table,
            storage: RwLock::new(HashMap::new()),
            replication_factor,
            bucket_size: 20,
        }
    }
    
    /// Add a node to the routing table
    pub fn add_node(&mut self, node: DHTNode) {
        let bucket_index = self.bucket_index(&node.node_id);
        self.routing_table[bucket_index].add_node(node);
    }
    
    /// Store a value in the DHT
    pub async fn store(&self, key: DHTKey, value: DHTValue) -> Result<()> {
        // Store locally
        let mut storage = self.storage.write().await;
        storage.insert(key.clone(), value.clone());
        drop(storage);
        
        // TODO: Replicate to closest nodes
        // For now, just store locally
        
        Ok(())
    }
    
    /// Retrieve a value from the DHT
    pub async fn get(&self, key: &DHTKey) -> Result<Option<DHTValue>> {
        // Check local storage first
        let storage = self.storage.read().await;
        if let Some(value) = storage.get(key) {
            if !value.is_expired() {
                return Ok(Some(value.clone()));
            }
        }
        drop(storage);
        
        // TODO: Query other nodes
        // For now, just check locally
        
        Ok(None)
    }
    
    /// Find the closest nodes to a given key
    pub fn find_closest_nodes(&self, target: &DHTKey, count: usize) -> Vec<DHTNode> {
        let mut all_nodes = Vec::new();
        
        // Collect nodes from all buckets
        for bucket in &self.routing_table {
            all_nodes.extend(bucket.nodes.iter().cloned());
        }
        
        // Sort by distance to target
        all_nodes.sort_by(|a, b| {
            let dist_a = key_distance(target, &a.node_id);
            let dist_b = key_distance(target, &b.node_id);
            dist_a.cmp(&dist_b)
        });
        
        all_nodes.into_iter().take(count).collect()
    }
    
    /// Update a mutable value (only if newer version)
    pub async fn update(&self, key: DHTKey, new_value: DHTValue) -> Result<bool> {
        let mut storage = self.storage.write().await;
        
        if let Some(existing) = storage.get(&key) {
            // Check if new version is newer and from same publisher
            if new_value.publisher != existing.publisher {
                return Err(NetworkError::PermissionDenied(
                    "Cannot update content from different publisher".to_string()
                ));
            }
            
            if new_value.version <= existing.version {
                return Ok(false); // Not newer
            }
        }
        
        storage.insert(key, new_value);
        Ok(true)
    }
    
    /// Delete a value (only by original publisher)
    pub async fn delete(&self, key: &DHTKey, deleter: &[u8]) -> Result<bool> {
        let mut storage = self.storage.write().await;
        
        if let Some(existing) = storage.get(key) {
            if existing.publisher != deleter {
                return Err(NetworkError::PermissionDenied(
                    "Cannot delete content from different publisher".to_string()
                ));
            }
            
            storage.remove(key);
            return Ok(true);
        }
        
        Ok(false) // Key not found
    }
    
    /// Cleanup expired values
    pub async fn cleanup_expired(&self) {
        let mut storage = self.storage.write().await;
        storage.retain(|_, value| !value.is_expired());
    }
    
    /// Get statistics about the DHT
    pub async fn stats(&self) -> DHTStats {
        let storage = self.storage.read().await;
        let stored_items = storage.len();
        let total_size: usize = storage.values().map(|v| v.data.len()).sum();
        drop(storage);
        
        let total_nodes: usize = self.routing_table.iter().map(|b| b.nodes.len()).sum();
        let active_buckets = self.routing_table.iter().filter(|b| !b.nodes.is_empty()).count();
        
        DHTStats {
            stored_items,
            total_size,
            total_nodes,
            active_buckets,
            replication_factor: self.replication_factor,
        }
    }
    
    /// Calculate which bucket a key belongs to
    fn bucket_index(&self, key: &DHTKey) -> usize {
        let distance = key_distance(&self.our_node.node_id, key);
        
        // Find the first differing bit
        for (byte_idx, &byte) in distance.iter().enumerate() {
            if byte != 0 {
                // Find the first set bit in this byte
                for bit_idx in 0..8 {
                    if (byte >> (7 - bit_idx)) & 1 == 1 {
                        return byte_idx * 8 + bit_idx;
                    }
                }
            }
        }
        
        // All bits are the same (shouldn't happen)
        255
    }
    
    /// Periodic maintenance
    pub async fn maintenance(&mut self) {
        // Clean up dead nodes
        for bucket in &mut self.routing_table {
            bucket.cleanup_dead_nodes();
        }
        
        // Clean up expired values
        self.cleanup_expired().await;
    }
}

/// DHT statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTStats {
    pub stored_items: usize,
    pub total_size: usize,
    pub total_nodes: usize,
    pub active_buckets: usize,
    pub replication_factor: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;

    #[tokio::test]
    async fn test_dht_creation() {
        let (identity, _) = quid_core::QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let dht = DHT::new(identity, "127.0.0.1:8080".to_string(), 3);
        
        let stats = dht.stats().await;
        assert_eq!(stats.stored_items, 0);
        assert_eq!(stats.replication_factor, 3);
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let (identity, _) = quid_core::QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let dht = DHT::new(identity.clone(), "127.0.0.1:8080".to_string(), 3);
        
        let key = consistent_hash(b"test-key");
        let value = DHTValue::new(
            b"test data".to_vec(),
            "text/plain".to_string(),
            identity.id.clone(),
            vec![1, 2, 3], // Mock signature
            3600, // 1 hour TTL
            1,    // Version 1
        );
        
        // Store value
        dht.store(key.clone(), value.clone()).await.unwrap();
        
        // Retrieve value
        let retrieved = dht.get(&key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data, b"test data");
    }

    #[tokio::test]
    async fn test_value_expiration() {
        let (identity, _) = quid_core::QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let mut value = DHTValue::new(
            b"test".to_vec(),
            "text/plain".to_string(),
            identity.id,
            vec![],
            1, // 1 second TTL
            1,
        );
        
        assert!(!value.is_expired());
        
        // Manually set timestamp to past
        value.timestamp = 0;
        assert!(value.is_expired());
    }

    #[test]
    fn test_bucket_index_calculation() {
        let (identity1, _) = quid_core::QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let (identity2, _) = quid_core::QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let dht = DHT::new(identity1, "127.0.0.1:8080".to_string(), 3);
        let key = consistent_hash(&identity2.id);
        
        let bucket_idx = dht.bucket_index(&key);
        assert!(bucket_idx < 256);
    }
}
