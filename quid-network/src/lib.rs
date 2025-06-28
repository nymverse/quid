//! QuID Network Layer - Decentralized content storage and peer-to-peer networking
//! 
//! This module implements the content layer that sits on top of the NYM consensus layer.
//! It provides decentralized domain resolution, content storage, and offline-first synchronization.

pub mod dht;
pub mod peer;
pub mod content;
pub mod domain;
pub mod sync;
pub mod storage;
pub mod error;

pub use dht::{DHT, DHTNode, DHTKey, DHTValue};
pub use peer::{Peer, PeerInfo, PeerManager};
pub use content::{Content, ContentHash, ContentStore};
pub use domain::{DomainResolver, DomainRecord};
pub use sync::{SyncManager, SyncStrategy};
pub use storage::{LocalStorage, StorageBackend};
pub use error::NetworkError;

use quid_core::QuIDIdentity;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Result type for network operations
pub type Result<T> = std::result::Result<T, NetworkError>;

/// Network protocol version
pub const NETWORK_VERSION: &str = "0.1.0";

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Maximum number of peers to maintain connections with
    pub max_peers: usize,
    
    /// Maximum content cache size (in bytes)
    pub max_cache_size: u64,
    
    /// DHT replication factor (how many nodes store each piece of data)
    pub replication_factor: usize,
    
    /// Bootstrap nodes for initial network discovery
    pub bootstrap_nodes: Vec<String>,
    
    /// Local listening port
    pub listen_port: u16,
    
    /// Content sync interval (seconds)
    pub sync_interval: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            max_peers: 50,
            max_cache_size: 1024 * 1024 * 1024, // 1GB
            replication_factor: 3,
            bootstrap_nodes: vec![
                "bootstrap1.quid.network:8080".to_string(),
                "bootstrap2.quid.network:8080".to_string(),
            ],
            listen_port: 8080,
            sync_interval: 300, // 5 minutes
        }
    }
}

/// Generate a consistent hash for DHT key distribution
pub fn consistent_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"quid-dht-hash");
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calculate distance between two DHT keys
pub fn key_distance(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    
    let mut distance = vec![0u8; a.len()];
    for i in 0..a.len() {
        distance[i] = a[i] ^ b[i];
    }
    distance
}

/// Check if key `target` is closer to `reference` than `current`
pub fn is_closer(reference: &[u8], target: &[u8], current: &[u8]) -> bool {
    let dist_target = key_distance(reference, target);
    let dist_current = key_distance(reference, current);
    dist_target < dist_current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistent_hash() {
        let data1 = b"test data";
        let data2 = b"test data";
        let data3 = b"different data";
        
        let hash1 = consistent_hash(data1);
        let hash2 = consistent_hash(data2);
        let hash3 = consistent_hash(data3);
        
        assert_eq!(hash1, hash2); // Same data should produce same hash
        assert_ne!(hash1, hash3); // Different data should produce different hash
        assert_eq!(hash1.len(), 32); // SHA3-256 produces 32 bytes
    }

    #[test]
    fn test_key_distance() {
        let key1 = vec![0b10101010, 0b11110000];
        let key2 = vec![0b01010101, 0b11110000];
        let expected = vec![0b11111111, 0b00000000];
        
        assert_eq!(key_distance(&key1, &key2), expected);
    }

    #[test]
    fn test_is_closer() {
        let reference = vec![0b00000000];
        let target = vec![0b00000001];
        let current = vec![0b00000010];
        
        assert!(is_closer(&reference, &target, &current));
        assert!(!is_closer(&reference, &current, &target));
    }
}