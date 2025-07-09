//! Anonymous relay system for QuID messaging
//!
//! License: 0BSD

use crate::{QuIDError, QuIDResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;

/// Anonymous relay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Relay listening address
    pub listen_addr: SocketAddr,
    /// Maximum connections
    pub max_connections: usize,
    /// Relay hops (minimum 3 for anonymity)
    pub relay_hops: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Relay timeout
    pub relay_timeout: Duration,
    /// Enable relay discovery
    pub enable_discovery: bool,
    /// Discovery interval
    pub discovery_interval: Duration,
    /// Minimum relay nodes required
    pub min_relay_nodes: usize,
}

/// Anonymous relay system
#[derive(Debug)]
pub struct AnonymousRelay {
    config: RelayConfig,
    relay_nodes: Arc<RwLock<HashMap<String, RelayNode>>>,
    active_circuits: Arc<RwLock<HashMap<String, RelayCircuit>>>,
    message_queue: Arc<RwLock<VecDeque<RelayMessage>>>,
    reputation_system: Arc<RwLock<RelayReputationSystem>>,
}

/// Relay node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayNode {
    /// Node ID
    pub id: String,
    /// Node address
    pub addr: SocketAddr,
    /// Node public key
    pub public_key: Vec<u8>,
    /// Node capabilities
    pub capabilities: RelayCapabilities,
    /// Reputation score
    pub reputation: f64,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Latency statistics
    pub latency: Duration,
    /// Bandwidth statistics
    pub bandwidth: u64,
}

/// Relay capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayCapabilities {
    /// Supports entry guard
    pub entry_guard: bool,
    /// Supports middle relay
    pub middle_relay: bool,
    /// Supports exit node
    pub exit_node: bool,
    /// Maximum bandwidth
    pub max_bandwidth: u64,
    /// Maximum connections
    pub max_connections: usize,
}

/// Relay circuit
#[derive(Debug, Clone)]
pub struct RelayCircuit {
    /// Circuit ID
    pub id: String,
    /// Circuit path (relay node IDs)
    pub path: Vec<String>,
    /// Circuit status
    pub status: CircuitStatus,
    /// Creation timestamp
    pub created_at: Instant,
    /// Last activity
    pub last_activity: Instant,
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Encryption layers
    pub encryption_layers: Vec<EncryptionLayer>,
}

/// Circuit status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitStatus {
    Building,
    Built,
    Active,
    Closing,
    Closed,
    Failed,
}

/// Encryption layer for onion routing
#[derive(Debug, Clone)]
pub struct EncryptionLayer {
    /// Layer ID
    pub id: String,
    /// Encryption key
    pub key: Vec<u8>,
    /// Relay node ID
    pub relay_id: String,
    /// Layer type
    pub layer_type: LayerType,
}

/// Layer type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerType {
    Entry,
    Middle,
    Exit,
}

/// Relay message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayMessage {
    /// Message ID
    pub id: String,
    /// Circuit ID
    pub circuit_id: String,
    /// Message type
    pub message_type: MessageType,
    /// Message payload
    pub payload: Vec<u8>,
    /// Timestamp
    pub timestamp: Instant,
    /// Hop count
    pub hop_count: usize,
}

/// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Data message
    Data,
    /// Circuit setup
    CircuitSetup,
    /// Circuit teardown
    CircuitTeardown,
    /// Relay heartbeat
    Heartbeat,
    /// Error message
    Error,
}

/// Relay reputation system
#[derive(Debug, Clone)]
pub struct RelayReputationSystem {
    /// Node reputation scores
    pub scores: HashMap<String, ReputationScore>,
    /// Reputation decay rate
    pub decay_rate: f64,
    /// Last update timestamp
    pub last_update: Instant,
}

/// Reputation score
#[derive(Debug, Clone)]
pub struct ReputationScore {
    /// Success rate
    pub success_rate: f64,
    /// Uptime percentage
    pub uptime: f64,
    /// Bandwidth score
    pub bandwidth_score: f64,
    /// Latency score
    pub latency_score: f64,
    /// Total interactions
    pub total_interactions: u64,
    /// Successful interactions
    pub successful_interactions: u64,
}

/// Relay statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayStats {
    /// Total relay nodes
    pub total_nodes: usize,
    /// Active circuits
    pub active_circuits: usize,
    /// Messages relayed
    pub messages_relayed: u64,
    /// Bytes relayed
    pub bytes_relayed: u64,
    /// Average latency
    pub avg_latency: Duration,
    /// Success rate
    pub success_rate: f64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            max_connections: 100,
            relay_hops: 3,
            connection_timeout: Duration::from_secs(30),
            relay_timeout: Duration::from_secs(300),
            enable_discovery: true,
            discovery_interval: Duration::from_secs(60),
            min_relay_nodes: 10,
        }
    }
}

impl AnonymousRelay {
    /// Create new anonymous relay
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            relay_nodes: Arc::new(RwLock::new(HashMap::new())),
            active_circuits: Arc::new(RwLock::new(HashMap::new())),
            message_queue: Arc::new(RwLock::new(VecDeque::new())),
            reputation_system: Arc::new(RwLock::new(RelayReputationSystem::new())),
        }
    }
    
    /// Start relay server
    pub async fn start_server(&self) -> QuIDResult<()> {
        let listener = TcpListener::bind(&self.config.listen_addr).await
            .map_err(|e| QuIDError::NetworkError(format!("Failed to bind relay listener: {}", e)))?;
        
        log::info!("Anonymous relay started on {}", self.config.listen_addr);
        
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    log::debug!("New connection from {}", addr);
                    let relay = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = relay.handle_connection(stream).await {
                            log::error!("Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("Error accepting connection: {}", e);
                }
            }
        }
    }
    
    /// Create new relay circuit
    pub async fn create_circuit(&self, target_addr: SocketAddr) -> QuIDResult<String> {
        let circuit_id = uuid::Uuid::new_v4().to_string();
        
        // Select relay nodes for circuit
        let relay_path = self.select_relay_path().await?;
        
        // Create encryption layers
        let encryption_layers = self.create_encryption_layers(&relay_path).await?;
        
        let circuit = RelayCircuit {
            id: circuit_id.clone(),
            path: relay_path,
            status: CircuitStatus::Building,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            bytes_transferred: 0,
            encryption_layers,
        };
        
        // Store circuit
        {
            let mut circuits = self.active_circuits.write().await;
            circuits.insert(circuit_id.clone(), circuit);
        }
        
        // Build circuit
        self.build_circuit(&circuit_id).await?;
        
        Ok(circuit_id)
    }
    
    /// Send message through relay circuit
    pub async fn send_message(&self, circuit_id: &str, data: Vec<u8>) -> QuIDResult<()> {
        let message = RelayMessage {
            id: uuid::Uuid::new_v4().to_string(),
            circuit_id: circuit_id.to_string(),
            message_type: MessageType::Data,
            payload: data,
            timestamp: Instant::now(),
            hop_count: 0,
        };
        
        // Encrypt message with onion layers
        let encrypted_message = self.encrypt_message(&message).await?;
        
        // Send through circuit
        self.relay_message(encrypted_message).await?;
        
        Ok(())
    }
    
    /// Discover relay nodes
    pub async fn discover_nodes(&self) -> QuIDResult<Vec<RelayNode>> {
        if !self.config.enable_discovery {
            return Ok(vec![]);
        }
        
        // Mock node discovery - in real implementation would use DHT or other discovery mechanism
        let mut discovered_nodes = Vec::new();
        
        for i in 0..20 {
            let node = RelayNode {
                id: format!("relay-node-{}", i),
                addr: format!("127.0.0.1:{}", 8081 + i).parse().unwrap(),
                public_key: vec![i as u8; 32],
                capabilities: RelayCapabilities {
                    entry_guard: i % 3 == 0,
                    middle_relay: true,
                    exit_node: i % 5 == 0,
                    max_bandwidth: 1024 * 1024 * (i + 1) as u64,
                    max_connections: 50 + i * 10,
                },
                reputation: 0.8 + (i as f64 * 0.01),
                last_seen: Instant::now(),
                latency: Duration::from_millis(10 + i * 5),
                bandwidth: 1024 * 1024 * (i + 1) as u64,
            };
            
            discovered_nodes.push(node);
        }
        
        // Update relay nodes
        {
            let mut nodes = self.relay_nodes.write().await;
            for node in &discovered_nodes {
                nodes.insert(node.id.clone(), node.clone());
            }
        }
        
        Ok(discovered_nodes)
    }
    
    /// Get relay statistics
    pub async fn get_stats(&self) -> RelayStats {
        let nodes = self.relay_nodes.read().await;
        let circuits = self.active_circuits.read().await;
        
        let active_circuits = circuits.values()
            .filter(|c| matches!(c.status, CircuitStatus::Active | CircuitStatus::Built))
            .count();
        
        let total_bytes: u64 = circuits.values()
            .map(|c| c.bytes_transferred)
            .sum();
        
        let avg_latency = if !nodes.is_empty() {
            nodes.values().map(|n| n.latency).sum::<Duration>() / nodes.len() as u32
        } else {
            Duration::from_millis(0)
        };
        
        RelayStats {
            total_nodes: nodes.len(),
            active_circuits,
            messages_relayed: 1000, // Mock value
            bytes_relayed: total_bytes,
            avg_latency,
            success_rate: 0.95,
        }
    }
    
    /// Close relay circuit
    pub async fn close_circuit(&self, circuit_id: &str) -> QuIDResult<()> {
        let mut circuits = self.active_circuits.write().await;
        
        if let Some(mut circuit) = circuits.get_mut(circuit_id) {
            circuit.status = CircuitStatus::Closing;
            circuit.last_activity = Instant::now();
            
            // Send teardown message
            let teardown_message = RelayMessage {
                id: uuid::Uuid::new_v4().to_string(),
                circuit_id: circuit_id.to_string(),
                message_type: MessageType::CircuitTeardown,
                payload: Vec::new(),
                timestamp: Instant::now(),
                hop_count: 0,
            };
            
            // Remove circuit after teardown
            circuit.status = CircuitStatus::Closed;
            circuits.remove(circuit_id);
        }
        
        Ok(())
    }
    
    // Private helper methods
    
    /// Handle incoming connection
    async fn handle_connection(&self, mut stream: TcpStream) -> QuIDResult<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        let mut buffer = vec![0; 4096];
        
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    // Process received data
                    let data = &buffer[..n];
                    
                    // Deserialize message
                    if let Ok(message) = bincode::deserialize::<RelayMessage>(data) {
                        self.process_relay_message(message).await?;
                    }
                }
                Err(e) => {
                    log::error!("Error reading from connection: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Select relay path for circuit
    async fn select_relay_path(&self) -> QuIDResult<Vec<String>> {
        let nodes = self.relay_nodes.read().await;
        
        if nodes.len() < self.config.relay_hops {
            return Err(QuIDError::NetworkError("Insufficient relay nodes".to_string()));
        }
        
        let mut path = Vec::new();
        let mut available_nodes: Vec<_> = nodes.values().collect();
        
        // Sort by reputation
        available_nodes.sort_by(|a, b| b.reputation.partial_cmp(&a.reputation).unwrap());
        
        // Select entry guard
        if let Some(entry_node) = available_nodes.iter().find(|n| n.capabilities.entry_guard) {
            path.push(entry_node.id.clone());
        }
        
        // Select middle relays
        for _ in 1..self.config.relay_hops - 1 {
            if let Some(middle_node) = available_nodes.iter()
                .find(|n| n.capabilities.middle_relay && !path.contains(&n.id)) {
                path.push(middle_node.id.clone());
            }
        }
        
        // Select exit node
        if let Some(exit_node) = available_nodes.iter()
            .find(|n| n.capabilities.exit_node && !path.contains(&n.id)) {
            path.push(exit_node.id.clone());
        }
        
        if path.len() < self.config.relay_hops {
            return Err(QuIDError::NetworkError("Could not select sufficient relay nodes".to_string()));
        }
        
        Ok(path)
    }
    
    /// Create encryption layers for onion routing
    async fn create_encryption_layers(&self, relay_path: &[String]) -> QuIDResult<Vec<EncryptionLayer>> {
        let mut layers = Vec::new();
        
        for (i, relay_id) in relay_path.iter().enumerate() {
            let layer_type = match i {
                0 => LayerType::Entry,
                i if i == relay_path.len() - 1 => LayerType::Exit,
                _ => LayerType::Middle,
            };
            
            let layer = EncryptionLayer {
                id: uuid::Uuid::new_v4().to_string(),
                key: vec![i as u8; 32], // Simplified key generation
                relay_id: relay_id.clone(),
                layer_type,
            };
            
            layers.push(layer);
        }
        
        Ok(layers)
    }
    
    /// Build relay circuit
    async fn build_circuit(&self, circuit_id: &str) -> QuIDResult<()> {
        let mut circuits = self.active_circuits.write().await;
        
        if let Some(circuit) = circuits.get_mut(circuit_id) {
            circuit.status = CircuitStatus::Built;
            circuit.last_activity = Instant::now();
        }
        
        Ok(())
    }
    
    /// Encrypt message with onion layers
    async fn encrypt_message(&self, message: &RelayMessage) -> QuIDResult<RelayMessage> {
        let circuits = self.active_circuits.read().await;
        
        if let Some(circuit) = circuits.get(&message.circuit_id) {
            // Apply encryption layers in reverse order
            let mut encrypted_payload = message.payload.clone();
            
            for layer in circuit.encryption_layers.iter().rev() {
                // Simplified encryption - in real implementation use proper crypto
                for (i, byte) in encrypted_payload.iter_mut().enumerate() {
                    *byte ^= layer.key[i % layer.key.len()];
                }
            }
            
            let mut encrypted_message = message.clone();
            encrypted_message.payload = encrypted_payload;
            
            Ok(encrypted_message)
        } else {
            Err(QuIDError::NetworkError("Circuit not found".to_string()))
        }
    }
    
    /// Process relay message
    async fn process_relay_message(&self, message: RelayMessage) -> QuIDResult<()> {
        match message.message_type {
            MessageType::Data => {
                // Decrypt one layer and forward
                self.decrypt_and_forward(message).await?;
            }
            MessageType::CircuitSetup => {
                // Handle circuit setup
                self.handle_circuit_setup(message).await?;
            }
            MessageType::CircuitTeardown => {
                // Handle circuit teardown
                self.handle_circuit_teardown(message).await?;
            }
            MessageType::Heartbeat => {
                // Update node status
                self.handle_heartbeat(message).await?;
            }
            MessageType::Error => {
                // Handle error message
                log::error!("Relay error: {:?}", message);
            }
        }
        
        Ok(())
    }
    
    /// Decrypt and forward message
    async fn decrypt_and_forward(&self, mut message: RelayMessage) -> QuIDResult<()> {
        // Decrypt one layer
        // In real implementation, this would decrypt the current layer
        // and forward to the next hop
        
        message.hop_count += 1;
        
        // Add to message queue for processing
        {
            let mut queue = self.message_queue.write().await;
            queue.push_back(message);
        }
        
        Ok(())
    }
    
    /// Handle circuit setup
    async fn handle_circuit_setup(&self, message: RelayMessage) -> QuIDResult<()> {
        log::info!("Setting up circuit: {}", message.circuit_id);
        Ok(())
    }
    
    /// Handle circuit teardown
    async fn handle_circuit_teardown(&self, message: RelayMessage) -> QuIDResult<()> {
        log::info!("Tearing down circuit: {}", message.circuit_id);
        Ok(())
    }
    
    /// Handle heartbeat
    async fn handle_heartbeat(&self, message: RelayMessage) -> QuIDResult<()> {
        log::debug!("Received heartbeat from circuit: {}", message.circuit_id);
        Ok(())
    }
    
    /// Relay message to next hop
    async fn relay_message(&self, message: RelayMessage) -> QuIDResult<()> {
        // In real implementation, this would send the message to the next relay
        log::debug!("Relaying message: {}", message.id);
        Ok(())
    }
}

impl Clone for AnonymousRelay {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            relay_nodes: self.relay_nodes.clone(),
            active_circuits: self.active_circuits.clone(),
            message_queue: self.message_queue.clone(),
            reputation_system: self.reputation_system.clone(),
        }
    }
}

impl RelayReputationSystem {
    /// Create new reputation system
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            decay_rate: 0.95,
            last_update: Instant::now(),
        }
    }
    
    /// Update node reputation
    pub fn update_reputation(&mut self, node_id: &str, success: bool) {
        let score = self.scores.entry(node_id.to_string())
            .or_insert_with(|| ReputationScore::new());
        
        score.total_interactions += 1;
        if success {
            score.successful_interactions += 1;
        }
        
        score.success_rate = score.successful_interactions as f64 / score.total_interactions as f64;
    }
    
    /// Get node reputation
    pub fn get_reputation(&self, node_id: &str) -> f64 {
        self.scores.get(node_id)
            .map(|score| score.success_rate)
            .unwrap_or(0.5) // Default reputation
    }
    
    /// Apply reputation decay
    pub fn apply_decay(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);
        
        if elapsed > Duration::from_secs(3600) { // Apply decay every hour
            for score in self.scores.values_mut() {
                score.success_rate *= self.decay_rate;
                score.uptime *= self.decay_rate;
                score.bandwidth_score *= self.decay_rate;
                score.latency_score *= self.decay_rate;
            }
            
            self.last_update = now;
        }
    }
}

impl ReputationScore {
    /// Create new reputation score
    pub fn new() -> Self {
        Self {
            success_rate: 0.5,
            uptime: 0.5,
            bandwidth_score: 0.5,
            latency_score: 0.5,
            total_interactions: 0,
            successful_interactions: 0,
        }
    }
    
    /// Calculate overall reputation
    pub fn calculate_overall(&self) -> f64 {
        (self.success_rate * 0.4 + 
         self.uptime * 0.3 + 
         self.bandwidth_score * 0.2 + 
         self.latency_score * 0.1).max(0.0).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_relay_config_default() {
        let config = RelayConfig::default();
        assert_eq!(config.relay_hops, 3);
        assert_eq!(config.max_connections, 100);
        assert!(config.enable_discovery);
    }
    
    #[tokio::test]
    async fn test_anonymous_relay_creation() {
        let config = RelayConfig::default();
        let relay = AnonymousRelay::new(config);
        
        let stats = relay.get_stats().await;
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.active_circuits, 0);
    }
    
    #[tokio::test]
    async fn test_node_discovery() {
        let config = RelayConfig::default();
        let relay = AnonymousRelay::new(config);
        
        let nodes = relay.discover_nodes().await.unwrap();
        assert_eq!(nodes.len(), 20);
        
        let stats = relay.get_stats().await;
        assert_eq!(stats.total_nodes, 20);
    }
    
    #[tokio::test]
    async fn test_circuit_creation() {
        let config = RelayConfig::default();
        let relay = AnonymousRelay::new(config);
        
        // First discover nodes
        relay.discover_nodes().await.unwrap();
        
        let target_addr = "127.0.0.1:8080".parse().unwrap();
        let circuit_id = relay.create_circuit(target_addr).await.unwrap();
        
        assert!(!circuit_id.is_empty());
        
        let stats = relay.get_stats().await;
        assert_eq!(stats.active_circuits, 1);
    }
    
    #[tokio::test]
    async fn test_message_relay() {
        let config = RelayConfig::default();
        let relay = AnonymousRelay::new(config);
        
        // Discover nodes and create circuit
        relay.discover_nodes().await.unwrap();
        let target_addr = "127.0.0.1:8080".parse().unwrap();
        let circuit_id = relay.create_circuit(target_addr).await.unwrap();
        
        // Send message
        let data = vec![1, 2, 3, 4, 5];
        let result = relay.send_message(&circuit_id, data).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_circuit_closure() {
        let config = RelayConfig::default();
        let relay = AnonymousRelay::new(config);
        
        // Discover nodes and create circuit
        relay.discover_nodes().await.unwrap();
        let target_addr = "127.0.0.1:8080".parse().unwrap();
        let circuit_id = relay.create_circuit(target_addr).await.unwrap();
        
        // Close circuit
        let result = relay.close_circuit(&circuit_id).await;
        assert!(result.is_ok());
        
        let stats = relay.get_stats().await;
        assert_eq!(stats.active_circuits, 0);
    }
    
    #[test]
    fn test_reputation_system() {
        let mut reputation = RelayReputationSystem::new();
        
        // Update reputation
        reputation.update_reputation("node1", true);
        reputation.update_reputation("node1", true);
        reputation.update_reputation("node1", false);
        
        let score = reputation.get_reputation("node1");
        assert!((score - 0.6666666666666666).abs() < 0.0001);
        
        // Test decay
        reputation.apply_decay();
        let decayed_score = reputation.get_reputation("node1");
        assert!(decayed_score < score);
    }
    
    #[test]
    fn test_reputation_score() {
        let mut score = ReputationScore::new();
        
        score.success_rate = 0.8;
        score.uptime = 0.9;
        score.bandwidth_score = 0.7;
        score.latency_score = 0.6;
        
        let overall = score.calculate_overall();
        assert!((overall - 0.79).abs() < 0.01);
    }
    
    #[test]
    fn test_relay_capabilities() {
        let capabilities = RelayCapabilities {
            entry_guard: true,
            middle_relay: true,
            exit_node: false,
            max_bandwidth: 1024 * 1024,
            max_connections: 100,
        };
        
        assert!(capabilities.entry_guard);
        assert!(capabilities.middle_relay);
        assert!(!capabilities.exit_node);
        assert_eq!(capabilities.max_bandwidth, 1024 * 1024);
        assert_eq!(capabilities.max_connections, 100);
    }
    
    #[test]
    fn test_circuit_status() {
        let mut circuit = RelayCircuit {
            id: "test-circuit".to_string(),
            path: vec!["node1".to_string(), "node2".to_string(), "node3".to_string()],
            status: CircuitStatus::Building,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            bytes_transferred: 0,
            encryption_layers: Vec::new(),
        };
        
        assert_eq!(circuit.status, CircuitStatus::Building);
        assert_eq!(circuit.path.len(), 3);
        
        circuit.status = CircuitStatus::Built;
        assert_eq!(circuit.status, CircuitStatus::Built);
    }
    
    #[test]
    fn test_encryption_layers() {
        let layer = EncryptionLayer {
            id: "layer1".to_string(),
            key: vec![1, 2, 3, 4],
            relay_id: "relay1".to_string(),
            layer_type: LayerType::Entry,
        };
        
        assert_eq!(layer.id, "layer1");
        assert_eq!(layer.key, vec![1, 2, 3, 4]);
        assert_eq!(layer.relay_id, "relay1");
        assert_eq!(layer.layer_type, LayerType::Entry);
    }
    
    #[test]
    fn test_message_types() {
        let message = RelayMessage {
            id: "msg1".to_string(),
            circuit_id: "circuit1".to_string(),
            message_type: MessageType::Data,
            payload: vec![1, 2, 3],
            timestamp: Instant::now(),
            hop_count: 0,
        };
        
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.payload, vec![1, 2, 3]);
        assert_eq!(message.hop_count, 0);
    }
}