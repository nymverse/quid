//! Traffic obfuscation and timing analysis resistance
//!
//! License: 0BSD

use crate::{QuIDError, QuIDResult};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use rand::Rng;

/// Traffic obfuscation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationConfig {
    /// Enable packet padding
    pub packet_padding: bool,
    /// Target packet size
    pub target_packet_size: usize,
    /// Enable timing obfuscation
    pub timing_obfuscation: bool,
    /// Delay distribution
    pub delay_distribution: DelayDistribution,
    /// Cover traffic rate (packets per second)
    pub cover_traffic_rate: f64,
    /// Enable traffic shaping
    pub traffic_shaping: bool,
    /// Bandwidth target (bytes per second)
    pub bandwidth_target: u64,
    /// Burst size
    pub burst_size: usize,
}

/// Delay distribution types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelayDistribution {
    /// Uniform distribution
    Uniform { min: Duration, max: Duration },
    /// Exponential distribution
    Exponential { lambda: f64 },
    /// Poisson distribution
    Poisson { lambda: f64 },
    /// Fixed delay
    Fixed { delay: Duration },
}

/// Traffic obfuscator
#[derive(Debug)]
pub struct TrafficObfuscator {
    config: ObfuscationConfig,
    cover_traffic_generator: CoverTrafficGenerator,
    packet_shaper: PacketShaper,
    timing_obfuscator: TimingObfuscator,
}

/// Cover traffic generator
#[derive(Debug)]
pub struct CoverTrafficGenerator {
    rate: f64,
    last_packet_time: Instant,
    packet_queue: VecDeque<CoverPacket>,
}

/// Cover packet
#[derive(Debug, Clone)]
pub struct CoverPacket {
    /// Packet data
    pub data: Vec<u8>,
    /// Timestamp
    pub timestamp: Instant,
    /// Packet type
    pub packet_type: CoverPacketType,
}

/// Cover packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverPacketType {
    /// Regular cover traffic
    Cover,
    /// Heartbeat packet
    Heartbeat,
    /// Noise packet
    Noise,
}

/// Packet shaper for bandwidth control
#[derive(Debug)]
pub struct PacketShaper {
    bandwidth_target: u64,
    burst_size: usize,
    tokens: usize,
    last_refill: Instant,
    pending_packets: VecDeque<Vec<u8>>,
}

/// Timing obfuscator
#[derive(Debug)]
pub struct TimingObfuscator {
    delay_distribution: DelayDistribution,
    pending_delays: VecDeque<Duration>,
}

/// Obfuscated packet
#[derive(Debug, Clone)]
pub struct ObfuscatedPacket {
    /// Original data
    pub data: Vec<u8>,
    /// Padded data
    pub padded_data: Vec<u8>,
    /// Delay before sending
    pub delay: Duration,
    /// Timestamp
    pub timestamp: Instant,
}

/// Traffic statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    /// Total packets sent
    pub packets_sent: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Cover packets sent
    pub cover_packets_sent: u64,
    /// Average delay
    pub average_delay: Duration,
    /// Bandwidth utilization
    pub bandwidth_utilization: f64,
    /// Padding overhead
    pub padding_overhead: f64,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            packet_padding: true,
            target_packet_size: 1024,
            timing_obfuscation: true,
            delay_distribution: DelayDistribution::Exponential { lambda: 0.1 },
            cover_traffic_rate: 1.0,
            traffic_shaping: true,
            bandwidth_target: 1024 * 1024, // 1 MB/s
            burst_size: 10,
        }
    }
}

impl TrafficObfuscator {
    /// Create new traffic obfuscator
    pub fn new(config: ObfuscationConfig) -> Self {
        let cover_traffic_generator = CoverTrafficGenerator::new(config.cover_traffic_rate);
        let packet_shaper = PacketShaper::new(config.bandwidth_target, config.burst_size);
        let timing_obfuscator = TimingObfuscator::new(config.delay_distribution.clone());
        
        Self {
            config,
            cover_traffic_generator,
            packet_shaper,
            timing_obfuscator,
        }
    }
    
    /// Obfuscate outgoing packet
    pub async fn obfuscate_packet(&mut self, data: Vec<u8>) -> QuIDResult<ObfuscatedPacket> {
        // Apply packet padding
        let padded_data = if self.config.packet_padding {
            self.pad_packet(data.clone())?
        } else {
            data.clone()
        };
        
        // Generate timing delay
        let delay = if self.config.timing_obfuscation {
            self.timing_obfuscator.generate_delay()
        } else {
            Duration::from_millis(0)
        };
        
        Ok(ObfuscatedPacket {
            data,
            padded_data,
            delay,
            timestamp: Instant::now(),
        })
    }
    
    /// Process incoming packet (remove padding, etc.)
    pub async fn deobfuscate_packet(&mut self, data: Vec<u8>) -> QuIDResult<Vec<u8>> {
        // Remove padding if present
        if self.config.packet_padding {
            self.remove_padding(data)
        } else {
            Ok(data)
        }
    }
    
    /// Generate cover traffic
    pub async fn generate_cover_traffic(&mut self) -> QuIDResult<Vec<CoverPacket>> {
        self.cover_traffic_generator.generate_packets().await
    }
    
    /// Shape traffic according to bandwidth limits
    pub async fn shape_traffic(&mut self, packets: Vec<Vec<u8>>) -> QuIDResult<Vec<Vec<u8>>> {
        if self.config.traffic_shaping {
            self.packet_shaper.shape_packets(packets).await
        } else {
            Ok(packets)
        }
    }
    
    /// Get traffic statistics
    pub fn get_stats(&self) -> TrafficStats {
        // Mock statistics - in real implementation would track actual values
        TrafficStats {
            packets_sent: 100,
            bytes_sent: 102400,
            cover_packets_sent: 20,
            average_delay: Duration::from_millis(100),
            bandwidth_utilization: 0.75,
            padding_overhead: 0.15,
        }
    }
    
    /// Update configuration
    pub fn update_config(&mut self, config: ObfuscationConfig) {
        self.config = config.clone();
        self.cover_traffic_generator.update_rate(config.cover_traffic_rate);
        self.packet_shaper.update_bandwidth(config.bandwidth_target);
        self.timing_obfuscator.update_distribution(config.delay_distribution);
    }
    
    // Private helper methods
    
    /// Pad packet to target size
    fn pad_packet(&self, mut data: Vec<u8>) -> QuIDResult<Vec<u8>> {
        let target_size = self.config.target_packet_size;
        let current_size = data.len();
        
        if current_size >= target_size {
            return Ok(data);
        }
        
        let padding_size = target_size - current_size;
        let mut padding = vec![0u8; padding_size];
        
        // Fill padding with random data
        rand::thread_rng().fill(&mut padding[..]);
        
        // Add padding marker (last byte indicates padding size)
        if padding_size > 0 {
            padding[padding_size - 1] = (padding_size % 256) as u8;
        }
        
        data.extend_from_slice(&padding);
        Ok(data)
    }
    
    /// Remove padding from packet
    fn remove_padding(&self, data: Vec<u8>) -> QuIDResult<Vec<u8>> {
        if data.is_empty() {
            return Ok(data);
        }
        
        let last_byte = data[data.len() - 1];
        let padding_size = last_byte as usize;
        
        if padding_size == 0 || padding_size > data.len() {
            return Ok(data); // No padding or invalid padding
        }
        
        let unpadded_size = data.len() - padding_size;
        Ok(data[..unpadded_size].to_vec())
    }
}

impl CoverTrafficGenerator {
    /// Create new cover traffic generator
    pub fn new(rate: f64) -> Self {
        Self {
            rate,
            last_packet_time: Instant::now(),
            packet_queue: VecDeque::new(),
        }
    }
    
    /// Generate cover packets
    pub async fn generate_packets(&mut self) -> QuIDResult<Vec<CoverPacket>> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_packet_time);
        
        // Calculate number of packets to generate based on rate
        let packets_to_generate = (elapsed.as_secs_f64() * self.rate) as usize;
        
        let mut packets = Vec::new();
        
        for _ in 0..packets_to_generate {
            let packet = self.generate_cover_packet().await?;
            packets.push(packet);
        }
        
        self.last_packet_time = now;
        Ok(packets)
    }
    
    /// Generate single cover packet
    async fn generate_cover_packet(&mut self) -> QuIDResult<CoverPacket> {
        let packet_type = match rand::thread_rng().gen_range(0..3) {
            0 => CoverPacketType::Cover,
            1 => CoverPacketType::Heartbeat,
            _ => CoverPacketType::Noise,
        };
        
        let data_size = match packet_type {
            CoverPacketType::Cover => rand::thread_rng().gen_range(100..1500),
            CoverPacketType::Heartbeat => 64,
            CoverPacketType::Noise => rand::thread_rng().gen_range(50..200),
        };
        
        let mut data = vec![0u8; data_size];
        rand::thread_rng().fill(&mut data[..]);
        
        Ok(CoverPacket {
            data,
            timestamp: Instant::now(),
            packet_type,
        })
    }
    
    /// Update cover traffic rate
    pub fn update_rate(&mut self, rate: f64) {
        self.rate = rate;
    }
}

impl PacketShaper {
    /// Create new packet shaper
    pub fn new(bandwidth_target: u64, burst_size: usize) -> Self {
        Self {
            bandwidth_target,
            burst_size,
            tokens: burst_size,
            last_refill: Instant::now(),
            pending_packets: VecDeque::new(),
        }
    }
    
    /// Shape packets according to bandwidth limits
    pub async fn shape_packets(&mut self, packets: Vec<Vec<u8>>) -> QuIDResult<Vec<Vec<u8>>> {
        let mut shaped_packets = Vec::new();
        
        for packet in packets {
            // Refill tokens based on elapsed time
            self.refill_tokens();
            
            // Check if we have enough tokens
            if self.tokens > 0 {
                self.tokens -= 1;
                shaped_packets.push(packet);
            } else {
                // Queue packet for later
                self.pending_packets.push_back(packet);
            }
        }
        
        // Process pending packets if tokens are available
        while self.tokens > 0 && !self.pending_packets.is_empty() {
            if let Some(packet) = self.pending_packets.pop_front() {
                self.tokens -= 1;
                shaped_packets.push(packet);
            }
        }
        
        Ok(shaped_packets)
    }
    
    /// Refill token bucket
    fn refill_tokens(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        
        // Calculate tokens to add based on bandwidth target
        let tokens_to_add = (elapsed.as_secs_f64() * self.bandwidth_target as f64 / 1024.0) as usize;
        
        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.burst_size);
            self.last_refill = now;
        }
    }
    
    /// Update bandwidth target
    pub fn update_bandwidth(&mut self, bandwidth_target: u64) {
        self.bandwidth_target = bandwidth_target;
    }
}

impl TimingObfuscator {
    /// Create new timing obfuscator
    pub fn new(delay_distribution: DelayDistribution) -> Self {
        Self {
            delay_distribution,
            pending_delays: VecDeque::new(),
        }
    }
    
    /// Generate delay based on distribution
    pub fn generate_delay(&mut self) -> Duration {
        match &self.delay_distribution {
            DelayDistribution::Uniform { min, max } => {
                let min_millis = min.as_millis() as u64;
                let max_millis = max.as_millis() as u64;
                let delay_millis = rand::thread_rng().gen_range(min_millis..=max_millis);
                Duration::from_millis(delay_millis)
            }
            DelayDistribution::Exponential { lambda } => {
                let random_value: f64 = rand::thread_rng().gen();
                let delay_secs = -random_value.ln() / lambda;
                Duration::from_secs_f64(delay_secs.max(0.0))
            }
            DelayDistribution::Poisson { lambda } => {
                // Simplified Poisson distribution
                let delay_secs = 1.0 / lambda;
                Duration::from_secs_f64(delay_secs)
            }
            DelayDistribution::Fixed { delay } => *delay,
        }
    }
    
    /// Update delay distribution
    pub fn update_distribution(&mut self, delay_distribution: DelayDistribution) {
        self.delay_distribution = delay_distribution;
    }
}

/// Traffic pattern analyzer
pub struct TrafficPatternAnalyzer {
    packet_timings: VecDeque<Instant>,
    packet_sizes: VecDeque<usize>,
    analysis_window: Duration,
}

impl TrafficPatternAnalyzer {
    /// Create new traffic pattern analyzer
    pub fn new(analysis_window: Duration) -> Self {
        Self {
            packet_timings: VecDeque::new(),
            packet_sizes: VecDeque::new(),
            analysis_window,
        }
    }
    
    /// Record packet
    pub fn record_packet(&mut self, size: usize) {
        let now = Instant::now();
        
        // Remove old entries outside analysis window
        while let Some(&front_time) = self.packet_timings.front() {
            if now.duration_since(front_time) > self.analysis_window {
                self.packet_timings.pop_front();
                self.packet_sizes.pop_front();
            } else {
                break;
            }
        }
        
        // Add new entry
        self.packet_timings.push_back(now);
        self.packet_sizes.push_back(size);
    }
    
    /// Analyze traffic patterns
    pub fn analyze_patterns(&self) -> TrafficPatternAnalysis {
        let packet_count = self.packet_timings.len();
        
        if packet_count == 0 {
            return TrafficPatternAnalysis::default();
        }
        
        // Calculate inter-packet intervals
        let mut intervals = Vec::new();
        for i in 1..packet_count {
            let interval = self.packet_timings[i].duration_since(self.packet_timings[i-1]);
            intervals.push(interval);
        }
        
        // Calculate statistics
        let total_bytes: usize = self.packet_sizes.iter().sum();
        let avg_packet_size = total_bytes as f64 / packet_count as f64;
        
        let avg_interval = if !intervals.is_empty() {
            intervals.iter().sum::<Duration>() / intervals.len() as u32
        } else {
            Duration::from_secs(0)
        };
        
        let bandwidth = if !intervals.is_empty() {
            total_bytes as f64 / self.analysis_window.as_secs_f64()
        } else {
            0.0
        };
        
        TrafficPatternAnalysis {
            packet_count: packet_count as u64,
            total_bytes: total_bytes as u64,
            avg_packet_size,
            avg_interval,
            bandwidth,
            regularity_score: self.calculate_regularity_score(&intervals),
        }
    }
    
    /// Calculate regularity score (0.0 = completely irregular, 1.0 = perfectly regular)
    fn calculate_regularity_score(&self, intervals: &[Duration]) -> f64 {
        if intervals.len() < 2 {
            return 0.0;
        }
        
        let mean_interval = intervals.iter().sum::<Duration>() / intervals.len() as u32;
        let mean_millis = mean_interval.as_millis() as f64;
        
        // Calculate standard deviation
        let variance: f64 = intervals.iter()
            .map(|interval| {
                let diff = interval.as_millis() as f64 - mean_millis;
                diff * diff
            })
            .sum::<f64>() / intervals.len() as f64;
        
        let std_dev = variance.sqrt();
        
        // Regularity score (lower standard deviation = higher regularity)
        if mean_millis > 0.0 {
            (1.0 - (std_dev / mean_millis)).max(0.0)
        } else {
            0.0
        }
    }
}

/// Traffic pattern analysis results
#[derive(Debug, Clone, Default)]
pub struct TrafficPatternAnalysis {
    /// Number of packets
    pub packet_count: u64,
    /// Total bytes
    pub total_bytes: u64,
    /// Average packet size
    pub avg_packet_size: f64,
    /// Average inter-packet interval
    pub avg_interval: Duration,
    /// Bandwidth (bytes per second)
    pub bandwidth: f64,
    /// Regularity score (0.0 = irregular, 1.0 = regular)
    pub regularity_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_obfuscation_config_default() {
        let config = ObfuscationConfig::default();
        assert!(config.packet_padding);
        assert_eq!(config.target_packet_size, 1024);
        assert!(config.timing_obfuscation);
        assert_eq!(config.cover_traffic_rate, 1.0);
    }
    
    #[test]
    fn test_traffic_obfuscator_creation() {
        let config = ObfuscationConfig::default();
        let obfuscator = TrafficObfuscator::new(config);
        assert_eq!(obfuscator.config.target_packet_size, 1024);
    }
    
    #[tokio::test]
    async fn test_packet_obfuscation() {
        let config = ObfuscationConfig::default();
        let mut obfuscator = TrafficObfuscator::new(config);
        
        let data = vec![1, 2, 3, 4, 5];
        let obfuscated = obfuscator.obfuscate_packet(data.clone()).await.unwrap();
        
        assert_eq!(obfuscated.data, data);
        assert_eq!(obfuscated.padded_data.len(), 1024); // Target packet size
        
        let deobfuscated = obfuscator.deobfuscate_packet(obfuscated.padded_data).await.unwrap();
        assert_eq!(deobfuscated, data);
    }
    
    #[tokio::test]
    async fn test_cover_traffic_generation() {
        let mut generator = CoverTrafficGenerator::new(2.0);
        
        // Wait a bit to accumulate some time
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let packets = generator.generate_packets().await.unwrap();
        assert!(!packets.is_empty());
        
        for packet in packets {
            assert!(!packet.data.is_empty());
            assert!(matches!(packet.packet_type, CoverPacketType::Cover | CoverPacketType::Heartbeat | CoverPacketType::Noise));
        }
    }
    
    #[tokio::test]
    async fn test_packet_shaping() {
        let mut shaper = PacketShaper::new(1024, 5);
        
        let packets = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
        ];
        
        let shaped = shaper.shape_packets(packets).await.unwrap();
        assert!(!shaped.is_empty());
        assert!(shaped.len() <= 5); // Burst size limit
    }
    
    #[test]
    fn test_timing_obfuscator() {
        let mut obfuscator = TimingObfuscator::new(DelayDistribution::Fixed { 
            delay: Duration::from_millis(100) 
        });
        
        let delay = obfuscator.generate_delay();
        assert_eq!(delay, Duration::from_millis(100));
        
        // Test uniform distribution
        obfuscator.update_distribution(DelayDistribution::Uniform {
            min: Duration::from_millis(50),
            max: Duration::from_millis(150),
        });
        
        let delay = obfuscator.generate_delay();
        assert!(delay >= Duration::from_millis(50));
        assert!(delay <= Duration::from_millis(150));
    }
    
    #[test]
    fn test_traffic_pattern_analyzer() {
        let mut analyzer = TrafficPatternAnalyzer::new(Duration::from_secs(60));
        
        // Record some packets
        analyzer.record_packet(100);
        analyzer.record_packet(200);
        analyzer.record_packet(150);
        
        let analysis = analyzer.analyze_patterns();
        assert_eq!(analysis.packet_count, 3);
        assert_eq!(analysis.total_bytes, 450);
        assert_eq!(analysis.avg_packet_size, 150.0);
    }
    
    #[test]
    fn test_delay_distributions() {
        let uniform = DelayDistribution::Uniform {
            min: Duration::from_millis(10),
            max: Duration::from_millis(100),
        };
        
        let exponential = DelayDistribution::Exponential { lambda: 0.5 };
        let poisson = DelayDistribution::Poisson { lambda: 2.0 };
        let fixed = DelayDistribution::Fixed { delay: Duration::from_millis(50) };
        
        let mut obfuscator = TimingObfuscator::new(uniform);
        let delay1 = obfuscator.generate_delay();
        assert!(delay1 >= Duration::from_millis(10));
        assert!(delay1 <= Duration::from_millis(100));
        
        obfuscator.update_distribution(exponential);
        let delay2 = obfuscator.generate_delay();
        assert!(delay2 >= Duration::from_millis(0));
        
        obfuscator.update_distribution(poisson);
        let delay3 = obfuscator.generate_delay();
        assert!(delay3 >= Duration::from_millis(0));
        
        obfuscator.update_distribution(fixed);
        let delay4 = obfuscator.generate_delay();
        assert_eq!(delay4, Duration::from_millis(50));
    }
    
    #[test]
    fn test_cover_packet_types() {
        let cover = CoverPacket {
            data: vec![1, 2, 3],
            timestamp: Instant::now(),
            packet_type: CoverPacketType::Cover,
        };
        
        let heartbeat = CoverPacket {
            data: vec![4, 5, 6],
            timestamp: Instant::now(),
            packet_type: CoverPacketType::Heartbeat,
        };
        
        let noise = CoverPacket {
            data: vec![7, 8, 9],
            timestamp: Instant::now(),
            packet_type: CoverPacketType::Noise,
        };
        
        assert_eq!(cover.packet_type, CoverPacketType::Cover);
        assert_eq!(heartbeat.packet_type, CoverPacketType::Heartbeat);
        assert_eq!(noise.packet_type, CoverPacketType::Noise);
    }
}