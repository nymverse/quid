//! Configuration for Zero-Knowledge Proof operations

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Main configuration for ZKP operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKPConfig {
    /// Proof system configuration
    pub proof_systems: ProofSystemConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Network configuration for distributed proving
    pub network: NetworkConfig,
    /// Enable quantum-resistant features
    pub quantum_resistant: bool,
    /// Maximum proof size in bytes
    pub max_proof_size: usize,
    /// Verification timeout in seconds
    pub verification_timeout: u64,
}

/// Proof system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSystemConfig {
    /// Enable zk-SNARKs
    pub enable_snarks: bool,
    /// Enable zk-STARKs
    pub enable_starks: bool,
    /// Enable Bulletproofs
    pub enable_bulletproofs: bool,
    /// Enable PLONK
    pub enable_plonk: bool,
    /// Enable Groth16
    pub enable_groth16: bool,
    /// Default proof system
    pub default_system: String,
    /// SNARK configuration
    pub snark_config: SnarkConfig,
    /// STARK configuration
    pub stark_config: StarkConfig,
    /// Bulletproof configuration
    pub bulletproof_config: BulletproofConfig,
}

/// SNARK configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkConfig {
    /// Circuit compilation timeout
    pub compilation_timeout: u64,
    /// Trusted setup parameters directory
    pub trusted_setup_dir: PathBuf,
    /// Enable universal setup
    pub universal_setup: bool,
    /// Maximum circuit size
    pub max_circuit_size: u32,
    /// Enable optimizations
    pub enable_optimizations: bool,
}

/// STARK configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkConfig {
    /// Field size (bits)
    pub field_size: u32,
    /// Security level (bits)
    pub security_level: u32,
    /// Hash function for Merkle trees
    pub hash_function: String,
    /// Enable FRI optimization
    pub enable_fri_optimization: bool,
    /// Query complexity
    pub query_complexity: u32,
}

/// Bulletproof configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulletproofConfig {
    /// Maximum bit length for range proofs
    pub max_bit_length: u32,
    /// Enable batch verification
    pub enable_batch_verification: bool,
    /// Aggregation factor
    pub aggregation_factor: u32,
    /// Enable inner product optimization
    pub enable_inner_product_optimization: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Minimum security level (bits)
    pub min_security_level: u32,
    /// Enable secure random number generation
    pub secure_random: bool,
    /// Enable side-channel protection
    pub side_channel_protection: bool,
    /// Enable timing attack protection
    pub timing_attack_protection: bool,
    /// Key derivation iterations
    pub key_derivation_iterations: u32,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Number of parallel proving threads
    pub proving_threads: u32,
    /// Number of parallel verification threads
    pub verification_threads: u32,
    /// Enable GPU acceleration
    pub enable_gpu: bool,
    /// Memory limit for proving (MB)
    pub memory_limit_mb: u64,
    /// Enable caching
    pub enable_caching: bool,
    /// Cache size (MB)
    pub cache_size_mb: u64,
    /// Enable proof compression
    pub enable_compression: bool,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage directory
    pub storage_dir: PathBuf,
    /// Enable persistent storage
    pub persistent_storage: bool,
    /// Enable proof archival
    pub enable_archival: bool,
    /// Archival retention period (days)
    pub archival_retention_days: u32,
    /// Enable compression
    pub enable_compression: bool,
    /// Backup configuration
    pub backup_config: BackupConfig,
}

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Enable automatic backups
    pub enabled: bool,
    /// Backup interval (hours)
    pub interval_hours: u32,
    /// Maximum backups to keep
    pub max_backups: u32,
    /// Backup directory
    pub backup_dir: PathBuf,
}

/// Network configuration for distributed proving
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable distributed proving
    pub enable_distributed: bool,
    /// Coordinator address
    pub coordinator_address: String,
    /// Coordinator port
    pub coordinator_port: u16,
    /// Enable load balancing
    pub enable_load_balancing: bool,
    /// Maximum network latency (ms)
    pub max_latency_ms: u64,
    /// Enable encryption
    pub enable_encryption: bool,
}

impl Default for ZKPConfig {
    fn default() -> Self {
        Self {
            proof_systems: ProofSystemConfig::default(),
            security: SecurityConfig::default(),
            performance: PerformanceConfig::default(),
            storage: StorageConfig::default(),
            network: NetworkConfig::default(),
            quantum_resistant: true,
            max_proof_size: 1024 * 1024, // 1MB
            verification_timeout: 300, // 5 minutes
        }
    }
}

impl Default for ProofSystemConfig {
    fn default() -> Self {
        Self {
            enable_snarks: true,
            enable_starks: true,
            enable_bulletproofs: true,
            enable_plonk: true,
            enable_groth16: true,
            default_system: "zk-stark".to_string(),
            snark_config: SnarkConfig::default(),
            stark_config: StarkConfig::default(),
            bulletproof_config: BulletproofConfig::default(),
        }
    }
}

impl Default for SnarkConfig {
    fn default() -> Self {
        Self {
            compilation_timeout: 600, // 10 minutes
            trusted_setup_dir: PathBuf::from("./trusted_setup"),
            universal_setup: true,
            max_circuit_size: 1000000, // 1M constraints
            enable_optimizations: true,
        }
    }
}

impl Default for StarkConfig {
    fn default() -> Self {
        Self {
            field_size: 256,
            security_level: 128,
            hash_function: "blake3".to_string(),
            enable_fri_optimization: true,
            query_complexity: 80,
        }
    }
}

impl Default for BulletproofConfig {
    fn default() -> Self {
        Self {
            max_bit_length: 64,
            enable_batch_verification: true,
            aggregation_factor: 4,
            enable_inner_product_optimization: true,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            min_security_level: 128,
            secure_random: true,
            side_channel_protection: true,
            timing_attack_protection: true,
            key_derivation_iterations: 100000,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            proving_threads: 4,
            verification_threads: 2,
            enable_gpu: false,
            memory_limit_mb: 4096, // 4GB
            enable_caching: true,
            cache_size_mb: 512, // 512MB
            enable_compression: true,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_dir: PathBuf::from("./quid-zkp-data"),
            persistent_storage: true,
            enable_archival: true,
            archival_retention_days: 30,
            enable_compression: true,
            backup_config: BackupConfig::default(),
        }
    }
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: 24,
            max_backups: 7,
            backup_dir: PathBuf::from("./quid-zkp-backups"),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enable_distributed: false,
            coordinator_address: "127.0.0.1".to_string(),
            coordinator_port: 8080,
            enable_load_balancing: true,
            max_latency_ms: 1000,
            enable_encryption: true,
        }
    }
}

impl ZKPConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate security settings
        if self.security.min_security_level < 80 {
            return Err("Minimum security level must be at least 80 bits".to_string());
        }
        
        if self.security.key_derivation_iterations < 10000 {
            return Err("Key derivation iterations must be at least 10,000".to_string());
        }
        
        // Validate performance settings
        if self.performance.proving_threads == 0 {
            return Err("Proving threads must be greater than 0".to_string());
        }
        
        if self.performance.verification_threads == 0 {
            return Err("Verification threads must be greater than 0".to_string());
        }
        
        // Validate proof system settings
        if self.proof_systems.snark_config.max_circuit_size == 0 {
            return Err("Maximum circuit size must be greater than 0".to_string());
        }
        
        if self.proof_systems.stark_config.field_size < 128 {
            return Err("STARK field size must be at least 128 bits".to_string());
        }
        
        // Validate storage settings
        if self.storage.archival_retention_days == 0 {
            return Err("Archival retention period must be greater than 0".to_string());
        }
        
        // Validate network settings
        if self.network.enable_distributed && self.network.coordinator_port == 0 {
            return Err("Coordinator port must be specified for distributed proving".to_string());
        }
        
        Ok(())
    }
    
    /// Get proving timeout
    pub fn proving_timeout(&self) -> Duration {
        Duration::from_secs(self.proof_systems.snark_config.compilation_timeout)
    }
    
    /// Get verification timeout
    pub fn verification_timeout(&self) -> Duration {
        Duration::from_secs(self.verification_timeout)
    }
    
    /// Check if proof system is enabled
    pub fn is_proof_system_enabled(&self, system: &str) -> bool {
        match system {
            "zk-snark" => self.proof_systems.enable_snarks,
            "zk-stark" => self.proof_systems.enable_starks,
            "bulletproof" => self.proof_systems.enable_bulletproofs,
            "plonk" => self.proof_systems.enable_plonk,
            "groth16" => self.proof_systems.enable_groth16,
            _ => false,
        }
    }
    
    /// Get memory limit in bytes
    pub fn memory_limit_bytes(&self) -> u64 {
        self.performance.memory_limit_mb * 1024 * 1024
    }
    
    /// Get cache size in bytes
    pub fn cache_size_bytes(&self) -> u64 {
        self.performance.cache_size_mb * 1024 * 1024
    }
}

// Re-export for convenience
pub use ZKPConfig as Config;

// Convenience getters
impl ZKPConfig {
    pub fn enable_snarks(&self) -> bool {
        self.proof_systems.enable_snarks
    }
    
    pub fn enable_starks(&self) -> bool {
        self.proof_systems.enable_starks
    }
    
    pub fn enable_bulletproofs(&self) -> bool {
        self.proof_systems.enable_bulletproofs
    }
    
    pub fn enable_plonk(&self) -> bool {
        self.proof_systems.enable_plonk
    }
    
    pub fn enable_groth16(&self) -> bool {
        self.proof_systems.enable_groth16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_default_config() {
        let config = ZKPConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.quantum_resistant);
        assert!(config.enable_snarks());
        assert!(config.enable_starks());
        assert!(config.enable_bulletproofs());
    }
    
    #[test]
    fn test_config_serialization() {
        let config = ZKPConfig::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: ZKPConfig = toml::from_str(&serialized).unwrap();
        
        assert_eq!(config.quantum_resistant, deserialized.quantum_resistant);
        assert_eq!(config.max_proof_size, deserialized.max_proof_size);
        assert_eq!(config.verification_timeout, deserialized.verification_timeout);
    }
    
    #[test]
    fn test_config_file_operations() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("zkp_config.toml");
        
        let config = ZKPConfig::default();
        config.save_to_file(&config_path).unwrap();
        
        let loaded_config = ZKPConfig::load_from_file(&config_path).unwrap();
        assert_eq!(config.quantum_resistant, loaded_config.quantum_resistant);
        assert_eq!(config.max_proof_size, loaded_config.max_proof_size);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = ZKPConfig::default();
        
        // Valid configuration
        assert!(config.validate().is_ok());
        
        // Invalid security level
        config.security.min_security_level = 50;
        assert!(config.validate().is_err());
        
        // Fix security level, break threads
        config.security.min_security_level = 128;
        config.performance.proving_threads = 0;
        assert!(config.validate().is_err());
        
        // Fix threads, break circuit size
        config.performance.proving_threads = 4;
        config.proof_systems.snark_config.max_circuit_size = 0;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_convenience_methods() {
        let config = ZKPConfig::default();
        
        assert_eq!(config.proving_timeout(), Duration::from_secs(600));
        assert_eq!(config.verification_timeout(), Duration::from_secs(300));
        assert_eq!(config.memory_limit_bytes(), 4096 * 1024 * 1024);
        assert_eq!(config.cache_size_bytes(), 512 * 1024 * 1024);
        
        assert!(config.is_proof_system_enabled("zk-snark"));
        assert!(config.is_proof_system_enabled("zk-stark"));
        assert!(!config.is_proof_system_enabled("unknown"));
    }
}