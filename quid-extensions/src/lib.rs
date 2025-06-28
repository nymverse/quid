//! QuID Network Adapter Framework
//! 
//! This crate provides the network adapter architecture for QuID identities,
//! enabling universal authentication across different networks and protocols.

pub mod adapter;
pub mod registry;
pub mod key_derivation;
pub mod error;
pub mod adapters;

// Re-export main types
pub use adapter::{NetworkAdapter, AuthenticationRequest, AuthenticationResponse, NetworkKeys};
pub use registry::{AdapterRegistry, InitializationReport, ShutdownReport, MonitoringReport, AdapterMetrics, RegistryStatistics};
pub use key_derivation::{KeyDerivation, DerivedKeys, HmacKeyDerivation};
pub use error::{AdapterError, AdapterResult};
pub use adapters::{WebAdapter, SshAdapter, GenericAdapter};

/// QuID Extensions version
pub const VERSION: &str = "0.1.0";

/// Default timeout for adapter operations (in milliseconds)
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(VERSION, "0.1.0");
    }
}