//! Network privacy enhancements for QuID
//!
//! This module provides advanced privacy features for network communications
//! including Tor integration, traffic obfuscation, anonymous relay systems,
//! and decentralized mixnet integration.
//!
//! License: 0BSD

pub mod tor;
pub mod obfuscation;
pub mod relay;
pub mod mixnet;
pub mod privacy;

pub use tor::TorProxy;
pub use obfuscation::TrafficObfuscator;
pub use relay::AnonymousRelay;
pub use mixnet::MixnetRouter;
pub use privacy::NetworkPrivacyManager;