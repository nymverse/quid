//! Basic network adapter implementations
//! 
//! This module contains concrete implementations of the NetworkAdapter trait
//! for common networks and protocols.

pub mod web;
pub mod ssh;
pub mod generic;

// Re-export adapter implementations
pub use web::WebAdapter;
pub use ssh::SshAdapter;
pub use generic::GenericAdapter;