# QuID - Quantum-resistant Universal Identity Protocol

A nomadic authentication and digital signing system designed to replace traditional login mechanisms across all digital platforms with quantum-resistant cryptography.

## Overview

QuID (Quantum-resistant Universal Identity Protocol) provides a single, quantum-resistant identity that can authenticate to any system - from cryptocurrency wallets to web applications, from SSH servers to mobile apps. The protocol operates offline-first, enabling users to carry their identity and authenticate anywhere, even without network connectivity.

### Key Features

- **Universal Authentication**: Single identity for all platforms and services
- **Quantum-Resistant**: Uses NIST-standardized post-quantum cryptography (ML-DSA, ML-KEM, SHAKE256)
- **Offline-First**: Works completely without network connectivity
- **Network Agnostic**: Supports any blockchain, protocol, or application through adapters
- **Zero Dependencies**: No centralized servers, internet connectivity, or trusted third parties required
- **Cross-Platform**: Consistent authentication across desktop, web, and mobile platforms

## Architecture

QuID consists of three main components:

### Core Components

- **quid-core**: Core identity management and quantum-resistant cryptography
- **quid-cli**: Command-line interface for identity management and authentication
- **quid-extensions**: Network adapters for various platforms (Bitcoin, Ethereum, SSH, Web, etc.)

### Network Adapter System

QuID uses a modular adapter architecture to support any network or protocol:

```rust
trait NetworkAdapter {
    fn network_id(&self) -> &str;
    fn generate_keys(&self, master_key: &MLDSAKey) -> Result<NetworkKeys>;
    fn sign_challenge(&self, challenge: &[u8], keys: &NetworkKeys) -> Result<Signature>;
    fn verify_signature(&self, signature: &Signature, public_key: &PublicKey) -> Result<bool>;
    fn format_address(&self, public_key: &PublicKey) -> Result<String>;
}
```

Current adapters include:
- Generic adapter for custom protocols
- SSH authentication adapter  
- Web authentication adapter (WebAuthn-compatible)

## Installation

### Prerequisites

- Rust 1.70+ with stable toolchain
- Git

### Building from Source

```bash
git clone https://github.com/nymverse/quid.git
cd quid
cargo build --release
```

### Running Tests

```bash
cargo test
```

### Benchmarks

```bash
cargo bench
```

## Quick Start

### Creating a QuID Identity

```bash
# Create new identity
./target/release/quid-cli create-identity

# View identity information
./target/release/quid-cli show-identity
```

### Authentication Example

```rust
use quid_core::{QuIDIdentity, SecurityLevel};
use quid_extensions::{AdapterRegistry, AuthenticationRequest, AuthContext};

// Create or load identity
let identity = QuIDIdentity::new(SecurityLevel::Level1)?;

// Set up adapter registry
let mut registry = AdapterRegistry::new();
registry.register_default_adapters();

// Authenticate to a web service
let auth_request = AuthenticationRequest {
    challenge: web_app.generate_challenge(),
    context: AuthContext {
        network_type: "web".to_string(),
        application_id: "myapp.com".to_string(),
        required_capabilities: vec!["authenticate".to_string()],
    },
    timestamp: current_timestamp(),
};

let response = registry.authenticate(auth_request)?;
web_app.verify_and_login(response)?;
```

## Project Status

This project is in active development. See [docs/roadmap.md](docs/roadmap.md) for detailed development phases and milestones.

### Current Status (Phase 1)
- ✅ Core cryptographic framework with ML-DSA signatures
- ✅ Identity creation and management
- ✅ Network adapter architecture
- ✅ Basic adapters (Generic, SSH, Web)
- 🚧 Encrypted storage and recovery mechanisms
- 🚧 Comprehensive testing and documentation

## Documentation

- [Whitepaper](docs/whitepaper.md) - Complete technical specification and protocol design
- [Roadmap](docs/roadmap.md) - Development phases and milestones
- [Examples](examples/) - Code examples and integration guides

## Security

QuID uses only NIST-standardized post-quantum cryptographic algorithms:

- **ML-DSA (FIPS 204)**: Primary signature scheme
- **ML-KEM (FIPS 203)**: Key encapsulation when needed  
- **SHAKE256**: All hashing and key derivation
- **SLH-DSA (FIPS 205)**: Backup signature scheme

### Security Features

- Memory protection with secure deletion (`zeroize`)
- Constant-time operations to prevent timing attacks
- Hardware security module integration support
- Social recovery mechanisms
- Key rotation and versioning

## Contributing

We welcome contributions! Please read our contributing guidelines and code of conduct.

### Development Setup

```bash
# Clone repository
git clone https://github.com/nymverse/quid.git
cd quid

# Install development dependencies
cargo install cargo-audit cargo-deny

# Run security audit
cargo audit

# Run all checks
./scripts/test.sh
```

## License

This project is licensed under [LICENSE](LICENSE).

## Contact

For questions, suggestions, or security issues, please contact the development team through the project's issue tracker.

---

**⚠️ Security Notice**: This software is in development and has not undergone formal security audits. Do not use in production environments without proper security review.