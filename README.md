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
- **quid-ssh**: SSH client and server integration with QuID authentication
- **quid-tls**: TLS/PKI integration with X.509 certificates and quantum-resistant signatures
- **quid-blockchain**: Comprehensive blockchain integration supporting Bitcoin, Ethereum, privacy coins, and universal blockchain adapter framework

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
- **Blockchain Adapters**: Bitcoin, Ethereum, Monero, Zcash, and Universal blockchain support
- **System Integration**: SSH authentication, TLS/PKI certificate management
- **Privacy Coins**: Enhanced privacy features for Monero and Zcash with stealth addresses
- **Universal Framework**: Generic adapter for any blockchain or protocol
- **Web Authentication**: WebAuthn-compatible web browser integration

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

### Blockchain Integration Example

```rust
use quid_blockchain::{derive_address, sign_transaction, BlockchainType};
use quid_core::QuIDClient;

// Initialize QuID client
let quid_client = QuIDClient::new("config.toml").await?;
let identity = quid_client.get_identity("my-identity").await?;

// Derive Bitcoin address
let bitcoin_account = derive_address(
    &quid_client,
    &identity,
    BlockchainType::Bitcoin,
    Some("m/44'/0'/0'/0/0"), // BIP44 derivation path
).await?;

println!("Bitcoin address: {}", bitcoin_account.address);

// Derive Ethereum address  
let ethereum_account = derive_address(
    &quid_client,
    &identity,
    BlockchainType::Ethereum,
    None,
).await?;

println!("Ethereum address: {}", ethereum_account.address);

// Sign a Bitcoin transaction
let mut transaction = create_bitcoin_transaction(
    &bitcoin_account,
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    50000, // satoshis
)?;

let signature = sign_transaction(&quid_client, &identity, &mut transaction).await?;
```

### Privacy Coin Integration

```rust
use quid_blockchain::privacy::{MoneroAdapter, ZcashAdapter};

// Monero with ring signatures and stealth addresses
let monero_adapter = MoneroAdapter::new(privacy_config).await?;
let stealth_address = monero_adapter.generate_stealth_address(
    &quid_client,
    &identity,
    current_block_height,
).await?;

// Zcash with shielded transactions
let zcash_adapter = ZcashAdapter::new(privacy_config).await?;
let shielded_transaction = zcash_adapter.create_shielded_transaction(
    &quid_client,
    &identity,
    &inputs,
    &outputs,
).await?;
```

## CLI Tools

QuID provides comprehensive command-line tools for blockchain integration:

### Universal Blockchain CLI

```bash
# Initialize blockchain configuration
quid-blockchain init

# List supported blockchains
quid-blockchain list --detailed

# Add custom blockchain
quid-blockchain add polygon \
  --rpc-url https://polygon-rpc.com \
  --chain-id 137 \
  --token MATIC \
  --address-format ethereum-hex

# Derive addresses for any supported blockchain
quid-blockchain derive bitcoin --identity my-wallet
quid-blockchain derive ethereum --identity my-wallet
quid-blockchain derive monero --identity privacy-wallet

# Check balances
quid-blockchain balance bitcoin 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# Send transactions with quantum-resistant signatures
quid-blockchain send ethereum \
  --to 0x742C3cF9bF1bD96C6d0cC8B2A5d4bbf8b8C8A3F8 \
  --amount 0.1 \
  --fee standard

# Validate addresses
quid-blockchain validate bitcoin 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# Registry management
quid-blockchain registry list
quid-blockchain registry health
quid-blockchain registry discover
```

### SSH Integration CLI

```bash
# SSH client with QuID authentication
quid-ssh client connect user@server.com --identity my-ssh-key

# SSH server with QuID authentication
quid-ssh server start --port 2222 --identity server-key

# Certificate authority management
quid-ssh ca create --identity ca-root --validity-days 365
quid-ssh ca issue --ca ca-root --identity client-cert --subject "CN=client"

# Migrate from legacy SSH keys
quid-ssh migrate --legacy-key ~/.ssh/id_rsa --identity my-quid-key
```

### TLS/PKI Management CLI

```bash
# Generate quantum-resistant X.509 certificates
quid-tls cert generate --identity web-server \
  --subject "CN=example.com" \
  --validity-days 365

# PKI management
quid-tls pki create-ca --identity root-ca --subject "CN=Root CA"
quid-tls pki issue --ca root-ca --identity server-cert \
  --subject "CN=server.example.com"

# Certificate chain verification
quid-tls verify --cert server-cert --ca-bundle ca-certs.pem
```

## Project Status

This project is in active development. See [docs/roadmap.md](docs/roadmap.md) for detailed development phases and milestones.

### Current Status (Phases 1-3)
- ✅ Core cryptographic framework with ML-DSA signatures
- ✅ Identity creation and management
- ✅ Network adapter architecture
- ✅ SSH client and server integration with certificate authority
- ✅ TLS/PKI integration with X.509 quantum-resistant certificates
- ✅ Bitcoin integration with address derivation and transaction signing
- ✅ Ethereum integration with EVM transaction support and smart contracts
- ✅ Privacy coins integration (Monero ring signatures, Zcash shielded transactions)
- ✅ Universal blockchain adapter framework for any blockchain protocol
- ✅ Comprehensive CLI tools and configuration management
- 🚧 Cryptocurrency infrastructure and exchange integration
- 🚧 Enterprise SSO and Zero Trust architecture

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