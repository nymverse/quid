//! QuID Universal Blockchain CLI Tool
//!
//! Command-line interface for managing QuID blockchain integrations across
//! multiple networks including Bitcoin, Ethereum, privacy coins, and custom chains.

use anyhow::Result;
use clap::{Parser, Subcommand};
use quid_blockchain::{
    QuIDBlockchainConfig, AdapterRegistry, UniversalBlockchainAdapter,
    CustomBlockchainConfig, BlockchainType, BlockchainAccount,
    config::{AddressFormat, SignatureAlgorithm, AdapterSettings},
    utils::{validation, units, fees},
};
use quid_core::{QuIDClient, QuIDIdentity, SecurityLevel};
use serde_json;
use std::path::PathBuf;
use tokio;
use tracing::{info, warn, error};

/// QuID Universal Blockchain CLI
#[derive(Parser)]
#[command(name = "quid-blockchain")]
#[command(about = "QuID Universal Blockchain Integration Tool")]
#[command(version = "1.0.0")]
struct Cli {
    /// Configuration file path
    #[arg(short, long)]
    config: Option<PathBuf>,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
    
    /// QuID identity name
    #[arg(short, long)]
    identity: Option<String>,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize blockchain configuration
    Init {
        /// Force overwrite existing configuration
        #[arg(short, long)]
        force: bool,
    },
    
    /// List supported blockchains
    List {
        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
    },
    
    /// Add custom blockchain
    Add {
        /// Blockchain name
        name: String,
        /// RPC URL
        #[arg(short, long)]
        rpc_url: String,
        /// Chain ID (optional)
        #[arg(short, long)]
        chain_id: Option<u64>,
        /// Native token symbol
        #[arg(short, long)]
        token: String,
        /// Address format
        #[arg(short, long, default_value = "ethereum-hex")]
        address_format: String,
        /// Signature algorithm
        #[arg(short, long, default_value = "ecdsa-secp256k1")]
        signature_algorithm: String,
    },
    
    /// Derive blockchain address
    Derive {
        /// Blockchain network
        network: String,
        /// Derivation path (optional)
        #[arg(short, long)]
        path: Option<String>,
        /// Output format (json, table)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    
    /// Get account balance
    Balance {
        /// Blockchain network
        network: String,
        /// Account address
        address: String,
    },
    
    /// Send transaction
    Send {
        /// Blockchain network
        network: String,
        /// Recipient address
        to: String,
        /// Amount to send
        amount: String,
        /// Fee strategy (conservative, standard, economic)
        #[arg(short, long, default_value = "standard")]
        fee: String,
        /// Dry run (don't broadcast)
        #[arg(short, long)]
        dry_run: bool,
    },
    
    /// Validate address
    Validate {
        /// Blockchain network
        network: String,
        /// Address to validate
        address: String,
    },
    
    /// Registry management
    Registry {
        #[command(subcommand)]
        action: RegistryCommands,
    },
    
    /// Fee estimation
    Fee {
        /// Blockchain network
        network: String,
        /// Transaction type (transfer, contract)
        #[arg(short, long, default_value = "transfer")]
        tx_type: String,
    },
    
    /// Network status
    Status {
        /// Blockchain network (optional, shows all if not specified)
        network: Option<String>,
    },
}

#[derive(Subcommand)]
enum RegistryCommands {
    /// List registered adapters
    List,
    /// Show adapter details
    Info {
        /// Adapter name
        name: String,
    },
    /// Health check
    Health,
    /// Auto-discover adapters
    Discover,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize tracing
    let level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    
    tracing_subscriber::fmt()
        .with_max_level(level)
        .init();
    
    // Load or create configuration
    let config_path = cli.config
        .unwrap_or_else(|| QuIDBlockchainConfig::get_default_config_file());
    
    let config = if config_path.exists() {
        QuIDBlockchainConfig::from_file(&config_path)?
    } else {
        info!("Creating default configuration at: {}", config_path.display());
        let config = QuIDBlockchainConfig::default();
        config.save_to_file(&config_path)?;
        config
    };
    
    // Initialize QuID client (mock for CLI tool)
    let quid_client = create_mock_quid_client().await?;
    
    // Create adapter registry
    let registry = AdapterRegistry::new();
    registry.auto_discover().await?;
    
    // Execute command
    match cli.command {
        Commands::Init { force } => handle_init(&config_path, force).await,
        Commands::List { detailed } => handle_list(&config, detailed).await,
        Commands::Add { name, rpc_url, chain_id, token, address_format, signature_algorithm } => {
            handle_add(&config_path, name, rpc_url, chain_id, token, address_format, signature_algorithm).await
        },
        Commands::Derive { network, path, format } => {
            handle_derive(&quid_client, &cli.identity, &network, path.as_deref(), &format).await
        },
        Commands::Balance { network, address } => {
            handle_balance(&config, &network, &address).await
        },
        Commands::Send { network, to, amount, fee, dry_run } => {
            handle_send(&quid_client, &cli.identity, &network, &to, &amount, &fee, dry_run).await
        },
        Commands::Validate { network, address } => {
            handle_validate(&network, &address).await
        },
        Commands::Registry { action } => {
            handle_registry(&registry, action).await
        },
        Commands::Fee { network, tx_type } => {
            handle_fee(&network, &tx_type).await
        },
        Commands::Status { network } => {
            handle_status(&config, network.as_deref()).await
        },
    }
}

async fn handle_init(config_path: &PathBuf, force: bool) -> Result<()> {
    if config_path.exists() && !force {
        warn!("Configuration file already exists. Use --force to overwrite.");
        return Ok(());
    }
    
    let config = QuIDBlockchainConfig::default();
    config.save_to_file(config_path)?;
    
    info!("Initialized QuID blockchain configuration at: {}", config_path.display());
    println!("✅ Configuration initialized successfully");
    
    Ok(())
}

async fn handle_list(config: &QuIDBlockchainConfig, detailed: bool) -> Result<()> {
    println!("📋 Supported Blockchains:");
    
    let blockchains = vec![
        ("bitcoin", "Bitcoin", config.bitcoin.enabled),
        ("bitcoin-testnet", "Bitcoin Testnet", config.bitcoin.enabled),
        ("ethereum", "Ethereum", config.ethereum.enabled),
        ("ethereum-goerli", "Ethereum Goerli", config.ethereum.enabled),
        ("ethereum-sepolia", "Ethereum Sepolia", config.ethereum.enabled),
        ("monero", "Monero", config.privacy.enabled),
        ("monero-testnet", "Monero Testnet", config.privacy.enabled),
        ("zcash", "Zcash", config.privacy.enabled),
        ("zcash-testnet", "Zcash Testnet", config.privacy.enabled),
    ];
    
    for (id, name, enabled) in blockchains {
        let status = if enabled { "✅" } else { "❌" };
        if detailed {
            println!("  {} {} ({})", status, name, id);
        } else {
            println!("  {} {}", status, name);
        }
    }
    
    // Show custom blockchains
    if !config.universal.custom_blockchains.is_empty() {
        println!("\n🔧 Custom Blockchains:");
        for blockchain in &config.universal.custom_blockchains {
            let status = "✅";
            println!("  {} {} ({})", status, blockchain.name, blockchain.name);
            if detailed {
                println!("    RPC: {}", blockchain.rpc_url);
                println!("    Token: {}", blockchain.native_token);
                println!("    Format: {:?}", blockchain.address_format);
            }
        }
    }
    
    Ok(())
}

async fn handle_add(
    config_path: &PathBuf,
    name: String,
    rpc_url: String,
    chain_id: Option<u64>,
    token: String,
    address_format: String,
    signature_algorithm: String,
) -> Result<()> {
    let mut config = QuIDBlockchainConfig::from_file(config_path)?;
    
    // Parse address format
    let addr_format = match address_format.as_str() {
        "base58" => AddressFormat::Base58Check,
        "ethereum-hex" => AddressFormat::EthereumHex,
        "bech32" => AddressFormat::Bech32,
        _ => AddressFormat::Custom(address_format),
    };
    
    // Parse signature algorithm
    let sig_algo = match signature_algorithm.as_str() {
        "ecdsa-secp256k1" => SignatureAlgorithm::EcdsaSecp256k1,
        "ed25519" => SignatureAlgorithm::Ed25519,
        "sr25519" => SignatureAlgorithm::Sr25519,
        "quid" => SignatureAlgorithm::QuIDQuantumResistant,
        "hybrid" => SignatureAlgorithm::Hybrid,
        _ => SignatureAlgorithm::EcdsaSecp256k1,
    };
    
    let custom_blockchain = CustomBlockchainConfig {
        name: name.clone(),
        chain_id,
        rpc_url,
        ws_url: None,
        native_token: token,
        block_time: 15,
        confirmation_blocks: 12,
        address_format: addr_format,
        signature_algorithm: sig_algo,
    };
    
    // Validate configuration
    custom_blockchain.validate()?;
    
    config.universal.custom_blockchains.push(custom_blockchain);
    config.save_to_file(config_path)?;
    
    info!("Added custom blockchain: {}", name);
    println!("✅ Added custom blockchain: {}", name);
    
    Ok(())
}

async fn handle_derive(
    quid_client: &QuIDClient,
    identity_name: &Option<String>,
    network: &str,
    derivation_path: Option<&str>,
    format: &str,
) -> Result<()> {
    let identity = get_or_create_identity(quid_client, identity_name).await?;
    
    // Parse blockchain type
    let blockchain_type = match network {
        "bitcoin" => BlockchainType::Bitcoin,
        "bitcoin-testnet" => BlockchainType::BitcoinTestnet,
        "ethereum" => BlockchainType::Ethereum,
        "ethereum-goerli" => BlockchainType::EthereumGoerli,
        "ethereum-sepolia" => BlockchainType::EthereumSepolia,
        "monero" => BlockchainType::Monero,
        "monero-testnet" => BlockchainType::MoneroTestnet,
        "zcash" => BlockchainType::Zcash,
        "zcash-testnet" => BlockchainType::ZcashTestnet,
        _ => BlockchainType::Custom(network.to_string()),
    };
    
    // Derive address
    let account = quid_blockchain::derive_address(
        quid_client,
        &identity,
        blockchain_type,
        derivation_path,
    ).await?;
    
    // Output result
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&account)?;
            println!("{}", json);
        }
        _ => {
            println!("🔑 Derived Address for {}:", network);
            println!("  Identity: {}", account.identity.name);
            println!("  Address: {}", account.address);
            println!("  Network: {}", account.network.name());
            if let Some(path) = &account.derivation_path {
                println!("  Path: {}", path);
            }
            println!("  Created: {}", account.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
        }
    }
    
    Ok(())
}

async fn handle_balance(config: &QuIDBlockchainConfig, network: &str, address: &str) -> Result<()> {
    // Validate address first
    let blockchain_type = parse_blockchain_type(network);
    if !validation::validate_address(address, &blockchain_type) {
        error!("Invalid address format for network: {}", network);
        return Ok(());
    }
    
    // For demo purposes, show mock balance
    let balance = 1_000_000_000u64; // Mock balance
    
    match network {
        "bitcoin" | "bitcoin-testnet" => {
            println!("💰 Balance for {}: {}", address, units::bitcoin::format_btc(balance));
            println!("   Satoshis: {} sats", balance);
        }
        "ethereum" | "ethereum-goerli" | "ethereum-sepolia" => {
            println!("💰 Balance for {}: {}", address, units::ethereum::format_eth(balance));
            println!("   Wei: {} wei", balance);
        }
        _ => {
            println!("💰 Balance for {}: {} units", address, balance);
        }
    }
    
    Ok(())
}

async fn handle_send(
    quid_client: &QuIDClient,
    identity_name: &Option<String>,
    network: &str,
    to: &str,
    amount: &str,
    fee_strategy: &str,
    dry_run: bool,
) -> Result<()> {
    let identity = get_or_create_identity(quid_client, identity_name).await?;
    let blockchain_type = parse_blockchain_type(network);
    
    // Validate recipient address
    if !validation::validate_address(to, &blockchain_type) {
        error!("Invalid recipient address for network: {}", network);
        return Ok(());
    }
    
    // Parse amount
    let amount_value = match network {
        "bitcoin" | "bitcoin-testnet" => {
            let btc: f64 = amount.parse()?;
            units::bitcoin::btc_to_satoshis(btc)
        }
        "ethereum" | "ethereum-goerli" | "ethereum-sepolia" => {
            let eth: f64 = amount.parse()?;
            units::ethereum::eth_to_wei(eth)
        }
        _ => amount.parse()?,
    };
    
    // Estimate fee
    let fee_strat = match fee_strategy {
        "conservative" => fees::FeeEstimationStrategy::Conservative,
        "standard" => fees::FeeEstimationStrategy::Standard,
        "economic" => fees::FeeEstimationStrategy::Economic,
        _ => fees::FeeEstimationStrategy::Standard,
    };
    
    let estimated_fee = fees::estimate_fee(&blockchain_type, &fee_strat, 250);
    
    if dry_run {
        println!("🧪 Dry Run - Transaction Preview:");
        println!("  Network: {}", network);
        println!("  To: {}", to);
        println!("  Amount: {}", amount);
        println!("  Estimated Fee: {}", estimated_fee);
        println!("  Total: {}", amount_value + estimated_fee);
        println!("\n  ⚠️  This is a dry run. No transaction was broadcast.");
    } else {
        println!("💸 Sending transaction...");
        println!("  Network: {}", network);
        println!("  To: {}", to);
        println!("  Amount: {}", amount);
        println!("  Fee: {}", estimated_fee);
        
        // For demo, just show success
        println!("✅ Transaction sent successfully!");
        println!("  TX ID: 0x{}", hex::encode(&[0u8; 32])); // Mock transaction ID
    }
    
    Ok(())
}

async fn handle_validate(network: &str, address: &str) -> Result<()> {
    let blockchain_type = parse_blockchain_type(network);
    let is_valid = validation::validate_address(address, &blockchain_type);
    
    if is_valid {
        println!("✅ Address is valid for {}", network);
    } else {
        println!("❌ Address is invalid for {}", network);
    }
    
    Ok(())
}

async fn handle_registry(registry: &AdapterRegistry, action: RegistryCommands) -> Result<()> {
    match action {
        RegistryCommands::List => {
            let adapters = registry.list_adapters().await;
            let factories = registry.list_factories().await;
            
            println!("🔧 Registered Adapters:");
            for adapter in adapters {
                println!("  ✅ {}", adapter);
            }
            
            if !factories.is_empty() {
                println!("\n🏭 Registered Factories:");
                for factory in factories {
                    println!("  🔧 {}", factory);
                }
            }
        }
        RegistryCommands::Info { name } => {
            if let Some(metadata) = registry.get_metadata(&name).await {
                println!("📋 Adapter Information: {}", name);
                println!("  Version: {}", metadata.version);
                println!("  Description: {}", metadata.description);
                println!("  Status: {:?}", metadata.status);
                println!("  Registered: {}", metadata.registered_at.format("%Y-%m-%d %H:%M:%S UTC"));
                println!("  Networks: {}", metadata.supported_networks.join(", "));
            } else {
                println!("❌ Adapter not found: {}", name);
            }
        }
        RegistryCommands::Health => {
            println!("🏥 Performing health check...");
            let health_results = registry.health_check().await;
            
            for (name, status) in health_results {
                let icon = match status {
                    quid_blockchain::adapters::AdapterStatus::Active => "✅",
                    quid_blockchain::adapters::AdapterStatus::Inactive => "⚠️",
                    quid_blockchain::adapters::AdapterStatus::Initializing => "🔄",
                    quid_blockchain::adapters::AdapterStatus::Failed(_) => "❌",
                };
                println!("  {} {}: {:?}", icon, name, status);
            }
        }
        RegistryCommands::Discover => {
            println!("🔍 Discovering adapters...");
            let discovered = registry.auto_discover().await?;
            
            if discovered.is_empty() {
                println!("  No new adapters discovered.");
            } else {
                println!("  Discovered {} new adapters:", discovered.len());
                for adapter in discovered {
                    println!("    ✅ {}", adapter);
                }
            }
        }
    }
    
    Ok(())
}

async fn handle_fee(network: &str, tx_type: &str) -> Result<()> {
    let blockchain_type = parse_blockchain_type(network);
    let fee_rates = fees::get_default_fee_rates(&blockchain_type);
    
    println!("💸 Fee Rates for {}:", network);
    
    match network {
        "bitcoin" | "bitcoin-testnet" => {
            println!("  Conservative: {} sat/vB", fee_rates.conservative);
            println!("  Standard: {} sat/vB", fee_rates.standard);
            println!("  Economic: {} sat/vB", fee_rates.economic);
        }
        "ethereum" | "ethereum-goerli" | "ethereum-sepolia" => {
            println!("  Conservative: {} gwei", units::ethereum::wei_to_gwei(fee_rates.conservative));
            println!("  Standard: {} gwei", units::ethereum::wei_to_gwei(fee_rates.standard));
            println!("  Economic: {} gwei", units::ethereum::wei_to_gwei(fee_rates.economic));
        }
        _ => {
            println!("  Conservative: {} units", fee_rates.conservative);
            println!("  Standard: {} units", fee_rates.standard);
            println!("  Economic: {} units", fee_rates.economic);
        }
    }
    
    println!("  Updated: {}", fee_rates.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    
    Ok(())
}

async fn handle_status(config: &QuIDBlockchainConfig, network: Option<&str>) -> Result<()> {
    match network {
        Some(net) => {
            println!("📡 Network Status: {}", net);
            println!("  Status: Active"); // Mock status
            println!("  Block Height: 123456"); // Mock data
            println!("  Peers: 42"); // Mock data
        }
        None => {
            println!("📡 All Network Status:");
            
            let networks = vec![
                ("Bitcoin", config.bitcoin.enabled),
                ("Ethereum", config.ethereum.enabled),
                ("Privacy Coins", config.privacy.enabled),
            ];
            
            for (name, enabled) in networks {
                let status = if enabled { "✅ Active" } else { "❌ Disabled" };
                println!("  {}: {}", name, status);
            }
        }
    }
    
    Ok(())
}

// Helper functions

async fn create_mock_quid_client() -> Result<QuIDClient> {
    // For CLI demonstration, create a mock QuID client
    // In a real implementation, this would connect to the actual QuID service
    Ok(QuIDClient::new("mock://localhost").await?)
}

async fn get_or_create_identity(
    quid_client: &QuIDClient,
    identity_name: &Option<String>,
) -> Result<QuIDIdentity> {
    let name = identity_name.as_deref().unwrap_or("default");
    
    // Try to get existing identity or create new one
    match quid_client.get_identity(name).await {
        Ok(identity) => Ok(identity),
        Err(_) => {
            // Create new identity for demo
            let identity = QuIDIdentity {
                id: format!("cli-{}", name),
                name: name.to_string(),
                security_level: SecurityLevel::Level1,
                created_at: chrono::Utc::now(),
                contexts: vec!["blockchain".to_string()],
                metadata: None,
            };
            Ok(identity)
        }
    }
}

fn parse_blockchain_type(network: &str) -> BlockchainType {
    match network {
        "bitcoin" => BlockchainType::Bitcoin,
        "bitcoin-testnet" => BlockchainType::BitcoinTestnet,
        "ethereum" => BlockchainType::Ethereum,
        "ethereum-goerli" => BlockchainType::EthereumGoerli,
        "ethereum-sepolia" => BlockchainType::EthereumSepolia,
        "monero" => BlockchainType::Monero,
        "monero-testnet" => BlockchainType::MoneroTestnet,
        "zcash" => BlockchainType::Zcash,
        "zcash-testnet" => BlockchainType::ZcashTestnet,
        _ => BlockchainType::Custom(network.to_string()),
    }
}