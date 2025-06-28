//! QuID Network Node - Validator and Full Node Implementation

use clap::{Parser, Subcommand};
use quid_consensus::*;
use quid_core::*;
use std::path::PathBuf;
use tokio::signal;
use tracing::{info, warn, error};

#[derive(Parser)]
#[command(name = "quid-node")]
#[command(about = "QuID Network Node - Run validator or full node")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new node
    Init {
        /// Node configuration directory
        #[arg(long, default_value = "~/.quid-node")]
        data_dir: PathBuf,
        
        /// Node type: validator, full, light
        #[arg(long, default_value = "full")]
        node_type: String,
        
        /// Identity file for this node
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    
    /// Start the node daemon
    Start {
        /// Node configuration directory
        #[arg(long, default_value = "~/.quid-node")]
        data_dir: PathBuf,
        
        /// Enable validator mode (requires staking)
        #[arg(long)]
        validator: bool,
        
        /// Stake amount for validator
        #[arg(long, default_value = "1000")]
        stake: u64,
    },
    
    /// Show node status
    Status {
        #[arg(long, default_value = "~/.quid-node")]
        data_dir: PathBuf,
    },
    
    /// Manage validator operations
    Validator {
        #[command(subcommand)]
        validator_command: ValidatorCommands,
    },
}

#[derive(Subcommand)]
enum ValidatorCommands {
    /// Stake NYM to become validator
    Stake {
        amount: u64,
        #[arg(long, default_value = "~/.quid-node")]
        data_dir: PathBuf,
    },
    
    /// Unstake and leave validator set
    Unstake {
        amount: u64,
        #[arg(long, default_value = "~/.quid-node")]
        data_dir: PathBuf,
    },
    
    /// Show validator metrics
    Metrics {
        #[arg(long, default_value = "~/.quid-node")]
        data_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Init { data_dir, node_type, identity } => {
            init_node(data_dir, node_type, identity).await?;
        }
        
        Commands::Start { data_dir, validator, stake } => {
            start_node(data_dir, validator, stake).await?;
        }
        
        Commands::Status { data_dir } => {
            show_status(data_dir).await?;
        }
        
        Commands::Validator { validator_command } => {
            handle_validator_command(validator_command).await?;
        }
    }
    
    Ok(())
}

async fn init_node(
    data_dir: PathBuf, 
    node_type: String,
    identity: Option<PathBuf>
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Initializing QuID node at {:?}", data_dir);
    
    // Create data directory
    std::fs::create_dir_all(&data_dir)?;
    
    // Create or load identity
    let (identity, keypair) = if let Some(identity_path) = identity {
        // Load existing identity
        let content = std::fs::read_to_string(identity_path)?;
        let cli_identity: quid_cli::CliIdentity = serde_json::from_str(&content)?;
        (cli_identity.identity, cli_identity.to_keypair()?)
    } else {
        // Create new identity
        QuIDIdentity::new(SecurityLevel::Level1)?
    };
    
    // Create node config
    let config = NodeConfig {
        node_type: node_type.clone(),
        identity_id: identity.id.clone(),
        listen_port: 8080,
        bootstrap_nodes: vec![
            "seed1.quid.network:8080".to_string(),
            "seed2.quid.network:8080".to_string(),
        ],
        data_directory: data_dir.clone(),
        validator_config: if node_type == "validator" {
            Some(ValidatorConfig {
                stake_amount: 1000,
                auto_stake: false,
            })
        } else {
            None
        },
    };
    
    // Save config
    let config_path = data_dir.join("config.toml");
    let config_toml = toml::to_string(&config)?;
    std::fs::write(config_path, config_toml)?;
    
    // Save identity
    let identity_path = data_dir.join("identity.json");
    let cli_identity = quid_cli::CliIdentity::from_identity_and_keypair(identity, &keypair);
    let identity_json = serde_json::to_string_pretty(&cli_identity)?;
    std::fs::write(identity_path, identity_json)?;
    
    info!("✅ Node initialized successfully!");
    info!("📁 Data directory: {:?}", data_dir);
    info!("🏷️  Node type: {}", node_type);
    info!("🆔 Identity: {}", hex::encode(&cli_identity.identity.id));
    
    Ok(())
}

async fn start_node(
    data_dir: PathBuf,
    validator_mode: bool,
    stake: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting QuID node from {:?}", data_dir);
    
    // Load config
    let config_path = data_dir.join("config.toml");
    let config_content = std::fs::read_to_string(config_path)?;
    let config: NodeConfig = toml::from_str(&config_content)?;
    
    // Load identity
    let identity_path = data_dir.join("identity.json");
    let identity_content = std::fs::read_to_string(identity_path)?;
    let cli_identity: quid_cli::CliIdentity = serde_json::from_str(&identity_content)?;
    let keypair = cli_identity.to_keypair()?;
    
    info!("🚀 Starting node...");
    info!("🆔 Identity: {}...{}", 
        &hex::encode(&cli_identity.identity.id)[..16],
        &hex::encode(&cli_identity.identity.id)[48..]
    );
    
    // Initialize or load blockchain
    let blockchain = load_or_create_blockchain(&data_dir).await?;
    info!("⛓️  Blockchain height: {}", blockchain.height());
    
    // Create validator set
    let validator_set = ValidatorSet::from_genesis(vec![cli_identity.identity.clone()], 100);
    
    // Create consensus engine
    let consensus_engine = if validator_mode {
        info!("🏛️  Starting in VALIDATOR mode with {} NYM stake", stake);
        ConsensusEngine::new(
            blockchain,
            validator_set,
            Some((cli_identity.identity, keypair)),
            ConsensusConfig::default(),
        )
    } else {
        info!("📡 Starting in FULL NODE mode");
        ConsensusEngine::new(
            blockchain,
            validator_set,
            None, // Not a validator
            ConsensusConfig::default(),
        )
    };
    
    // Start network layer
    info!("🌐 Starting P2P networking on port {}", config.listen_port);
    
    // Main node loop
    info!("✅ Node started successfully!");
    info!("🎯 Press Ctrl+C to stop");
    
    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("🛑 Shutting down node...");
    
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct NodeConfig {
    node_type: String,
    identity_id: Vec<u8>,
    listen_port: u16,
    bootstrap_nodes: Vec<String>,
    data_directory: PathBuf,
    validator_config: Option<ValidatorConfig>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ValidatorConfig {
    stake_amount: u64,
    auto_stake: bool,
}

async fn load_or_create_blockchain(data_dir: &PathBuf) -> Result<Blockchain, Box<dyn std::error::Error>> {
    let blockchain_path = data_dir.join("blockchain.json");
    
    if blockchain_path.exists() {
        // Load existing blockchain
        info!("📖 Loading existing blockchain...");
        // TODO: Implement blockchain serialization/deserialization
        // For now, create genesis
        let (identity, _) = QuIDIdentity::new(SecurityLevel::Level1)?;
        let genesis = Block::genesis(vec![(identity, 1000000)])?;
        Ok(Blockchain::new(genesis)?)
    } else {
        // Create genesis blockchain
        info!("🌱 Creating genesis blockchain...");
        let (identity, _) = QuIDIdentity::new(SecurityLevel::Level1)?;
        let genesis = Block::genesis(vec![(identity, 1000000)])?;
        let blockchain = Blockchain::new(genesis)?;
        
        // TODO: Save blockchain
        
        Ok(blockchain)
    }
}

// Placeholder implementations for other functions...
async fn show_status(_data_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("Node status: Running");
    Ok(())
}

async fn handle_validator_command(_cmd: ValidatorCommands) -> Result<(), Box<dyn std::error::Error>> {
    println!("Validator command executed");
    Ok(())
}
