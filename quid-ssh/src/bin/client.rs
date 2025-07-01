//! QuID SSH Client CLI
//!
//! Command-line interface for QuID SSH client functionality.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use quid_core::QuIDClient;
use quid_ssh::{
    config::{QuIDSSHConfig, ConfigManager},
    client::{QuIDSSHClient, ConnectionInfo},
    keys::{QuIDSSHKey, KeyConversion},
    QuIDSSHResult,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "quid-ssh-client",
    about = "QuID SSH Client - Quantum-resistant SSH authentication",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Configuration file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// QuID client data directory
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to an SSH server
    Connect {
        /// Server address (host:port)
        address: String,
        /// Username for authentication
        #[arg(short, long)]
        username: Option<String>,
        /// QuID identity to use
        #[arg(short, long)]
        identity: Option<String>,
        /// Command to execute (instead of interactive session)
        #[arg(short, long)]
        command: Option<String>,
        /// Use interactive identity selection
        #[arg(short = 'I', long)]
        interactive: bool,
    },
    /// List available QuID identities
    ListIdentities,
    /// Generate SSH public key from QuID identity
    KeyGen {
        /// QuID identity name
        identity: String,
        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Test connection to server
    Test {
        /// Server address (host:port)
        address: String,
    },
    /// Export QuID identity as SSH key pair
    Export {
        /// QuID identity name
        identity: String,
        /// Output directory
        #[arg(short, long)]
        output_dir: PathBuf,
    },
    /// Import SSH key as QuID identity
    Import {
        /// SSH public key file path
        ssh_key: PathBuf,
        /// New identity name
        #[arg(short, long)]
        name: String,
    },
    /// Show configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    Show,
    /// Create example configuration
    Init {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate configuration
    Validate,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("quid_ssh={},quid_core={}", log_level, log_level))
        .init();

    // Load configuration
    let config = if let Some(config_path) = cli.config {
        QuIDSSHConfig::load_from_file(&config_path)
            .context("Failed to load configuration file")?
    } else {
        QuIDSSHConfig::load_default()
            .context("Failed to load default configuration")?
    };

    info!("QuID SSH Client starting");

    // Initialize QuID client
    let quid_config = quid_core::QuIDConfig {
        data_directory: cli.data_dir,
        ..Default::default()
    };
    let quid_client = Arc::new(
        QuIDClient::new(quid_config)
            .context("Failed to initialize QuID client")?
    );

    // Execute command
    let result = match cli.command {
        Commands::Connect {
            address,
            username,
            identity,
            command,
            interactive,
        } => {
            handle_connect(
                quid_client,
                &config,
                &address,
                username.as_deref(),
                identity.as_deref(),
                command.as_deref(),
                interactive,
            )
            .await
        }
        Commands::ListIdentities => handle_list_identities(quid_client).await,
        Commands::KeyGen { identity, output } => {
            handle_keygen(quid_client, &identity, output.as_deref()).await
        }
        Commands::Test { address } => handle_test(quid_client, &config, &address).await,
        Commands::Export {
            identity,
            output_dir,
        } => handle_export(quid_client, &identity, &output_dir).await,
        Commands::Import { ssh_key, name } => {
            handle_import(quid_client, &ssh_key, &name).await
        }
        Commands::Config { action } => handle_config(&config, action).await,
    };

    if let Err(e) = result {
        error!("Command failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

async fn handle_connect(
    quid_client: Arc<QuIDClient>,
    config: &QuIDSSHConfig,
    address: &str,
    username: Option<&str>,
    identity_name: Option<&str>,
    command: Option<&str>,
    interactive: bool,
) -> Result<()> {
    let addr: SocketAddr = address.parse()
        .context("Invalid server address format")?;

    let username = username
        .or(config.client.default_username.as_deref())
        .or_else(|| std::env::var("USER").ok().as_deref())
        .context("Username not specified and could not be determined")?;

    let ssh_config = config.to_ssh_client_config();
    let ssh_client = QuIDSSHClient::new(quid_client.clone(), ssh_config);

    let mut session = if interactive || identity_name.is_none() {
        info!("Using interactive identity selection");
        ssh_client.connect_interactive(addr, username).await?
    } else {
        let identity_name = identity_name.unwrap();
        let identities = quid_client.list_identities().await?;
        let identity = identities
            .iter()
            .find(|id| id.name == identity_name)
            .context(format!("Identity '{}' not found", identity_name))?;

        info!("Connecting with identity: {}", identity.name);
        ssh_client.connect(addr, username, identity).await?
    };

    if let Some(cmd) = command {
        info!("Executing command: {}", cmd);
        let result = session.execute_command(cmd).await?;
        
        print!("{}", result.stdout_string());
        if !result.stderr_string().is_empty() {
            eprint!("{}", result.stderr_string());
        }
        
        std::process::exit(result.exit_status);
    } else {
        info!("Starting interactive session");
        session.start_shell().await?;
        
        // In a real implementation, we would handle the interactive session
        // For now, we'll just wait for user input to close
        println!("Interactive session started. Press Enter to close...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        session.close().await?;
    }

    Ok(())
}

async fn handle_list_identities(quid_client: Arc<QuIDClient>) -> Result<()> {
    let identities = quid_client.list_identities().await?;
    
    if identities.is_empty() {
        println!("No QuID identities found.");
        println!("Create a new identity with: quid create-identity <name>");
        return Ok(());
    }

    println!("Available QuID identities:");
    println!("{:<20} {:<40} {:<15} {}", "Name", "ID", "Security Level", "Created");
    println!("{}", "-".repeat(80));
    
    for identity in identities {
        println!(
            "{:<20} {:<40} {:<15} {}",
            identity.name,
            identity.id,
            format!("{:?}", identity.security_level),
            identity.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    }

    Ok(())
}

async fn handle_keygen(
    quid_client: Arc<QuIDClient>,
    identity_name: &str,
    output: Option<&std::path::Path>,
) -> Result<()> {
    let identities = quid_client.list_identities().await?;
    let identity = identities
        .iter()
        .find(|id| id.name == identity_name)
        .context(format!("Identity '{}' not found", identity_name))?;

    let quid_key = QuIDSSHKey::from_identity(&quid_client, identity).await?;
    let public_key = quid_key.to_ssh_public_key()?;

    if let Some(output_path) = output {
        std::fs::write(output_path, &public_key)?;
        info!("SSH public key written to: {}", output_path.display());
    } else {
        println!("{}", public_key);
    }

    Ok(())
}

async fn handle_test(
    quid_client: Arc<QuIDClient>,
    config: &QuIDSSHConfig,
    address: &str,
) -> Result<()> {
    let addr: SocketAddr = address.parse()
        .context("Invalid server address format")?;

    let ssh_config = config.to_ssh_client_config();
    let ssh_client = QuIDSSHClient::new(quid_client, ssh_config);

    info!("Testing connection to {}", addr);
    
    match ssh_client.test_connection(addr).await {
        Ok(info) => {
            println!("Connection test successful:");
            println!("  Server: {}", info.server_version);
            println!("  Address: {}", info.address);
            println!("  Reachable: {}", info.reachable);
        }
        Err(e) => {
            warn!("Connection test failed: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

async fn handle_export(
    quid_client: Arc<QuIDClient>,
    identity_name: &str,
    output_dir: &std::path::Path,
) -> Result<()> {
    let identities = quid_client.list_identities().await?;
    let identity = identities
        .iter()
        .find(|id| id.name == identity_name)
        .context(format!("Identity '{}' not found", identity_name))?;

    let (public_key_path, private_key_path) = KeyConversion::export_ssh_key_pair(
        &quid_client,
        identity,
        output_dir,
    )
    .await?;

    println!("QuID identity exported as SSH key pair:");
    println!("  Public key:  {}", public_key_path.display());
    println!("  Private key: {}", private_key_path.display());
    println!();
    println!("Note: The 'private key' file contains a reference to the QuID identity,");
    println!("not an exportable private key. Use quid-ssh-client for authentication.");

    Ok(())
}

async fn handle_import(
    quid_client: Arc<QuIDClient>,
    ssh_key_path: &std::path::Path,
    identity_name: &str,
) -> Result<()> {
    if !ssh_key_path.exists() {
        return Err(anyhow::anyhow!("SSH key file not found: {}", ssh_key_path.display()));
    }

    let identity = KeyConversion::import_ssh_key(
        &quid_client,
        ssh_key_path,
        identity_name,
    )
    .await?;

    println!("SSH key imported as QuID identity:");
    println!("  Name: {}", identity.name);
    println!("  ID: {}", identity.id);
    println!("  Security Level: {:?}", identity.security_level);
    println!();
    println!("You can now use this identity for SSH authentication with:");
    println!("  quid-ssh-client connect <server> -i {}", identity.name);

    Ok(())
}

async fn handle_config(config: &QuIDSSHConfig, action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => {
            let toml_str = toml::to_string_pretty(config)?;
            println!("{}", toml_str);
        }
        ConfigAction::Init { output } => {
            let config_path = if let Some(path) = output {
                path
            } else {
                let config_dir = ConfigManager::init_config_dir()?;
                config_dir.join("config.toml")
            };

            QuIDSSHConfig::create_example_config(&config_path)?;
            println!("Example configuration created: {}", config_path.display());
        }
        ConfigAction::Validate => {
            match config.validate() {
                Ok(()) => println!("Configuration is valid"),
                Err(e) => {
                    error!("Configuration validation failed: {}", e);
                    return Err(e.into());
                }
            }
        }
    }

    Ok(())
}