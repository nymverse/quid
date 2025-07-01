//! QuID SSH Server CLI
//!
//! Command-line interface for QuID SSH server functionality.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use quid_core::QuIDClient;
use quid_ssh::{
    config::{QuIDSSHConfig, ConfigManager},
    server::{QuIDSSHServer, AuthorizedUsersConfig, UserConfig},
    certificate::{CertificateAuthority, CertificateOptions, CAConfig},
    QuIDSSHResult,
};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "quid-ssh-server",
    about = "QuID SSH Server - Quantum-resistant SSH server",
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

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the SSH server
    Start,
    /// Stop the SSH server
    Stop,
    /// Restart the SSH server
    Restart,
    /// Check server status
    Status,
    /// Test server configuration
    Test,
    /// User management
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Certificate Authority operations
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum UserAction {
    /// Add a new user
    Add {
        /// Username
        username: String,
        /// QuID identity IDs (comma-separated)
        #[arg(short, long)]
        identities: String,
        /// User's shell
        #[arg(short, long)]
        shell: Option<String>,
        /// Home directory
        #[arg(long)]
        home: Option<PathBuf>,
    },
    /// Remove a user
    Remove {
        /// Username
        username: String,
    },
    /// List users
    List,
    /// Show user details
    Show {
        /// Username
        username: String,
    },
    /// Enable/disable user
    Toggle {
        /// Username
        username: String,
        /// Enable user
        #[arg(short, long)]
        enable: bool,
    },
}

#[derive(Subcommand)]
enum CaAction {
    /// Initialize Certificate Authority
    Init {
        /// CA identity name
        ca_identity: String,
    },
    /// Issue a certificate
    Issue {
        /// Public key file
        public_key: PathBuf,
        /// Certificate type (user/host)
        #[arg(short, long)]
        cert_type: String,
        /// Key ID
        #[arg(short, long)]
        key_id: String,
        /// Valid principals (comma-separated)
        #[arg(short, long)]
        principals: String,
        /// Validity duration in hours
        #[arg(short, long, default_value = "24")]
        validity: u64,
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Revoke a certificate
    Revoke {
        /// Certificate serial number
        serial: u64,
        /// Revocation reason
        #[arg(short, long)]
        reason: String,
    },
    /// List certificates
    List,
    /// Show CA public key
    PublicKey,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    Show,
    /// Validate configuration
    Validate,
    /// Create example configuration
    Init {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
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

    info!("QuID SSH Server starting");

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
        Commands::Start => handle_start(quid_client, &config, cli.foreground).await,
        Commands::Stop => handle_stop(&config).await,
        Commands::Restart => handle_restart(quid_client, &config).await,
        Commands::Status => handle_status(&config).await,
        Commands::Test => handle_test(&config).await,
        Commands::User { action } => handle_user_action(action, &config).await,
        Commands::Ca { action } => handle_ca_action(quid_client, action, &config).await,
        Commands::Config { action } => handle_config_action(&config, action).await,
    };

    if let Err(e) = result {
        error!("Command failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

async fn handle_start(
    quid_client: Arc<QuIDClient>,
    config: &QuIDSSHConfig,
    foreground: bool,
) -> Result<()> {
    let server_config = config.to_ssh_server_config()
        .context("No server configuration found")?;

    info!("Starting QuID SSH server on {}", server_config.bind_address);

    if !foreground {
        info!("Running in background mode");
        // In a real implementation, we would daemonize here
        warn!("Daemonization not implemented, running in foreground");
    }

    let server = QuIDSSHServer::new(quid_client, server_config);
    
    // This will run indefinitely
    server.start().await?;

    Ok(())
}

async fn handle_stop(config: &QuIDSSHConfig) -> Result<()> {
    let server_config = config.to_ssh_server_config()
        .context("No server configuration found")?;

    if let Some(pid_file) = &server_config.pid_file {
        if pid_file.exists() {
            let pid_str = std::fs::read_to_string(pid_file)?;
            let pid: u32 = pid_str.trim().parse()
                .context("Invalid PID in PID file")?;
            
            info!("Stopping server with PID: {}", pid);
            
            // In a real implementation, we would send a signal to the process
            #[cfg(unix)]
            {
                use nix::sys::signal::{self, Signal};
                use nix::unistd::Pid;
                
                signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
                    .context("Failed to send SIGTERM to server process")?;
                
                // Remove PID file
                std::fs::remove_file(pid_file)?;
                info!("Server stopped");
            }
            
            #[cfg(not(unix))]
            {
                warn!("Process termination not implemented on this platform");
            }
        } else {
            warn!("PID file not found, server may not be running");
        }
    } else {
        warn!("No PID file configured, cannot stop server");
    }

    Ok(())
}

async fn handle_restart(quid_client: Arc<QuIDClient>, config: &QuIDSSHConfig) -> Result<()> {
    info!("Restarting QuID SSH server");
    
    handle_stop(config).await?;
    
    // Wait a moment for the server to stop
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    handle_start(quid_client, config, true).await
}

async fn handle_status(config: &QuIDSSHConfig) -> Result<()> {
    let server_config = config.to_ssh_server_config()
        .context("No server configuration found")?;

    println!("QuID SSH Server Status:");
    println!("  Bind Address: {}", server_config.bind_address);
    println!("  Max Connections: {}", server_config.max_connections);
    
    if let Some(pid_file) = &server_config.pid_file {
        if pid_file.exists() {
            let pid_str = std::fs::read_to_string(pid_file)?;
            let pid: u32 = pid_str.trim().parse()
                .context("Invalid PID in PID file")?;
            
            #[cfg(unix)]
            {
                use nix::sys::signal::{self, Signal};
                use nix::unistd::Pid;
                
                match signal::kill(Pid::from_raw(pid as i32), None) {
                    Ok(()) => println!("  Status: Running (PID: {})", pid),
                    Err(_) => println!("  Status: Not running (stale PID file)"),
                }
            }
            
            #[cfg(not(unix))]
            {
                println!("  Status: Unknown (PID: {})", pid);
            }
        } else {
            println!("  Status: Not running");
        }
    } else {
        println!("  Status: Unknown (no PID file configured)");
    }

    Ok(())
}

async fn handle_test(config: &QuIDSSHConfig) -> Result<()> {
    println!("Testing QuID SSH server configuration...");

    // Validate configuration
    config.validate()?;
    println!("✓ Configuration is valid");

    // Check server config
    let server_config = config.to_ssh_server_config()
        .context("No server configuration found")?;
    println!("✓ Server configuration found");

    // Test bind address
    match tokio::net::TcpListener::bind(server_config.bind_address).await {
        Ok(_) => println!("✓ Bind address {} is available", server_config.bind_address),
        Err(e) => {
            error!("✗ Cannot bind to {}: {}", server_config.bind_address, e);
            return Err(e.into());
        }
    }

    // Check authorized users
    let user_count = server_config.authorized_users.users.len();
    println!("✓ {} authorized users configured", user_count);

    println!("Configuration test passed!");

    Ok(())
}

async fn handle_user_action(action: UserAction, config: &QuIDSSHConfig) -> Result<()> {
    match action {
        UserAction::Add {
            username,
            identities,
            shell,
            home,
        } => {
            let identity_list: Vec<String> = identities
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();

            let user_config = UserConfig {
                shell: shell.or_else(|| Some("/bin/bash".to_string())),
                home_directory: home,
                quid_identities: identity_list,
                enabled: true,
                ..Default::default()
            };

            println!("Added user configuration for '{}':", username);
            println!("  Identities: {}", identities);
            println!("  Shell: {:?}", user_config.shell);
            println!("  Home: {:?}", user_config.home_directory);
            println!();
            println!("Note: This is a preview. In a real implementation,");
            println!("this would update the server configuration file.");
        }
        UserAction::Remove { username } => {
            println!("Would remove user: {}", username);
            println!("Note: In a real implementation, this would update the configuration.");
        }
        UserAction::List => {
            let server_config = config.to_ssh_server_config()
                .context("No server configuration found")?;

            if server_config.authorized_users.users.is_empty() {
                println!("No users configured");
                return Ok(());
            }

            println!("Configured users:");
            println!("{:<15} {:<10} {:<20} {}", "Username", "Enabled", "Shell", "Identities");
            println!("{}", "-".repeat(70));

            for (username, user_config) in &server_config.authorized_users.users {
                println!(
                    "{:<15} {:<10} {:<20} {}",
                    username,
                    if user_config.enabled { "Yes" } else { "No" },
                    user_config.shell.as_deref().unwrap_or("default"),
                    user_config.quid_identities.join(", ")
                );
            }
        }
        UserAction::Show { username } => {
            let server_config = config.to_ssh_server_config()
                .context("No server configuration found")?;

            if let Some(user_config) = server_config.authorized_users.users.get(&username) {
                println!("User: {}", username);
                println!("  Enabled: {}", user_config.enabled);
                println!("  Shell: {:?}", user_config.shell);
                println!("  Home: {:?}", user_config.home_directory);
                println!("  QuID Identities: {}", user_config.quid_identities.join(", "));
                println!("  SSH Keys: {}", user_config.ssh_keys.len());
                if let Some(commands) = &user_config.allowed_commands {
                    println!("  Allowed Commands: {}", commands.join(", "));
                }
            } else {
                error!("User '{}' not found", username);
            }
        }
        UserAction::Toggle { username, enable } => {
            println!("Would {} user: {}", if enable { "enable" } else { "disable" }, username);
            println!("Note: In a real implementation, this would update the configuration.");
        }
    }

    Ok(())
}

async fn handle_ca_action(
    quid_client: Arc<QuIDClient>,
    action: CaAction,
    config: &QuIDSSHConfig,
) -> Result<()> {
    match action {
        CaAction::Init { ca_identity } => {
            let identities = quid_client.list_identities().await?;
            let identity = identities
                .iter()
                .find(|id| id.name == ca_identity)
                .context(format!("Identity '{}' not found", ca_identity))?;

            let ca_config = CAConfig::default();
            let ca = CertificateAuthority::new(quid_client, identity.clone(), ca_config);

            let ca_public_key = ca.get_ca_public_key().await?;
            
            println!("Certificate Authority initialized:");
            println!("  CA Identity: {}", identity.name);
            println!("  CA Public Key: {}", ca_public_key);
            println!();
            println!("Save this public key to distribute to SSH clients.");
        }
        CaAction::Issue {
            public_key,
            cert_type,
            key_id,
            principals,
            validity,
            output,
        } => {
            let public_key_data = std::fs::read(&public_key)
                .context("Failed to read public key file")?;

            let cert_type = match cert_type.as_str() {
                "user" => quid_ssh::certificate::CertificateType::User,
                "host" => quid_ssh::certificate::CertificateType::Host,
                _ => return Err(anyhow::anyhow!("Invalid certificate type: {}", cert_type)),
            };

            let principals_list: Vec<String> = principals
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();

            let validity_duration = chrono::Duration::hours(validity as i64);

            let cert_options = CertificateOptions {
                cert_type,
                serial: rand::random(),
                key_id,
                valid_principals: principals_list,
                validity: quid_ssh::certificate::ValidityPeriod::from_duration(validity_duration),
                extensions: Default::default(),
                metadata: Default::default(),
            };

            println!("Would issue certificate with options:");
            println!("  Type: {:?}", cert_options.cert_type);
            println!("  Key ID: {}", cert_options.key_id);
            println!("  Principals: {}", cert_options.valid_principals.join(", "));
            println!("  Validity: {} hours", validity);
            println!("  Output: {}", output.display());
            println!();
            println!("Note: Certificate issuance requires a configured CA identity.");
        }
        CaAction::Revoke { serial, reason } => {
            println!("Would revoke certificate:");
            println!("  Serial: {}", serial);
            println!("  Reason: {}", reason);
            println!();
            println!("Note: Certificate revocation requires a configured CA.");
        }
        CaAction::List => {
            println!("Would list issued certificates.");
            println!("Note: Certificate listing requires a configured CA and certificate database.");
        }
        CaAction::PublicKey => {
            println!("Would display CA public key.");
            println!("Note: This requires a configured CA identity.");
        }
    }

    Ok(())
}

async fn handle_config_action(config: &QuIDSSHConfig, action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => {
            let toml_str = toml::to_string_pretty(config)?;
            println!("{}", toml_str);
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
        ConfigAction::Init { output } => {
            let config_path = if let Some(path) = output {
                path
            } else {
                let config_dir = ConfigManager::init_config_dir()?;
                config_dir.join("server-config.toml")
            };

            QuIDSSHConfig::create_example_config(&config_path)?;
            println!("Example server configuration created: {}", config_path.display());
        }
    }

    Ok(())
}