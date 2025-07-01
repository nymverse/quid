//! QuID SSH Certificate Authority CLI
//!
//! Command-line tool for managing SSH certificates with QuID.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use chrono::Duration;
use quid_core::QuIDClient;
use quid_ssh::{
    certificate::{CertificateAuthority, CertificateOptions, CertificateType, CAConfig, ValidityPeriod},
    config::ConfigManager,
    QuIDSSHResult,
};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "quid-ssh-ca",
    about = "QuID SSH Certificate Authority - Manage SSH certificates with quantum-resistant signatures",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// QuID client data directory
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// CA configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Certificate Authority
    Init {
        /// CA identity name (must exist in QuID)
        identity: String,
        /// CA configuration output file
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Certificate validity duration in days
        #[arg(long, default_value = "365")]
        validity_days: u64,
        /// Serial number file path
        #[arg(long)]
        serial_file: Option<PathBuf>,
        /// Certificate database file path
        #[arg(long)]
        cert_db: Option<PathBuf>,
        /// Audit log file path
        #[arg(long)]
        audit_log: Option<PathBuf>,
    },
    /// Issue a new certificate
    Issue {
        /// Public key file (SSH format)
        public_key: PathBuf,
        /// Certificate type: user or host
        #[arg(short, long)]
        cert_type: String,
        /// Key identifier
        #[arg(short, long)]
        key_id: String,
        /// Valid principals (comma-separated)
        #[arg(short, long)]
        principals: String,
        /// Certificate validity in hours
        #[arg(long, default_value = "24")]
        validity_hours: u64,
        /// Output certificate file
        #[arg(short, long)]
        output: PathBuf,
        /// Force command (for user certificates)
        #[arg(long)]
        force_command: Option<String>,
        /// Source address restrictions (comma-separated IPs)
        #[arg(long)]
        source_addresses: Option<String>,
    },
    /// Show CA public key
    PublicKey {
        /// Output format: ssh, pem, or raw
        #[arg(short, long, default_value = "ssh")]
        format: String,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List issued certificates
    List {
        /// Show only valid certificates
        #[arg(long)]
        valid_only: bool,
        /// Filter by certificate type
        #[arg(long)]
        cert_type: Option<String>,
        /// Output format: table, json, or csv
        #[arg(long, default_value = "table")]
        format: String,
    },
    /// Show certificate details
    Show {
        /// Certificate serial number or file path
        cert: String,
    },
    /// Revoke a certificate
    Revoke {
        /// Certificate serial number
        serial: u64,
        /// Revocation reason
        #[arg(short, long)]
        reason: String,
    },
    /// Verify a certificate
    Verify {
        /// Certificate file path
        certificate: PathBuf,
        /// Check validity period
        #[arg(long)]
        check_validity: bool,
        /// Principal to verify against
        #[arg(short, long)]
        principal: Option<String>,
    },
    /// Generate configuration template
    Config {
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
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

    info!("QuID SSH Certificate Authority starting");

    // Initialize QuID client
    let quid_config = quid_core::QuIDConfig {
        data_directory: cli.data_dir,
        ..Default::default()
    };
    let quid_client = Arc::new(
        QuIDClient::new(quid_config)
            .context("Failed to initialize QuID client")?
    );

    // Load CA configuration if specified
    let ca_config = if let Some(config_path) = cli.config {
        load_ca_config(&config_path)?
    } else {
        CAConfig::default()
    };

    // Execute command
    let result = match cli.command {
        Commands::Init {
            identity,
            output,
            validity_days,
            serial_file,
            cert_db,
            audit_log,
        } => {
            handle_init(
                quid_client,
                &identity,
                output,
                validity_days,
                serial_file,
                cert_db,
                audit_log,
            )
            .await
        }
        Commands::Issue {
            public_key,
            cert_type,
            key_id,
            principals,
            validity_hours,
            output,
            force_command,
            source_addresses,
        } => {
            handle_issue(
                quid_client,
                &ca_config,
                public_key,
                &cert_type,
                &key_id,
                &principals,
                validity_hours,
                output,
                force_command,
                source_addresses,
            )
            .await
        }
        Commands::PublicKey { format, output } => {
            handle_public_key(quid_client, &ca_config, &format, output).await
        }
        Commands::List {
            valid_only,
            cert_type,
            format,
        } => handle_list(quid_client, &ca_config, valid_only, cert_type, &format).await,
        Commands::Show { cert } => handle_show(quid_client, &ca_config, &cert).await,
        Commands::Revoke { serial, reason } => {
            handle_revoke(quid_client, &ca_config, serial, &reason).await
        }
        Commands::Verify {
            certificate,
            check_validity,
            principal,
        } => {
            handle_verify(
                quid_client,
                &ca_config,
                certificate,
                check_validity,
                principal,
            )
            .await
        }
        Commands::Config { output } => handle_config_template(output).await,
    };

    if let Err(e) = result {
        error!("Command failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

async fn handle_init(
    quid_client: Arc<QuIDClient>,
    identity_name: &str,
    output: Option<PathBuf>,
    validity_days: u64,
    serial_file: Option<PathBuf>,
    cert_db: Option<PathBuf>,
    audit_log: Option<PathBuf>,
) -> Result<()> {
    // Find the CA identity
    let identities = quid_client.list_identities().await?;
    let ca_identity = identities
        .iter()
        .find(|id| id.name == identity_name)
        .context(format!("Identity '{}' not found", identity_name))?;

    info!("Initializing CA with identity: {}", ca_identity.name);

    // Create CA configuration
    let ca_config = CAConfig {
        default_validity: Duration::hours(24),
        max_validity: Duration::days(validity_days as i64),
        allowed_cert_types: vec![CertificateType::User, CertificateType::Host],
        serial_file,
        cert_database: cert_db,
        audit_log,
        ..Default::default()
    };

    // Create the CA
    let ca = CertificateAuthority::new(quid_client, ca_identity.clone(), ca_config.clone());

    // Get CA public key
    let ca_public_key = ca.get_ca_public_key().await?;

    println!("Certificate Authority initialized successfully!");
    println!("CA Identity: {}", ca_identity.name);
    println!("CA ID: {}", ca_identity.id);
    println!("Security Level: {:?}", ca_identity.security_level);
    println!();
    println!("CA Public Key (SSH format):");
    println!("{}", ca_public_key);
    println!();

    // Save configuration if requested
    if let Some(config_path) = output {
        save_ca_config(&ca_config, &config_path)?;
        println!("CA configuration saved to: {}", config_path.display());
    }

    println!("Setup complete! Next steps:");
    println!("1. Distribute the CA public key to SSH servers");
    println!("2. Configure SSH servers to trust certificates from this CA");
    println!("3. Start issuing certificates with: quid-ssh-ca issue");

    Ok(())
}

async fn handle_issue(
    quid_client: Arc<QuIDClient>,
    ca_config: &CAConfig,
    public_key_path: PathBuf,
    cert_type: &str,
    key_id: &str,
    principals: &str,
    validity_hours: u64,
    output: PathBuf,
    force_command: Option<String>,
    source_addresses: Option<String>,
) -> Result<()> {
    // Load the CA identity (this would normally be configured)
    let identities = quid_client.list_identities().await?;
    let ca_identity = identities
        .first()
        .context("No QuID identities found. Please create a CA identity first.")?;

    // Parse certificate type
    let cert_type = match cert_type.to_lowercase().as_str() {
        "user" => CertificateType::User,
        "host" => CertificateType::Host,
        _ => return Err(anyhow::anyhow!("Invalid certificate type: {}", cert_type)),
    };

    // Read public key
    let public_key_content = std::fs::read_to_string(&public_key_path)
        .context("Failed to read public key file")?;
    
    let parts: Vec<&str> = public_key_content.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("Invalid SSH public key format"));
    }
    
    let public_key_data = base64::decode(parts[1])
        .context("Failed to decode public key data")?;

    // Parse principals
    let principals_list: Vec<String> = principals
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    // Parse source addresses if provided
    let source_ips = if let Some(addresses) = source_addresses {
        let ips: Result<Vec<IpAddr>, _> = addresses
            .split(',')
            .map(|s| s.trim().parse())
            .collect();
        Some(ips.context("Invalid source address format")?)
    } else {
        None
    };

    // Create certificate options
    let validity = ValidityPeriod::from_duration(Duration::hours(validity_hours as i64));
    let mut cert_options = match cert_type {
        CertificateType::User => CertificateOptions::user_cert(&principals_list[0], Duration::hours(validity_hours as i64)),
        CertificateType::Host => CertificateOptions::host_cert(&principals_list[0], Duration::hours(validity_hours as i64)),
    };

    cert_options.key_id = key_id.to_string();
    cert_options.valid_principals = principals_list;

    if let Some(command) = force_command {
        cert_options.extensions.force_command = Some(command);
    }

    if let Some(ips) = source_ips {
        cert_options.extensions.source_address = Some(ips);
    }

    // Create CA and issue certificate
    let ca = CertificateAuthority::new(quid_client, ca_identity.clone(), ca_config.clone());
    let certificate = ca.issue_certificate(&public_key_data, cert_options).await?;

    // Export certificate
    certificate.export_to_file(&output)?;

    println!("Certificate issued successfully!");
    println!("Certificate Type: {:?}", certificate.cert_type);
    println!("Serial Number: {}", certificate.serial);
    println!("Key ID: {}", certificate.key_id);
    println!("Valid Principals: {}", certificate.valid_principals.join(", "));
    println!("Valid From: {}", certificate.validity.valid_after);
    println!("Valid Until: {}", certificate.validity.valid_before);
    println!("Output: {}", output.display());
    println!();
    println!("Certificate fingerprint: {}", certificate.fingerprint());

    Ok(())
}

async fn handle_public_key(
    quid_client: Arc<QuIDClient>,
    ca_config: &CAConfig,
    format: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    let identities = quid_client.list_identities().await?;
    let ca_identity = identities
        .first()
        .context("No QuID identities found")?;

    let ca = CertificateAuthority::new(quid_client, ca_identity.clone(), ca_config.clone());
    let public_key = ca.get_ca_public_key().await?;

    let formatted_key = match format.to_lowercase().as_str() {
        "ssh" => public_key,
        "pem" => {
            // In a real implementation, we would convert to PEM format
            format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", 
                    base64::encode(public_key.as_bytes()))
        }
        "raw" => {
            // Return raw key data
            public_key
        }
        _ => return Err(anyhow::anyhow!("Unsupported format: {}", format)),
    };

    if let Some(output_path) = output {
        std::fs::write(&output_path, &formatted_key)?;
        println!("CA public key written to: {}", output_path.display());
    } else {
        println!("{}", formatted_key);
    }

    Ok(())
}

async fn handle_list(
    quid_client: Arc<QuIDClient>,
    ca_config: &CAConfig,
    valid_only: bool,
    cert_type_filter: Option<String>,
    format: &str,
) -> Result<()> {
    let identities = quid_client.list_identities().await?;
    let ca_identity = identities
        .first()
        .context("No QuID identities found")?;

    let ca = CertificateAuthority::new(quid_client, ca_identity.clone(), ca_config.clone());
    let certificates = ca.list_certificates().await?;

    let filtered_certs: Vec<_> = certificates
        .into_iter()
        .filter(|cert| {
            if valid_only && !cert.validity.is_valid() {
                return false;
            }
            if let Some(ref filter_type) = cert_type_filter {
                let cert_type_str = match cert.cert_type {
                    CertificateType::User => "user",
                    CertificateType::Host => "host",
                };
                if cert_type_str != filter_type.to_lowercase() {
                    return false;
                }
            }
            true
        })
        .collect();

    match format.to_lowercase().as_str() {
        "table" => {
            println!("Issued Certificates ({} total):", filtered_certs.len());
            println!("{:<10} {:<6} {:<30} {:<20} {:<20} {:<8}", 
                     "Serial", "Type", "Key ID", "Valid From", "Valid Until", "Status");
            println!("{}", "-".repeat(100));
            
            for cert in filtered_certs {
                let status = if cert.validity.is_valid() { "Valid" } else { "Expired" };
                println!("{:<10} {:<6} {:<30} {:<20} {:<20} {:<8}",
                         cert.serial,
                         match cert.cert_type {
                             CertificateType::User => "User",
                             CertificateType::Host => "Host",
                         },
                         cert.key_id,
                         cert.validity.valid_after.format("%Y-%m-%d %H:%M:%S"),
                         cert.validity.valid_before.format("%Y-%m-%d %H:%M:%S"),
                         status);
            }
        }
        "json" => {
            let json = serde_json::to_string_pretty(&filtered_certs)?;
            println!("{}", json);
        }
        "csv" => {
            println!("Serial,Type,KeyID,ValidFrom,ValidUntil,Status");
            for cert in filtered_certs {
                let status = if cert.validity.is_valid() { "Valid" } else { "Expired" };
                println!("{},{},{},{},{},{}",
                         cert.serial,
                         match cert.cert_type {
                             CertificateType::User => "User",
                             CertificateType::Host => "Host",
                         },
                         cert.key_id,
                         cert.validity.valid_after.to_rfc3339(),
                         cert.validity.valid_before.to_rfc3339(),
                         status);
            }
        }
        _ => return Err(anyhow::anyhow!("Unsupported format: {}", format)),
    }

    Ok(())
}

async fn handle_show(
    quid_client: Arc<QuIDClient>,
    ca_config: &CAConfig,
    cert_identifier: &str,
) -> Result<()> {
    let identities = quid_client.list_identities().await?;
    let ca_identity = identities
        .first()
        .context("No QuID identities found")?;

    let ca = CertificateAuthority::new(quid_client, ca_identity.clone(), ca_config.clone());

    // Try to parse as serial number first
    if let Ok(serial) = cert_identifier.parse::<u64>() {
        if let Some(cert) = ca.get_certificate(serial).await? {
            display_certificate_details(&cert);
        } else {
            println!("Certificate with serial {} not found", serial);
        }
    } else {
        // Assume it's a file path
        let cert_path = std::path::PathBuf::from(cert_identifier);
        if cert_path.exists() {
            println!("Certificate file analysis would be implemented here");
            println!("File: {}", cert_path.display());
        } else {
            return Err(anyhow::anyhow!("Certificate not found: {}", cert_identifier));
        }
    }

    Ok(())
}

async fn handle_revoke(
    quid_client: Arc<QuIDClient>,
    ca_config: &CAConfig,
    serial: u64,
    reason: &str,
) -> Result<()> {
    let identities = quid_client.list_identities().await?;
    let ca_identity = identities
        .first()
        .context("No QuID identities found")?;

    let ca = CertificateAuthority::new(quid_client, ca_identity.clone(), ca_config.clone());
    ca.revoke_certificate(serial, reason).await?;

    println!("Certificate {} revoked successfully", serial);
    println!("Reason: {}", reason);
    println!();
    println!("Note: Update your Certificate Revocation List (CRL) and");
    println!("notify all systems that trust this CA.");

    Ok(())
}

async fn handle_verify(
    quid_client: Arc<QuIDClient>,
    ca_config: &CAConfig,
    certificate_path: PathBuf,
    check_validity: bool,
    principal: Option<String>,
) -> Result<()> {
    println!("Certificate verification would be implemented here");
    println!("Certificate: {}", certificate_path.display());
    println!("Check validity: {}", check_validity);
    if let Some(p) = principal {
        println!("Principal: {}", p);
    }
    
    println!();
    println!("This would:");
    println!("1. Load the certificate from file");
    println!("2. Verify signature against CA public key");
    println!("3. Check validity period if requested");
    println!("4. Verify principal if specified");

    Ok(())
}

async fn handle_config_template(output: PathBuf) -> Result<()> {
    let template = r#"# QuID SSH Certificate Authority Configuration
# 
# This file configures the behavior of the QuID SSH CA

# Default certificate validity duration (24 hours)
default_validity = "24h"

# Maximum certificate validity duration (1 year)
max_validity = "8760h"

# Allowed certificate types
allowed_cert_types = ["user", "host"]

# Serial number file (tracks issued certificates)
serial_file = "/etc/quid/ca/serial"

# Certificate database (stores issued certificates)
cert_database = "/etc/quid/ca/certificates.db"

# Audit log file (logs all CA operations)
audit_log = "/var/log/quid-ca.log"

# Default extensions for user certificates
[default_user_extensions]
permit_x11_forwarding = true
permit_agent_forwarding = true
permit_port_forwarding = true
permit_pty = true
permit_user_rc = true

# Default extensions for host certificates
[default_host_extensions]
# Host certificates typically have no extensions
"#;

    std::fs::write(&output, template)?;
    println!("CA configuration template written to: {}", output.display());
    println!();
    println!("Edit this file to customize your CA settings, then use:");
    println!("  quid-ssh-ca --config {} <command>", output.display());

    Ok(())
}

fn display_certificate_details(cert: &quid_ssh::certificate::SSHCertificate) {
    println!("Certificate Details:");
    println!("  Serial Number: {}", cert.serial);
    println!("  Type: {:?}", cert.cert_type);
    println!("  Key ID: {}", cert.key_id);
    println!("  Valid Principals: {}", cert.valid_principals.join(", "));
    println!("  Valid From: {}", cert.validity.valid_after);
    println!("  Valid Until: {}", cert.validity.valid_before);
    println!("  Currently Valid: {}", cert.validity.is_valid());
    
    if let Some(remaining) = cert.validity.remaining_duration() {
        println!("  Remaining Validity: {} hours", remaining.num_hours());
    }
    
    println!("  Created: {}", cert.created_at);
    println!("  Fingerprint: {}", cert.fingerprint());
    
    println!("  Extensions:");
    println!("    X11 Forwarding: {}", cert.extensions.permit_x11_forwarding);
    println!("    Agent Forwarding: {}", cert.extensions.permit_agent_forwarding);
    println!("    Port Forwarding: {}", cert.extensions.permit_port_forwarding);
    println!("    PTY: {}", cert.extensions.permit_pty);
    println!("    User RC: {}", cert.extensions.permit_user_rc);
    
    if let Some(ref cmd) = cert.extensions.force_command {
        println!("    Force Command: {}", cmd);
    }
    
    if let Some(ref addrs) = cert.extensions.source_address {
        println!("    Source Addresses: {}", 
                 addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "));
    }
    
    if !cert.metadata.is_empty() {
        println!("  Metadata:");
        for (key, value) in &cert.metadata {
            println!("    {}: {}", key, value);
        }
    }
}

fn load_ca_config(path: &std::path::Path) -> Result<CAConfig> {
    // In a real implementation, this would load from a TOML/JSON file
    // For now, return default config
    Ok(CAConfig::default())
}

fn save_ca_config(config: &CAConfig, path: &std::path::Path) -> Result<()> {
    let toml_content = toml::to_string_pretty(config)?;
    std::fs::write(path, toml_content)?;
    Ok(())
}