//! QuID SSH Migration Tool
//!
//! Command-line tool for migrating existing SSH keys to QuID identities.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use quid_core::{QuIDClient, SecurityLevel};
use quid_ssh::{
    migration::{SSHKeyMigrator, MigrationOptions, MigrationResult},
    QuIDSSHResult,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "quid-ssh-migrate",
    about = "QuID SSH Migration Tool - Migrate SSH keys to QuID identities",
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

    /// Dry run mode (don't make actual changes)
    #[arg(short = 'n', long)]
    dry_run: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Migrate SSH keys from a directory
    Migrate {
        /// Source SSH directory (default: ~/.ssh)
        #[arg(short, long)]
        source: Option<PathBuf>,
        /// Target QuID directory (default: ~/.ssh/quid)
        #[arg(short, long)]
        target: Option<PathBuf>,
        /// Backup directory for original keys
        #[arg(short, long)]
        backup: Option<PathBuf>,
        /// Default security level for migrated identities
        #[arg(long, default_value = "level1")]
        security_level: String,
        /// Skip existing QuID identities
        #[arg(long)]
        skip_existing: bool,
        /// Don't backup original keys
        #[arg(long)]
        no_backup: bool,
        /// Migrate authorized_keys file
        #[arg(long)]
        migrate_authorized_keys: bool,
        /// Migrate known_hosts file
        #[arg(long)]
        migrate_known_hosts: bool,
    },
    /// Analyze SSH keys without migration
    Analyze {
        /// SSH directory to analyze (default: ~/.ssh)
        #[arg(short, long)]
        directory: Option<PathBuf>,
    },
    /// Create migration plan
    Plan {
        /// Source SSH directory (default: ~/.ssh)
        #[arg(short, long)]
        source: Option<PathBuf>,
        /// Output plan file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Execute migration from plan file
    Execute {
        /// Migration plan file
        plan: PathBuf,
    },
    /// Rollback migration
    Rollback {
        /// Migration result file
        result: PathBuf,
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

    info!("QuID SSH Migration Tool starting");

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
        Commands::Migrate {
            source,
            target,
            backup,
            security_level,
            skip_existing,
            no_backup,
            migrate_authorized_keys,
            migrate_known_hosts,
        } => {
            handle_migrate(
                quid_client,
                source,
                target,
                backup,
                &security_level,
                skip_existing,
                !no_backup,
                migrate_authorized_keys,
                migrate_known_hosts,
                cli.dry_run,
            )
            .await
        }
        Commands::Analyze { directory } => handle_analyze(directory).await,
        Commands::Plan { source, output } => handle_plan(source, output).await,
        Commands::Execute { plan } => handle_execute(quid_client, plan).await,
        Commands::Rollback { result } => handle_rollback(quid_client, result).await,
    };

    if let Err(e) = result {
        error!("Command failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

async fn handle_migrate(
    quid_client: Arc<QuIDClient>,
    source: Option<PathBuf>,
    target: Option<PathBuf>,
    backup: Option<PathBuf>,
    security_level: &str,
    skip_existing: bool,
    backup_keys: bool,
    migrate_authorized_keys: bool,
    migrate_known_hosts: bool,
    dry_run: bool,
) -> Result<()> {
    let default_security_level = parse_security_level(security_level)?;

    let source_dir = source.unwrap_or_else(|| {
        dirs::home_dir().unwrap_or_default().join(".ssh")
    });

    let target_dir = target.unwrap_or_else(|| {
        dirs::home_dir().unwrap_or_default().join(".ssh").join("quid")
    });

    let options = MigrationOptions {
        source_directory: source_dir.clone(),
        target_directory: target_dir.clone(),
        backup_original_keys: backup_keys,
        backup_directory: backup,
        preserve_comments: true,
        default_security_level,
        migrate_private_keys: true,
        migrate_authorized_keys,
        migrate_known_hosts,
        key_type_mapping: create_key_type_mapping(),
        skip_existing,
        dry_run,
    };

    info!("Starting SSH key migration");
    info!("  Source: {}", source_dir.display());
    info!("  Target: {}", target_dir.display());
    info!("  Security Level: {:?}", default_security_level);
    info!("  Backup: {}", backup_keys);
    info!("  Skip Existing: {}", skip_existing);
    info!("  Dry Run: {}", dry_run);

    if dry_run {
        warn!("DRY RUN MODE - No changes will be made");
    }

    let migrator = SSHKeyMigrator::new(quid_client, options);
    let result = migrator.migrate().await?;

    display_migration_result(&result);

    // Save migration result for potential rollback
    if !dry_run {
        let result_file = target_dir.join("migration_result.json");
        let result_json = serde_json::to_string_pretty(&result)?;
        std::fs::write(&result_file, result_json)?;
        info!("Migration result saved to: {}", result_file.display());
    }

    Ok(())
}

async fn handle_analyze(directory: Option<PathBuf>) -> Result<()> {
    let ssh_dir = directory.unwrap_or_else(|| {
        dirs::home_dir().unwrap_or_default().join(".ssh")
    });

    info!("Analyzing SSH keys in: {}", ssh_dir.display());

    if !ssh_dir.exists() {
        warn!("SSH directory does not exist: {}", ssh_dir.display());
        return Ok(());
    }

    let entries = std::fs::read_dir(&ssh_dir)?;
    let mut ssh_keys = Vec::new();
    let mut other_files = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let filename = path.file_name().unwrap().to_string_lossy();
            
            if filename.ends_with(".pub") {
                ssh_keys.push(path);
            } else if !filename.starts_with('.') {
                other_files.push(path);
            }
        }
    }

    println!("SSH Directory Analysis: {}", ssh_dir.display());
    println!("{}", "=".repeat(60));

    println!("\nSSH Public Keys Found: {}", ssh_keys.len());
    for key_path in ssh_keys {
        analyze_ssh_key(&key_path)?;
    }

    println!("\nOther SSH Files: {}", other_files.len());
    for file_path in other_files {
        println!("  {}", file_path.file_name().unwrap().to_string_lossy());
    }

    // Check for special files
    let authorized_keys = ssh_dir.join("authorized_keys");
    let known_hosts = ssh_dir.join("known_hosts");
    let config_file = ssh_dir.join("config");

    println!("\nSpecial Files:");
    println!("  authorized_keys: {}", if authorized_keys.exists() { "Found" } else { "Not found" });
    println!("  known_hosts: {}", if known_hosts.exists() { "Found" } else { "Not found" });
    println!("  config: {}", if config_file.exists() { "Found" } else { "Not found" });

    Ok(())
}

fn analyze_ssh_key(key_path: &std::path::Path) -> Result<()> {
    let content = std::fs::read_to_string(key_path)?;
    let parts: Vec<&str> = content.trim().split_whitespace().collect();
    
    if parts.len() >= 2 {
        let key_type = parts[0];
        let comment = if parts.len() > 2 { parts[2] } else { "no comment" };
        
        let recommended_level = match key_type {
            "ssh-ed25519" | "ecdsa-sha2-nistp256" => "Level1",
            "ecdsa-sha2-nistp384" => "Level2",
            "ecdsa-sha2-nistp521" => "Level3",
            "ssh-rsa" => "Level1 (consider upgrading)",
            _ => "Unknown",
        };

        // Check for corresponding private key
        let private_key_path = if key_path.extension() == Some(std::ffi::OsStr::new("pub")) {
            key_path.with_extension("")
        } else {
            key_path.parent().unwrap().join(key_path.file_stem().unwrap())
        };

        let has_private = private_key_path.exists();

        println!("  {}", key_path.file_name().unwrap().to_string_lossy());
        println!("    Type: {}", key_type);
        println!("    Comment: {}", comment);
        println!("    Private Key: {}", if has_private { "Found" } else { "Not found" });
        println!("    Recommended Security Level: {}", recommended_level);
        println!();
    } else {
        warn!("Invalid SSH key format: {}", key_path.display());
    }

    Ok(())
}

async fn handle_plan(source: Option<PathBuf>, output: Option<PathBuf>) -> Result<()> {
    let ssh_dir = source.unwrap_or_else(|| {
        dirs::home_dir().unwrap_or_default().join(".ssh")
    });

    info!("Creating migration plan for: {}", ssh_dir.display());

    let options = MigrationOptions {
        source_directory: ssh_dir,
        target_directory: dirs::home_dir().unwrap_or_default().join(".ssh").join("quid"),
        backup_original_keys: true,
        backup_directory: None,
        preserve_comments: true,
        default_security_level: SecurityLevel::Level1,
        migrate_private_keys: true,
        migrate_authorized_keys: true,
        migrate_known_hosts: true,
        key_type_mapping: create_key_type_mapping(),
        skip_existing: true,
        dry_run: true, // Always dry run for planning
    };

    let plan_json = serde_json::to_string_pretty(&options)?;
    
    if let Some(output_path) = output {
        std::fs::write(&output_path, &plan_json)?;
        println!("Migration plan saved to: {}", output_path.display());
    } else {
        println!("Migration Plan:");
        println!("{}", plan_json);
    }

    Ok(())
}

async fn handle_execute(quid_client: Arc<QuIDClient>, plan_path: PathBuf) -> Result<()> {
    info!("Executing migration plan: {}", plan_path.display());

    let plan_content = std::fs::read_to_string(&plan_path)?;
    let mut options: MigrationOptions = serde_json::from_str(&plan_content)?;
    
    // Disable dry run for actual execution
    options.dry_run = false;

    let migrator = SSHKeyMigrator::new(quid_client, options);
    let result = migrator.migrate().await?;

    display_migration_result(&result);

    // Save result for potential rollback
    let result_path = plan_path.with_extension("result.json");
    let result_json = serde_json::to_string_pretty(&result)?;
    std::fs::write(&result_path, result_json)?;
    info!("Migration result saved to: {}", result_path.display());

    Ok(())
}

async fn handle_rollback(quid_client: Arc<QuIDClient>, result_path: PathBuf) -> Result<()> {
    info!("Rolling back migration: {}", result_path.display());

    let result_content = std::fs::read_to_string(&result_path)?;
    let result: MigrationResult = serde_json::from_str(&result_content)?;

    println!("Migration Rollback Plan:");
    println!("  {} identities to remove", result.migrated_identities.len());
    
    for migrated in &result.migrated_identities {
        println!("  - Remove identity: {}", migrated.quid_identity_name);
        println!("    Original key: {}", migrated.original_key_path.display());
        
        // In a real implementation, we would:
        // 1. Remove the QuID identity
        // 2. Restore the original SSH key if backed up
        // 3. Clean up generated files
    }

    warn!("Rollback is not yet implemented!");
    warn!("Please manually remove the created QuID identities:");
    for migrated in &result.migrated_identities {
        println!("  quid delete-identity {}", migrated.quid_identity_name);
    }

    Ok(())
}

fn parse_security_level(level_str: &str) -> Result<SecurityLevel> {
    match level_str.to_lowercase().as_str() {
        "level1" | "1" | "low" => Ok(SecurityLevel::Level1),
        "level2" | "2" | "medium" => Ok(SecurityLevel::Level2),
        "level3" | "3" | "high" => Ok(SecurityLevel::Level3),
        _ => Err(anyhow::anyhow!("Invalid security level: {}", level_str)),
    }
}

fn create_key_type_mapping() -> HashMap<String, SecurityLevel> {
    let mut mapping = HashMap::new();
    mapping.insert("ssh-ed25519".to_string(), SecurityLevel::Level1);
    mapping.insert("ecdsa-sha2-nistp256".to_string(), SecurityLevel::Level1);
    mapping.insert("ecdsa-sha2-nistp384".to_string(), SecurityLevel::Level2);
    mapping.insert("ecdsa-sha2-nistp521".to_string(), SecurityLevel::Level3);
    mapping.insert("ssh-rsa".to_string(), SecurityLevel::Level1);
    mapping
}

fn display_migration_result(result: &MigrationResult) {
    println!("\nMigration Results:");
    println!("{}", "=".repeat(50));
    println!("  Successfully migrated: {}", result.migrated_keys);
    println!("  Skipped: {}", result.skipped_keys);
    println!("  Failed: {}", result.failed_keys);
    println!("  Total time: {:?}", result.migration_time);

    if !result.migrated_identities.is_empty() {
        println!("\nMigrated Identities:");
        for migrated in &result.migrated_identities {
            println!("  {} -> {}", 
                migrated.original_key_path.display(),
                migrated.quid_identity_name
            );
            println!("    ID: {}", migrated.quid_identity_id);
            println!("    Security Level: {:?}", migrated.security_level);
        }
    }

    if !result.errors.is_empty() {
        println!("\nErrors:");
        for error in &result.errors {
            println!("  {}: {}", error.key_path.display(), error.error);
        }
    }

    if !result.warnings.is_empty() {
        println!("\nWarnings:");
        for warning in &result.warnings {
            println!("  {}", warning);
        }
    }

    if result.migrated_keys > 0 {
        println!("\nNext Steps:");
        println!("1. Test QuID SSH authentication:");
        println!("   quid-ssh-client connect <server> -i <identity-name>");
        println!("2. Update your SSH configuration to use QuID keys");
        println!("3. Verify server configuration accepts QuID authentication");
    }
}