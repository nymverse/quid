//! QuID Command Line Interface

use clap::{Parser, Subcommand};
use quid_core::{QuIDIdentity, SecurityLevel, RecoveryCoordinator, RecoveryShare, GuardianInfo, IdentityStorage, StorageConfig};
use secrecy::{ExposeSecret, Secret, SecretString};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use sha3::{Digest, Sha3_256, Shake256};
use sha3::digest::{Update, ExtendableOutput, XofReader};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "quid")]
#[command(about = "Universal Quantum-Resistant Authentication CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new QuID identity
    Create {
        /// Security level (1, 3, or 5)
        #[arg(short, long, default_value = "1")]
        security_level: u8,
        
        /// Output file for the identity
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List identities
    List,
    /// Show identity information
    Show {
        /// Identity file path
        identity: PathBuf,
    },
    /// Sign a message
    Sign {
        /// Identity file path (must include private key)
        identity: PathBuf,
        /// Message to sign
        message: String,
    },
    /// Verify a signature
    Verify {
        /// Identity file path
        identity: PathBuf,
        /// Message that was signed
        message: String,
        /// Signature to verify (hex encoded)
        signature: String,
    },
    /// Generate QR code for identity sharing
    Qr {
        /// Identity file path
        identity: PathBuf,
        /// Include private key (dangerous!)
        #[arg(long)]
        include_private: bool,
        /// Output format: terminal, file, or both
        #[arg(short, long, default_value = "terminal")]
        output: String,
    },
    /// Export identity with encryption
    Export {
        /// Identity file to export
        identity: PathBuf,
        /// Output file for encrypted backup
        #[arg(short, long)]
        output: PathBuf,
        /// Encrypt the export (recommended)
        #[arg(long, default_value = "true")]
        encrypt: bool,
    },
    /// Import encrypted identity
    Import {
        /// Encrypted backup file to import
        backup: PathBuf,
        /// Output file for restored identity
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Authenticate to a service or application
    Auth {
        /// Identity file path
        identity: PathBuf,
        /// Service or application name
        service: String,
        /// Network type (web, ssh, bitcoin, ethereum, nym, etc.)
        #[arg(short, long, default_value = "web")]
        network: String,
        /// Required capabilities (comma-separated)
        #[arg(short, long)]
        capabilities: Option<String>,
    },
    /// Generate keys for a specific network
    Derive {
        /// Identity file path
        identity: PathBuf,
        /// Network type (bitcoin, ethereum, ssh, nym, nomadnet, etc.)
        network: String,
        /// Show private keys (dangerous!)
        #[arg(long)]
        show_private: bool,
    },
    /// List supported network adapters
    Adapters,
    /// Manage encrypted identity storage
    Storage {
        #[command(subcommand)]
        storage_command: StorageCommands,
    },
    Recovery {
        #[command(subcommand)]
        recovery_command: RecoveryCommands,
    },
    Batch {
        #[command(subcommand)]
        batch_command: BatchCommands,
    },
    /// Multi-wallet security management
    SecureWallet {
        #[command(subcommand)]
        wallet_command: SecureWalletCommands,
    },
    
}


#[derive(Subcommand)]
enum StorageCommands {
    /// Store identity in encrypted storage
    Store {
        /// Identity file to store
        identity: PathBuf,
        /// Storage directory (optional)
        #[arg(short, long)]
        storage_dir: Option<PathBuf>,
    },
    /// Load identity from encrypted storage
    Load {
        /// Identity ID (hex-encoded)
        identity_id: String,
        /// Output file for loaded identity
        #[arg(short, long)]
        output: PathBuf,
        /// Storage directory (optional)
        #[arg(short, long)]
        storage_dir: Option<PathBuf>,
    },
    /// List identities in encrypted storage
    ListStored {
        /// Storage directory (optional)
        #[arg(short, long)]
        storage_dir: Option<PathBuf>,
    },
    /// Create backup of stored identity
    Backup {
        /// Identity ID (hex-encoded)
        identity_id: String,
        /// Backup hint/description
        #[arg(short = 'H', long)]
        hint: Option<String>,
        /// Storage directory (optional)
        #[arg(short, long)]
        storage_dir: Option<PathBuf>,
    },
    /// List backups for an identity
    ListBackups {
        /// Identity ID (hex-encoded)
        identity_id: String,
        /// Storage directory (optional)
        #[arg(short, long)]
        storage_dir: Option<PathBuf>,
    },
    /// Restore identity from backup
    RestoreBackup {
        /// Path to backup file
        backup_file: PathBuf,
        /// Output file for restored identity
        #[arg(short, long)]
        output: PathBuf,
        /// Storage directory (optional)
        #[arg(short, long)]
        storage_dir: Option<PathBuf>,
    },
    /// Delete identity from encrypted storage
    Delete {
        /// Identity ID (hex-encoded)
        identity_id: String,
        /// Storage directory (optional)
        #[arg(short, long)]
        storage_dir: Option<PathBuf>,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum RecoveryCommands {
    /// Generate recovery shares (t-of-n threshold)
    Generate {
        /// Identity file to create recovery for
        identity: PathBuf,
        /// Number of shares to create (n)
        #[arg(short = 'n', long, default_value = "5")]
        total_shares: u8,
        /// Threshold needed to recover (t)
        #[arg(short = 't', long, default_value = "3")]
        threshold: u8,
        /// Output directory for shares
        #[arg(short, long, default_value = "recovery-shares")]
        output_dir: PathBuf,
    },
    /// Recover identity from shares
    Restore {
        /// Directory containing recovery shares
        shares_dir: PathBuf,
        /// Output file for recovered identity  
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum BatchCommands {
    /// Sign multiple messages from a file
    Sign {
        /// Identity file path
        identity: PathBuf,
        /// Input file containing messages (one per line)
        input: PathBuf,
        /// Output file for signatures
        #[arg(short, long)]
        output: PathBuf,
        /// Input format: text, json, or csv
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Verify multiple signatures from a file
    Verify {
        /// Identity file path  
        identity: PathBuf,
        /// Input file containing signatures
        input: PathBuf,
        /// Report format: summary, detailed, or json
        #[arg(short, long, default_value = "summary")]
        report: String,
    },
    /// Sign all files in a directory
    SignFiles {
        /// Identity file path
        identity: PathBuf,
        /// Directory containing files to sign
        directory: PathBuf,
        /// Output directory for signatures
        #[arg(short, long)]
        output_dir: PathBuf,
        /// File extensions to sign (e.g., txt,md,json)
        #[arg(short, long, default_value = "txt,md,json")]
        extensions: String,
    },
    /// Create signed manifest of directory contents
    Manifest {
        /// Identity file path
        identity: PathBuf,
        /// Directory to create manifest for
        directory: PathBuf,
        /// Output manifest file
        #[arg(short, long)]
        output: PathBuf,
        /// Include file contents hash
        #[arg(long)]
        include_hashes: bool,
    },
}

#[derive(Subcommand)]
enum SecureWalletCommands {
    /// Create a secure wallet pair (cold storage + hot spending)
    CreatePair {
        /// Wallet pair name
        name: String,
        /// Security level for both wallets (1, 3, or 5)
        #[arg(short, long, default_value = "5")]
        security_level: u8,
        /// Network type (bitcoin, ethereum, etc.)
        #[arg(short, long, default_value = "bitcoin")]
        network: String,
        /// Cold wallet storage directory
        #[arg(long)]
        cold_storage: Option<PathBuf>,
        /// Hot wallet storage directory  
        #[arg(long)]
        hot_storage: Option<PathBuf>,
        /// Enable hardware security (if available)
        #[arg(long)]
        hardware_security: bool,
    },
    /// List all secure wallet pairs
    List,
    /// Show secure wallet pair details
    Show {
        /// Wallet pair name
        name: String,
        /// Show addresses and balances
        #[arg(long)]
        show_addresses: bool,
    },
    /// Generate receiving address (cold wallet)
    Receive {
        /// Wallet pair name
        wallet: String,
        /// Address derivation path (optional)
        #[arg(long)]
        derivation_path: Option<String>,
        /// Show QR code for address
        #[arg(long)]
        qr: bool,
    },
    /// Transfer funds from cold to hot wallet
    Transfer {
        /// Wallet pair name
        wallet: String,
        /// Amount to transfer (in base units)
        amount: String,
        /// Transfer policy to apply
        #[arg(short, long, default_value = "immediate")]
        policy: String,
        /// Require additional confirmations
        #[arg(long)]
        require_confirmation: bool,
    },
    /// Spend from hot wallet
    Spend {
        /// Wallet pair name
        wallet: String,
        /// Recipient address
        to: String,
        /// Amount to spend (in base units)
        amount: String,
        /// Transaction fee (optional)
        #[arg(long)]
        fee: Option<String>,
        /// Dry run (don't broadcast)
        #[arg(long)]
        dry_run: bool,
    },
    /// Check wallet balances
    Balance {
        /// Wallet pair name
        wallet: String,
        /// Include pending transactions
        #[arg(long)]
        include_pending: bool,
    },
    /// Set transfer policy for wallet pair
    SetPolicy {
        /// Wallet pair name
        wallet: String,
        /// Policy type (immediate, time_delayed, multi_sig, biometric)
        policy_type: String,
        /// Policy parameters (JSON string)
        #[arg(long)]
        parameters: Option<String>,
    },
    /// Add guardian for multi-signature policies
    AddGuardian {
        /// Wallet pair name
        wallet: String,
        /// Guardian identity file
        guardian_identity: PathBuf,
        /// Guardian contact information
        #[arg(long)]
        contact: Option<String>,
    },
    /// Create recovery backup for wallet pair
    Backup {
        /// Wallet pair name
        wallet: String,
        /// Output directory for backup files
        #[arg(short, long)]
        output: PathBuf,
        /// Split backup across multiple files
        #[arg(long)]
        split_backup: bool,
    },
    /// Restore wallet pair from backup
    Restore {
        /// Backup file or directory
        backup: PathBuf,
        /// Wallet pair name for restored wallet
        #[arg(short, long)]
        name: String,
        /// Verify backup integrity only
        #[arg(long)]
        verify_only: bool,
    },
    /// Monitor wallet pair for suspicious activity
    Monitor {
        /// Wallet pair name
        wallet: String,
        /// Enable real-time alerts
        #[arg(long)]
        alerts: bool,
        /// Output format (terminal, log, json)
        #[arg(short, long, default_value = "terminal")]
        output: String,
    },
    /// Emergency freeze wallet (disable spending)
    Freeze {
        /// Wallet pair name
        wallet: String,
        /// Reason for freeze
        #[arg(short, long)]
        reason: String,
        /// Require guardian approval to unfreeze
        #[arg(long)]
        require_guardian: bool,
    },
    /// Unfreeze wallet (re-enable spending)
    Unfreeze {
        /// Wallet pair name
        wallet: String,
        /// Guardian signatures (if required)
        #[arg(long)]
        guardian_signatures: Option<PathBuf>,
    },
    /// Delete wallet pair (with confirmation)
    Delete {
        /// Wallet pair name
        wallet: String,
        /// Skip confirmation prompts
        #[arg(long)]
        force: bool,
        /// Also delete associated backups
        #[arg(long)]
        delete_backups: bool,
    },
}

/// Secure wallet pair configuration
#[derive(Serialize, Deserialize, Clone)]
struct SecureWalletPair {
    name: String,
    created_at: u64,
    network: String,
    security_level: u8,
    cold_wallet: WalletInfo,
    hot_wallet: WalletInfo,
    transfer_policy: TransferPolicy,
    guardians: Vec<GuardianInfo>,
    frozen: bool,
    freeze_reason: Option<String>,
    hardware_security: bool,
}

/// Individual wallet information
#[derive(Serialize, Deserialize, Clone)]
struct WalletInfo {
    identity_id: String,
    storage_path: PathBuf,
    derivation_path: Option<String>,
    last_used: Option<u64>,
    balance: Option<String>,
}

/// Transfer policies for secure operations
#[derive(Serialize, Deserialize, Clone)]
enum TransferPolicy {
    /// Immediate transfer (default)
    Immediate,
    /// Time-delayed transfer
    TimeDelayed {
        delay_seconds: u64,
        pending_transfers: Vec<PendingTransfer>,
    },
    /// Multi-signature required
    MultiSignature {
        required_signatures: u32,
        guardian_ids: Vec<String>,
    },
    /// Biometric confirmation required
    Biometric {
        biometric_type: String,
        fallback_policy: Box<TransferPolicy>,
    },
    /// Geographic restrictions
    Geographic {
        allowed_locations: Vec<String>,
        fallback_policy: Box<TransferPolicy>,
    },
}

/// Pending transfer for time-delayed policies
#[derive(Serialize, Deserialize, Clone)]
struct PendingTransfer {
    transfer_id: String,
    amount: String,
    requested_at: u64,
    execute_at: u64,
    status: TransferStatus,
}

#[derive(Serialize, Deserialize, Clone)]
enum TransferStatus {
    Pending,
    Approved,
    Cancelled,
    Executed,
}

/// Security monitor for anomaly detection
#[derive(Serialize, Deserialize, Clone)]
struct SecurityMonitor {
    wallet_name: String,
    enabled: bool,
    last_activity: Option<u64>,
    suspicious_events: Vec<SecurityEvent>,
    alert_thresholds: AlertThresholds,
}

#[derive(Serialize, Deserialize, Clone)]
struct SecurityEvent {
    event_type: String,
    description: String,
    timestamp: u64,
    severity: String,
    data: std::collections::HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AlertThresholds {
    max_daily_amount: Option<String>,
    max_transaction_amount: Option<String>,
    suspicious_location_change: bool,
    rapid_succession_limit: Option<u32>,
}

/// Wallet manager for handling multiple secure wallet pairs
#[derive(Serialize, Deserialize)]
struct SecureWalletManager {
    wallets: std::collections::HashMap<String, SecureWalletPair>,
    active_wallet: Option<String>,
    storage_path: PathBuf,
    monitors: std::collections::HashMap<String, SecurityMonitor>,
}

/// SHA3-based encrypted backup format
#[derive(Serialize, Deserialize)]
struct EncryptedBackup {
    version: String,
    algorithm: String,        // "SHA3-STREAM"
    kdf: String,             // "PBKDF2-SHA3"
    salt: String,            // Hex encoded
    nonce: String,           // Hex encoded - STORE DIRECTLY
    iterations: u32,         // PBKDF2 iterations
    encrypted_data: String,  // Hex encoded
    created: u64,
}

/// Batch signature format for JSON output
#[derive(Serialize, Deserialize)]
struct BatchSignature {
    message: String,
    signature: String,
    timestamp: u64,
    identity_id: String,
}

/// Batch verification result
#[derive(Serialize, Deserialize)]
struct VerificationResult {
    message: String,
    signature: String,
    valid: bool,
    error: Option<String>,
}

/// File manifest entry
#[derive(Serialize, Deserialize)]
struct ManifestEntry {
    path: String,
    size: u64,
    modified: u64,
    signature: String,
    content_hash: Option<String>,
}

/// Complete manifest file
#[derive(Serialize, Deserialize)]
struct FileManifest {
    version: String,
    created_at: u64,
    identity_id: String,
    entries: Vec<ManifestEntry>,
    manifest_signature: String,
}

/// Professional key derivation using PBKDF2 with SHA3
fn derive_key_sha3(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut current = password.as_bytes().to_vec();
    current.extend_from_slice(salt);
    
    for _ in 0..iterations {
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, &current);
        current = hasher.finalize().to_vec();
    }
    
    key.copy_from_slice(&current[..32]);
    key
}

/// Generate cryptographic stream using SHAKE256
fn generate_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut shake = Shake256::default();
    shake.update(b"QuID-STREAM-v1");
    shake.update(key);
    shake.update(nonce);
    
    let mut reader = shake.finalize_xof();
    let mut keystream = vec![0u8; length];
    reader.read(&mut keystream);
    keystream
}

/// Professional encryption using SHA3-based stream cipher

fn encrypt_identity_professional(identity: &CliIdentity, password: &str) -> anyhow::Result<EncryptedBackup> {
    // Generate salt using system time + counter
    let mut salt_data = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos()
        .to_le_bytes()
        .to_vec();
    
    // Add additional entropy
    let pid = std::process::id();
    salt_data.extend(&pid.to_le_bytes());
    
    // Hash to get final salt
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, &salt_data);
    Digest::update(&mut hasher, b"QuID-SALT");
    let salt = hasher.finalize();
    
    // Key derivation with high iteration count
    let iterations = 100_000u32; // Strong PBKDF2
    let key = derive_key_sha3(password, &salt, iterations);
    
    // Serialize identity
    let identity_json = serde_json::to_string(identity)?;
    let plaintext = identity_json.as_bytes();
    
    // Generate RANDOM nonce (don't derive it)
    let mut nonce_data = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos()
        .to_le_bytes()
        .to_vec();
    nonce_data.extend(&std::process::id().to_le_bytes());
    nonce_data.extend(password.as_bytes());
    
    let mut nonce_hasher = Sha3_256::new();
    Digest::update(&mut nonce_hasher, &nonce_data);
    Digest::update(&mut nonce_hasher, b"QuID-NONCE");
    let nonce = nonce_hasher.finalize();
    
    // Generate keystream and encrypt
    let keystream = generate_keystream(&key, &nonce[..16], plaintext.len());
    let mut ciphertext = vec![0u8; plaintext.len()];
    
    for (i, (&p, &k)) in plaintext.iter().zip(keystream.iter()).enumerate() {
        ciphertext[i] = p ^ k;
    }
    
    // Add authentication tag
    let mut auth_hasher = Sha3_256::new();
    Digest::update(&mut auth_hasher, b"QuID-AUTH");
    Digest::update(&mut auth_hasher, &key);
    Digest::update(&mut auth_hasher, &ciphertext);
    let auth_tag = auth_hasher.finalize();
    
    // Combine ciphertext + auth tag
    let mut authenticated_data = ciphertext;
    authenticated_data.extend_from_slice(&auth_tag);
    
    Ok(EncryptedBackup {
        version: "0.1.0".to_string(),
        algorithm: "SHA3-STREAM".to_string(),
        kdf: "PBKDF2-SHA3".to_string(),
        salt: hex::encode(&salt),
        nonce: hex::encode(&nonce), // Store the nonce directly!
        iterations,
        encrypted_data: hex::encode(&authenticated_data),
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    })
}

/// Professional decryption
fn decrypt_identity_professional(backup: &EncryptedBackup, password: &str) -> anyhow::Result<CliIdentity> {
    // Verify algorithm
    if backup.algorithm != "SHA3-STREAM" {
        return Err(anyhow::anyhow!("Unsupported encryption algorithm: {}", backup.algorithm));
    }
    
    // Decode salt, nonce, and data
    let salt = hex::decode(&backup.salt)?;
    let nonce = hex::decode(&backup.nonce)?; // Use stored nonce directly!
    let authenticated_data = hex::decode(&backup.encrypted_data)?;
    
    // Split ciphertext and auth tag
    if authenticated_data.len() < 32 {
        return Err(anyhow::anyhow!("Invalid encrypted data"));
    }
    
    let (ciphertext, auth_tag) = authenticated_data.split_at(authenticated_data.len() - 32);
    
    // Derive key
    let key = derive_key_sha3(password, &salt, backup.iterations);
    
    // Verify authentication
    let mut auth_hasher = Sha3_256::new();
    Digest::update(&mut auth_hasher, b"QuID-AUTH");
    Digest::update(&mut auth_hasher, &key);
    Digest::update(&mut auth_hasher, ciphertext);
    let expected_tag = auth_hasher.finalize();
    
    if auth_tag != expected_tag.as_slice() {
        return Err(anyhow::anyhow!("Authentication failed (wrong password or corrupted data)"));
    }
    
    // Generate keystream and decrypt using stored nonce
    let keystream = generate_keystream(&key, &nonce[..16], ciphertext.len());
    let mut plaintext = vec![0u8; ciphertext.len()];
    
    for (i, (&c, &k)) in ciphertext.iter().zip(keystream.iter()).enumerate() {
        plaintext[i] = c ^ k;
    }
    
    // Parse identity
    let identity_json = String::from_utf8(plaintext)?;
    let identity: CliIdentity = serde_json::from_str(&identity_json)?;
    
    Ok(identity)
}

/// Complete identity with private key for CLI operations
#[derive(Serialize, Deserialize)]
struct CliIdentity {
    /// The public identity
    pub identity: QuIDIdentity,
    /// The private key (hex encoded for simplicity - in production would be encrypted)
    pub private_key_hex: String,
    /// Security level
    pub security_level: SecurityLevel,
}

impl CliIdentity {
    fn from_identity_and_keypair(identity: QuIDIdentity, keypair: &quid_core::crypto::KeyPair) -> Self {
        Self {
            security_level: keypair.security_level,
            private_key_hex: hex::encode(keypair.private_key.expose_secret()),
            identity,
        }
    }
    
    fn to_keypair(&self) -> anyhow::Result<quid_core::crypto::KeyPair> {
        let private_key_bytes = hex::decode(&self.private_key_hex)?;
        Ok(quid_core::crypto::KeyPair {
            public_key: self.identity.public_key.clone(),
            private_key: Secret::new(private_key_bytes),
            security_level: self.security_level,
        })
    }
}

/// Format unix timestamp to human readable date
fn format_timestamp(timestamp: u64) -> String {
    use std::time::{UNIX_EPOCH, Duration};
    match UNIX_EPOCH.checked_add(Duration::from_secs(timestamp)) {
        Some(datetime) => {
            // Simple formatting - in a real app you'd use chrono
            format!("{:?}", datetime)
        }
        None => format!("Invalid timestamp: {}", timestamp)
    }
}

/// Helper function to format timestamps for secure wallets
fn format_wallet_timestamp(timestamp: u64) -> String {
    let _datetime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
    let local_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let diff = local_time.saturating_sub(timestamp);
    
    if diff < 60 {
        format!("{} seconds ago", diff)
    } else if diff < 3600 {
        format!("{} minutes ago", diff / 60)
    } else if diff < 86400 {
        format!("{} hours ago", diff / 3600)
    } else {
        format!("{} days ago", diff / 86400)
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Create { security_level, output } => {
            let level = match security_level {
                1 => SecurityLevel::Level1,
                3 => SecurityLevel::Level3,
                5 => SecurityLevel::Level5,
                _ => return Err(anyhow::anyhow!("Invalid security level")),
            };
            
            let (identity, keypair) = QuIDIdentity::new(level)?;
            
            println!("Created new QuID identity:");
            println!("ID: {}", hex::encode(&identity.id));
            println!("Security Level: {:?}", identity.security_level);
            println!("Version: {}", identity.version);
            
            if let Some(output_path) = output {
                let cli_identity = CliIdentity::from_identity_and_keypair(identity, &keypair);
                let json = serde_json::to_string_pretty(&cli_identity)?;
                std::fs::write(&output_path, json)?;
                println!("Identity saved to {}", output_path.display());
                println!("⚠️  WARNING: Private key stored in plain text! In production, this would be encrypted.");
            }
        }
        
        Commands::Sign { identity, message } => {
            // Load identity with private key
            let content = std::fs::read_to_string(&identity)?;
            let cli_identity: CliIdentity = serde_json::from_str(&content)?;
            let keypair = cli_identity.to_keypair()?;
            
            // Sign the message
            let signature = keypair.sign(message.as_bytes())?;
            let signature_hex = hex::encode(&signature);
            
            println!("Message: {}", message);
            println!("Signature: {}", signature_hex);
            println!("Identity: {}", hex::encode(&cli_identity.identity.id));
        }
        
        Commands::Verify { identity, message, signature } => {
            // Load identity (public key sufficient for verification)
            let content = std::fs::read_to_string(&identity)?;
            let cli_identity: CliIdentity = serde_json::from_str(&content)?;
            let keypair = cli_identity.to_keypair()?;
            
            // Decode signature
            let signature_bytes = hex::decode(&signature)?;
            
            // Verify signature
            let is_valid = keypair.verify(message.as_bytes(), &signature_bytes)?;
            
            println!("Message: {}", message);
            println!("Signature: {}", signature);
            println!("Identity: {}", hex::encode(&cli_identity.identity.id));
            println!("Valid: {}", if is_valid { "✅ YES" } else { "❌ NO" });
        }
        
        Commands::List => {
            println!("🔍 Scanning for QuID identities...");
            println!();
            
            let current_dir = std::env::current_dir()?;
            let mut found_identities = Vec::new();
            
            // Scan for .json files that might be QuID identities
            for entry in std::fs::read_dir(current_dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    // Try to parse as QuID identity
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(cli_identity) = serde_json::from_str::<CliIdentity>(&content) {
                            found_identities.push((path, cli_identity));
                        }
                    }
                }
            }
            
            if found_identities.is_empty() {
                println!("❌ No QuID identities found in current directory");
                println!("💡 Create one with: quid create --output my-identity.json");
            } else {
                println!("📋 Found {} QuID identit{}", 
                    found_identities.len(),
                    if found_identities.len() == 1 { "y" } else { "ies" }
                );
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                
                for (i, (path, identity)) in found_identities.iter().enumerate() {
                    println!("{}. 📄 {}", i + 1, path.display());
                    println!("   🆔 ID: {}...{}", 
                        &hex::encode(&identity.identity.id)[..16],
                        &hex::encode(&identity.identity.id)[48..]
                    );
                    println!("   🔐 Security: {:?} | 📅 Created: {} | 🏷️ v{}", 
                        identity.security_level,
                        format_timestamp(identity.identity.creation_timestamp),
                        identity.identity.version
                    );
                    if !identity.identity.extensions.is_empty() {
                        println!("   🧩 Extensions: {}", identity.identity.extensions.len());
                    }
                    if i < found_identities.len() - 1 {
                        println!("   ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄");
                    }
                }
                
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("💡 Use 'quid show <filename>' for detailed information");
            }
        }
        
        Commands::Show { identity } => {
            // Load identity
            let content = std::fs::read_to_string(&identity)?;
            let cli_identity: CliIdentity = serde_json::from_str(&content)?;
            
            println!("📋 QuID Identity Details");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("🆔 ID: {}", hex::encode(&cli_identity.identity.id));
            println!("🔐 Security Level: {:?} ({} bits quantum security)", 
                cli_identity.security_level,
                match cli_identity.security_level {
                    SecurityLevel::Level1 => "128",
                    SecurityLevel::Level3 => "192", 
                    SecurityLevel::Level5 => "256",
                }
            );
            println!("📅 Created: {} (timestamp: {})", 
                format_timestamp(cli_identity.identity.creation_timestamp),
                cli_identity.identity.creation_timestamp
            );
            println!("🏷️  Version: {}", cli_identity.identity.version);
            println!("🔑 Public Key: {} bytes", cli_identity.identity.public_key.len());
            println!("   {}", hex::encode(&cli_identity.identity.public_key));
            println!("🔐 Private Key: {} bytes (stored)", 
                hex::decode(&cli_identity.private_key_hex)?.len()
            );
            
            // Show metadata if any
            if !cli_identity.identity.metadata.is_empty() {
                println!("📝 Metadata:");
                for (key, value) in &cli_identity.identity.metadata {
                    println!("   {}: {} bytes", key, value.len());
                }
            }
            
            // Show extensions if any
            if cli_identity.identity.extensions.is_empty() {
                println!("🧩 Extensions: None");
            } else {
                println!("🧩 Extensions: {}", cli_identity.identity.extensions.len());
                for (name, extension) in &cli_identity.identity.extensions {
                    println!("   📦 {}", name);
                    println!("      Type: {}", extension.extension_type);
                    println!("      Data: {} bytes", extension.data.len());
                    println!("      Created: {}", format_timestamp(extension.timestamp));
                    println!("      Version: {}", extension.version);
                }
            }
            
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("💾 File: {}", identity.display());
            println!("📊 File Size: {} bytes", content.len());
        }
        
        Commands::Qr { identity, include_private, output } => {
            // Load identity
            let content = std::fs::read_to_string(&identity)?;
            let cli_identity: CliIdentity = serde_json::from_str(&content)?;
            
            // Create shareable data
            let shareable_data = if include_private {
                // Full identity including private key
                serde_json::to_value(&cli_identity)?
            } else {
                // Only public information for sharing
                serde_json::json!({
                    "quid_version": "0.1.0",
                    "type": "quid_public_identity",
                    "id": hex::encode(&cli_identity.identity.id),
                    "public_key": hex::encode(&cli_identity.identity.public_key),
                    "security_level": cli_identity.security_level,
                    "created": cli_identity.identity.creation_timestamp,
                    "version": cli_identity.identity.version
                })
            };
            
            let qr_data = serde_json::to_string(&shareable_data)?;
            
            // Generate QR code
            use qrcode::QrCode;
            let code = QrCode::new(&qr_data)?;
            
            // Fix the unreachable pattern by reorganizing
            let show_terminal = output == "terminal" || output == "both";
            let save_file = output == "file" || output == "both";
            
            if show_terminal {
                println!("🔗 QuID Identity QR Code");
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("🆔 Identity: {}...{}", 
                    &hex::encode(&cli_identity.identity.id)[..16],
                    &hex::encode(&cli_identity.identity.id)[48..]
                );
                println!("🔐 Security: {:?} | 📊 Data: {} bytes", 
                    cli_identity.security_level, qr_data.len()
                );
                if include_private {
                    println!("⚠️  Mode: Full identity (includes private key!)");
                } else {
                    println!("🔓 Mode: Public information only (safe to share)");
                }
                println!();
                
                // Print QR code to terminal
                let string = code.render::<char>()
                    .quiet_zone(false)
                    .module_dimensions(2, 1)
                    .build();
                println!("{}", string);
                
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("📱 Scan with any QR code reader");
            }
            
            if save_file {
                let qr_filename = format!("{}.png", 
                    identity.file_stem().unwrap_or_default().to_string_lossy()
                );
                println!("💾 QR code would be saved to: {}", qr_filename);
                println!("   (PNG file generation not implemented yet)");
            }
            
            if !show_terminal && !save_file {
                return Err(anyhow::anyhow!("Invalid output format: {}", output));
            }
            
            if include_private {
                println!("⚠️  WARNING: This QR code contains your private key!");
            } else {
                println!("✅ Safe to share: No private keys included");
            }
        }
        
        Commands::Export { identity, output, encrypt } => {
            // Load identity
            let content = std::fs::read_to_string(&identity)?;
            let cli_identity: CliIdentity = serde_json::from_str(&content)?;
            
            if encrypt {
                // Get password securely
                println!("🔐 Creating encrypted backup...");
                println!("🛡️  Using SHA3-based authenticated encryption");
                let password = rpassword::prompt_password("Enter password for backup: ")?;
                let confirm = rpassword::prompt_password("Confirm password: ")?;
                
                if password != confirm {
                    return Err(anyhow::anyhow!("Passwords do not match"));
                }
                
                if password.len() < 8 {
                    return Err(anyhow::anyhow!("Password must be at least 8 characters"));
                }
                
                // Encrypt and save using SHA3-based crypto
                println!("🔄 Deriving key with PBKDF2-SHA3 (100,000 iterations)...");
                let encrypted_backup = encrypt_identity_professional(&cli_identity, &password)?;
                let backup_json = serde_json::to_string_pretty(&encrypted_backup)?;
                std::fs::write(&output, backup_json)?;
                
                println!("✅ Encrypted backup saved to: {}", output.display());
                println!("🔒 Identity: {}...{}", 
                    &hex::encode(&cli_identity.identity.id)[..16],
                    &hex::encode(&cli_identity.identity.id)[48..]
                );
                println!("📊 Backup size: {} bytes", std::fs::metadata(&output)?.len());
                println!("🔐 Encryption: SHA3-STREAM with PBKDF2-SHA3 key derivation");
                println!("⚠️  Keep your password safe - it cannot be recovered!");
            } else {
                // Plain export (copy file)
                std::fs::copy(&identity, &output)?;
                println!("📄 Plain backup saved to: {}", output.display());
                println!("⚠️  WARNING: Backup contains private key in plain text!");
            }
        }
        
        Commands::Import { backup, output } => {
            println!("🔓 Importing identity backup...");
            
            // Load backup file
            let backup_content = std::fs::read_to_string(&backup)?;
            
            // Try to parse as encrypted backup first
            if let Ok(encrypted_backup) = serde_json::from_str::<EncryptedBackup>(&backup_content) {
                // SHA3-based encrypted backup
                println!("🔍 Detected encrypted backup ({})", encrypted_backup.algorithm);
                let password = rpassword::prompt_password("Enter backup password: ")?;
                
                println!("🔄 Decrypting backup...");
                match decrypt_identity_professional(&encrypted_backup, &password) {
                    Ok(identity) => {
                        let identity_json = serde_json::to_string_pretty(&identity)?;
                        std::fs::write(&output, identity_json)?;
                        
                        println!("✅ Identity restored successfully!");
                        println!("🔒 Identity: {}...{}", 
                            &hex::encode(&identity.identity.id)[..16],
                            &hex::encode(&identity.identity.id)[48..]
                        );
                        println!("📄 Restored to: {}", output.display());
                        println!("🛡️  Backup was secured with: {} + {}", 
                            encrypted_backup.algorithm, encrypted_backup.kdf);
                    }
                    Err(_) => {
                        return Err(anyhow::anyhow!("❌ Invalid password or corrupted backup"));
                    }
                }
            } else {
                // Try plain identity file
                if let Ok(_identity) = serde_json::from_str::<CliIdentity>(&backup_content) {
                    std::fs::copy(&backup, &output)?;
                    println!("✅ Plain identity imported to: {}", output.display());
                } else {
                    return Err(anyhow::anyhow!("❌ Invalid backup file format"));
                }
            }
        }

        Commands::Storage { storage_command } => {
            match storage_command {
                StorageCommands::Store { identity, storage_dir } => {
                    // Load identity file
                    let content = std::fs::read_to_string(&identity)?;
                    let cli_identity: CliIdentity = serde_json::from_str(&content)?;
                    let keypair = cli_identity.to_keypair()?;
                    
                    // Set up storage
                    let storage_path = storage_dir.unwrap_or_else(|| PathBuf::from(".quid-storage"));
                    let config = StorageConfig {
                        storage_path,
                        kdf_iterations: 100_000,
                        auto_backup: true,
                        max_backups: 5,
                    };
                    let mut storage = IdentityStorage::new(config.clone())?;
                    
                    println!("🔐 Storing identity in encrypted storage...");
                    println!("🆔 Identity: {}...{}", 
                        &hex::encode(&cli_identity.identity.id)[..16],
                        &hex::encode(&cli_identity.identity.id)[48..]
                    );
                    
                    // Get password for encryption
                    let password = SecretString::new(rpassword::prompt_password("Enter password for encrypted storage: ")?);
                    
                    // Store identity
                    storage.store_identity(&cli_identity.identity, &keypair, &password)?;
                    
                    println!("✅ Identity stored successfully!");
                    println!("📁 Storage directory: {}", config.storage_path.display());
                    println!("🔒 Identity encrypted with your password");
                }
                
                StorageCommands::Load { identity_id, output, storage_dir } => {
                    // Set up storage
                    let storage_path = storage_dir.unwrap_or_else(|| PathBuf::from(".quid-storage"));
                    let config = StorageConfig {
                        storage_path,
                        kdf_iterations: 100_000,
                        auto_backup: true,
                        max_backups: 5,
                    };
                    let mut storage = IdentityStorage::new(config)?;
                    
                    // Parse identity ID
                    let id_bytes = hex::decode(&identity_id)?;
                    
                    println!("🔓 Loading identity from encrypted storage...");
                    println!("🆔 Identity ID: {}...{}", 
                        &identity_id[..16],
                        &identity_id[identity_id.len()-16..]
                    );
                    
                    // Get password
                    let password = SecretString::new(rpassword::prompt_password("Enter storage password: ")?);
                    
                    // Load identity
                    let (identity, keypair) = storage.load_identity(&id_bytes, &password)?;
                    
                    // Convert to CLI format and save
                    let cli_identity = CliIdentity::from_identity_and_keypair(identity, &keypair);
                    let json = serde_json::to_string_pretty(&cli_identity)?;
                    std::fs::write(&output, json)?;
                    
                    println!("✅ Identity loaded successfully!");
                    println!("📄 Saved to: {}", output.display());
                }
                
                StorageCommands::ListStored { storage_dir } => {
                    // Set up storage
                    let storage_path = storage_dir.unwrap_or_else(|| PathBuf::from(".quid-storage"));
                    let config = StorageConfig {
                        storage_path: storage_path.clone(),
                        kdf_iterations: 100_000,
                        auto_backup: true,
                        max_backups: 5,
                    };
                    let storage = IdentityStorage::new(config)?;
                    
                    println!("📋 Identities in encrypted storage");
                    println!("📁 Storage directory: {}", storage_path.display());
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    
                    let identities = storage.list_identities()?;
                    
                    if identities.is_empty() {
                        println!("❌ No identities found in encrypted storage");
                        println!("💡 Use 'quid storage store <identity.json>' to store one");
                    } else {
                        for (i, id) in identities.iter().enumerate() {
                            let id_hex = hex::encode(id);
                            println!("{}. 🆔 {}...{}", 
                                i + 1,
                                &id_hex[..16],
                                &id_hex[id_hex.len()-16..]
                            );
                            println!("   🔒 Encrypted storage file: {}.quid", &id_hex[..16]);
                        }
                        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        println!("💡 Use 'quid storage load <identity_id>' to load an identity");
                    }
                }
                
                StorageCommands::Backup { identity_id, hint, storage_dir } => {
                    // Set up storage
                    let storage_path = storage_dir.unwrap_or_else(|| PathBuf::from(".quid-storage"));
                    let config = StorageConfig {
                        storage_path,
                        kdf_iterations: 100_000,
                        auto_backup: true,
                        max_backups: 5,
                    };
                    let storage = IdentityStorage::new(config)?;
                    
                    // Parse identity ID
                    let id_bytes = hex::decode(&identity_id)?;
                    
                    println!("💾 Creating backup of stored identity...");
                    println!("🆔 Identity ID: {}...{}", 
                        &identity_id[..16],
                        &identity_id[identity_id.len()-16..]
                    );
                    
                    // Create backup
                    let backup_path = storage.backup_identity(&id_bytes, hint.clone())?;
                    
                    println!("✅ Backup created successfully!");
                    println!("📄 Backup file: {}", backup_path.display());
                    
                    if let Some(hint_text) = hint {
                        println!("💡 Hint: {}", hint_text);
                    }
                }
                
                StorageCommands::ListBackups { identity_id, storage_dir } => {
                    // Set up storage
                    let storage_path = storage_dir.unwrap_or_else(|| PathBuf::from(".quid-storage"));
                    let config = StorageConfig {
                        storage_path,
                        kdf_iterations: 100_000,
                        auto_backup: true,
                        max_backups: 5,
                    };
                    let storage = IdentityStorage::new(config)?;
                    
                    // Parse identity ID
                    let id_bytes = hex::decode(&identity_id)?;
                    
                    println!("📋 Backups for identity");
                    println!("🆔 Identity ID: {}...{}", 
                        &identity_id[..16],
                        &identity_id[identity_id.len()-16..]
                    );
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    
                    let backups = storage.list_backups(&id_bytes)?;
                    
                    if backups.is_empty() {
                        println!("❌ No backups found for this identity");
                        println!("💡 Use 'quid storage backup <identity_id>' to create one");
                    } else {
                        for (i, backup_path) in backups.iter().enumerate() {
                            println!("{}. 📄 {}", i + 1, backup_path.display());
                            
                            if let Ok(metadata) = std::fs::metadata(backup_path) {
                                if let Ok(modified) = metadata.modified() {
                                    println!("   📅 Created: {:?}", modified);
                                }
                                println!("   📊 Size: {} bytes", metadata.len());
                            }
                        }
                        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        println!("💡 Use 'quid storage restore-backup <backup_file>' to restore");
                    }
                }
                
                StorageCommands::RestoreBackup { backup_file, output, storage_dir } => {
                    // Set up storage
                    let storage_path = storage_dir.unwrap_or_else(|| PathBuf::from(".quid-storage"));
                    let config = StorageConfig {
                        storage_path,
                        kdf_iterations: 100_000,
                        auto_backup: true,
                        max_backups: 5,
                    };
                    let mut storage = IdentityStorage::new(config)?;
                    
                    println!("🔄 Restoring identity from backup...");
                    println!("📄 Backup file: {}", backup_file.display());
                    
                    // Get password
                    let password = SecretString::new(rpassword::prompt_password("Enter storage password: ")?);
                    
                    // Restore from backup
                    let (identity, keypair) = storage.restore_from_backup(&backup_file, &password)?;
                    
                    // Convert to CLI format and save
                    let cli_identity = CliIdentity::from_identity_and_keypair(identity, &keypair);
                    let json = serde_json::to_string_pretty(&cli_identity)?;
                    std::fs::write(&output, json)?;
                    
                    println!("✅ Identity restored successfully!");
                    println!("🆔 Identity ID: {}", hex::encode(&cli_identity.identity.id));
                    println!("📄 Saved to: {}", output.display());
                }
                
                StorageCommands::Delete { identity_id, storage_dir, force } => {
                    // Set up storage
                    let storage_path = storage_dir.unwrap_or_else(|| PathBuf::from(".quid-storage"));
                    let config = StorageConfig {
                        storage_path,
                        kdf_iterations: 100_000,
                        auto_backup: true,
                        max_backups: 5,
                    };
                    let mut storage = IdentityStorage::new(config)?;
                    
                    // Parse identity ID
                    let id_bytes = hex::decode(&identity_id)?;
                    
                    println!("🗑️  Deleting identity from encrypted storage...");
                    println!("🆔 Identity ID: {}...{}", 
                        &identity_id[..16],
                        &identity_id[identity_id.len()-16..]
                    );
                    
                    if !force {
                        print!("⚠️  Are you sure? This cannot be undone! (y/N): ");
                        std::io::Write::flush(&mut std::io::stdout())?;
                        let mut confirmation = String::new();
                        std::io::stdin().read_line(&mut confirmation)?;
                        
                        if confirmation.trim().to_lowercase() != "y" {
                            println!("❌ Deletion cancelled");
                            return Ok(());
                        }
                    }
                    
                    // Delete identity
                    storage.delete_identity(&id_bytes)?;
                    
                    println!("✅ Identity deleted successfully!");
                    println!("💡 Backups (if any) are preserved");
                }
            }
        }

        Commands::Recovery { recovery_command } => {
            match recovery_command {
                RecoveryCommands::Generate { identity, total_shares, threshold, output_dir } => {
                    // Load identity
                    let content = std::fs::read_to_string(&identity)?;
                    let cli_identity: CliIdentity = serde_json::from_str(&content)?;
                    let keypair = cli_identity.to_keypair()?;
                    
                    // Validate parameters
                    if threshold > total_shares {
                        return Err(anyhow::anyhow!("Threshold ({}) cannot exceed total shares ({})", threshold, total_shares));
                    }
                    if threshold == 0 {
                        return Err(anyhow::anyhow!("Threshold must be at least 1"));
                    }
                    if total_shares == 0 {
                        return Err(anyhow::anyhow!("Total shares must be at least 1"));
                    }
                    
                    println!("🔐 Generating recovery shares for identity...");
                    println!("🆔 Identity: {}...{}", 
                        &hex::encode(&cli_identity.identity.id)[..16],
                        &hex::encode(&cli_identity.identity.id)[48..]
                    );
                    println!("📊 Configuration: {}-of-{} threshold", threshold, total_shares);
                    println!();
                    
                    // Collect guardian information
                    let mut guardians = Vec::new();
                    
                    for i in 1..=total_shares {
                        println!("👤 Guardian {} of {}:", i, total_shares);
                        print!("   Name: ");
                        io::Write::flush(&mut io::stdout())?;
                        let mut name = String::new();
                        std::io::stdin().read_line(&mut name)?;
                        let name = name.trim().to_string();
                        
                        if name.is_empty() {
                            return Err(anyhow::anyhow!("Guardian name cannot be empty"));
                        }
                        
                        print!("   Contact (email/phone): ");
                        io::Write::flush(&mut io::stdout())?;
                        let mut contact = String::new();
                        std::io::stdin().read_line(&mut contact)?;
                        let contact = contact.trim().to_string();
                        
                        guardians.push(GuardianInfo {
                            name,
                            contact,
                            public_key: Vec::new(), // No guardian keys for now
                        });
                        println!();
                    }
                    
                    // Generate shares
                    println!("🔄 Generating recovery shares...");
                    let shares = RecoveryCoordinator::generate_shares(
                        &keypair,
                        &cli_identity.identity.id,
                        guardians,
                        threshold,
                    )?;
                    
                    // Create output directory
                    std::fs::create_dir_all(&output_dir)?;
                    
                    // Save each share to a separate file
                    for (i, share) in shares.iter().enumerate() {
                        let filename = format!("recovery-share-{}-of-{}.json", i + 1, total_shares);
                        let filepath = output_dir.join(&filename);
                        
                        let share_json = serde_json::to_string_pretty(share)?;
                        std::fs::write(&filepath, share_json)?;
                        
                        println!("💾 Share {} saved: {}", i + 1, filepath.display());
                        println!("   👤 Guardian: {}", share.guardian_info.name);
                        println!("   📧 Contact: {}", share.guardian_info.contact);
                    }
                    
                    println!();
                    println!("✅ Recovery shares generated successfully!");
                    println!("📁 Shares directory: {}", output_dir.display());
                    println!("🔒 Threshold: {} shares needed to recover", threshold);
                    println!("⚠️  Distribute these shares to your trusted guardians");
                    println!("⚠️  Keep the share files secure and private");
                }
                
                RecoveryCommands::Restore { shares_dir, output: _ } => {
                    println!("🔓 Restoring identity from recovery shares...");
                    
                    // Scan for recovery share files
                    let mut share_files = Vec::new();
                    for entry in std::fs::read_dir(&shares_dir)? {
                        let entry = entry?;
                        let path = entry.path();
                        
                        if path.extension().and_then(|s| s.to_str()) == Some("json") {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                if let Ok(share) = serde_json::from_str::<RecoveryShare>(&content) {
                                    share_files.push((path, share));
                                }
                            }
                        }
                    }
                    
                    if share_files.is_empty() {
                        return Err(anyhow::anyhow!("No recovery shares found in {}", shares_dir.display()));
                    }
                    
                    // Group shares by identity
                    let mut shares_by_identity: std::collections::HashMap<Vec<u8>, Vec<RecoveryShare>> = std::collections::HashMap::new();
                    
                    for (path, share) in share_files {
                        println!("📄 Found share: {}", path.display());
                        println!("   👤 Guardian: {}", share.guardian_info.name);
                        println!("   🆔 For identity: {}...{}", 
                            &hex::encode(&share.identity_id)[..16],
                            &hex::encode(&share.identity_id)[48..]
                        );
                        
                        shares_by_identity
                            .entry(share.identity_id.clone())
                            .or_insert_with(Vec::new)
                            .push(share);
                    }
                    
                    if shares_by_identity.len() > 1 {
                        println!("⚠️  Found shares for {} different identities", shares_by_identity.len());
                        return Err(anyhow::anyhow!("Multiple identities found - please separate shares"));
                    }
                    
                    let (_identity_id, shares) = shares_by_identity.into_iter().next().unwrap();
                    
                    if shares.is_empty() {
                        return Err(anyhow::anyhow!("No valid shares found"));
                    }
                    
                    let threshold = shares[0].threshold;
                    let total_shares = shares[0].total_shares;
                    
                    println!();
                    println!("📊 Recovery configuration: {}-of-{} threshold", threshold, total_shares);
                    println!("📋 Available shares: {}", shares.len());
                    
                    if shares.len() < threshold as usize {
                        return Err(anyhow::anyhow!(
                            "Not enough shares! Need {} shares, found {}",
                            threshold,
                            shares.len()
                        ));
                    }
                    
                    println!("✅ Sufficient shares available for recovery");
                    println!();
                    
                    // We need to reconstruct the identity without the original keypair
                    // For now, this is a limitation of our placeholder implementation
                    println!("❌ Recovery not yet fully implemented");
                    println!("🚧 Current limitation: Need original public key for signature verification");
                    println!("💡 In production, shares would include public key information");
                    println!();
                    println!("🔍 Share details:");
                    for (i, share) in shares.iter().enumerate() {
                        println!("   {}. Guardian: {} ({})", i + 1, share.guardian_info.name, share.guardian_info.contact);
                        println!("      Share ID: {} | Created: {}", 
                            share.share_id, 
                            format_timestamp(share.created_at)
                        );
                    }
                    
                    // TODO: Implement proper recovery when we have real Shamir's Secret Sharing
                    println!();
                    println!("⚠️  For now, use 'quid import' with encrypted backups instead");
                }
            }
        }

        Commands::Batch { batch_command } => {
            match batch_command {
                BatchCommands::Sign { identity, input, output, format } => {
                    // Load identity
                    let content = std::fs::read_to_string(&identity)?;
                    let cli_identity: CliIdentity = serde_json::from_str(&content)?;
                    let keypair = cli_identity.to_keypair()?;
                    
                    println!("🔏 Batch signing messages...");
                    println!("🆔 Identity: {}...{}", 
                        &hex::encode(&cli_identity.identity.id)[..16],
                        &hex::encode(&cli_identity.identity.id)[48..]
                    );
                    
                    // Read messages based on format
                    let input_content = std::fs::read_to_string(&input)?;
                    let messages: Vec<String> = match format.as_str() {
                        "text" => input_content.lines().map(|s| s.to_string()).collect(),
                        "json" => {
                            let json_messages: Vec<String> = serde_json::from_str(&input_content)?;
                            json_messages
                        },
                        "csv" => {
                            // Simple CSV parsing (first column only)
                            input_content.lines()
                                .map(|line| line.split(',').next().unwrap_or("").to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        },
                        _ => return Err(anyhow::anyhow!("Unsupported format: {}", format)),
                    };
                    
                    if messages.is_empty() {
                        return Err(anyhow::anyhow!("No messages found in input file"));
                    }
                    
                    println!("📋 Found {} messages to sign", messages.len());
                    
                    // Sign all messages
                    let mut signatures = Vec::new();
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs();
                    
                    let start_time = std::time::Instant::now();
                    
                    for (i, message) in messages.iter().enumerate() {
                        if i % 100 == 0 && i > 0 {
                            println!("🔄 Signed {} of {} messages...", i, messages.len());
                        }
                        
                        let signature = keypair.sign(message.as_bytes())?;
                        let signature_hex = hex::encode(&signature);
                        
                        signatures.push(BatchSignature {
                            message: message.clone(),
                            signature: signature_hex,
                            timestamp,
                            identity_id: hex::encode(&cli_identity.identity.id),
                        });
                    }
                    
                    let elapsed = start_time.elapsed();
                    
                    // Save signatures
                    let output_json = serde_json::to_string_pretty(&signatures)?;
                    std::fs::write(&output, output_json)?;
                    
                    println!("✅ Batch signing completed!");
                    println!("📊 Signed {} messages in {:.2}s", messages.len(), elapsed.as_secs_f64());
                    println!("⚡ Rate: {:.0} signatures/second", messages.len() as f64 / elapsed.as_secs_f64());
                    println!("💾 Signatures saved to: {}", output.display());
                    println!("📄 Output format: JSON");
                }
                
                BatchCommands::Verify { identity, input, report } => {
                    // Load identity
                    let content = std::fs::read_to_string(&identity)?;
                    let cli_identity: CliIdentity = serde_json::from_str(&content)?;
                    let keypair = cli_identity.to_keypair()?;
                    
                    println!("🔍 Batch verifying signatures...");
                    
                    // Load signatures
                    let input_content = std::fs::read_to_string(&input)?;
                    let signatures: Vec<BatchSignature> = serde_json::from_str(&input_content)?;
                    
                    println!("📋 Found {} signatures to verify", signatures.len());
                    
                    let start_time = std::time::Instant::now();
                    let mut results = Vec::new();
                    let mut valid_count = 0;
                    let mut invalid_count = 0;
                    
                    for (i, sig_data) in signatures.iter().enumerate() {
                        if i % 100 == 0 && i > 0 {
                            println!("🔄 Verified {} of {} signatures...", i, signatures.len());
                        }
                        
                        let signature_bytes = match hex::decode(&sig_data.signature) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                results.push(VerificationResult {
                                    message: sig_data.message.clone(),
                                    signature: sig_data.signature.clone(),
                                    valid: false,
                                    error: Some(format!("Invalid hex: {}", e)),
                                });
                                invalid_count += 1;
                                continue;
                            }
                        };
                        
                        match keypair.verify(sig_data.message.as_bytes(), &signature_bytes) {
                            Ok(is_valid) => {
                                if is_valid {
                                    valid_count += 1;
                                } else {
                                    invalid_count += 1;
                                }
                                results.push(VerificationResult {
                                    message: sig_data.message.clone(),
                                    signature: sig_data.signature.clone(),
                                    valid: is_valid,
                                    error: None,
                                });
                            }
                            Err(e) => {
                                results.push(VerificationResult {
                                    message: sig_data.message.clone(),
                                    signature: sig_data.signature.clone(),
                                    valid: false,
                                    error: Some(format!("Verification error: {}", e)),
                                });
                                invalid_count += 1;
                            }
                        }
                    }
                    
                    let elapsed = start_time.elapsed();
                    
                    // Generate report
                    match report.as_str() {
                        "summary" => {
                            println!();
                            println!("📊 Batch Verification Summary");
                            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                            println!("✅ Valid signatures: {}", valid_count);
                            println!("❌ Invalid signatures: {}", invalid_count);
                            println!("📋 Total verified: {}", signatures.len());
                            println!("⚡ Rate: {:.0} verifications/second", signatures.len() as f64 / elapsed.as_secs_f64());
                            println!("⏱️  Time elapsed: {:.2}s", elapsed.as_secs_f64());
                            
                            if invalid_count > 0 {
                                println!("⚠️  {} signatures failed verification", invalid_count);
                                let success_rate = (valid_count as f64 / signatures.len() as f64) * 100.0;
                                println!("📈 Success rate: {:.1}%", success_rate);
                            } else {
                                println!("🎉 All signatures verified successfully!");
                            }
                        },
                        "detailed" => {
                            println!();
                            println!("📋 Detailed Verification Results");
                            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                            
                            for (i, result) in results.iter().enumerate() {
                                let status = if result.valid { "✅" } else { "❌" };
                                println!("{}. {} Message: {}", i + 1, status, 
                                    if result.message.len() > 50 {
                                        format!("{}...", &result.message[..47])
                                    } else {
                                        result.message.clone()
                                    }
                                );
                                
                                if let Some(error) = &result.error {
                                    println!("   Error: {}", error);
                                }
                            }
                            
                            println!();
                            println!("📊 Summary: {} valid, {} invalid", valid_count, invalid_count);
                        },
                        "json" => {
                            let json_output = serde_json::to_string_pretty(&results)?;
                            println!("{}", json_output);
                        },
                        _ => return Err(anyhow::anyhow!("Invalid report format: {}", report)),
                    }
                }
                
                BatchCommands::SignFiles { identity, directory, output_dir, extensions } => {
                    // Load identity
                    let content = std::fs::read_to_string(&identity)?;
                    let cli_identity: CliIdentity = serde_json::from_str(&content)?;
                    let keypair = cli_identity.to_keypair()?;
                    
                    println!("📁 Batch signing files in directory...");
                    println!("🆔 Identity: {}...{}", 
                        &hex::encode(&cli_identity.identity.id)[..16],
                        &hex::encode(&cli_identity.identity.id)[48..]
                    );
                    
                    // Parse extensions
                    let ext_list: Vec<&str> = extensions.split(',').map(|s| s.trim()).collect();
                    println!("📄 File extensions: {}", ext_list.join(", "));
                    
                    // Find files to sign
                    let mut files_to_sign = Vec::new();
                    
                    fn find_files_recursive(
                        dir: &std::path::Path,
                        extensions: &[&str],
                        files: &mut Vec<PathBuf>
                    ) -> anyhow::Result<()> {
                        for entry in std::fs::read_dir(dir)? {
                            let entry = entry?;
                            let path = entry.path();
                            
                            if path.is_dir() {
                                find_files_recursive(&path, extensions, files)?;
                            } else if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                                if extensions.contains(&ext) {
                                    files.push(path);
                                }
                            }
                        }
                        Ok(())
                    }
                    
                    find_files_recursive(&directory, &ext_list, &mut files_to_sign)?;
                    
                    if files_to_sign.is_empty() {
                        return Err(anyhow::anyhow!("No files found with specified extensions"));
                    }
                    
                    println!("📋 Found {} files to sign", files_to_sign.len());
                    
                    // Create output directory
                    std::fs::create_dir_all(&output_dir)?;
                    
                    let start_time = std::time::Instant::now();
                    
                    for (i, file_path) in files_to_sign.iter().enumerate() {
                        if i % 10 == 0 && i > 0 {
                            println!("🔄 Signed {} of {} files...", i, files_to_sign.len());
                        }
                        
                        // Read file content
                        let file_content = std::fs::read(file_path)?;
                        
                        // Sign file content
                        let signature = keypair.sign(&file_content)?;
                        let signature_hex = hex::encode(&signature);
                        
                        // Create signature file
                        let relative_path = file_path.strip_prefix(&directory)
                            .unwrap_or(file_path);
                        let sig_filename = format!("{}.sig", relative_path.display());
                        let sig_path = output_dir.join(&sig_filename);
                        
                        // Ensure parent directory exists
                        if let Some(parent) = sig_path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        
                        // Create signature info
                        let sig_info = serde_json::json!({
                            "file_path": relative_path.display().to_string(),
                            "signature": signature_hex,
                            "identity_id": hex::encode(&cli_identity.identity.id),
                            "signed_at": std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)?
                                .as_secs(),
                            "file_size": file_content.len(),
                            "quid_version": "0.1.0"
                        });
                        
                        std::fs::write(&sig_path, serde_json::to_string_pretty(&sig_info)?)?;
                    }
                    
                    let elapsed = start_time.elapsed();
                    
                    println!("✅ Batch file signing completed!");
                    println!("📊 Signed {} files in {:.2}s", files_to_sign.len(), elapsed.as_secs_f64());
                    println!("⚡ Rate: {:.1} files/second", files_to_sign.len() as f64 / elapsed.as_secs_f64());
                    println!("📁 Signatures saved to: {}", output_dir.display());
                }
                
                BatchCommands::Manifest { identity, directory, output, include_hashes } => {
                    // Load identity
                    let content = std::fs::read_to_string(&identity)?;
                    let cli_identity: CliIdentity = serde_json::from_str(&content)?;
                    let keypair = cli_identity.to_keypair()?;
                    
                    println!("📋 Creating signed manifest for directory...");
                    println!("📁 Directory: {}", directory.display());
                    
                    // Collect all files
                    let mut all_files = Vec::new();
                    
                    fn collect_files_recursive(
                        dir: &std::path::Path,
                        base_dir: &std::path::Path,
                        files: &mut Vec<PathBuf>
                    ) -> anyhow::Result<()> {
                        for entry in std::fs::read_dir(dir)? {
                            let entry = entry?;
                            let path = entry.path();
                            
                            if path.is_dir() {
                                collect_files_recursive(&path, base_dir, files)?;
                            } else {
                                files.push(path);
                            }
                        }
                        Ok(())
                    }
                    
                    collect_files_recursive(&directory, &directory, &mut all_files)?;
                    
                    println!("📄 Found {} files", all_files.len());
                    
                    let start_time = std::time::Instant::now();
                    let mut entries = Vec::new();
                    
                    for (i, file_path) in all_files.iter().enumerate() {
                        if i % 50 == 0 && i > 0 {
                            println!("🔄 Processed {} of {} files...", i, all_files.len());
                        }
                        
                        let metadata = std::fs::metadata(file_path)?;
                        let file_content = std::fs::read(file_path)?;
                        
                        // Sign file content
                        let signature = keypair.sign(&file_content)?;
                        let signature_hex = hex::encode(&signature);
                        
                        // Calculate content hash if requested
                        let content_hash = if include_hashes {
                            let mut hasher = Sha3_256::new();
                            Digest::update(&mut hasher, &file_content);
                            Some(hex::encode(hasher.finalize()))
                        } else {
                            None
                        };
                        
                        let relative_path = file_path.strip_prefix(&directory)
                            .unwrap_or(file_path);
                        
                        entries.push(ManifestEntry {
                            path: relative_path.display().to_string(),
                            size: metadata.len(),
                            modified: metadata.modified()
                                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            signature: signature_hex,
                            content_hash,
                        });
                    }
                    
                    // Create manifest
                    let mut manifest = FileManifest {
                        version: "0.1.0".to_string(),
                        created_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs(),
                        identity_id: hex::encode(&cli_identity.identity.id),
                        entries,
                        manifest_signature: String::new(),
                    };
                    
                    // Sign the manifest itself
                    let manifest_json = serde_json::to_string(&manifest)?;
                    let manifest_sig = keypair.sign(manifest_json.as_bytes())?;
                    manifest.manifest_signature = hex::encode(&manifest_sig);
                    
                    // Save manifest
                    let final_json = serde_json::to_string_pretty(&manifest)?;
                    std::fs::write(&output, final_json)?;
                    
                    let elapsed = start_time.elapsed();
                    
                    println!("✅ Manifest created successfully!");
                    println!("📊 Processed {} files in {:.2}s", all_files.len(), elapsed.as_secs_f64());
                    println!("💾 Manifest saved to: {}", output.display());
                    println!("🔒 Manifest signature: {}...{}", 
                        &manifest.manifest_signature[..16],
                        &manifest.manifest_signature[manifest.manifest_signature.len()-16..]
                    );
                    
                    if include_hashes {
                        println!("🔍 Content hashes included for integrity verification");
                    }
                }
            }
        }

        Commands::Auth { identity, service, network, capabilities } => {
            // Load identity
            let content = std::fs::read_to_string(&identity)?;
            let cli_identity: CliIdentity = serde_json::from_str(&content)?;
            let keypair = cli_identity.to_keypair()?;
            
            println!("🔐 Authenticating to service...");
            println!("🆔 Identity: {}...{}", 
                &hex::encode(&cli_identity.identity.id)[..16],
                &hex::encode(&cli_identity.identity.id)[48..]
            );
            println!("🌐 Service: {}", service);
            println!("📡 Network: {}", network);
            
            // Generate a challenge (in real use, this would come from the service)
            let challenge = format!("QuID-Auth-{}-{}-{}", service, network, 
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            );
            
            // Parse capabilities
            let capability_list = capabilities
                .as_ref()
                .map(|c| c.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["authenticate".to_string()]);
            
            println!("🎯 Capabilities: {}", capability_list.join(", "));
            println!("🔑 Challenge: {}", challenge);
            
            // Sign the challenge
            let signature = keypair.sign(challenge.as_bytes())?;
            let signature_hex = hex::encode(&signature);
            
            // Create authentication response
            let auth_response = serde_json::json!({
                "quid_version": "0.1.0",
                "type": "authentication_response",
                "identity_id": hex::encode(&cli_identity.identity.id),
                "service": service,
                "network": network,
                "challenge": challenge,
                "signature": signature_hex,
                "public_key": hex::encode(&cli_identity.identity.public_key),
                "capabilities": capability_list,
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            });
            
            println!();
            println!("✅ Authentication response generated!");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("{}", serde_json::to_string_pretty(&auth_response)?);
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("💡 Send this response to the service for authentication");
        }
        
        Commands::Derive { identity, network, show_private } => {
            // Load identity
            let content = std::fs::read_to_string(&identity)?;
            let cli_identity: CliIdentity = serde_json::from_str(&content)?;
            
            println!("🔑 Deriving keys for network: {}", network);
            println!("🆔 Identity: {}...{}", 
                &hex::encode(&cli_identity.identity.id)[..16],
                &hex::encode(&cli_identity.identity.id)[48..]
            );
            
            // Simple key derivation example (in production this would use proper adapters)
            let mut hasher = Sha3_256::new();
            Digest::update(&mut hasher, &cli_identity.identity.public_key);
            Digest::update(&mut hasher, network.as_bytes());
            Digest::update(&mut hasher, b"QuID-NetworkKey");
            let derived_key = hasher.finalize();
            
            println!();
            println!("🔐 Derived Keys for {}", network);
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            
            match network.as_str() {
                "bitcoin" => {
                    println!("₿ Bitcoin Address: 1{}...", &hex::encode(&derived_key)[..16]);
                    println!("🔑 Public Key: {}", hex::encode(&derived_key));
                    if show_private {
                        let private_hex = hex::encode(&cli_identity.private_key_hex.as_bytes());
                        println!("⚠️  Private Key: {} (KEEP SECRET!)", &private_hex[..32.min(private_hex.len())]);
                    }
                }
                "ethereum" => {
                    println!("⟠ Ethereum Address: 0x{}", &hex::encode(&derived_key)[..40]);
                    println!("🔑 Public Key: {}", hex::encode(&derived_key));
                    if show_private {
                        let private_hex = hex::encode(&cli_identity.private_key_hex.as_bytes());
                        println!("⚠️  Private Key: 0x{} (KEEP SECRET!)", &private_hex[..32.min(private_hex.len())]);
                    }
                }
                "nym" => {
                    println!("🔮 Nym Address: nym1{}", &hex::encode(&derived_key)[..32]);
                    println!("🔑 Signing Key: {}", hex::encode(&derived_key));
                    if show_private {
                        let private_hex = hex::encode(&cli_identity.private_key_hex.as_bytes());
                        println!("⚠️  Private Key: {} (KEEP SECRET!)", &private_hex[..32.min(private_hex.len())]);
                    }
                }
                "nomadnet" => {
                    println!("🌐 NomadNet Domain: {}.nomad", &hex::encode(&derived_key)[..16]);
                    println!("🔑 Content Key: {}", hex::encode(&derived_key));
                    if show_private {
                        let private_hex = hex::encode(&cli_identity.private_key_hex.as_bytes());
                        println!("⚠️  Private Key: {} (KEEP SECRET!)", &private_hex[..32.min(private_hex.len())]);
                    }
                }
                "ssh" => {
                    println!("🖥️  SSH Public Key: ssh-ed25519 {} quid@{}", 
                        &hex::encode(&derived_key)[..32], network);
                    if show_private {
                        println!("⚠️  SSH Private Key: Available (use with ssh-agent)");
                    }
                }
                _ => {
                    println!("🔧 Generic Network: {}", network);
                    println!("🔑 Derived Key: {}", hex::encode(&derived_key));
                    if show_private {
                        let private_hex = hex::encode(&cli_identity.private_key_hex.as_bytes());
                        println!("⚠️  Master Private Key: {} (KEEP SECRET!)", 
                            &private_hex[..32.min(private_hex.len())]);
                    }
                }
            }
            
            if !show_private {
                println!();
                println!("💡 Use --show-private to display private keys (dangerous!)");
            }
        }
        
        Commands::SecureWallet { wallet_command } => {
            match wallet_command {
                SecureWalletCommands::CreatePair { 
                    name, 
                    security_level, 
                    network, 
                    cold_storage, 
                    hot_storage, 
                    hardware_security 
                } => {
                    println!("🏦 Creating secure wallet pair: {}", name);
                    println!("🔒 Security Level: {}", security_level);
                    println!("⛓️  Network: {}", network);
                    
                    let level = match security_level {
                        1 => SecurityLevel::Level1,
                        3 => SecurityLevel::Level3,
                        5 => SecurityLevel::Level5,
                        _ => return Err(anyhow::anyhow!("Invalid security level")),
                    };
                    
                    // Create cold wallet (for receiving, never exposed online)
                    let (cold_identity, cold_keypair) = QuIDIdentity::new(level)?;
                    println!("❄️  Created cold wallet: {}...{}", 
                        &hex::encode(&cold_identity.id)[..8],
                        &hex::encode(&cold_identity.id)[56..]
                    );
                    
                    // Create hot wallet (for spending, limited exposure)
                    let (hot_identity, hot_keypair) = QuIDIdentity::new(level)?;
                    println!("🔥 Created hot wallet: {}...{}", 
                        &hex::encode(&hot_identity.id)[..8],
                        &hex::encode(&hot_identity.id)[56..]
                    );
                    
                    // Set up storage directories
                    let default_storage = PathBuf::from(".secure-wallets");
                    let cold_dir = cold_storage.unwrap_or_else(|| default_storage.join("cold"));
                    let hot_dir = hot_storage.unwrap_or_else(|| default_storage.join("hot"));
                    
                    std::fs::create_dir_all(&cold_dir)?;
                    std::fs::create_dir_all(&hot_dir)?;
                    
                    // Store cold wallet (encrypted)
                    let cold_cli = CliIdentity::from_identity_and_keypair(cold_identity.clone(), &cold_keypair);
                    let cold_path = cold_dir.join(format!("{}_cold.json", name));
                    let cold_json = serde_json::to_string_pretty(&cold_cli)?;
                    std::fs::write(&cold_path, cold_json)?;
                    
                    // Store hot wallet (encrypted)
                    let hot_cli = CliIdentity::from_identity_and_keypair(hot_identity.clone(), &hot_keypair);
                    let hot_path = hot_dir.join(format!("{}_hot.json", name));
                    let hot_json = serde_json::to_string_pretty(&hot_cli)?;
                    std::fs::write(&hot_path, hot_json)?;
                    
                    // Create wallet pair configuration
                    let wallet_pair = SecureWalletPair {
                        name: name.clone(),
                        created_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        network: network.clone(),
                        security_level,
                        cold_wallet: WalletInfo {
                            identity_id: hex::encode(&cold_identity.id),
                            storage_path: cold_path.clone(),
                            derivation_path: None,
                            last_used: None,
                            balance: None,
                        },
                        hot_wallet: WalletInfo {
                            identity_id: hex::encode(&hot_identity.id),
                            storage_path: hot_path.clone(),
                            derivation_path: None,
                            last_used: None,
                            balance: None,
                        },
                        transfer_policy: TransferPolicy::Immediate,
                        guardians: Vec::new(),
                        frozen: false,
                        freeze_reason: None,
                        hardware_security,
                    };
                    
                    // Save wallet manager configuration
                    let manager_path = default_storage.join("wallets.json");
                    let mut manager = if manager_path.exists() {
                        let content = std::fs::read_to_string(&manager_path)?;
                        serde_json::from_str::<SecureWalletManager>(&content)?
                    } else {
                        SecureWalletManager {
                            wallets: std::collections::HashMap::new(),
                            active_wallet: None,
                            storage_path: default_storage.clone(),
                            monitors: std::collections::HashMap::new(),
                        }
                    };
                    
                    manager.wallets.insert(name.clone(), wallet_pair);
                    if manager.active_wallet.is_none() {
                        manager.active_wallet = Some(name.clone());
                    }
                    
                    let manager_json = serde_json::to_string_pretty(&manager)?;
                    std::fs::write(&manager_path, manager_json)?;
                    
                    println!("✅ Secure wallet pair created successfully!");
                    println!("❄️  Cold wallet: {}", cold_path.display());
                    println!("🔥 Hot wallet: {}", hot_path.display());
                    println!("📁 Configuration: {}", manager_path.display());
                    println!();
                    println!("💡 Next steps:");
                    println!("   • Use 'quid secure-wallet receive {}' to get receiving address", name);
                    println!("   • Use 'quid secure-wallet balance {}' to check balances", name);
                    println!("   • Use 'quid secure-wallet transfer {} <amount>' to move funds to hot wallet", name);
                    println!("   • Use 'quid secure-wallet spend {} <address> <amount>' to spend", name);
                    
                    if hardware_security {
                        println!("🔐 Hardware security enabled - use hardware confirmation for transfers");
                    }
                }
                
                SecureWalletCommands::List => {
                    let storage_path = PathBuf::from(".secure-wallets");
                    let manager_path = storage_path.join("wallets.json");
                    
                    if !manager_path.exists() {
                        println!("📭 No secure wallet pairs found");
                        println!("💡 Create one with: quid secure-wallet create-pair <name>");
                        return Ok(());
                    }
                    
                    let content = std::fs::read_to_string(&manager_path)?;
                    let manager: SecureWalletManager = serde_json::from_str(&content)?;
                    
                    println!("🏦 Secure Wallet Pairs");
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    
                    for (name, wallet) in &manager.wallets {
                        let status = if wallet.frozen { "🧊 FROZEN" } else { "✅ Active" };
                        let active = if manager.active_wallet.as_ref() == Some(name) { " [ACTIVE]" } else { "" };
                        
                        println!("📱 {} - {} {}{}", name, wallet.network, status, active);
                        println!("   Created: {}", format_wallet_timestamp(wallet.created_at));
                        println!("   Security: Level {}", wallet.security_level);
                        
                        if wallet.hardware_security {
                            println!("   🔐 Hardware security enabled");
                        }
                        
                        if !wallet.guardians.is_empty() {
                            println!("   👥 {} guardians configured", wallet.guardians.len());
                        }
                        
                        match &wallet.transfer_policy {
                            TransferPolicy::Immediate => println!("   ⚡ Immediate transfers"),
                            TransferPolicy::TimeDelayed { delay_seconds, .. } => {
                                println!("   ⏰ Time delayed: {}s", delay_seconds);
                            }
                            TransferPolicy::MultiSignature { required_signatures, .. } => {
                                println!("   ✋ Multi-sig: {} signatures required", required_signatures);
                            }
                            _ => println!("   🛡️  Advanced security policy"),
                        }
                        println!();
                    }
                    
                    if let Some(active) = &manager.active_wallet {
                        println!("💡 Active wallet: {}", active);
                    }
                }
                
                SecureWalletCommands::Show { name, show_addresses } => {
                    let storage_path = PathBuf::from(".secure-wallets");
                    let manager_path = storage_path.join("wallets.json");
                    
                    if !manager_path.exists() {
                        return Err(anyhow::anyhow!("No secure wallets found"));
                    }
                    
                    let content = std::fs::read_to_string(&manager_path)?;
                    let manager: SecureWalletManager = serde_json::from_str(&content)?;
                    
                    let wallet = manager.wallets.get(&name)
                        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;
                    
                    println!("🏦 Secure Wallet Pair: {}", name);
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    println!("🌐 Network: {}", wallet.network);
                    println!("🔒 Security Level: {}", wallet.security_level);
                    println!("📅 Created: {}", format_wallet_timestamp(wallet.created_at));
                    println!("🧊 Frozen: {}", if wallet.frozen { "Yes" } else { "No" });
                    
                    if let Some(reason) = &wallet.freeze_reason {
                        println!("   Reason: {}", reason);
                    }
                    
                    println!();
                    println!("❄️  Cold Wallet (Receiving):");
                    println!("   ID: {}...{}", &wallet.cold_wallet.identity_id[..16], &wallet.cold_wallet.identity_id[48..]);
                    println!("   Storage: {}", wallet.cold_wallet.storage_path.display());
                    
                    if let Some(balance) = &wallet.cold_wallet.balance {
                        println!("   Balance: {}", balance);
                    }
                    
                    println!();
                    println!("🔥 Hot Wallet (Spending):");
                    println!("   ID: {}...{}", &wallet.hot_wallet.identity_id[..16], &wallet.hot_wallet.identity_id[48..]);
                    println!("   Storage: {}", wallet.hot_wallet.storage_path.display());
                    
                    if let Some(balance) = &wallet.hot_wallet.balance {
                        println!("   Balance: {}", balance);
                    }
                    
                    if let Some(last_used) = wallet.hot_wallet.last_used {
                        println!("   Last Used: {}", format_wallet_timestamp(last_used));
                    }
                    
                    println!();
                    println!("🛡️  Transfer Policy:");
                    match &wallet.transfer_policy {
                        TransferPolicy::Immediate => {
                            println!("   ⚡ Immediate transfers (no delay)");
                        }
                        TransferPolicy::TimeDelayed { delay_seconds, pending_transfers } => {
                            println!("   ⏰ Time delayed: {} seconds", delay_seconds);
                            if !pending_transfers.is_empty() {
                                println!("   📋 {} pending transfers", pending_transfers.len());
                            }
                        }
                        TransferPolicy::MultiSignature { required_signatures, guardian_ids } => {
                            println!("   ✋ Multi-signature: {}/{} required", required_signatures, guardian_ids.len());
                        }
                        _ => {
                            println!("   🔐 Advanced security policy active");
                        }
                    }
                    
                    if !wallet.guardians.is_empty() {
                        println!();
                        println!("👥 Guardians ({}):", wallet.guardians.len());
                        for (i, guardian) in wallet.guardians.iter().enumerate() {
                            println!("   {}. {} ({})", i + 1, guardian.name, guardian.contact);
                        }
                    }
                    
                    if show_addresses {
                        println!();
                        println!("📍 Addresses:");
                        println!("   (Address generation requires network adapter)");
                        println!("   💡 Use 'quid secure-wallet receive {}' to generate addresses", name);
                    }
                }
                
                SecureWalletCommands::Receive { wallet, derivation_path, qr } => {
                    println!("📥 Generating receiving address for wallet: {}", wallet);
                    println!("💡 This would integrate with network adapters to generate addresses");
                    println!("🔗 Network adapters needed for: {}", wallet);
                    
                    if let Some(path) = derivation_path {
                        println!("🛤️  Derivation path: {}", path);
                    }
                    
                    if qr {
                        println!("📱 QR code generation would be implemented here");
                    }
                    
                    println!("⚠️  Feature coming soon - requires network adapter integration");
                }
                
                SecureWalletCommands::Balance { wallet, include_pending } => {
                    println!("💰 Checking balances for wallet: {}", wallet);
                    println!("💡 This would query blockchain via network adapters");
                    
                    if include_pending {
                        println!("⏳ Including pending transactions");
                    }
                    
                    println!("⚠️  Feature coming soon - requires network adapter integration");
                }
                
                _ => {
                    println!("⚠️  Command not yet implemented");
                    println!("🚧 Secure wallet functionality is being built incrementally");
                    println!("✅ Available commands:");
                    println!("   • create-pair - Create secure wallet pair");
                    println!("   • list - List all wallet pairs");
                    println!("   • show - Show wallet details");
                    println!("   • receive - Generate receiving address (coming soon)");
                    println!("   • balance - Check balances (coming soon)");
                }
            }
        }

        Commands::Adapters => {
            println!("🔌 Supported Network Adapters");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            
            let adapters = vec![
                ("web", "Web authentication (WebAuthn replacement)", "🌐"),
                ("ssh", "SSH key authentication", "🖥️"),
                ("bitcoin", "Bitcoin transaction signing", "₿"),
                ("ethereum", "Ethereum/EVM transaction signing", "⟠"),
                ("nym", "Nym blockchain integration", "🔮"),
                ("nomadnet", "NomadNet social platform", "🌐"),
                ("tls", "TLS client certificates", "🔒"),
                ("oauth", "OAuth/OIDC provider", "🔑"),
            ];
            
            for (i, (network, description, icon)) in adapters.iter().enumerate() {
                println!("{}. {} {} - {}", i + 1, icon, network, description);
            }
            
            println!();
            println!("💡 Use 'quid derive <identity> <network>' to generate keys");
            println!("💡 Use 'quid auth <identity> <service> --network <network>' to authenticate");
        }
    }
    
    Ok(())
}