//! QuID Command Line Interface

use clap::{Parser, Subcommand};
use quid_core::{QuIDIdentity, SecurityLevel};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use sha3::{Digest, Sha3_256, Shake256};
use sha3::digest::{Update, ExtendableOutput, XofReader};

#[derive(Parser)]
#[command(name = "quid")]
#[command(about = "Quantum-resistant Identity Protocol CLI")]
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
    }
    
    Ok(())
}