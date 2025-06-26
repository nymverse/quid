//! QuID Command Line Interface

use clap::{Parser, Subcommand};
use quid_core::{QuIDIdentity, SecurityLevel};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
            println!("Identity listing not yet implemented");
        }
        Commands::Show { identity: _ } => {
            println!("Identity inspection not yet implemented");
        }
    }
    
    Ok(())
}