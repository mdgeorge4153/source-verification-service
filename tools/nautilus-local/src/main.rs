mod eif;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "nautilus-local", about = "Local mock environment for Nautilus enclaves")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse an EIF file and display metadata
    Parse {
        /// Path to the EIF file
        eif_path: PathBuf,
    },
    /// Boot an EIF in QEMU with mock NSM
    Run {
        /// Path to the EIF file
        eif_path: PathBuf,
        /// Secrets JSON to inject
        #[arg(long)]
        secrets: Option<String>,
        /// Path to secrets JSON file
        #[arg(long)]
        secrets_file: Option<PathBuf>,
        /// Show VM console output
        #[arg(long)]
        verbose: bool,
        /// Host port for enclave:3000
        #[arg(long, default_value = "3000")]
        port: u16,
        /// VM memory
        #[arg(long, default_value = "512M")]
        memory: String,
    },
    /// Generate a standalone mock attestation document
    Attest {
        /// Ed25519 public key (hex-encoded)
        #[arg(long)]
        public_key: String,
        /// PCR0 value (hex, default all zeros)
        #[arg(long)]
        pcr0: Option<String>,
        /// PCR1 value (hex, default all zeros)
        #[arg(long)]
        pcr1: Option<String>,
        /// PCR2 value (hex, default all zeros)
        #[arg(long)]
        pcr2: Option<String>,
        /// Output file (default: stdout hex)
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { eif_path } => {
            let eif = eif::parse_eif(&eif_path)?;
            eif.print_summary();
        }
        Commands::Run { .. } => {
            eprintln!("'run' subcommand not yet implemented");
        }
        Commands::Attest { .. } => {
            eprintln!("'attest' subcommand not yet implemented");
        }
    }

    Ok(())
}
