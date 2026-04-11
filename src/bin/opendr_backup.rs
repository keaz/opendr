use std::path::{Path, PathBuf};
use std::process;

use clap::{Parser, Subcommand};
use opendr::backup::{
    create_full_backup, create_incremental_backup, read_manifest, verify_manifest_files,
    BackupManifest,
};
use opendr::config::ServerConfig;

#[derive(Debug, Parser)]
#[command(name = "opendr-backup")]
#[command(about = "Create and inspect OpenDR LMDB backups")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Server configuration file
    #[arg(long, global = true, default_value = "config/server.toml")]
    config: PathBuf,

    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create a full online LMDB backup
    Full {
        /// Empty directory where the backup will be written
        #[arg(long)]
        target: PathBuf,

        /// Use LMDB compact copy mode
        #[arg(long)]
        compact: bool,
    },

    /// Create an incremental changelog backup
    Incremental {
        /// Parent backup directory or manifest path
        #[arg(long)]
        parent: PathBuf,

        /// Empty directory where the backup will be written
        #[arg(long)]
        target: PathBuf,
    },

    /// Validate checksums and print backup manifest metadata
    Inspect {
        /// Backup directory or manifest path
        #[arg(long)]
        backup: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("opendr-backup failed: {err}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Full { target, compact } => {
            let config = load_config(&cli.config)?;
            let manifest = create_full_backup(&config, &target, compact)?;
            print_manifest(&manifest, cli.json);
        }
        Commands::Incremental { parent, target } => {
            let config = load_config(&cli.config)?;
            let parent_manifest = opendr::backup::manifest_path(&parent);
            let manifest = create_incremental_backup(&config, &parent_manifest, &target)?;
            print_manifest(&manifest, cli.json);
        }
        Commands::Inspect { backup } => {
            let manifest_path = opendr::backup::manifest_path(&backup);
            let manifest = if manifest_path.exists() {
                verify_manifest_files(&manifest_path)?
            } else {
                read_manifest(&manifest_path)?
            };
            print_manifest(&manifest, cli.json);
        }
    }
    Ok(())
}

fn load_config(path: &Path) -> Result<ServerConfig, opendr::config::ConfigError> {
    ServerConfig::from_file(&path.to_string_lossy())
}

fn print_manifest(manifest: &BackupManifest, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(manifest).expect("manifest should serialize")
        );
        return;
    }

    println!("backup_id: {}", manifest.backup_id);
    println!("backup_type: {:?}", manifest.backup_type);
    if let Some(parent) = &manifest.parent_backup_id {
        println!("parent_backup_id: {parent}");
    }
    println!("checkpoint_source: {:?}", manifest.checkpoint.source);
    println!(
        "start_context_csn: {}",
        manifest
            .checkpoint
            .start_context_csn
            .as_deref()
            .unwrap_or("<none>")
    );
    println!(
        "end_context_csn: {}",
        manifest
            .checkpoint
            .end_context_csn
            .as_deref()
            .unwrap_or("<none>")
    );
    println!(
        "snapshot_context_csn: {}",
        manifest
            .checkpoint
            .snapshot_context_csn
            .as_deref()
            .unwrap_or("<none>")
    );
    println!("files: {}", manifest.files.len());
}
