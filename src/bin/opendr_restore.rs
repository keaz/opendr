use std::path::PathBuf;
use std::process;

use clap::Parser;
use opendr::backup::restore_backup_chain;

#[derive(Debug, Parser)]
#[command(name = "opendr-restore")]
#[command(about = "Restore OpenDR LMDB backups into an offline data directory")]
struct Cli {
    /// Full backup directory or manifest path
    #[arg(long)]
    backup: PathBuf,

    /// Incremental backup directories or manifest paths, in restore order
    #[arg(long = "incremental")]
    incrementals: Vec<PathBuf>,

    /// Target LMDB data directory
    #[arg(long)]
    target_data_dir: PathBuf,

    /// Replace a non-empty target data directory
    #[arg(long)]
    force: bool,

    /// Validate the chain without writing to the target data directory
    #[arg(long)]
    dry_run: bool,

    /// Emit machine-readable JSON
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli).await {
        eprintln!("opendr-restore failed: {err}");
        process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let report = restore_backup_chain(
        &cli.backup,
        &cli.incrementals,
        &cli.target_data_dir,
        cli.force,
        cli.dry_run,
    )
    .await?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("full_backup_id: {}", report.full_backup_id);
        println!(
            "incrementals_applied: {}",
            report.applied_incremental_backup_ids.len()
        );
        println!("target_data_directory: {}", report.target_data_directory);
        println!(
            "final_context_csn: {}",
            report.final_context_csn.as_deref().unwrap_or("<none>")
        );
        println!("dry_run: {}", report.dry_run);
    }

    Ok(())
}
