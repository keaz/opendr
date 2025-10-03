// OpenDR LDAP Server Setup CLI
// First-time setup wizard

use clap::{Parser, Subcommand};
use opendr::setup::{BackendType, SetupConfig, SetupHandler};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "opendr-setup")]
#[command(about = "OpenDR LDAP Server Setup Utility", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Configuration directory
    #[arg(short, long, default_value = "./config")]
    config_dir: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Run interactive setup wizard
    Interactive,

    /// Run non-interactive setup from configuration file
    NonInteractive {
        /// Path to setup configuration file (TOML)
        #[arg(short, long)]
        config: PathBuf,
    },

    /// Generate a sample configuration file
    GenerateConfig {
        /// Output file path
        #[arg(short, long, default_value = "setup-config.toml")]
        output: PathBuf,
    },

    /// Check if server is configured
    Status,

    /// Reset server configuration (WARNING: destroys all data)
    Reset {
        /// Force reset without confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let handler = SetupHandler::new(&cli.config_dir);

    match cli.command {
        Commands::Interactive => {
            // Check if already configured
            if handler.is_configured().await? {
                eprintln!("\n⚠️  Server is already configured!");
                eprintln!("To reconfigure, first run: opendr-setup reset\n");
                return Err("Server already configured".to_string());
            }

            // Run interactive setup
            let config = handler.run_interactive_setup().await?;
            handler.run_non_interactive_setup(config).await?;
        }

        Commands::NonInteractive { config } => {
            // Check if already configured
            if handler.is_configured().await? {
                return Err("Server already configured. Run 'reset' first.".to_string());
            }

            // Load config from file
            let config_content = tokio::fs::read_to_string(&config)
                .await
                .map_err(|e| format!("Failed to read config file: {}", e))?;

            let setup_config: SetupConfig = toml::from_str(&config_content)
                .map_err(|e| format!("Failed to parse config file: {}", e))?;

            handler.run_non_interactive_setup(setup_config).await?;
        }

        Commands::GenerateConfig { output } => {
            let config = SetupConfig::default();
            let content = toml::to_string_pretty(&config)
                .map_err(|e| format!("Failed to serialize config: {}", e))?;

            tokio::fs::write(&output, content)
                .await
                .map_err(|e| format!("Failed to write config file: {}", e))?;

            println!("✓ Generated sample configuration file: {}", output.display());
            println!("\nEdit this file and then run:");
            println!("  opendr-setup non-interactive --config {}", output.display());
        }

        Commands::Status => {
            if handler.is_configured().await? {
                println!("✓ Server is configured and ready to use");
                println!("\nStart the server with:");
                println!("  opendr-server start");
            } else {
                println!("✗ Server is not configured");
                println!("\nRun setup with:");
                println!("  opendr-setup interactive");
            }
        }

        Commands::Reset { force } => {
            if !handler.is_configured().await? {
                println!("Server is not configured. Nothing to reset.");
                return Ok(());
            }

            if !force {
                println!("\n⚠️  WARNING: This will delete all server configuration and data!");
                print!("Are you sure you want to continue? (yes/no): ");
                std::io::Write::flush(&mut std::io::stdout())
                    .map_err(|e| format!("Failed to flush stdout: {}", e))?;

                use std::io::BufRead;
                let mut input = String::new();
                std::io::stdin()
                    .lock()
                    .read_line(&mut input)
                    .map_err(|e| format!("Failed to read input: {}", e))?;

                if input.trim().to_lowercase() != "yes" {
                    println!("Reset cancelled.");
                    return Ok(());
                }
            }

            // Remove configuration files
            let config_dir = cli.config_dir;
            if config_dir.exists() {
                tokio::fs::remove_dir_all(&config_dir)
                    .await
                    .map_err(|e| format!("Failed to remove config directory: {}", e))?;
            }

            println!("✓ Server configuration has been reset");
            println!("\nRun setup again with:");
            println!("  opendr-setup interactive");
        }
    }

    Ok(())
}
