// First-time setup module for OpenDR LDAP server
// Inspired by OpenDJ setup process

use crate::config::ServerConfig;
use crate::schema::bundled_schema_files;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};

const DEFAULT_LOG4RS_CONFIG: &str = r#"refresh_rate: 5 seconds
appenders:
  stdout:
    kind: console
    encoder:
      pattern: "{d(%Y-%m-%d %H:%M:%S)} | {({l}):5.5} | {f}:{L} - {m}{n}"
root:
  level: info
  appenders:
    - stdout
"#;

/// Setup configuration for first-time server initialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConfig {
    /// Base DN for the directory (e.g., "dc=example,dc=com")
    pub base_dn: String,

    /// Root user DN (e.g., "cn=Directory Manager" or "uid=admin")
    pub root_user_dn: String,

    /// Root user password (will be hashed)
    pub root_password: String,

    /// LDAP port
    pub ldap_port: u16,

    /// LDAPS port (secure LDAP)
    pub ldaps_port: u16,

    /// TLS/SSL configuration
    #[serde(default)]
    pub tls: TlsConfig,

    /// Server hostname
    pub hostname: String,

    /// Organization name
    pub organization_name: String,

    /// Replica ID used in generated CSNs. Must be unique per replicated node.
    #[serde(default = "default_setup_replica_id")]
    pub replica_id: u16,

    /// Storage backend type
    pub backend_type: BackendType,

    /// Data directory path
    pub data_directory: PathBuf,

    /// Enable sample data
    pub import_sample_data: bool,

    /// Replication configuration
    #[serde(default)]
    pub replication: ReplicationConfig,
}

/// Replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Enable replication
    pub enabled: bool,

    /// Replication role: Provider, Consumer, or Both
    pub role: ReplicationRole,

    /// Provider-specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderConfig>,

    /// Consumer-specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<ConsumerConfig>,
}

/// Replication role
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum ReplicationRole {
    /// Provider (master) server
    #[serde(alias = "provider")]
    Provider,
    /// Consumer (replica) server
    #[serde(alias = "consumer")]
    Consumer,
    /// Provider and consumer on the same node
    #[serde(alias = "both")]
    Both,
}

/// Provider-specific replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Enable changelog tracking
    pub changelog_enabled: bool,

    /// Maximum number of changelog entries to keep in memory
    pub changelog_max_entries: usize,

    /// Maximum number of entries to send in a single batch
    pub max_batch_size: usize,

    /// Enable real-time change streaming
    pub enable_streaming: bool,

    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,

    /// Maximum concurrent replication consumers
    #[serde(default = "default_setup_max_concurrent_consumers")]
    pub max_concurrent_consumers: usize,

    /// Consumer session timeout in seconds
    #[serde(default = "default_setup_consumer_timeout_secs")]
    pub consumer_timeout_secs: u64,
}

/// Consumer-specific replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerConfig {
    /// Provider server URL (e.g., "ldaps://provider.example.com:636")
    pub provider_url: String,

    /// Provider bind DN (optional, for authentication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_bind_dn: Option<String>,

    /// Provider bind password (optional, for authentication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_bind_password: Option<String>,

    /// Environment variable containing the provider bind password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_bind_password_env: Option<String>,

    /// File containing the provider bind password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_bind_password_file: Option<PathBuf>,

    /// Legacy refresh interval in seconds. Listener-based replication is mandatory.
    pub sync_interval_secs: u64,

    /// Maximum retry attempts for failed operations
    pub max_retry_attempts: u32,

    /// Delay between retry attempts in seconds
    pub retry_delay_secs: u64,

    /// Enable continuous listening for changes. Consumer replication requires this.
    pub enable_change_listening: bool,

    /// Heartbeat interval in seconds
    #[serde(default = "default_setup_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    /// Maximum entries per sync batch
    #[serde(default = "default_setup_max_batch_size")]
    pub max_batch_size: usize,

    /// Provider request timeout in seconds
    #[serde(default = "default_setup_provider_timeout_secs")]
    pub provider_timeout_secs: u64,

    /// State persistence timeout in seconds
    #[serde(default = "default_setup_state_persistence_timeout_secs")]
    pub state_persistence_timeout_secs: u64,

    /// Live change buffer size
    #[serde(default = "default_setup_change_buffer_size")]
    pub change_buffer_size: usize,

    /// Path to store replication state
    pub state_storage_path: PathBuf,
}

/// TLS/SSL configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS/SSL and start the LDAPS listener
    pub enabled: bool,

    /// Server certificate file path
    pub cert_file: PathBuf,

    /// Server private key file path
    pub key_file: PathBuf,

    /// CA certificate file path for client certificate verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,

    /// Require client certificates
    pub require_client_cert: bool,

    /// Minimum TLS version: "1.2" or "1.3"
    pub min_tls_version: String,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            role: ReplicationRole::Provider,
            provider: None,
            consumer: None,
        }
    }
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            changelog_enabled: true,
            changelog_max_entries: 100000,
            max_batch_size: 100,
            enable_streaming: true,
            heartbeat_interval_secs: 60,
            max_concurrent_consumers: 10,
            consumer_timeout_secs: 300,
        }
    }
}

impl Default for ConsumerConfig {
    fn default() -> Self {
        Self {
            provider_url: "ldaps://provider.example.com:636".to_string(),
            provider_bind_dn: None,
            provider_bind_password: None,
            provider_bind_password_env: None,
            provider_bind_password_file: None,
            sync_interval_secs: 30,
            max_retry_attempts: 3,
            retry_delay_secs: 5,
            enable_change_listening: true,
            heartbeat_interval_secs: 30,
            max_batch_size: 100,
            provider_timeout_secs: 30,
            state_persistence_timeout_secs: 10,
            change_buffer_size: 1000,
            state_storage_path: PathBuf::from("./data/replication_state"),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: PathBuf::from("certs/server.crt"),
            key_file: PathBuf::from("certs/server.key"),
            ca_file: None,
            require_client_cert: false,
            min_tls_version: "1.2".to_string(),
        }
    }
}

/// Backend storage type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackendType {
    /// In-memory storage (for testing)
    InMemory,
    /// LMDB storage
    Lmdb,
    /// Future: Other backends
    Custom(String),
}

/// Setup state tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupState {
    pub is_configured: bool,
    pub setup_timestamp: Option<String>,
    pub config_version: String,
    pub base_dn: Option<String>,
}

fn default_setup_max_concurrent_consumers() -> usize {
    10
}

fn default_setup_consumer_timeout_secs() -> u64 {
    300
}

fn default_setup_heartbeat_interval_secs() -> u64 {
    30
}

fn default_setup_max_batch_size() -> usize {
    100
}

fn default_setup_provider_timeout_secs() -> u64 {
    30
}

fn default_setup_state_persistence_timeout_secs() -> u64 {
    10
}

fn default_setup_change_buffer_size() -> usize {
    1000
}

fn default_setup_replica_id() -> u16 {
    1
}

fn requested_schema_bundles(bundles: &[String]) -> Vec<String> {
    if bundles.is_empty()
        || bundles
            .iter()
            .any(|bundle| bundle.eq_ignore_ascii_case("all"))
    {
        vec![
            "core".to_string(),
            "posix".to_string(),
            "cosine".to_string(),
            "x509".to_string(),
        ]
    } else {
        bundles.to_vec()
    }
}

impl Default for SetupConfig {
    fn default() -> Self {
        Self {
            base_dn: "dc=example,dc=com".to_string(),
            root_user_dn: "cn=Directory Manager".to_string(),
            root_password: String::new(),
            ldap_port: 1389,
            ldaps_port: 1636,
            tls: TlsConfig::default(),
            hostname: "localhost".to_string(),
            organization_name: "Example Organization".to_string(),
            replica_id: default_setup_replica_id(),
            backend_type: BackendType::Lmdb,
            data_directory: PathBuf::from("./data"),
            import_sample_data: false,
            replication: ReplicationConfig::default(),
        }
    }
}

impl ReplicationRole {
    fn as_runtime_mode(&self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Consumer => "consumer",
            Self::Both => "both",
        }
    }

    fn requires_provider(&self) -> bool {
        matches!(self, Self::Provider | Self::Both)
    }

    fn requires_consumer(&self) -> bool {
        matches!(self, Self::Consumer | Self::Both)
    }
}

impl SetupConfig {
    fn backend_type_name(&self) -> &str {
        match self.backend_type {
            BackendType::Lmdb => "lmdb",
            BackendType::InMemory => "memory",
            BackendType::Custom(ref name) => name.as_str(),
        }
    }

    fn replication_state_storage_path(&self) -> Option<PathBuf> {
        if !self.replication.enabled {
            return None;
        }

        if self.replication.role.requires_consumer() {
            return self
                .replication
                .consumer
                .as_ref()
                .map(|consumer| consumer.state_storage_path.clone());
        }

        Some(self.data_directory.join("replication_state"))
    }

    fn to_server_config(&self, hashed_root_password: String) -> Result<ServerConfig, String> {
        let mut server_config = ServerConfig::default();

        server_config.server.bind_address = self.hostname.clone();
        server_config.server.ldap_port = self.ldap_port;
        server_config.server.ldaps_port = self.ldaps_port;
        server_config.server.hostname = self.hostname.clone();
        server_config.server.runtime = "fsm".to_string();
        server_config.server.replica_id = self.replica_id;
        server_config.server.base_dn = self.base_dn.clone();
        server_config.server.root_user_dn = self.root_user_dn.clone();
        server_config.server.root_password = hashed_root_password;
        server_config.server.organization_name = self.organization_name.clone();

        server_config.tls.enabled = self.tls.enabled;
        server_config.tls.cert_file = self.tls.cert_file.clone();
        server_config.tls.key_file = self.tls.key_file.clone();
        server_config.tls.ca_file = self.tls.ca_file.clone();
        server_config.tls.require_client_cert = self.tls.require_client_cert;
        server_config.tls.min_tls_version = self.tls.min_tls_version.clone();

        server_config.backend.backend_type = self.backend_type_name().to_string();
        server_config.backend.data_directory = self.data_directory.clone();
        server_config.backend.import_sample_data = self.import_sample_data;

        if self.replication.enabled {
            server_config.replication.enabled = true;
            server_config.replication.mode = self.replication.role.as_runtime_mode().to_string();

            if let Some(state_path) = self.replication_state_storage_path() {
                server_config.replication.state_storage_path = state_path;
            }

            if self.replication.role.requires_provider() {
                let provider = self
                    .replication
                    .provider
                    .as_ref()
                    .ok_or_else(|| "Provider replication config is required".to_string())?;

                server_config.replication.changelog_enabled = provider.changelog_enabled;
                server_config.replication.changelog_capacity = provider.changelog_max_entries;
                server_config.replication.max_batch_size = provider.max_batch_size;
                server_config.replication.enable_streaming = provider.enable_streaming;
                server_config.replication.heartbeat_interval_secs =
                    provider.heartbeat_interval_secs;
                server_config.replication.max_concurrent_consumers =
                    provider.max_concurrent_consumers;
                server_config.replication.consumer_timeout_secs = provider.consumer_timeout_secs;
            }

            if self.replication.role.requires_consumer() {
                let consumer = self
                    .replication
                    .consumer
                    .as_ref()
                    .ok_or_else(|| "Consumer replication config is required".to_string())?;

                server_config.replication.provider_url = Some(consumer.provider_url.clone());
                server_config.replication.bind_dn = consumer.provider_bind_dn.clone();
                server_config.replication.bind_password = consumer.provider_bind_password.clone();
                server_config.replication.bind_password_env =
                    consumer.provider_bind_password_env.clone();
                server_config.replication.bind_password_file =
                    consumer.provider_bind_password_file.clone();
                server_config.replication.sync_interval_secs = consumer.sync_interval_secs;
                server_config.replication.max_retry_attempts = consumer.max_retry_attempts;
                server_config.replication.retry_delay_secs = consumer.retry_delay_secs;
                server_config.replication.enable_change_listening =
                    consumer.enable_change_listening;
                server_config.replication.heartbeat_interval_secs =
                    consumer.heartbeat_interval_secs;
                server_config.replication.max_batch_size = consumer.max_batch_size;
                server_config.replication.provider_timeout_secs = consumer.provider_timeout_secs;
                server_config.replication.state_persistence_timeout_secs =
                    consumer.state_persistence_timeout_secs;
                server_config.replication.change_buffer_size = consumer.change_buffer_size;
                server_config.replication.state_storage_path = consumer.state_storage_path.clone();
            }
        }

        Ok(server_config)
    }
}

/// Interactive setup handler
pub struct SetupHandler {
    config_path: PathBuf,
    state_path: PathBuf,
}

impl SetupHandler {
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        let config_dir = config_dir.as_ref();
        Self {
            config_path: config_dir.join("server.toml"),
            state_path: config_dir.join("setup.state"),
        }
    }

    fn config_dir(&self) -> &Path {
        self.config_path.parent().unwrap_or_else(|| Path::new("."))
    }

    fn log_config_path(&self) -> PathBuf {
        self.config_dir().join("log4rs.yml")
    }

    pub async fn generate_builtin_schema_files(
        &self,
        output_dir: impl AsRef<Path>,
        bundles: &[String],
        overwrite: bool,
    ) -> Result<Vec<PathBuf>, String> {
        let output_dir = output_dir.as_ref();
        let requested_bundles = requested_schema_bundles(bundles);
        let mut written = Vec::new();

        for bundle in requested_bundles {
            for schema_file in bundled_schema_files(&bundle).map_err(|err| err.to_string())? {
                let output_path = output_dir.join(schema_file.relative_path);
                if output_path.exists() && !overwrite {
                    return Err(format!(
                        "schema file already exists: {}. Re-run with --overwrite to replace it",
                        output_path.display()
                    ));
                }
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent)
                        .await
                        .map_err(|err| format!("Failed to create schema directory: {}", err))?;
                }
                fs::write(&output_path, schema_file.contents)
                    .await
                    .map_err(|err| format!("Failed to write schema file: {}", err))?;
                written.push(output_path);
            }
        }

        Ok(written)
    }

    /// Check if server has been set up
    pub async fn is_configured(&self) -> Result<bool, String> {
        if !self.state_path.exists() {
            return Ok(false);
        }

        let state = self.load_state().await?;
        Ok(state.is_configured)
    }

    /// Load setup state
    async fn load_state(&self) -> Result<SetupState, String> {
        let content = fs::read_to_string(&self.state_path)
            .await
            .map_err(|e| format!("Failed to read setup state: {}", e))?;

        toml::from_str(&content).map_err(|e| format!("Failed to parse setup state: {}", e))
    }

    /// Save setup state
    async fn save_state(&self, state: &SetupState) -> Result<(), String> {
        let content = toml::to_string_pretty(state)
            .map_err(|e| format!("Failed to serialize state: {}", e))?;

        // Ensure parent directory exists
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }

        fs::write(&self.state_path, content)
            .await
            .map_err(|e| format!("Failed to write setup state: {}", e))
    }

    /// Save setup configuration
    async fn save_config(&self, config: &SetupConfig) -> Result<(), String> {
        let server_config = config.to_server_config(format!(
            "{{SSHA512}}{}",
            self.hash_password(&config.root_password)
        ))?;
        let server_config_toml = server_config
            .to_toml_string()
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        let content = format!(
            "# OpenDR LDAP Server Configuration\n# Generated by opendr-setup on {}\n# Setup output uses the development profile by default.\n# For production, set security.profile = \"production\" and move the root secret to root_password_file or root_password_env.\n\n{}",
            chrono::Utc::now().to_rfc3339(),
            server_config_toml
        );

        // Ensure parent directory exists
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }

        fs::write(&self.config_path, content)
            .await
            .map_err(|e| format!("Failed to write config: {}", e))
    }

    async fn save_log_config(&self) -> Result<(), String> {
        let log_config_path = self.log_config_path();
        if let Some(parent) = log_config_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }

        fs::write(&log_config_path, DEFAULT_LOG4RS_CONFIG)
            .await
            .map_err(|e| format!("Failed to write log config: {}", e))
    }

    async fn create_config_dir(&self) -> Result<(), String> {
        fs::create_dir_all(self.config_dir())
            .await
            .map_err(|e| format!("Failed to create config directory: {}", e))
    }

    /// Run interactive setup
    pub async fn run_interactive_setup(&self) -> Result<SetupConfig, String> {
        println!("\n╔════════════════════════════════════════════════╗");
        println!("║   OpenDR LDAP Server - First Time Setup       ║");
        println!("╚════════════════════════════════════════════════╝\n");

        let mut config = SetupConfig::default();

        // 1. Base DN
        config.base_dn = self
            .prompt_with_default("Enter the base DN for your directory", &config.base_dn)
            .await?;

        // 2. Organization name
        config.organization_name = self
            .prompt_with_default("Enter your organization name", &config.organization_name)
            .await?;

        // 3. Root user DN
        config.root_user_dn = self
            .prompt_with_default(
                "Enter the root user DN (administrator account)",
                &config.root_user_dn,
            )
            .await?;

        // 4. Root password
        config.root_password = self.prompt_password("Enter the root user password").await?;
        let confirm_password = self
            .prompt_password("Confirm the root user password")
            .await?;

        if config.root_password != confirm_password {
            return Err("Passwords do not match".to_string());
        }

        // Validate password strength
        self.validate_password(&config.root_password)?;

        // 5. LDAP port
        let port_str = self
            .prompt_with_default("Enter the LDAP port", &config.ldap_port.to_string())
            .await?;
        config.ldap_port = port_str
            .parse()
            .map_err(|_| "Invalid port number".to_string())?;

        // 6. LDAPS port
        let ports_str = self
            .prompt_with_default(
                "Enter the LDAPS port (secure)",
                &config.ldaps_port.to_string(),
            )
            .await?;
        config.ldaps_port = ports_str
            .parse()
            .map_err(|_| "Invalid port number".to_string())?;

        // 7. TLS configuration
        let enable_tls = self
            .prompt_with_default("Enable TLS/LDAPS? (yes/no)", "no")
            .await?;
        config.tls.enabled = enable_tls.to_lowercase() == "yes" || enable_tls.to_lowercase() == "y";

        if config.tls.enabled {
            config.tls.cert_file = PathBuf::from(
                self.prompt_with_default(
                    "TLS certificate file",
                    config.tls.cert_file.to_string_lossy().as_ref(),
                )
                .await?,
            );
            config.tls.key_file = PathBuf::from(
                self.prompt_with_default(
                    "TLS private key file",
                    config.tls.key_file.to_string_lossy().as_ref(),
                )
                .await?,
            );

            let require_client_cert = self
                .prompt_with_default("Require client certificates? (yes/no)", "no")
                .await?;
            config.tls.require_client_cert = require_client_cert.to_lowercase() == "yes"
                || require_client_cert.to_lowercase() == "y";

            let default_ca_file = if config.tls.require_client_cert {
                "certs/ca.crt"
            } else {
                ""
            };
            let ca_file = self
                .prompt_with_default(
                    "CA certificate file (required for client certs, blank for none)",
                    default_ca_file,
                )
                .await?;
            config.tls.ca_file = if ca_file.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(ca_file))
            };

            config.tls.min_tls_version = self
                .prompt_with_default(
                    "Minimum TLS version (1.2 or 1.3)",
                    &config.tls.min_tls_version,
                )
                .await?;
        }

        // 8. Hostname
        config.hostname = self
            .prompt_with_default("Enter the server hostname", &config.hostname)
            .await?;

        // 9. Replica ID
        let replica_id = self
            .prompt_with_default(
                "Enter the replica ID (unique per replicated node)",
                &config.replica_id.to_string(),
            )
            .await?;
        config.replica_id = replica_id
            .parse()
            .map_err(|_| "Invalid replica ID".to_string())?;

        // 10. Backend type
        println!("\nSelect storage backend:");
        println!("  1. LMDB (recommended for production)");
        println!("  2. In-Memory (for testing only)");

        let backend_choice = self.prompt_with_default("Enter your choice", "1").await?;

        config.backend_type = match backend_choice.as_str() {
            "1" => BackendType::Lmdb,
            "2" => BackendType::InMemory,
            _ => return Err("Invalid backend choice".to_string()),
        };

        // 11. Data directory (only for persistent backends)
        if config.backend_type != BackendType::InMemory {
            let data_dir = self
                .prompt_with_default(
                    "Enter the data directory path",
                    config.data_directory.to_string_lossy().as_ref(),
                )
                .await?;
            config.data_directory = PathBuf::from(data_dir);
        }

        // 12. Sample data
        let sample_data = self
            .prompt_with_default("Import sample data? (yes/no)", "no")
            .await?;
        config.import_sample_data =
            sample_data.to_lowercase() == "yes" || sample_data.to_lowercase() == "y";

        // 13. Replication configuration
        println!("\n╔════════════════════════════════════════════════╗");
        println!("║        Replication Configuration              ║");
        println!("╚════════════════════════════════════════════════╝\n");

        let enable_repl = self
            .prompt_with_default("Enable replication? (yes/no)", "no")
            .await?;

        config.replication.enabled =
            enable_repl.to_lowercase() == "yes" || enable_repl.to_lowercase() == "y";

        if config.replication.enabled {
            println!("\nSelect replication role:");
            println!("  1. Provider (Master) - Source of directory data");
            println!("  2. Consumer (Replica) - Receives updates from provider");
            println!("  3. Both - Provider and consumer on this node");

            let role_choice = self.prompt_with_default("Enter your choice", "1").await?;

            config.replication.role = match role_choice.as_str() {
                "1" => ReplicationRole::Provider,
                "2" => ReplicationRole::Consumer,
                "3" => ReplicationRole::Both,
                _ => return Err("Invalid replication role choice".to_string()),
            };

            if config.replication.role.requires_provider() {
                println!("\n--- Provider Configuration ---");

                let mut provider_config = ProviderConfig::default();

                let changelog = self
                    .prompt_with_default("Enable changelog tracking? (yes/no)", "yes")
                    .await?;
                provider_config.changelog_enabled =
                    changelog.to_lowercase() == "yes" || changelog.to_lowercase() == "y";

                if provider_config.changelog_enabled {
                    let max_entries = self
                        .prompt_with_default(
                            "Maximum changelog entries",
                            &provider_config.changelog_max_entries.to_string(),
                        )
                        .await?;
                    provider_config.changelog_max_entries = max_entries
                        .parse()
                        .map_err(|_| "Invalid number".to_string())?;
                }

                let batch_size = self
                    .prompt_with_default(
                        "Maximum batch size (entries per sync)",
                        &provider_config.max_batch_size.to_string(),
                    )
                    .await?;
                provider_config.max_batch_size = batch_size
                    .parse()
                    .map_err(|_| "Invalid number".to_string())?;

                let streaming = self
                    .prompt_with_default("Enable real-time streaming? (yes/no)", "yes")
                    .await?;
                provider_config.enable_streaming =
                    streaming.to_lowercase() == "yes" || streaming.to_lowercase() == "y";

                let heartbeat_interval = self
                    .prompt_with_default(
                        "Provider heartbeat interval (seconds)",
                        &provider_config.heartbeat_interval_secs.to_string(),
                    )
                    .await?;
                provider_config.heartbeat_interval_secs = heartbeat_interval
                    .parse()
                    .map_err(|_| "Invalid number".to_string())?;

                config.replication.provider = Some(provider_config);
            }

            if config.replication.role.requires_consumer() {
                println!("\n--- Consumer Configuration ---");

                let mut consumer_config = ConsumerConfig::default();

                consumer_config.provider_url = self
                    .prompt_with_default(
                        "Provider URL (e.g., ldaps://provider.example.com:636)",
                        &consumer_config.provider_url,
                    )
                    .await?;

                let use_auth = self
                    .prompt_with_default("Authenticate to provider? (yes/no)", "no")
                    .await?;

                if use_auth.to_lowercase() == "yes" || use_auth.to_lowercase() == "y" {
                    consumer_config.provider_bind_dn = Some(
                        self.prompt_with_default(
                            "Provider bind DN",
                            "cn=replication,dc=example,dc=com",
                        )
                        .await?,
                    );

                    println!("\nSelect provider bind password source:");
                    println!("  1. Enter password now");
                    println!("  2. Environment variable");
                    println!("  3. File path");

                    let password_source =
                        self.prompt_with_default("Enter your choice", "1").await?;
                    match password_source.as_str() {
                        "1" => {
                            consumer_config.provider_bind_password =
                                Some(self.prompt_password("Provider bind password").await?);
                        }
                        "2" => {
                            consumer_config.provider_bind_password_env = Some(
                                self.prompt_with_default(
                                    "Provider bind password environment variable",
                                    "OPENDR_REPLICATION_BIND_PASSWORD",
                                )
                                .await?,
                            );
                        }
                        "3" => {
                            let password_file = self
                                .prompt_with_default(
                                    "Provider bind password file",
                                    "/run/secrets/opendr-replication-bind-password",
                                )
                                .await?;
                            consumer_config.provider_bind_password_file =
                                Some(PathBuf::from(password_file));
                        }
                        _ => return Err("Invalid password source choice".to_string()),
                    }
                }

                let sync_interval = self
                    .prompt_with_default(
                        "Legacy refresh interval (seconds; listener mode is always used)",
                        &consumer_config.sync_interval_secs.to_string(),
                    )
                    .await?;
                consumer_config.sync_interval_secs = sync_interval
                    .parse()
                    .map_err(|_| "Invalid number".to_string())?;

                let retry_attempts = self
                    .prompt_with_default(
                        "Maximum retry attempts",
                        &consumer_config.max_retry_attempts.to_string(),
                    )
                    .await?;
                consumer_config.max_retry_attempts = retry_attempts
                    .parse()
                    .map_err(|_| "Invalid number".to_string())?;

                let retry_delay = self
                    .prompt_with_default(
                        "Retry delay (seconds)",
                        &consumer_config.retry_delay_secs.to_string(),
                    )
                    .await?;
                consumer_config.retry_delay_secs = retry_delay
                    .parse()
                    .map_err(|_| "Invalid number".to_string())?;

                consumer_config.enable_change_listening = true;
                println!("Continuous change listening is required for replication and is enabled.");

                let heartbeat_interval = self
                    .prompt_with_default(
                        "Listening heartbeat interval (seconds)",
                        &consumer_config.heartbeat_interval_secs.to_string(),
                    )
                    .await?;
                consumer_config.heartbeat_interval_secs = heartbeat_interval
                    .parse()
                    .map_err(|_| "Invalid number".to_string())?;

                let state_path = self
                    .prompt_with_default(
                        "Replication state storage path",
                        consumer_config
                            .state_storage_path
                            .to_string_lossy()
                            .as_ref(),
                    )
                    .await?;
                consumer_config.state_storage_path = PathBuf::from(state_path);

                if config.replication.role == ReplicationRole::Both
                    && let Some(provider_config) = config.replication.provider.as_mut()
                {
                    provider_config.max_batch_size = consumer_config.max_batch_size;
                    provider_config.heartbeat_interval_secs =
                        consumer_config.heartbeat_interval_secs;
                }

                config.replication.consumer = Some(consumer_config);
            }
        }

        // Display summary
        println!("\n╔════════════════════════════════════════════════╗");
        println!("║           Setup Configuration Summary          ║");
        println!("╚════════════════════════════════════════════════╝");
        println!("  Base DN:        {}", config.base_dn);
        println!("  Organization:   {}", config.organization_name);
        println!("  Root User DN:   {}", config.root_user_dn);
        println!("  LDAP Port:      {}", config.ldap_port);
        println!("  LDAPS Port:     {}", config.ldaps_port);
        println!(
            "  TLS/LDAPS:      {}",
            if config.tls.enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        if config.tls.enabled {
            println!("  TLS Cert:       {}", config.tls.cert_file.display());
            println!("  TLS Key:        {}", config.tls.key_file.display());
            if let Some(ref ca_file) = config.tls.ca_file {
                println!("  TLS CA:         {}", ca_file.display());
            }
            println!(
                "  Client Certs:   {}",
                if config.tls.require_client_cert {
                    "Required"
                } else {
                    "Not required"
                }
            );
            println!("  Min TLS:        {}", config.tls.min_tls_version);
        }
        println!("  Hostname:       {}", config.hostname);
        println!("  Replica ID:     {}", config.replica_id);
        println!("  Backend:        {:?}", config.backend_type);
        if config.backend_type != BackendType::InMemory {
            println!("  Data Directory: {}", config.data_directory.display());
        }
        println!(
            "  Sample Data:    {}",
            if config.import_sample_data {
                "Yes"
            } else {
                "No"
            }
        );

        // Replication summary
        if config.replication.enabled {
            println!("\n  Replication:    Enabled");
            println!("  Role:           {:?}", config.replication.role);
            if config.replication.role.requires_provider()
                && let Some(ref provider) = config.replication.provider
            {
                println!(
                    "  Changelog:      {}",
                    if provider.changelog_enabled {
                        "Enabled"
                    } else {
                        "Disabled"
                    }
                );
                if provider.changelog_enabled {
                    println!("  Max Entries:    {}", provider.changelog_max_entries);
                }
                println!("  Batch Size:     {}", provider.max_batch_size);
                println!(
                    "  Streaming:      {}",
                    if provider.enable_streaming {
                        "Enabled"
                    } else {
                        "Disabled"
                    }
                );
            }
            if config.replication.role.requires_consumer()
                && let Some(ref consumer) = config.replication.consumer
            {
                println!("  Provider URL:   {}", consumer.provider_url);
                if consumer.provider_bind_dn.is_some() {
                    println!("  Auth:           Enabled");
                }
                println!(
                    "  Password Source: {}",
                    replication_password_source_summary(consumer)
                );
                println!(
                    "  Listener Mode:  Enabled (legacy refresh interval: {} seconds)",
                    consumer.sync_interval_secs
                );
                println!("  Retry Attempts: {}", consumer.max_retry_attempts);
                println!(
                    "  State Path:     {}",
                    consumer.state_storage_path.display()
                );
            }
        } else {
            println!("\n  Replication:    Disabled");
        }
        println!();

        let confirm = self
            .prompt_with_default("Proceed with this configuration? (yes/no)", "yes")
            .await?;

        if confirm.to_lowercase() != "yes" && confirm.to_lowercase() != "y" {
            return Err("Setup cancelled by user".to_string());
        }

        Ok(config)
    }

    /// Run non-interactive setup (from config file or parameters)
    pub async fn run_non_interactive_setup(&self, config: SetupConfig) -> Result<(), String> {
        // Validate configuration
        self.validate_config(&config)?;

        // Perform setup
        self.perform_setup(&config).await?;

        Ok(())
    }

    /// Perform the actual setup
    async fn perform_setup(&self, config: &SetupConfig) -> Result<(), String> {
        println!("\n🔧 Performing setup...\n");

        // 1. Create config directory first because setup writes LDIF scaffolding before server.toml.
        println!(
            "  ✓ Creating config directory: {}",
            self.config_dir().display()
        );
        self.create_config_dir().await?;

        // 2. Create data directory if needed
        if config.backend_type != BackendType::InMemory {
            println!(
                "  ✓ Creating data directory: {}",
                config.data_directory.display()
            );
            fs::create_dir_all(&config.data_directory)
                .await
                .map_err(|e| format!("Failed to create data directory: {}", e))?;
        }

        // 2b. Create replication state directory if replication is enabled.
        if let Some(replication_state_path) = config.replication_state_storage_path() {
            println!(
                "  ✓ Creating replication state directory: {}",
                replication_state_path.display()
            );
            fs::create_dir_all(&replication_state_path)
                .await
                .map_err(|e| format!("Failed to create replication state directory: {}", e))?;
        }

        // 3. Initialize backend
        println!("  ✓ Initializing {:?} backend", config.backend_type);
        self.initialize_backend(config).await?;

        // 4. Create root user entry
        println!(
            "  ✓ Creating root administrator account: {}",
            config.root_user_dn
        );
        self.create_root_user(config).await?;

        // 5. Create base DN structure
        println!("  ✓ Creating directory structure for: {}", config.base_dn);
        self.create_base_structure(config).await?;

        // 6. Import sample data if requested
        if config.import_sample_data {
            println!("  ✓ Importing sample data");
            self.import_sample_data(config).await?;
        }

        // 7. Save configuration
        println!("  ✓ Saving configuration");
        self.save_config(config).await?;

        // 7b. Save default logging configuration
        println!("  ✓ Saving logging configuration");
        self.save_log_config().await?;

        // 8. Mark as configured
        let state = SetupState {
            is_configured: true,
            setup_timestamp: Some(chrono::Utc::now().to_rfc3339()),
            config_version: "1.0.0".to_string(),
            base_dn: Some(config.base_dn.clone()),
        };
        self.save_state(&state).await?;

        println!("\n✨ Setup completed successfully!\n");
        println!("You can now start the server with:");
        println!(
            "  opendr --config {} --log-config {}\n",
            self.config_path.display(),
            self.log_config_path().display()
        );

        Ok(())
    }

    /// Validate configuration
    fn validate_config(&self, config: &SetupConfig) -> Result<(), String> {
        if config.base_dn.is_empty() {
            return Err("Base DN cannot be empty".to_string());
        }

        if config.root_user_dn.is_empty() {
            return Err("Root user DN cannot be empty".to_string());
        }

        self.validate_password(&config.root_password)?;

        if config.ldap_port == 0 {
            return Err("Invalid LDAP port".to_string());
        }

        if config.ldaps_port == 0 {
            return Err("Invalid LDAPS port".to_string());
        }

        if config.ldap_port == config.ldaps_port {
            return Err("LDAP and LDAPS ports must be different".to_string());
        }

        if config.tls.enabled {
            if config.tls.cert_file.as_os_str().is_empty() {
                return Err("TLS certificate file cannot be empty".to_string());
            }
            if !config.tls.cert_file.exists() {
                return Err(format!(
                    "TLS certificate file not found: {}",
                    config.tls.cert_file.display()
                ));
            }
            if config.tls.key_file.as_os_str().is_empty() {
                return Err("TLS private key file cannot be empty".to_string());
            }
            if !config.tls.key_file.exists() {
                return Err(format!(
                    "TLS private key file not found: {}",
                    config.tls.key_file.display()
                ));
            }
            if !["1.2", "1.3"].contains(&config.tls.min_tls_version.as_str()) {
                return Err(format!(
                    "Invalid minimum TLS version: {}",
                    config.tls.min_tls_version
                ));
            }
            if config.tls.require_client_cert && config.tls.ca_file.is_none() {
                return Err("Client certificate verification requires a CA file".to_string());
            }
            if let Some(ref ca_file) = config.tls.ca_file {
                if ca_file.as_os_str().is_empty() {
                    return Err("TLS CA file cannot be empty".to_string());
                }
                if !ca_file.exists() {
                    return Err(format!("TLS CA file not found: {}", ca_file.display()));
                }
            }
        }

        if config.replica_id == 0 {
            return Err("Replica ID must be between 1 and 65535".to_string());
        }

        if config.replication.enabled {
            if config.replication.role.requires_provider() {
                let provider = config
                    .replication
                    .provider
                    .as_ref()
                    .ok_or_else(|| "Provider replication config is required".to_string())?;

                if provider.changelog_max_entries == 0 {
                    return Err("Changelog capacity must be > 0".to_string());
                }
                if provider.max_batch_size == 0 {
                    return Err("Provider max batch size must be > 0".to_string());
                }
                if provider.heartbeat_interval_secs == 0 {
                    return Err("Provider heartbeat interval must be > 0".to_string());
                }
                if provider.max_concurrent_consumers == 0 {
                    return Err("Max concurrent consumers must be > 0".to_string());
                }
                if provider.consumer_timeout_secs == 0 {
                    return Err("Consumer timeout must be > 0".to_string());
                }
            }

            if config.replication.role.requires_consumer() {
                let consumer = config
                    .replication
                    .consumer
                    .as_ref()
                    .ok_or_else(|| "Consumer replication config is required".to_string())?;

                if consumer.provider_url.trim().is_empty() {
                    return Err("Provider URL cannot be empty".to_string());
                }

                let password_sources = usize::from(consumer.provider_bind_password.is_some())
                    + usize::from(consumer.provider_bind_password_env.is_some())
                    + usize::from(consumer.provider_bind_password_file.is_some());

                if password_sources > 1 {
                    return Err(
                        "Provider bind password may only use one of inline, env, or file"
                            .to_string(),
                    );
                }

                if consumer.sync_interval_secs == 0 {
                    return Err("Sync interval must be > 0".to_string());
                }
                if consumer.max_retry_attempts == 0 {
                    return Err("Max retry attempts must be > 0".to_string());
                }
                if consumer.retry_delay_secs == 0 {
                    return Err("Retry delay must be > 0".to_string());
                }
                if !consumer.enable_change_listening {
                    return Err(
                        "Poll-based replication has been removed; change listening must be enabled"
                            .to_string(),
                    );
                }
                if consumer.heartbeat_interval_secs == 0 {
                    return Err("Consumer heartbeat interval must be > 0".to_string());
                }
                if consumer.max_batch_size == 0 {
                    return Err("Consumer max batch size must be > 0".to_string());
                }
                if consumer.provider_timeout_secs == 0 {
                    return Err("Provider timeout must be > 0".to_string());
                }
                if consumer.state_persistence_timeout_secs == 0 {
                    return Err("State persistence timeout must be > 0".to_string());
                }
                if consumer.change_buffer_size == 0 {
                    return Err("Change buffer size must be > 0".to_string());
                }
            }

            if config.replication.role == ReplicationRole::Both {
                let provider = config
                    .replication
                    .provider
                    .as_ref()
                    .ok_or_else(|| "Provider replication config is required".to_string())?;
                let consumer = config
                    .replication
                    .consumer
                    .as_ref()
                    .ok_or_else(|| "Consumer replication config is required".to_string())?;

                if provider.max_batch_size != consumer.max_batch_size {
                    return Err(
                        "Both replication mode uses a single max_batch_size; provider and consumer values must match"
                            .to_string(),
                    );
                }
                if provider.heartbeat_interval_secs != consumer.heartbeat_interval_secs {
                    return Err(
                        "Both replication mode uses a single heartbeat_interval_secs; provider and consumer values must match"
                            .to_string(),
                    );
                }
            }
        }

        Ok(())
    }

    /// Validate password strength
    fn validate_password(&self, password: &str) -> Result<(), String> {
        if password.len() < 8 {
            return Err("Password must be at least 8 characters long".to_string());
        }

        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());

        if !has_uppercase || !has_lowercase || !has_digit {
            return Err(
                "Password must contain uppercase, lowercase, and numeric characters".to_string(),
            );
        }

        Ok(())
    }

    /// Initialize backend storage
    async fn initialize_backend(&self, config: &SetupConfig) -> Result<(), String> {
        match config.backend_type {
            BackendType::InMemory => {
                // In-memory backend doesn't need initialization
                Ok(())
            }
            BackendType::Lmdb => {
                // Create LMDB environment
                // This will be implemented when we have the LMDB backend
                Ok(())
            }
            BackendType::Custom(ref name) => {
                Err(format!("Custom backend '{}' not implemented", name))
            }
        }
    }

    /// Create root administrator user
    async fn create_root_user(&self, config: &SetupConfig) -> Result<(), String> {
        // Hash the password using Salted SHA512 (like OpenDJ)
        let password_hash = self.hash_password(&config.root_password);

        // Create LDIF entry for root user
        let ldif = format!(
            r#"dn: {}
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: {}
sn: Administrator
userPassword: {{SSHA512}}{}
description: Root Administrator Account
"#,
            config.root_user_dn,
            extract_cn(&config.root_user_dn).unwrap_or_else(|| "Directory Manager".to_string()),
            password_hash
        );

        // Store this in a special admin.ldif file
        let admin_file = self.config_dir().join("admin.ldif");

        fs::write(admin_file, ldif)
            .await
            .map_err(|e| format!("Failed to create admin entry: {}", e))?;

        Ok(())
    }

    /// Create base DN structure
    async fn create_base_structure(&self, config: &SetupConfig) -> Result<(), String> {
        // Parse base DN to create organizational structure
        let components = parse_dn(&config.base_dn)?;

        let mut entries = Vec::new();
        let mut current_dn = String::new();

        for (i, (attr, value)) in components.iter().enumerate() {
            if i > 0 {
                current_dn = format!("{attr}={value},{current_dn}");
            } else {
                current_dn = format!("{}={}", attr, value);
            }

            let object_class = match attr.as_str() {
                "dc" => "domain",
                "o" => "organization",
                "ou" => "organizationalUnit",
                "c" => "country",
                _ => "top",
            };

            let entry = format!(
                r#"dn: {}
objectClass: top
objectClass: {}
{}: {}
"#,
                current_dn, object_class, attr, value
            );

            entries.push(entry);
        }

        // Add organization entry if not already present
        if !config.base_dn.contains("o=") {
            entries.push(format!(
                r#"dn: {}
objectClass: top
objectClass: organization
o: {}
description: {}
"#,
                config.base_dn, config.organization_name, config.organization_name
            ));
        }

        // Create standard organizational units
        let ous = vec!["People", "Groups", "Applications"];
        for ou in ous {
            entries.push(format!(
                r#"dn: ou={},{}
objectClass: top
objectClass: organizationalUnit
ou: {}
description: {} container
"#,
                ou, config.base_dn, ou, ou
            ));
        }

        // Write to base.ldif
        let base_file = self.config_dir().join("base.ldif");

        let ldif_content = entries.join("\n");
        fs::write(base_file, ldif_content)
            .await
            .map_err(|e| format!("Failed to create base structure: {}", e))?;

        Ok(())
    }

    /// Import sample data
    async fn import_sample_data(&self, config: &SetupConfig) -> Result<(), String> {
        let sample_data = format!(
            r#"# Sample Users
dn: uid=john.doe,ou=People,{}
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: john.doe
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com
userPassword: {{SSHA512}}{}

dn: uid=jane.smith,ou=People,{}
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: jane.smith
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com
userPassword: {{SSHA512}}{}

# Sample Group
dn: cn=users,ou=Groups,{}
objectClass: top
objectClass: groupOfNames
cn: users
member: uid=john.doe,ou=People,{}
member: uid=jane.smith,ou=People,{}
description: Standard users group
"#,
            config.base_dn,
            self.hash_password("password123"),
            config.base_dn,
            self.hash_password("password123"),
            config.base_dn,
            config.base_dn,
            config.base_dn
        );

        let sample_file = self.config_dir().join("sample.ldif");

        fs::write(sample_file, sample_data)
            .await
            .map_err(|e| format!("Failed to create sample data: {}", e))?;

        Ok(())
    }

    /// Hash password using Salted SHA512 (like OpenDJ)
    fn hash_password(&self, password: &str) -> String {
        use rand::RngExt;

        // Generate 16-byte salt
        let salt: [u8; 16] = rand::rng().random();

        // Hash password + salt
        let mut hasher = Sha512::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let hash = hasher.finalize();

        // Combine hash + salt and encode in base64
        let mut combined = hash.to_vec();
        combined.extend_from_slice(&salt);

        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&combined)
    }

    /// Prompt user with default value
    async fn prompt_with_default(&self, prompt: &str, default: &str) -> Result<String, String> {
        use std::io::Write;
        print!("{} [{}]: ", prompt, default);
        std::io::stdout()
            .flush()
            .map_err(|e| format!("Failed to flush stdout: {}", e))?;

        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut input = String::new();

        reader
            .read_line(&mut input)
            .await
            .map_err(|e| format!("Failed to read input: {}", e))?;

        let input = input.trim();
        if input.is_empty() {
            Ok(default.to_string())
        } else {
            Ok(input.to_string())
        }
    }

    /// Prompt for password (hidden input in production, visible in this simplified version)
    async fn prompt_password(&self, prompt: &str) -> Result<String, String> {
        use std::io::Write;
        print!("{}: ", prompt);
        std::io::stdout()
            .flush()
            .map_err(|e| format!("Failed to flush stdout: {}", e))?;

        // In production, use rpassword crate for hidden input
        // For now, use regular input
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut input = String::new();

        reader
            .read_line(&mut input)
            .await
            .map_err(|e| format!("Failed to read input: {}", e))?;

        Ok(input.trim().to_string())
    }
}

/// Extract CN from DN
fn extract_cn(dn: &str) -> Option<String> {
    let parsed = crate::dn::parse_dn(dn).ok()?;
    parsed
        .rdns()
        .first()?
        .avas()
        .iter()
        .find(|ava| ava.attribute().eq_ignore_ascii_case("cn"))
        .or_else(|| parsed.rdns().first()?.avas().first())
        .map(|ava| ava.value().to_string())
}

fn replication_password_source_summary(config: &ConsumerConfig) -> &'static str {
    if config.provider_bind_password.is_some() {
        "Inline"
    } else if config.provider_bind_password_env.is_some() {
        "Environment"
    } else if config.provider_bind_password_file.is_some() {
        "File"
    } else {
        "None"
    }
}

/// Parse DN into components
fn parse_dn(dn: &str) -> Result<Vec<(String, String)>, String> {
    let parsed = crate::dn::parse_dn(dn).map_err(|err| err.to_string())?;
    Ok(parsed
        .rdns()
        .iter()
        .filter_map(|rdn| rdn.avas().first())
        .map(|ava| (ava.attribute().to_string(), ava.value().to_string()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn base_setup_config() -> SetupConfig {
        SetupConfig {
            base_dn: "dc=example,dc=com".to_string(),
            root_user_dn: "cn=manager".to_string(),
            root_password: "StrongPass123".to_string(),
            ldap_port: 1389,
            ldaps_port: 1636,
            tls: TlsConfig::default(),
            hostname: "ldap.example.com".to_string(),
            organization_name: "Example Org".to_string(),
            replica_id: 7,
            backend_type: BackendType::Lmdb,
            data_directory: PathBuf::from("/tmp/opendr/data"),
            import_sample_data: false,
            replication: ReplicationConfig::default(),
        }
    }

    fn provider_config() -> ProviderConfig {
        ProviderConfig {
            changelog_enabled: true,
            changelog_max_entries: 50_000,
            max_batch_size: 250,
            enable_streaming: true,
            heartbeat_interval_secs: 45,
            max_concurrent_consumers: 12,
            consumer_timeout_secs: 360,
        }
    }

    fn consumer_config() -> ConsumerConfig {
        ConsumerConfig {
            provider_url: "ldaps://provider.example.com:1636".to_string(),
            provider_bind_dn: Some("cn=replication,dc=example,dc=com".to_string()),
            provider_bind_password: None,
            provider_bind_password_env: Some("OPENDR_REPLICATION_BIND_PASSWORD".to_string()),
            provider_bind_password_file: None,
            sync_interval_secs: 30,
            max_retry_attempts: 5,
            retry_delay_secs: 10,
            enable_change_listening: true,
            heartbeat_interval_secs: 45,
            max_batch_size: 250,
            provider_timeout_secs: 60,
            state_persistence_timeout_secs: 15,
            change_buffer_size: 2048,
            state_storage_path: PathBuf::from("/tmp/opendr/replication_state"),
        }
    }

    #[tokio::test]
    async fn test_generate_builtin_schema_files_writes_loadable_posix_schema() {
        let temp_dir = tempfile::tempdir().unwrap();
        let handler = SetupHandler::new(temp_dir.path().join("config"));
        let output_dir = temp_dir.path().join("config").join("schema");

        let written = handler
            .generate_builtin_schema_files(&output_dir, &["posix".to_string()], false)
            .await
            .unwrap();

        let schema_path = output_dir.join("posix").join("rfc2307.ldif");
        assert_eq!(written, vec![schema_path.clone()]);
        assert!(schema_path.is_file());

        let mut schema = crate::schema::LdapSchema::with_core_schema();
        schema.load_schema_dir(&output_dir).unwrap();
        assert!(schema.get_object_class("posixAccount").is_some());
        assert!(schema.get_object_class("nisObject").is_some());
    }

    #[tokio::test]
    async fn test_generate_builtin_schema_files_writes_loadable_cosine_schema() {
        let temp_dir = tempfile::tempdir().unwrap();
        let handler = SetupHandler::new(temp_dir.path().join("config"));
        let output_dir = temp_dir.path().join("config").join("schema");

        let written = handler
            .generate_builtin_schema_files(&output_dir, &["cosine".to_string()], false)
            .await
            .unwrap();

        let schema_path = output_dir.join("cosine").join("rfc4524.ldif");
        assert_eq!(written, vec![schema_path.clone()]);
        assert!(schema_path.is_file());

        let mut schema = crate::schema::LdapSchema::with_core_schema();
        schema.load_schema_dir(&output_dir).unwrap();
        assert!(schema.get_attribute_type("associatedDomain").is_some());
        assert!(schema.get_object_class("document").is_some());
        assert!(schema.get_object_class("simpleSecurityObject").is_some());
    }

    #[tokio::test]
    async fn test_generate_builtin_schema_files_writes_loadable_x509_schema() {
        let temp_dir = tempfile::tempdir().unwrap();
        let handler = SetupHandler::new(temp_dir.path().join("config"));
        let output_dir = temp_dir.path().join("config").join("schema");

        let written = handler
            .generate_builtin_schema_files(&output_dir, &["x509".to_string()], false)
            .await
            .unwrap();

        let schema_path = output_dir.join("x509").join("rfc4523.ldif");
        assert_eq!(written, vec![schema_path.clone()]);
        assert!(schema_path.is_file());

        let mut schema = crate::schema::LdapSchema::with_core_schema();
        schema.load_schema_dir(&output_dir).unwrap();
        assert!(schema.get_attribute_type("cACertificate").is_some());
        assert!(
            schema
                .get_attribute_type("certificateRevocationList")
                .is_some()
        );
        assert!(schema.get_object_class("pkiUser").is_some());
        assert!(schema.get_object_class("cRLDistributionPoint").is_some());
    }

    #[tokio::test]
    async fn test_generate_builtin_schema_files_writes_loadable_core_schema_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let handler = SetupHandler::new(temp_dir.path().join("config"));
        let output_dir = temp_dir.path().join("config").join("schema");

        let written = handler
            .generate_builtin_schema_files(&output_dir, &["core".to_string()], false)
            .await
            .unwrap();

        let inetorgperson_schema_path = output_dir.join("core").join("rfc2798.ldif");
        let subentry_schema_path = output_dir.join("core").join("rfc3672.ldif");
        let collective_schema_path = output_dir.join("core").join("rfc3671.ldif");
        assert_eq!(
            written,
            vec![
                inetorgperson_schema_path.clone(),
                subentry_schema_path.clone(),
                collective_schema_path.clone()
            ]
        );
        assert!(inetorgperson_schema_path.is_file());
        assert!(subentry_schema_path.is_file());
        assert!(collective_schema_path.is_file());

        let mut schema = crate::schema::LdapSchema::with_core_schema();
        schema.load_schema_dir(&output_dir).unwrap();
        assert!(schema.get_object_class("inetOrgPerson").is_some());
        assert!(schema.get_attribute_type("subtreeSpecification").is_some());
        assert!(schema.get_object_class("subentry").is_some());
        assert!(
            schema
                .get_object_class("collectiveAttributeSubentry")
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_generate_builtin_schema_files_requires_overwrite_for_existing_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let handler = SetupHandler::new(temp_dir.path().join("config"));
        let output_dir = temp_dir.path().join("config").join("schema");

        handler
            .generate_builtin_schema_files(&output_dir, &["posix".to_string()], false)
            .await
            .unwrap();
        let error = handler
            .generate_builtin_schema_files(&output_dir, &["posix".to_string()], false)
            .await
            .unwrap_err();

        assert!(error.contains("--overwrite"));

        handler
            .generate_builtin_schema_files(&output_dir, &["posix".to_string()], true)
            .await
            .unwrap();
    }

    #[test]
    fn test_replication_role_runtime_modes() {
        assert_eq!(ReplicationRole::Provider.as_runtime_mode(), "provider");
        assert!(ReplicationRole::Provider.requires_provider());
        assert!(!ReplicationRole::Provider.requires_consumer());

        assert_eq!(ReplicationRole::Consumer.as_runtime_mode(), "consumer");
        assert!(!ReplicationRole::Consumer.requires_provider());
        assert!(ReplicationRole::Consumer.requires_consumer());

        assert_eq!(ReplicationRole::Both.as_runtime_mode(), "both");
        assert!(ReplicationRole::Both.requires_provider());
        assert!(ReplicationRole::Both.requires_consumer());
    }

    #[test]
    fn test_provider_setup_config_maps_to_runtime_server_config() {
        let mut config = base_setup_config();
        config.replication = ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Provider,
            provider: Some(provider_config()),
            consumer: None,
        };

        let server_config = config
            .to_server_config("{SSHA512}hashed-root-password".to_string())
            .unwrap();

        assert_eq!(server_config.server.bind_address, "ldap.example.com");
        assert_eq!(server_config.server.hostname, "ldap.example.com");
        assert_eq!(server_config.server.runtime, "fsm");
        assert_eq!(server_config.server.replica_id, 7);
        assert_eq!(
            server_config.server.root_password,
            "{SSHA512}hashed-root-password"
        );
        assert_eq!(server_config.backend.backend_type, "lmdb");
        assert_eq!(server_config.backend.data_directory, config.data_directory);
        assert!(server_config.replication.enabled);
        assert_eq!(server_config.replication.mode, "provider");
        assert_eq!(server_config.replication.changelog_capacity, 50_000);
        assert_eq!(server_config.replication.max_batch_size, 250);
        assert_eq!(server_config.replication.max_concurrent_consumers, 12);
        assert_eq!(
            server_config.replication.state_storage_path,
            PathBuf::from("/tmp/opendr/data/replication_state")
        );
        assert!(server_config.replication.provider_url.is_none());
    }

    #[test]
    fn test_both_setup_config_maps_consumer_secret_source_to_runtime_config() {
        let mut config = base_setup_config();
        config.replication = ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Both,
            provider: Some(provider_config()),
            consumer: Some(consumer_config()),
        };

        let server_config = config
            .to_server_config("{SSHA512}hashed-root-password".to_string())
            .unwrap();

        assert_eq!(server_config.replication.mode, "both");
        assert_eq!(server_config.replication.changelog_capacity, 50_000);
        assert_eq!(
            server_config.replication.provider_url.as_deref(),
            Some("ldaps://provider.example.com:1636")
        );
        assert_eq!(
            server_config.replication.bind_dn.as_deref(),
            Some("cn=replication,dc=example,dc=com")
        );
        assert_eq!(
            server_config.replication.bind_password_env.as_deref(),
            Some("OPENDR_REPLICATION_BIND_PASSWORD")
        );
        assert!(server_config.replication.bind_password.is_none());
        assert!(server_config.replication.bind_password_file.is_none());
        assert_eq!(server_config.replication.provider_timeout_secs, 60);
        assert_eq!(server_config.replication.state_persistence_timeout_secs, 15);
        assert_eq!(server_config.replication.change_buffer_size, 2048);
        assert_eq!(
            server_config.replication.state_storage_path,
            PathBuf::from("/tmp/opendr/replication_state")
        );
    }

    #[test]
    fn test_tls_setup_config_maps_to_runtime_server_config() {
        let mut config = base_setup_config();
        config.tls = TlsConfig {
            enabled: true,
            cert_file: PathBuf::from("/etc/opendr/certs/server.crt"),
            key_file: PathBuf::from("/etc/opendr/certs/server.key"),
            ca_file: Some(PathBuf::from("/etc/opendr/certs/ca.crt")),
            require_client_cert: true,
            min_tls_version: "1.3".to_string(),
        };

        let server_config = config
            .to_server_config("{SSHA512}hashed-root-password".to_string())
            .unwrap();

        assert!(server_config.tls.enabled);
        assert_eq!(
            server_config.tls.cert_file,
            PathBuf::from("/etc/opendr/certs/server.crt")
        );
        assert_eq!(
            server_config.tls.key_file,
            PathBuf::from("/etc/opendr/certs/server.key")
        );
        assert_eq!(
            server_config.tls.ca_file,
            Some(PathBuf::from("/etc/opendr/certs/ca.crt"))
        );
        assert!(server_config.tls.require_client_cert);
        assert_eq!(server_config.tls.min_tls_version, "1.3");
    }

    #[test]
    fn test_validate_config_rejects_tls_client_certs_without_ca_file() {
        let cert_file = tempfile::NamedTempFile::new().unwrap();
        let key_file = tempfile::NamedTempFile::new().unwrap();
        let mut config = base_setup_config();
        config.tls = TlsConfig {
            enabled: true,
            cert_file: cert_file.path().to_path_buf(),
            key_file: key_file.path().to_path_buf(),
            ca_file: None,
            require_client_cert: true,
            min_tls_version: "1.2".to_string(),
        };

        let handler = SetupHandler::new("/tmp/test");
        let error = handler.validate_config(&config).unwrap_err();

        assert!(error.contains("requires a CA file"));
    }

    #[test]
    fn test_validate_config_rejects_invalid_tls_version() {
        let cert_file = tempfile::NamedTempFile::new().unwrap();
        let key_file = tempfile::NamedTempFile::new().unwrap();
        let mut config = base_setup_config();
        config.tls = TlsConfig {
            enabled: true,
            cert_file: cert_file.path().to_path_buf(),
            key_file: key_file.path().to_path_buf(),
            ca_file: None,
            require_client_cert: false,
            min_tls_version: "1.1".to_string(),
        };

        let handler = SetupHandler::new("/tmp/test");
        let error = handler.validate_config(&config).unwrap_err();

        assert!(error.contains("Invalid minimum TLS version"));
    }

    #[test]
    fn test_validate_config_rejects_multiple_consumer_password_sources() {
        let mut consumer = consumer_config();
        consumer.provider_bind_password = Some("inline-secret".to_string());
        consumer.provider_bind_password_file = Some(PathBuf::from("/run/secrets/repl-password"));

        let mut config = base_setup_config();
        config.replication = ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Consumer,
            provider: None,
            consumer: Some(consumer),
        };

        let handler = SetupHandler::new("/tmp/test");
        let error = handler.validate_config(&config).unwrap_err();

        assert!(error.contains("only use one of inline, env, or file"));
    }

    #[test]
    fn test_validate_config_rejects_mismatched_both_shared_runtime_fields() {
        let mut consumer = consumer_config();
        consumer.max_batch_size = 500;

        let mut config = base_setup_config();
        config.replication = ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Both,
            provider: Some(provider_config()),
            consumer: Some(consumer),
        };

        let handler = SetupHandler::new("/tmp/test");
        let error = handler.validate_config(&config).unwrap_err();

        assert!(error.contains("single max_batch_size"));
    }

    #[test]
    fn test_replication_password_source_summary() {
        let mut consumer = ConsumerConfig::default();
        assert_eq!(replication_password_source_summary(&consumer), "None");

        consumer.provider_bind_password = Some("inline".to_string());
        assert_eq!(replication_password_source_summary(&consumer), "Inline");

        consumer.provider_bind_password = None;
        consumer.provider_bind_password_env = Some("OPENDR_REPL_PASSWORD".to_string());
        assert_eq!(
            replication_password_source_summary(&consumer),
            "Environment"
        );

        consumer.provider_bind_password_env = None;
        consumer.provider_bind_password_file = Some(PathBuf::from("/run/secrets/repl"));
        assert_eq!(replication_password_source_summary(&consumer), "File");
    }

    #[test]
    fn test_parse_dn() {
        let dn = "dc=example,dc=com";
        let components = parse_dn(dn).unwrap();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0], ("dc".to_string(), "example".to_string()));
        assert_eq!(components[1], ("dc".to_string(), "com".to_string()));
    }

    #[test]
    fn test_extract_cn() {
        assert_eq!(
            extract_cn("cn=admin,dc=example,dc=com"),
            Some("admin".to_string())
        );
        assert_eq!(
            extract_cn("uid=user,ou=people,dc=example,dc=com"),
            Some("user".to_string())
        );
    }

    #[test]
    fn test_validate_password() {
        let handler = SetupHandler::new("/tmp/test");

        assert!(handler.validate_password("Short1").is_err());
        assert!(handler.validate_password("nouppercase1").is_err());
        assert!(handler.validate_password("NOLOWERCASE1").is_err());
        assert!(handler.validate_password("NoDigits").is_err());
        assert!(handler.validate_password("ValidPass123").is_ok());
    }

    #[tokio::test]
    async fn test_setup_config_serialization() {
        let config = SetupConfig::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: SetupConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(config.base_dn, deserialized.base_dn);
    }
}
