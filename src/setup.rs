// First-time setup module for OpenDR LDAP server
// Inspired by OpenDJ setup process

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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

    /// Server hostname
    pub hostname: String,

    /// Organization name
    pub organization_name: String,

    /// Storage backend type
    pub backend_type: BackendType,

    /// Data directory path
    pub data_directory: PathBuf,

    /// Enable sample data
    pub import_sample_data: bool,
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

impl Default for SetupConfig {
    fn default() -> Self {
        Self {
            base_dn: "dc=example,dc=com".to_string(),
            root_user_dn: "cn=Directory Manager".to_string(),
            root_password: String::new(),
            ldap_port: 1389,
            ldaps_port: 1636,
            hostname: "localhost".to_string(),
            organization_name: "Example Organization".to_string(),
            backend_type: BackendType::Lmdb,
            data_directory: PathBuf::from("./data"),
            import_sample_data: false,
        }
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

        toml::from_str(&content)
            .map_err(|e| format!("Failed to parse setup state: {}", e))
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
        let content = toml::to_string_pretty(config)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;

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

    /// Run interactive setup
    pub async fn run_interactive_setup(&self) -> Result<SetupConfig, String> {
        println!("\n╔════════════════════════════════════════════════╗");
        println!("║   OpenDR LDAP Server - First Time Setup       ║");
        println!("╚════════════════════════════════════════════════╝\n");

        let mut config = SetupConfig::default();

        // 1. Base DN
        config.base_dn = self.prompt_with_default(
            "Enter the base DN for your directory",
            &config.base_dn,
        ).await?;

        // 2. Organization name
        config.organization_name = self.prompt_with_default(
            "Enter your organization name",
            &config.organization_name,
        ).await?;

        // 3. Root user DN
        config.root_user_dn = self.prompt_with_default(
            "Enter the root user DN (administrator account)",
            &config.root_user_dn,
        ).await?;

        // 4. Root password
        config.root_password = self.prompt_password("Enter the root user password").await?;
        let confirm_password = self.prompt_password("Confirm the root user password").await?;

        if config.root_password != confirm_password {
            return Err("Passwords do not match".to_string());
        }

        // Validate password strength
        self.validate_password(&config.root_password)?;

        // 5. LDAP port
        let port_str = self.prompt_with_default(
            "Enter the LDAP port",
            &config.ldap_port.to_string(),
        ).await?;
        config.ldap_port = port_str.parse()
            .map_err(|_| "Invalid port number".to_string())?;

        // 6. LDAPS port
        let ports_str = self.prompt_with_default(
            "Enter the LDAPS port (secure)",
            &config.ldaps_port.to_string(),
        ).await?;
        config.ldaps_port = ports_str.parse()
            .map_err(|_| "Invalid port number".to_string())?;

        // 7. Hostname
        config.hostname = self.prompt_with_default(
            "Enter the server hostname",
            &config.hostname,
        ).await?;

        // 8. Backend type
        println!("\nSelect storage backend:");
        println!("  1. LMDB (recommended for production)");
        println!("  2. In-Memory (for testing only)");

        let backend_choice = self.prompt_with_default(
            "Enter your choice",
            "1",
        ).await?;

        config.backend_type = match backend_choice.as_str() {
            "1" => BackendType::Lmdb,
            "2" => BackendType::InMemory,
            _ => return Err("Invalid backend choice".to_string()),
        };

        // 9. Data directory (only for persistent backends)
        if config.backend_type != BackendType::InMemory {
            let data_dir = self.prompt_with_default(
                "Enter the data directory path",
                config.data_directory.to_string_lossy().as_ref(),
            ).await?;
            config.data_directory = PathBuf::from(data_dir);
        }

        // 10. Sample data
        let sample_data = self.prompt_with_default(
            "Import sample data? (yes/no)",
            "no",
        ).await?;
        config.import_sample_data = sample_data.to_lowercase() == "yes"
            || sample_data.to_lowercase() == "y";

        // Display summary
        println!("\n╔════════════════════════════════════════════════╗");
        println!("║           Setup Configuration Summary          ║");
        println!("╚════════════════════════════════════════════════╝");
        println!("  Base DN:        {}", config.base_dn);
        println!("  Organization:   {}", config.organization_name);
        println!("  Root User DN:   {}", config.root_user_dn);
        println!("  LDAP Port:      {}", config.ldap_port);
        println!("  LDAPS Port:     {}", config.ldaps_port);
        println!("  Hostname:       {}", config.hostname);
        println!("  Backend:        {:?}", config.backend_type);
        if config.backend_type != BackendType::InMemory {
            println!("  Data Directory: {}", config.data_directory.display());
        }
        println!("  Sample Data:    {}", if config.import_sample_data { "Yes" } else { "No" });
        println!();

        let confirm = self.prompt_with_default(
            "Proceed with this configuration? (yes/no)",
            "yes",
        ).await?;

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

        // 1. Create data directory if needed
        if config.backend_type != BackendType::InMemory {
            println!("  ✓ Creating data directory: {}", config.data_directory.display());
            fs::create_dir_all(&config.data_directory)
                .await
                .map_err(|e| format!("Failed to create data directory: {}", e))?;
        }

        // 2. Initialize backend
        println!("  ✓ Initializing {:?} backend", config.backend_type);
        self.initialize_backend(config).await?;

        // 3. Create root user entry
        println!("  ✓ Creating root administrator account: {}", config.root_user_dn);
        self.create_root_user(config).await?;

        // 4. Create base DN structure
        println!("  ✓ Creating directory structure for: {}", config.base_dn);
        self.create_base_structure(config).await?;

        // 5. Import sample data if requested
        if config.import_sample_data {
            println!("  ✓ Importing sample data");
            self.import_sample_data(config).await?;
        }

        // 6. Save configuration
        println!("  ✓ Saving configuration");
        self.save_config(config).await?;

        // 7. Mark as configured
        let state = SetupState {
            is_configured: true,
            setup_timestamp: Some(chrono::Utc::now().to_rfc3339()),
            config_version: "1.0.0".to_string(),
            base_dn: Some(config.base_dn.clone()),
        };
        self.save_state(&state).await?;

        println!("\n✨ Setup completed successfully!\n");
        println!("You can now start the server with:");
        println!("  opendr-server start\n");

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
                "Password must contain uppercase, lowercase, and numeric characters".to_string()
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
            extract_cn(&config.root_user_dn).unwrap_or("Directory Manager"),
            password_hash
        );

        // Store this in a special admin.ldif file
        let admin_file = self.config_path.parent()
            .unwrap()
            .join("admin.ldif");

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
                current_dn = format!("{},{}", format!("{}={}", attr, value), current_dn);
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
                config.base_dn,
                config.organization_name,
                config.organization_name
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
        let base_file = self.config_path.parent()
            .unwrap()
            .join("base.ldif");

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

        let sample_file = self.config_path.parent()
            .unwrap()
            .join("sample.ldif");

        fs::write(sample_file, sample_data)
            .await
            .map_err(|e| format!("Failed to create sample data: {}", e))?;

        Ok(())
    }

    /// Hash password using Salted SHA512 (like OpenDJ)
    fn hash_password(&self, password: &str) -> String {
        use rand::Rng;

        // Generate 16-byte salt
        let salt: [u8; 16] = rand::thread_rng().gen();

        // Hash password + salt
        let mut hasher = Sha512::new();
        hasher.update(password.as_bytes());
        hasher.update(&salt);
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
        std::io::stdout().flush()
            .map_err(|e| format!("Failed to flush stdout: {}", e))?;

        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut input = String::new();

        reader.read_line(&mut input)
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
        std::io::stdout().flush()
            .map_err(|e| format!("Failed to flush stdout: {}", e))?;

        // In production, use rpassword crate for hidden input
        // For now, use regular input
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut input = String::new();

        reader.read_line(&mut input)
            .await
            .map_err(|e| format!("Failed to read input: {}", e))?;

        Ok(input.trim().to_string())
    }
}

/// Extract CN from DN
fn extract_cn(dn: &str) -> Option<&str> {
    dn.split(',')
        .next()?
        .split('=')
        .nth(1)
}

/// Parse DN into components
fn parse_dn(dn: &str) -> Result<Vec<(String, String)>, String> {
    let mut components = Vec::new();

    for part in dn.split(',') {
        let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
        if kv.len() != 2 {
            return Err(format!("Invalid DN component: {}", part));
        }
        components.push((kv[0].trim().to_string(), kv[1].trim().to_string()));
    }

    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(extract_cn("cn=admin,dc=example,dc=com"), Some("admin"));
        assert_eq!(extract_cn("uid=user,ou=people,dc=example,dc=com"), Some("user"));
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
