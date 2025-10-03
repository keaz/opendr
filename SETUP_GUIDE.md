# OpenDR First-Time Setup Guide

This guide explains how to set up OpenDR LDAP Server for the first time, following the OpenDJ setup approach.

## Overview

OpenDR provides a comprehensive setup utility (`opendr-setup`) that guides you through the initial server configuration. The setup process creates:

- Directory administrator account (similar to OpenDJ's "cn=Directory Manager")
- Base directory structure
- Configuration files
- Data storage initialization
- Optional sample data

## Installation

First, build OpenDR and the setup utility:

```bash
cargo build --release
```

The setup binary will be available at `target/release/opendr-setup`.

## Setup Methods

### 1. Interactive Setup (Recommended)

The interactive setup wizard guides you through all configuration options:

```bash
./target/release/opendr-setup interactive
```

You'll be prompted for:

1. **Base DN**: The root of your directory tree (e.g., `dc=example,dc=com`)
2. **Organization Name**: Your organization's name
3. **Root User DN**: Administrator account DN (default: `cn=Directory Manager`)
4. **Root Password**: Secure password for the administrator (minimum 8 characters, must contain uppercase, lowercase, and digits)
5. **LDAP Port**: Port for unencrypted LDAP (default: 1389)
6. **LDAPS Port**: Port for secure LDAP/TLS (default: 1636)
7. **Hostname**: Server hostname (default: localhost)
8. **Storage Backend**:
   - LMDB (recommended for production)
   - In-Memory (for testing only)
9. **Data Directory**: Where to store data (for persistent backends)
10. **Sample Data**: Whether to import sample users and groups

#### Example Interactive Session

```
╔════════════════════════════════════════════════╗
║   OpenDR LDAP Server - First Time Setup       ║
╚════════════════════════════════════════════════╝

Enter the base DN for your directory [dc=example,dc=com]: dc=mycompany,dc=com
Enter your organization name [Example Organization]: MyCompany Inc
Enter the root user DN (administrator account) [cn=Directory Manager]:
Enter the root user password: ********
Confirm the root user password: ********
Enter the LDAP port [1389]:
Enter the LDAPS port (secure) [1636]:
Enter the server hostname [localhost]: ldap.mycompany.com

Select storage backend:
  1. LMDB (recommended for production)
  2. In-Memory (for testing only)
Enter your choice [1]: 1
Enter the data directory path [./data]: /var/lib/opendr/data
Import sample data? (yes/no) [no]: yes

╔════════════════════════════════════════════════╗
║           Setup Configuration Summary          ║
╚════════════════════════════════════════════════╝
  Base DN:        dc=mycompany,dc=com
  Organization:   MyCompany Inc
  Root User DN:   cn=Directory Manager
  LDAP Port:      1389
  LDAPS Port:     1636
  Hostname:       ldap.mycompany.com
  Backend:        Lmdb
  Data Directory: /var/lib/opendr/data
  Sample Data:    Yes

Proceed with this configuration? (yes/no) [yes]: yes

🔧 Performing setup...

  ✓ Creating data directory: /var/lib/opendr/data
  ✓ Initializing Lmdb backend
  ✓ Creating root administrator account: cn=Directory Manager
  ✓ Creating directory structure for: dc=mycompany,dc=com
  ✓ Importing sample data
  ✓ Saving configuration

✨ Setup completed successfully!

You can now start the server with:
  opendr-server start
```

### 2. Non-Interactive Setup

For automated deployments, use a configuration file:

#### Step 1: Generate Sample Configuration

```bash
./target/release/opendr-setup generate-config --output setup.toml
```

This creates a TOML file with default values:

```toml
base_dn = "dc=example,dc=com"
root_user_dn = "cn=Directory Manager"
root_password = ""
ldap_port = 1389
ldaps_port = 1636
hostname = "localhost"
organization_name = "Example Organization"
data_directory = "./data"
import_sample_data = false

[backend_type]
Lmdb = []
```

#### Step 2: Edit Configuration

Modify the `setup.toml` file with your desired settings:

```toml
base_dn = "dc=mycompany,dc=com"
root_user_dn = "cn=Directory Manager"
root_password = "SecurePass123"
ldap_port = 1389
ldaps_port = 1636
hostname = "ldap.mycompany.com"
organization_name = "MyCompany Inc"
data_directory = "/var/lib/opendr/data"
import_sample_data = true

[backend_type]
Lmdb = []
```

#### Step 3: Run Setup

```bash
./target/release/opendr-setup non-interactive --config setup.toml
```

### 3. Check Setup Status

To verify if the server is configured:

```bash
./target/release/opendr-setup status
```

Output:
```
✓ Server is configured and ready to use

Start the server with:
  opendr-server start
```

Or if not configured:
```
✗ Server is not configured

Run setup with:
  opendr-setup interactive
```

## Configuration Details

### Base DN Structure

The setup creates a hierarchical directory structure based on your Base DN:

For `dc=example,dc=com`, the following entries are created:

```
dc=example,dc=com                    (root entry)
├── ou=People,dc=example,dc=com     (user accounts)
├── ou=Groups,dc=example,dc=com     (groups)
└── ou=Applications,dc=example,dc=com (application entries)
```

### Root Administrator Account

The root administrator (default: `cn=Directory Manager`) is created with:

- Full administrative privileges
- Password hashed using Salted SHA-512 (SSHA512)
- Stored in `config/admin.ldif`

**Security Note**: Like OpenDJ, the root DN account has unrestricted access. Use it only when necessary, and consider creating additional administrators with limited privileges for day-to-day operations.

### Password Security

Passwords must meet the following requirements:

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit

Passwords are hashed using **Salted SHA-512** with a random 16-byte salt, compatible with OpenDJ's password storage scheme.

### Sample Data

If you choose to import sample data, the following entries are created:

**Users:**
- `uid=john.doe,ou=People,dc=example,dc=com` (password: `password123`)
- `uid=jane.smith,ou=People,dc=example,dc=com` (password: `password123`)

**Groups:**
- `cn=users,ou=Groups,dc=example,dc=com` (contains both sample users)

These are for testing only and should be removed in production.

## Storage Backends

### LMDB (Lightning Memory-Mapped Database)

- **Recommended for production**
- High performance persistent storage
- ACID-compliant transactions
- Memory-mapped for fast access
- Requires data directory on disk

### In-Memory

- **For testing only**
- All data stored in RAM
- Fast but not persistent
- Data lost on server restart

## Configuration Files

Setup creates the following files in the config directory (default: `./config`):

```
config/
├── server.toml          # Main server configuration
├── setup.state          # Setup state tracking
├── admin.ldif           # Root administrator entry
├── base.ldif            # Base directory structure
└── sample.ldif          # Sample data (if requested)
```

## Resetting Configuration

To reset the server and start over:

```bash
./target/release/opendr-setup reset
```

This will prompt for confirmation:

```
⚠️  WARNING: This will delete all server configuration and data!
Are you sure you want to continue? (yes/no):
```

Or force reset without confirmation:

```bash
./target/release/opendr-setup reset --force
```

## Next Steps

After setup is complete:

1. **Start the Server** (when server binary is available):
   ```bash
   opendr-server start
   ```

2. **Connect with an LDAP Client**:
   ```bash
   ldapsearch -H ldap://localhost:1389 -D "cn=Directory Manager" -w "YourPassword" -b "dc=example,dc=com"
   ```

3. **Import Your Data**:
   ```bash
   ldapadd -H ldap://localhost:1389 -D "cn=Directory Manager" -w "YourPassword" -f your-data.ldif
   ```

4. **Configure TLS/SSL** for secure connections (see TLS documentation)

5. **Create Additional Users and Groups** as needed

## Troubleshooting

### "Server already configured" Error

If you see this error:
```
⚠️  Server is already configured!
To reconfigure, first run: opendr-setup reset
```

This means setup has already been run. Use `reset` to reconfigure.

### Permission Denied on Data Directory

Ensure the user running opendr-setup has write permissions to the data directory:

```bash
sudo mkdir -p /var/lib/opendr/data
sudo chown youruser:yourgroup /var/lib/opendr/data
```

### Password Validation Failed

Ensure your password meets all requirements:
- At least 8 characters
- Contains uppercase letters
- Contains lowercase letters
- Contains digits

### Port Already in Use

If ports 1389 or 1636 are already in use, choose different ports during setup:
- Non-privileged ports: 1024-65535
- Common alternatives: 10389, 10636

## Advanced Configuration

### Custom Backend Type

To use a custom backend (future feature):

```toml
[backend_type]
Custom = "MyBackend"
```

### Multiple Base DNs

Currently, only one base DN is supported during setup. For multiple base DNs, manually edit the configuration after setup or run setup multiple times in different config directories.

## Integration with OpenDJ Tools

OpenDR follows OpenDJ conventions where possible:

- Compatible LDIF format
- Similar DN structure
- Same password hashing scheme (SSHA512)
- Comparable configuration approach

This allows you to:
- Use OpenDJ documentation as a reference
- Migrate data from OpenDJ using standard LDIF export/import
- Use standard LDAP tools with both servers

## API Documentation

For programmatic setup, see the `opendr::setup` module:

```rust
use opendr::setup::{SetupHandler, SetupConfig, BackendType};

let handler = SetupHandler::new("./config");
let config = SetupConfig {
    base_dn: "dc=test,dc=org".to_string(),
    root_user_dn: "cn=admin".to_string(),
    root_password: "SecurePass123".to_string(),
    // ... other fields
};

handler.run_non_interactive_setup(config).await?;
```

## See Also

- [OpenDR Server Documentation](./SERVER.md)
- [Security and Authentication Guide](./PHASE3_SECURITY_COMPLETE.md)
- [Backend Performance Guide](./STORAGE_PERFORMANCE.md)
- [TLS Configuration](./TLS_CONFIG.md)
