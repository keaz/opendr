# Replication Authentication Fix Summary

## Problem

When the consumer attempted to connect to the provider server, it encountered two issues:

1. **Empty DN Bind Error**: The consumer was attempting anonymous bind (empty DN), which caused the LMDB backend on the provider to fail with:
   ```
   ERROR | Backend authentication error for : storage error: DN lookup failed: MDB_BAD_VALSIZE: Unsupported size of key/DB name/data, or wrong DUPFIXED size
   ```

2. **Configuration Mismatch**: The TOML configuration used `provider_bind_dn` and `provider_bind_password`, but the code was reading `bind_dn` and `bind_password`.

## Root Causes

### Issue 1: No Credentials in Connection

The `ProviderConnectionImpl::connect()` method was hardcoded to use anonymous bind:

```rust
// OLD CODE
match ldap.simple_bind("", "").await {  // ← Always anonymous!
```

This meant even if credentials were configured, they were never used during the LDAP bind operation.

### Issue 2: Configuration Key Mismatch

**TOML Configuration** (`config/server.toml`):
```toml
[replication]
provider_bind_dn = "cn=manager,dc=example,dc=com"
provider_bind_password = "Admin@123"
```

**Code** (`src/replication_service.rs` line 205):
```rust
provider_bind_dn: config.replication.bind_dn.clone(),  // ← Reading wrong key!
provider_bind_password: config.replication.bind_password.clone(),
```

The config struct in `config.rs` defines:
```rust
pub bind_dn: Option<String>,        // ← Without "provider_" prefix
pub bind_password: Option<String>,
```

## Solution

### Fix 1: Add Credential Support to ProviderConnectionImpl

**File: `src/replication.rs`**

1. **Updated struct to store credentials:**
   ```rust
   pub struct ProviderConnectionImpl {
       provider_url: Arc<Mutex<Option<String>>>,
       connected: Arc<Mutex<bool>>,
       changelog_provider: Arc<dyn ChangelogProvider>,
       ldap_connection: Arc<Mutex<Option<ldap3::Ldap>>>,
       bind_dn: Option<String>,           // ← NEW
       bind_password: Option<String>,     // ← NEW
   }
   ```

2. **Added constructor with credentials:**
   ```rust
   pub fn with_credentials(
       changelog_provider: Arc<dyn ChangelogProvider>,
       bind_dn: Option<String>,
       bind_password: Option<String>,
   ) -> Self {
       Self {
           provider_url: Arc::new(Mutex::new(None)),
           connected: Arc::new(Mutex::new(false)),
           changelog_provider,
           ldap_connection: Arc::new(Mutex::new(None)),
           bind_dn,
           bind_password,
       }
   }
   ```

3. **Updated connect() to use stored credentials:**
   ```rust
   // Bind with provided credentials or anonymous if none provided
   let bind_dn = self.bind_dn.as_deref().unwrap_or("");
   let bind_password = self.bind_password.as_deref().unwrap_or("");
   
   if bind_dn.is_empty() {
       warn!("Attempting anonymous bind to provider {} (no credentials configured)", url);
   } else {
       info!("Binding to provider {} as {}", url, bind_dn);
   }
   
   match ldap.simple_bind(bind_dn, bind_password).await {
       // ... error handling ...
   }
   ```

### Fix 2: Pass Credentials to ProviderConnectionImpl

**File: `src/replication_service.rs` (line 369)**

```rust
// OLD:
let provider_connection = Box::new(ProviderConnectionImpl::new(remote_changelog_provider));

// NEW:
let provider_connection = Box::new(ProviderConnectionImpl::with_credentials(
    remote_changelog_provider,
    consumer_config.provider_bind_dn.clone(),
    consumer_config.provider_bind_password.clone(),
));
```

### Fix 3: Correct Configuration Keys

**File: `config/server.toml`**

```toml
# OLD (incorrect keys):
provider_bind_dn = "cn=manager,dc=example,dc=com"
provider_bind_password = "Admin@123"

# NEW (correct keys matching code):
bind_dn = "cn=manager,dc=example,dc=com"
bind_password = "Admin@123"
```

## Testing Results

### Before Fixes

**Logs showing failures:**
```
WARN  | Attempting anonymous bind to provider ldap://localhost:1389 (no credentials configured)
ERROR | LDAP bind failed for : LDAP operation result: rc=52 (unavailable), dn: "", text: "backend failure"
ERROR | Replication sync cycle failed: ConnectionError { ... }
```

**Provider logs showing LMDB error:**
```
ERROR | Backend authentication error for : storage error: DN lookup failed: MDB_BAD_VALSIZE
```

### After Fixes

**Consumer logs showing success:**
```
INFO  | Binding to provider ldap://localhost:1389 as cn=manager,dc=example,dc=com
INFO  | Successfully connected to replication provider: ldap://localhost:1389
INFO  | Replication sync cycle completed successfully
```

**No errors on provider side** - proper authentication succeeds.

## Configuration Reference

### Provider Server (svr_1/config/server.toml):
```toml
[server]
ldap_port = 1389
base_dn = "dc=example,dc=com"
root_user_dn = "cn=manager"
root_password = "{SSHA512}..."

[replication]
enabled = true
mode = "provider"
changelog_enabled = true
```

### Consumer Server (config/server.toml):
```toml
[server]
ldap_port = 1388
base_dn = "dc=example,dc=com"

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://localhost:1389"
bind_dn = "cn=manager,dc=example,dc=com"      # ← Must match provider's root_user_dn
bind_password = "Admin@123"                     # ← Cleartext password for provider auth
sync_interval_secs = 15
```

## Important Notes

1. **Credential Requirements**: The consumer must authenticate to the provider using valid LDAP credentials. In this case, we're using the provider's root user (`cn=manager,dc=example,dc=com`).

2. **Configuration Key Names**: The TOML keys are `bind_dn` and `bind_password` (without the `provider_` prefix), matching the Rust struct definition in `config.rs`.

3. **Password Format**: The `bind_password` in the consumer config is cleartext (not hashed) because it's used for LDAP bind operations to the remote provider.

4. **Anonymous Bind Fallback**: If no credentials are configured (both `bind_dn` and `bind_password` are empty), the code will attempt anonymous bind and log a warning.

5. **Security Consideration**: Storing cleartext passwords in config files is not ideal for production. Consider using environment variables or secrets management systems.

## Future Improvements

1. **Dedicated Replication User**: Create a dedicated user account (e.g., `cn=replication,dc=example,dc=com`) with restricted permissions instead of using the root user.

2. **Password Security**: Support loading passwords from environment variables or external secrets management.

3. **Connection Pooling**: Reuse LDAP connections across sync cycles instead of connecting/disconnecting every time.

4. **TLS/SSL Support**: Add support for `ldaps://` URLs with proper certificate validation.

5. **Certificate-based Authentication**: Support client certificate authentication instead of password-based auth.

---

**Date:** October 7, 2025  
**Issue:** Consumer unable to authenticate to provider (anonymous bind causing backend errors)  
**Status:** ✅ FIXED  
**Files Modified:**
- `src/replication.rs` (added credential support)
- `src/replication_service.rs` (pass credentials to connection)
- `config/server.toml` (corrected configuration keys)
