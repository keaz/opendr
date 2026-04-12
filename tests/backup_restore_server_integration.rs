use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use base64::Engine;
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use sha2::{Digest, Sha512};
use tempfile::TempDir;
use tokio::time::sleep;

const BASE_DN: &str = "dc=example,dc=org";
const ADMIN_DN: &str = "cn=admin,dc=example,dc=org";
const ADMIN_PASSWORD: &str = "secret";

struct TestServer {
    child: Child,
    ldap_port: u16,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl TestServer {
    fn logs(&self) -> String {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            fs::read_to_string(&self.stdout_log).unwrap_or_else(|_| "<unreadable>".to_string()),
            fs::read_to_string(&self.stderr_log).unwrap_or_else(|_| "<unreadable>".to_string())
        )
    }
}

fn opendr_binary() -> PathBuf {
    stable_binary_path(env!("CARGO_BIN_EXE_opendr"), "opendr")
}

fn backup_binary() -> PathBuf {
    stable_binary_path(env!("CARGO_BIN_EXE_opendr-backup"), "opendr-backup")
}

fn restore_binary() -> PathBuf {
    stable_binary_path(env!("CARGO_BIN_EXE_opendr-restore"), "opendr-restore")
}

fn stable_binary_path(cargo_binary: &str, binary_name: &str) -> PathBuf {
    let cargo_binary = PathBuf::from(cargo_binary);
    let stable_binary = cargo_binary
        .parent()
        .and_then(|parent| parent.parent())
        .map(|parent| parent.join(binary_name));

    match stable_binary {
        Some(path) if path.exists() => path,
        _ => cargo_binary,
    }
}

fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn ssha512_hash(password: &str) -> String {
    let salt = b"opendr-backup-restore-server-test";
    let mut hasher = Sha512::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let digest = hasher.finalize();

    let mut combined = Vec::with_capacity(digest.len() + salt.len());
    combined.extend_from_slice(&digest);
    combined.extend_from_slice(salt);
    format!(
        "{{SSHA512}}{}",
        base64::engine::general_purpose::STANDARD.encode(combined)
    )
}

fn write_log_config(config_dir: &Path) {
    fs::create_dir_all(config_dir).unwrap();
    let log4rs = r#"
appenders:
  stdout:
    kind: console
root:
  level: error
  appenders:
    - stdout
"#;
    fs::write(config_dir.join("log4rs.yml"), log4rs).unwrap();
}

fn write_lmdb_server_config(
    config_dir: &Path,
    data_dir: &Path,
    state_dir: &Path,
    ldap_port: u16,
    ldaps_port: u16,
) -> PathBuf {
    fs::create_dir_all(config_dir).unwrap();
    fs::create_dir_all(data_dir).unwrap();
    fs::create_dir_all(state_dir).unwrap();
    let admin_password_hash = ssha512_hash(ADMIN_PASSWORD);

    let server_toml = format!(
        r#"
[server]
runtime = "legacy"
bind_address = "127.0.0.1"
ldap_port = {ldap_port}
ldaps_port = {ldaps_port}
base_dn = "{BASE_DN}"
root_user_dn = "cn=admin"
root_password = "{admin_password_hash}"
organization_name = "Example Org"

[backend]
backend_type = "lmdb"
data_directory = "{}"
lmdb_max_size = 67108864
lmdb_max_readers = 126
indexed_attributes = []

[tls]
enabled = false

[monitoring]
enabled = false

[replication]
enabled = false
state_storage_path = "{}"

[audit]
enabled = false

[access_control]
enabled = false

[rate_limit]
enabled = false

[performance]
indexing_enabled = false
"#,
        toml_path(data_dir),
        toml_path(state_dir),
    );

    let config_path = config_dir.join("server.toml");
    fs::write(&config_path, server_toml).unwrap();
    config_path
}

fn spawn_opendr(
    cwd: &Path,
    config_path: &Path,
    log_config_path: &Path,
    ldap_port: u16,
) -> TestServer {
    let stdout_log = cwd.join(format!("opendr-{ldap_port}.stdout.log"));
    let stderr_log = cwd.join(format!("opendr-{ldap_port}.stderr.log"));
    let stdout = fs::File::create(&stdout_log).unwrap();
    let stderr = fs::File::create(&stderr_log).unwrap();
    let child = Command::new(opendr_binary())
        .current_dir(cwd)
        .arg("--config")
        .arg(config_path)
        .arg("--log-config")
        .arg(log_config_path)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap();

    TestServer {
        child,
        ldap_port,
        stdout_log,
        stderr_log,
    }
}

async fn bind_admin_with_retry(server: &mut TestServer) -> Ldap {
    let url = format!("ldap://127.0.0.1:{}", server.ldap_port);

    for _ in 0..120 {
        if let Some(status) = server.child.try_wait().unwrap() {
            panic!(
                "OpenDR server on {} exited before bind succeeded with status {status}\n{}",
                server.ldap_port,
                server.logs()
            );
        }

        if let Ok((conn, mut ldap)) = LdapConnAsync::new(&url).await {
            ldap3::drive!(conn);
            if let Ok(result) = ldap.simple_bind(ADMIN_DN, ADMIN_PASSWORD).await {
                if result.success().is_ok() {
                    return ldap;
                }
            }
            let _ = ldap.unbind().await;
        }

        sleep(Duration::from_millis(50)).await;
    }

    panic!(
        "failed to bind to OpenDR server on {url}\n{}",
        server.logs()
    );
}

async fn add_backup_test_entry(ldap: &mut Ldap, user_dn: &str) {
    ldap.add(
        user_dn,
        vec![
            (
                "objectClass".to_string(),
                string_set(["top", "person", "inetOrgPerson"]),
            ),
            ("cn".to_string(), string_set(["backup-user"])),
            ("sn".to_string(), string_set(["Restored"])),
            (
                "description".to_string(),
                string_set(["created before online backup"]),
            ),
            ("userPassword".to_string(), string_set(["restore-secret"])),
        ],
    )
    .await
    .unwrap()
    .success()
    .unwrap();
}

async fn assert_backup_test_entry(ldap: &mut Ldap, user_dn: &str) {
    let (entries, _result) = ldap
        .search(
            user_dn,
            Scope::Base,
            "(objectClass=inetOrgPerson)",
            vec!["cn", "sn", "description"],
        )
        .await
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(entries.len(), 1, "expected restored LDAP entry {user_dn}");

    let entry = SearchEntry::construct(entries.into_iter().next().unwrap());
    assert_attr_contains(&entry, "cn", "backup-user");
    assert_attr_contains(&entry, "sn", "Restored");
    assert_attr_contains(&entry, "description", "created before online backup");
}

fn assert_attr_contains(entry: &SearchEntry, name: &str, expected: &str) {
    let values = entry
        .attrs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, values)| values)
        .unwrap_or_else(|| panic!("missing attribute {name} in {}", entry.dn));
    assert!(
        values.iter().any(|value| value == expected),
        "attribute {name} on {} did not contain {expected:?}: {values:?}",
        entry.dn
    );
}

fn string_set<I, S>(values: I) -> HashSet<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    values.into_iter().map(Into::into).collect()
}

fn assert_success(output: std::process::Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn online_backup_restores_data_into_running_opendr_server() {
    let root = TempDir::new().unwrap();
    let config_dir = root.path().join("config");
    write_log_config(&config_dir);
    let log_config_path = config_dir.join("log4rs.yml");

    let source_data = root.path().join("source-data");
    let source_state = root.path().join("source-state");
    let source_ldap_port = reserve_port();
    let source_config = write_lmdb_server_config(
        &config_dir,
        &source_data,
        &source_state,
        source_ldap_port,
        reserve_port(),
    );
    let mut source_server = spawn_opendr(
        root.path(),
        &source_config,
        &log_config_path,
        source_ldap_port,
    );

    let user_dn = format!("cn=backup-user,ou=People,{BASE_DN}");
    let mut source_ldap = bind_admin_with_retry(&mut source_server).await;
    add_backup_test_entry(&mut source_ldap, &user_dn).await;
    assert_backup_test_entry(&mut source_ldap, &user_dn).await;

    let backup_dir = root.path().join("online-full-backup");
    let backup_output = Command::new(backup_binary())
        .current_dir(root.path())
        .arg("--config")
        .arg(&source_config)
        .arg("--json")
        .arg("full")
        .arg("--target")
        .arg(&backup_dir)
        .output()
        .unwrap();
    assert_success(backup_output, "online backup");

    assert_backup_test_entry(&mut source_ldap, &user_dn).await;
    let _ = source_ldap.unbind().await;
    drop(source_server);

    let restored_data = root.path().join("restored-data");
    let restore_output = Command::new(restore_binary())
        .current_dir(root.path())
        .arg("--backup")
        .arg(&backup_dir)
        .arg("--target-data-dir")
        .arg(&restored_data)
        .arg("--json")
        .output()
        .unwrap();
    assert_success(restore_output, "restore");

    let restored_config_dir = root.path().join("restored-config");
    write_log_config(&restored_config_dir);
    let restored_log_config_path = restored_config_dir.join("log4rs.yml");
    let restored_ldap_port = reserve_port();
    let restored_config = write_lmdb_server_config(
        &restored_config_dir,
        &restored_data,
        &root.path().join("restored-state"),
        restored_ldap_port,
        reserve_port(),
    );
    let mut restored_server = spawn_opendr(
        root.path(),
        &restored_config,
        &restored_log_config_path,
        restored_ldap_port,
    );

    let mut restored_ldap = bind_admin_with_retry(&mut restored_server).await;
    assert_backup_test_entry(&mut restored_ldap, &user_dn).await;
    let _ = restored_ldap.unbind().await;
    drop(restored_server);
}
