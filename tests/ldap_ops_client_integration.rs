use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio::process::Command as TokioCommand;
use tokio::time::{sleep, timeout};

struct TestBinaryServer {
    _tempdir: TempDir,
    child: Child,
    ldap_port: u16,
}

impl Drop for TestBinaryServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn opendr_binary() -> PathBuf {
    let cargo_binary = PathBuf::from(env!("CARGO_BIN_EXE_opendr"));
    let stable_binary = cargo_binary
        .parent()
        .and_then(|parent| parent.parent())
        .map(|parent| parent.join("opendr"));

    match stable_binary {
        Some(path) if path.exists() => path,
        _ => cargo_binary,
    }
}

fn ldap_client_binary() -> PathBuf {
    let cargo_binary = PathBuf::from(env!("CARGO_BIN_EXE_ldap_ops_client"));
    let stable_binary = cargo_binary
        .parent()
        .and_then(|parent| parent.parent())
        .map(|parent| parent.join("ldap_ops_client"));

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

fn generate_test_certificate() -> (String, String) {
    let certified = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    (cert_pem, key_pem)
}

fn write_tls_fixture(tempdir: &TempDir, runtime: &str, ldap_port: u16, ldaps_port: u16) {
    let config_dir = tempdir.path().join("config");
    let cert_dir = tempdir.path().join("certs");
    let data_dir = tempdir.path().join("data");
    let (cert_pem, key_pem) = generate_test_certificate();

    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&cert_dir).unwrap();
    fs::create_dir_all(&data_dir).unwrap();

    fs::write(cert_dir.join("server.crt"), cert_pem).unwrap();
    fs::write(cert_dir.join("server.key"), key_pem).unwrap();

    let server_toml = format!(
        r#"
[server]
runtime = "{runtime}"
bind_address = "127.0.0.1"
ldap_port = {ldap_port}
ldaps_port = {ldaps_port}
base_dn = "dc=example,dc=org"
root_user_dn = "cn=admin"
root_password = "secret"

[backend]
backend_type = "memory"
data_directory = "./data"

[tls]
enabled = true
cert_file = "certs/server.crt"
key_file = "certs/server.key"
require_client_cert = false
min_tls_version = "1.2"

[monitoring]
enabled = false

[replication]
enabled = false

[audit]
enabled = false

[access_control]
enabled = false

[rate_limit]
enabled = false
"#
    );
    fs::write(config_dir.join("server.toml"), server_toml).unwrap();

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

fn spawn_opendr(tempdir: TempDir, ldap_port: u16) -> TestBinaryServer {
    let child = Command::new(opendr_binary())
        .current_dir(tempdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    TestBinaryServer {
        _tempdir: tempdir,
        child,
        ldap_port,
    }
}

async fn connect_with_retry(port: u16) -> TcpStream {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..120 {
        match TcpStream::connect(&addr).await {
            Ok(stream) => return stream,
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }

    panic!("failed to connect to LDAP server on port {port}");
}

async fn spawn_tls_runtime_server(runtime: &str) -> TestBinaryServer {
    let tempdir = tempfile::tempdir().unwrap();
    let ldap_port = reserve_port();
    let ldaps_port = reserve_port();
    write_tls_fixture(&tempdir, runtime, ldap_port, ldaps_port);
    let server = spawn_opendr(tempdir, ldap_port);
    let stream = connect_with_retry(server.ldap_port).await;
    drop(stream);
    server
}

#[tokio::test]
async fn ldap_ops_client_exercises_supported_operations_over_starttls() {
    let server = spawn_tls_runtime_server("legacy").await;
    let output = timeout(
        Duration::from_secs(60),
        TokioCommand::new(ldap_client_binary())
            .arg("--url")
            .arg(format!("ldap://127.0.0.1:{}", server.ldap_port))
            .arg("--starttls")
            .arg("--insecure")
            .arg("--bind-dn")
            .arg("cn=admin,dc=example,dc=org")
            .arg("--password")
            .arg("secret")
            .arg("--base-dn")
            .arg("dc=example,dc=org")
            .arg("--name-prefix")
            .arg("integration-client")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("ldap_ops_client timed out")
    .expect("failed to execute ldap_ops_client");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ldap_ops_client failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("All LDAP operations completed successfully."),
        "client output did not contain success marker\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Verified Password Modify"),
        "client output did not exercise Password Modify\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[tokio::test]
async fn ldap_ops_client_exercises_supported_operations_over_starttls_with_fsm() {
    let server = spawn_tls_runtime_server("fsm").await;
    let output = timeout(
        Duration::from_secs(60),
        TokioCommand::new(ldap_client_binary())
            .arg("--url")
            .arg(format!("ldap://127.0.0.1:{}", server.ldap_port))
            .arg("--starttls")
            .arg("--insecure")
            .arg("--bind-dn")
            .arg("cn=admin,dc=example,dc=org")
            .arg("--password")
            .arg("secret")
            .arg("--base-dn")
            .arg("dc=example,dc=org")
            .arg("--name-prefix")
            .arg("integration-client-fsm")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("ldap_ops_client timed out")
    .expect("failed to execute ldap_ops_client");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ldap_ops_client failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("All LDAP operations completed successfully."),
        "client output did not contain success marker\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Verified Password Modify"),
        "client output did not exercise Password Modify\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
