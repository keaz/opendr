use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_gate(config_path: &std::path::Path) -> std::process::Output {
    Command::new("bash")
        .arg(repo_root().join("scripts/production_config_gate.sh"))
        .arg(config_path)
        .current_dir(repo_root())
        .output()
        .expect("production config gate should run")
}

#[test]
fn production_template_passes_hardening_gate() {
    let output = run_gate(&repo_root().join("config/production.toml"));

    assert!(
        output.status.success(),
        "gate failed unexpectedly\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Production config gate passed"));
}

#[test]
fn production_gate_rejects_unsafe_baseline() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("unsafe-production.toml");
    fs::write(
        &config_path,
        r#"
[server]
root_password = "inline-secret"

[backend]
backend_type = "lmdb"
data_directory = "./data"

[tls]
enabled = false

[security]
profile = "production"
allow_cleartext_simple_bind = true
allow_anonymous_bind = true

[rate_limit]
enabled = false

[audit]
enabled = false
log_authentication = false

[access_control]
enabled = false
default_policy = "allow"

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.org:389"
bind_dn = "cn=replicator,dc=example,dc=org"
bind_password = "inline-replication-secret"
allow_insecure_provider_bind = true
state_storage_path = "./data/replication_state"
"#,
    )
    .unwrap();

    let output = run_gate(&config_path);

    assert!(
        !output.status.success(),
        "unsafe config unexpectedly passed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("tls.enabled must be true"));
    assert!(stderr.contains("server.root_password must not be inline"));
    assert!(stderr.contains("security.allow_cleartext_simple_bind must not be true"));
    assert!(stderr.contains("security.allow_anonymous_bind must not be true"));
    assert!(stderr.contains("audit.enabled must be true"));
    assert!(stderr.contains("access_control.enabled must be true"));
    assert!(stderr.contains("rate_limit.enabled must be true"));
    assert!(stderr.contains("replication.provider_url must use ldaps://"));
    assert!(stderr.contains("replication.bind_password must not be inline"));
}
