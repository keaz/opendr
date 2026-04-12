use std::process::Command;

fn assert_help(binary: &str, expected: &[&str]) {
    let output = Command::new(binary)
        .arg("--help")
        .output()
        .expect("failed to run binary help");

    assert!(
        output.status.success(),
        "help command failed for {binary}: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected_text in expected {
        assert!(
            stdout.contains(expected_text),
            "help output for {binary} did not contain {expected_text:?}:\n{stdout}"
        );
    }
}

#[test]
fn opendr_help_does_not_require_runtime_config() {
    assert_help(
        env!("CARGO_BIN_EXE_opendr"),
        &["OpenDR LDAP server", "Usage:"],
    );
}

#[test]
fn ldap_ops_client_help_smoke() {
    assert_help(
        env!("CARGO_BIN_EXE_ldap_ops_client"),
        &["Exercise the OpenDR LDAP server", "Usage:"],
    );
}

#[test]
fn ldap_perf_client_help_smoke() {
    assert_help(
        env!("CARGO_BIN_EXE_ldap_perf_client"),
        &["Benchmark OpenDR LDAP operations", "Usage:"],
    );
}
