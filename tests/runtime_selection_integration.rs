use opendr::config::ServerConfig;

#[test]
fn test_default_runtime_is_legacy() {
    let config = ServerConfig::default();
    assert_eq!(config.server.runtime, "legacy");
    assert!(config.validate().is_ok());
    assert!(config.validate_for_shipped_binary().is_ok());
}

#[test]
fn test_fsm_runtime_is_accepted_for_shipped_binary() {
    let toml = r#"
[server]
runtime = "fsm"
"#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    assert!(config.validate().is_ok());
    assert!(config.validate_for_shipped_binary().is_ok());
}

#[test]
fn test_legacy_runtime_round_trips_through_toml() {
    let toml = r#"
[server]
runtime = "legacy"
"#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    assert_eq!(config.server.runtime, "legacy");
    assert!(config.validate_for_shipped_binary().is_ok());

    let serialized = config.to_toml_string().unwrap();
    assert!(serialized.contains("runtime = \"legacy\""));
}

#[test]
fn test_fsm_runtime_round_trips_through_toml() {
    let toml = r#"
[server]
runtime = "fsm"
"#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    assert_eq!(config.server.runtime, "fsm");
    assert!(config.validate_for_shipped_binary().is_ok());

    let serialized = config.to_toml_string().unwrap();
    assert!(serialized.contains("runtime = \"fsm\""));
}

#[test]
fn test_legacy_runtime_rejects_nondefault_burst_size() {
    let toml = r#"
[server]
runtime = "legacy"

[rate_limit]
burst_size = 5
"#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    assert!(config.validate().is_ok());

    let error = config
        .validate_for_shipped_binary()
        .unwrap_err()
        .to_string();
    assert!(error.contains("burst_size"));
    assert!(error.contains("legacy runtime"));
}
