# OpenDR Security Review: Defaults, Bind Policy, Admin DN, And Audit

Date: 2026-04-16

Scope:

- Default and committed configuration posture.
- LDAP bind policy, anonymous bind, SASL PLAIN, StartTLS, and LDAPS behavior.
- Root/admin DN setup and secret-source handling.
- Audit coverage for authentication, authorization, mutation, replication, and
  sensitive operations.

## Summary

OpenDR has the core controls needed for a production profile: TLS/StartTLS,
production bind policy, SASL PLAIN confidentiality enforcement, secret file/env
sources, audit logging, deny-by-default ACI support, and tests for many
authentication and authorization paths.

It is not ready to describe the default repository configuration as production
safe. The main gaps are operational hardening and consistency issues:
committed/default root secrets are easy to reuse accidentally, root/admin DN
handling is inconsistent, replication audit coverage is missing, and there is no
single hardened config template/gate.

## Follow-Up Issues

| Issue | Severity | Finding |
| --- | --- | --- |
| [#162](https://github.com/keaz/opendr/issues/162) | High | Require secure transport for replication provider credentials. Remediated by default validation policy. |
| [#163](https://github.com/keaz/opendr/issues/163) | High | Remove committed/default root secret from production paths. |
| [#164](https://github.com/keaz/opendr/issues/164) | Medium | Canonicalize root/admin DN handling across auth, ACI, and console. |
| [#165](https://github.com/keaz/opendr/issues/165) | Medium | Add replication security audit events. |
| [#166](https://github.com/keaz/opendr/issues/166) | Medium | Ship a production-hardening config template and gate. |

These issues are release blockers for a full production-ready claim unless the
release notes explicitly exclude the affected feature or configuration path.

## Reviewed Controls

### Default And Sample Configuration

Implemented controls:

- `ServerConfig` supports `root_password`, `root_password_env`, and
  `root_password_file`, and validation rejects multiple root secret sources.
- Replication bind secrets support inline, environment, and file sources.
- TLS configuration validates certificate, key, and CA file existence when
  enabled.
- Code defaults enable audit, access control, and rate limiting, with
  deny-by-default ACI policy when access control is enabled.

Gaps:

- `ServerConfig::default()` still uses `root_password = "secret"`.
- The committed `config/server.toml` contains an inline root password hash and
  does not set `security.profile = "production"`.
- The same committed config disables access control and rate limiting.
- There is no production config gate that rejects disabled hardening controls.

Tracked remediation: [#163](https://github.com/keaz/opendr/issues/163) and
[#166](https://github.com/keaz/opendr/issues/166).

### Bind Policy And TLS

Implemented controls:

- `security.profile = "production"` maps to anonymous bind disabled and
  cleartext non-anonymous simple bind disabled.
- Non-anonymous simple bind over cleartext returns `confidentialityRequired`
  under the production profile.
- SASL PLAIN is only accepted over LDAPS or StartTLS, even outside the
  production profile.
- StartTLS is advertised only when TLS is configured and the connection is not
  already secure.
- StartTLS clears authentication state, so clients must bind again after the
  transport upgrade.
- Password Modify requires a confidential channel and can be disabled by policy.
- Credentialed replication provider URLs must use `ldaps://` by default. The
  development-only `replication.allow_insecure_provider_bind` escape hatch is
  rejected under `security.profile = "production"`.

Coverage:

- `tests/legacy_runtime_security_integration.rs`
- `tests/tls_runtime_integration.rs`
- `tests/security_integration.rs`
- `scripts/ldap_interop_gate.sh`
- `scripts/tls_rotation_gate.sh`

Gaps:

- Development profile remains the default and intentionally allows cleartext
  simple bind and anonymous bind.

Tracked remediation: [#166](https://github.com/keaz/opendr/issues/166). Secure
replication provider transport was remediated by
[#162](https://github.com/keaz/opendr/issues/162).

### Root/Admin DN And Secret Handling

Implemented controls:

- Setup validates password strength before writing setup output.
- Runtime can load root secrets from environment variables or files.
- Monitoring console authentication is restricted to the configured root DN and
  expands RDN-style root DNs before comparison.
- Password Modify distinguishes self-service changes from admin resets.

Gaps:

- Runtime initialization suffixes `root_user_dn` with `base_dn`, while
  `LegacySecurityConfig.root_dn` receives the raw `root_user_dn` value.
- Root/admin checks compare raw case-insensitive strings rather than canonical
  parsed DNs.
- Full-DN and RDN root configurations are not handled through one shared helper
  across initialization, ACI bypass, password modify, and the console.

Tracked remediation: [#164](https://github.com/keaz/opendr/issues/164).

### Audit Coverage

Implemented controls:

- Authentication audit covers simple bind, anonymous bind, and SASL PLAIN
  success/failure paths.
- Authorization audit covers ACI success and denial paths.
- Data modification audit covers Add, Modify, Delete, and ModifyDN.
- Sensitive operation audit covers StartTLS and Password Modify outcomes.
- Connection audit covers accepted and closed connections when enabled.
- Password Modify audit redacts generated and supplied password values.

Coverage:

- `tests/audit_integration.rs`
- `tests/legacy_runtime_security_integration.rs`
- `tests/ldap_ops_client_integration.rs`
- Runtime audit calls in `src/server.rs` and `src/fsm_server.rs`

Gaps:

- `AuditEventType::Replication` exists, but provider/consumer replication
  lifecycle, stale-cookie rejection, changelog-gap recovery, and disconnect
  paths do not emit structured audit events.
- Production readiness evidence does not yet require replication audit samples.

Tracked remediation: [#165](https://github.com/keaz/opendr/issues/165).

## Production Hardening Baseline

Before a deployment can claim production readiness, use or create a config with:

- `security.profile = "production"`.
- `tls.enabled = true` with managed certificate/key paths.
- `root_password_file` or `root_password_env`; no inline root secret.
- `[audit].enabled = true` with authentication, authorization, modification,
  and connection logging enabled.
- `[access_control].enabled = true`, `default_policy = "deny"`, and a reviewed
  ACI rules file.
- `[rate_limit].enabled = true` with bind/search/write limits sized for the
  deployment.
- Replication provider URLs using `ldaps://` confidential transport for every
  configured bind secret.
- Separate runtime directories for data, logs, audit logs, replication state,
  backup artifacts, and TLS key material.

## Release Decision

OpenDR can claim partial production readiness for tested protocol behavior after
the existing readiness gates pass. It should not claim full production readiness
for default deployment posture until #163, #164, #165, and #166 are resolved or
explicitly scoped out of the release.
