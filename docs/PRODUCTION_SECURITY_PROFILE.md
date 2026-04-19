# Production Security Profile

OpenDR supports a named `production` security profile for LDAP deployments that
need RFC 4513-aligned authentication and transport behavior. The default
`development` profile preserves local development behavior; production
deployments should opt in explicitly and enable TLS.

The 2026-04-16 security review in
[`SECURITY_REVIEW_2026_04_16.md`](./SECURITY_REVIEW_2026_04_16.md) tracks
remaining production-hardening gaps and linked remediation issues.

## Required Configuration

```toml
[tls]
enabled = true
cert_file = "/etc/opendr/tls/server.crt"
key_file = "/etc/opendr/tls/server.key"
min_tls_version = "1.2"

[security]
profile = "production"
```

`security.profile = "production"` requires `tls.enabled = true` at config
validation time. It also rejects inline `server.root_password`; use
`server.root_password_file` or `server.root_password_env` with an
operator-provided secret.

Start production deployment configs from
[`config/production.toml`](../config/production.toml), tune
[`config/production-aci.toml`](../config/production-aci.toml), and run
`scripts/production_config_gate.sh <server.toml>` against each final provider
and consumer config.

## Profile Defaults

| Policy | Development | Production |
| --- | --- | --- |
| `allow_anonymous_bind` | `true` | `false` |
| `allow_cleartext_simple_bind` | `true` | `false` |
| `allow_sasl_plain` | `true` | `true` |
| `allow_sasl_external` | `true` | `true` |
| `allow_password_modify` | `true` | `true` |
| `root_dse_requires_authentication` | `false` | `false` |

All values can be overridden under `[security]` when a deployment has a
controlled exception. SASL PLAIN still requires LDAPS or StartTLS even when
`allow_sasl_plain = true`. SASL EXTERNAL requires LDAPS or StartTLS plus a
verified client certificate that resolves to an existing LDAP DN.

## RFC 4513 Guarantees

- Anonymous bind is disabled by default in the production profile.
- Non-anonymous simple bind over cleartext LDAP is rejected with
  `confidentialityRequired` by default in the production profile.
- SASL PLAIN is supported only over LDAPS or StartTLS. Empty authzid,
  self-authzid in `dn:<distinguishedName>` form, and self-authzid in
  `u:<authcid>` form are accepted; proxy authorization is not enabled.
- SASL EXTERNAL is supported over verified mutual TLS. The client certificate
  subject common name is mapped through `security.sasl_external_identity_map`;
  when no mapping exists, the common name may be used directly if it is a valid
  LDAP DN. Empty authzid and self `dn:<distinguishedName>` authzid are accepted;
  proxy authorization is not enabled.
- GSSAPI, DIGEST-MD5, CRAM-MD5, SCRAM, and other multi-step SASL mechanisms are
  not production-enabled.
- StartTLS succeeds only when TLS is configured, rejects already-secure
  sequencing, clears authentication state, and requires clients to bind again.
- Password Modify requires a confidential channel and can be disabled by
  `allow_password_modify = false`.
- WhoAmI returns the current authorization identity and reflects the post-StartTLS
  authentication reset.
- Unknown critical controls continue to be rejected before operation dispatch.

## TLS Checklist

- Use `min_tls_version = "1.2"` or `"1.3"`.
- Set `require_client_cert = true` and `ca_file` when mutual TLS is required.
- Set `security.sasl_external_identity_map` for every client certificate common
  name that should bind with SASL EXTERNAL unless the common name is already the
  exact LDAP DN.
- Keep private keys readable only by the OpenDR service account.
- Use `server.root_password_env` or `server.root_password_file`; inline
  `server.root_password` is development-only and rejected by the production
  profile.
- Rotate service and replication bind credentials through secret files or
  environment sources.
- Use `ldaps://` provider URLs for credentialed replication. The
  `replication.allow_insecure_provider_bind` development escape hatch is
  rejected under the production profile.

## Audit And Authorization Checklist

- Keep `[audit].enabled = true`.
- Keep `log_authentication`, `log_authorization`, `log_modifications`,
  `log_connections`, and `log_replication` enabled for production.
- Keep `[access_control].enabled = true` and `default_policy = "deny"`.
- Add explicit ACI rules for every non-public read or write path.
- Review audit logs for successful and failed bind, SASL bind, StartTLS,
  Password Modify, authorization denial, connection, administrative, and
  replication lifecycle events. Replication audit records must identify session
  start/completion, stale-cookie or changelog-gap rejection, reconnects, and
  provider/consumer disconnects without bind passwords or URL credentials.
- Failed and successful bind metadata is stored in operational attributes when
  `auth_metadata.update_mode` is `sync` or `async_coalesced`.
