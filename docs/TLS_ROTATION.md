# TLS Certificate Rotation

OpenDR supports a restart-required TLS certificate rotation model. The server
loads `tls.cert_file` and `tls.key_file` once when the runtime creates the
rustls server configuration. Replacing files on disk does not change the
certificate presented by already running LDAP, LDAPS, or StartTLS listeners.

This model is explicit until OpenDR has a reload API or signal handler that
atomically rebuilds the TLS acceptor and reports reload failures to operators.

## Operator Workflow

1. Stage the new certificate and private key outside the live paths.
2. Validate the certificate chain, subject alternative names, expiry, and file
   permissions with your normal PKI tooling.
3. Replace `tls.cert_file` and `tls.key_file` atomically, preserving owner and
   mode. Private keys should remain readable only by the OpenDR service user.
4. Restart OpenDR.
5. Verify LDAPS and StartTLS with clients that trust the new issuing
   certificate.
6. Verify clients that trust only the old certificate fail. This catches trust
   bypass, stale trust bundles, and accidental plaintext fallback.
7. Keep the previous certificate, key, config, and service package available for
   rollback until the new trust bundle is deployed everywhere.

Existing TLS sessions continue with the certificate negotiated when they were
created. New LDAPS connections and new StartTLS upgrades use the certificate
loaded by the current OpenDR process.

## Validation Gate

Run the rotation gate before a production-ready release:

```bash
TLS_ROTATION_ARTIFACT_DIR=target/tls-rotation-gate/release-candidate \
./scripts/tls_rotation_gate.sh
```

If `ldap3` is installed in a virtual environment, set
`TLS_ROTATION_PYTHON=/path/to/venv/bin/python`.

The gate starts an isolated OpenDR instance, generates two temporary CAs and
CA-signed server certificates, and validates:

- LDAPS and StartTLS succeed with the active trust anchor.
- LDAPS and StartTLS fail with the inactive trust anchor.
- Replacing certificate files while OpenDR is running does not hot reload the
  active certificate.
- Restarting OpenDR activates the new certificate.
- Clients that trust only the stale certificate fail after restart.

All generated private keys and certificates stay under the artifact directory,
which defaults to `target/tls-rotation-gate/<timestamp>`. Do not copy those test
keys into tracked source directories.

## Artifacts

The gate retains:

- `summary.md` with each validation step and the final result.
- `logs/server-before-rotation.*.log` and
  `logs/server-after-rotation.*.log`.
- `logs/*LDAPS*.log` and `logs/*StartTLS*.log` with client command output.
- `generated-certs/` containing only short-lived test material.
- `server/config/server.toml` with the isolated test configuration.

On failure, inspect `summary.md` first, then the corresponding command log. A
success where failure was expected means the trust store was too broad or the
client bypassed certificate verification. A post-rotation bind/search failure
means the server did not load the new certificate or the new trust bundle does
not match the presented certificate.
