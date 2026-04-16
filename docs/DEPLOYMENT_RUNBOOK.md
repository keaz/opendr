# OpenDR Production Deployment Runbook

This runbook is the operator procedure for a single writable OpenDR provider
with one or more read-only consumers. It is intentionally conservative: backup
before upgrade, validate before exposing traffic, and roll back by restoring a
known-good provider backup plus re-bootstrapping consumers when provider data is
rolled back.

Full production readiness is still gated by the security findings tracked in
[`SECURITY_REVIEW_2026_04_16.md`](./SECURITY_REVIEW_2026_04_16.md). Do not use
this runbook to claim full production readiness while open High or Medium
findings remain in scope for the deployment.

## Supported Deployment Shape

Production-supported:

- One writable provider.
- One provider with one or more consumers.
- Fan-out from the same writable provider to independent consumers.
- Consumer rebootstrap through full refresh after provider restore.

Not production-supported:

- Multi-provider or multi-master writes.
- Conflict resolution between concurrent writes on different nodes.
- Cascading consumers as a high-availability topology.
- Replication of server config, schema files, ACL files, TLS material, logs,
  indexes, or setup state.
- Treating `mode = "both"` as multi-master. It is only acceptable with a clear
  single writable upstream and explicit operational approval.

See [`REPLICATION_PRODUCTION_GUARANTEES.md`](./REPLICATION_PRODUCTION_GUARANTEES.md)
for the detailed replication contract.

## Required Inputs

Record these before deployment:

- Release commit SHA and binary build artifact.
- Provider and consumer hostnames, LDAP/LDAPS ports, and firewall rules.
- Base DN, root/admin DN, replication bind DN, and secret source paths.
- TLS certificate, key, CA bundle, expiry dates, and rotation owner.
- Provider and consumer data directories, replication state directories, log
  directories, audit log paths, and backup target path.
- Changelog capacity sized for the longest expected consumer outage.
- Monitoring endpoint, alert recipients, and rollback owner.
- Last successful production-readiness evidence from
  [`PRODUCTION_READINESS_CHECKLIST.md`](./PRODUCTION_READINESS_CHECKLIST.md).

Required local tools on the operator host:

```bash
opendr --help
opendr-backup --help
opendr-restore --help
ldapsearch -VV
ldapadd -VV
openssl version
```

## Filesystem Layout

Use separate directories per role. Do not share data, replication state, logs, or
TLS key material between provider and consumer processes.

Provider:

```text
/etc/opendr/provider/server.toml
/etc/opendr/provider/log4rs.yml
/etc/opendr/provider/aci.toml
/etc/opendr/provider/certs/provider.crt
/etc/opendr/provider/certs/provider.key
/etc/opendr/provider/certs/ca.crt
/run/secrets/opendr-provider-root-password-hash
/run/secrets/opendr-replication-bind-password
/var/lib/opendr/provider/data
/var/lib/opendr/provider/replication_state
/var/log/opendr/provider.log
/var/log/opendr/provider-audit.log
/var/backups/opendr/provider
```

Consumer:

```text
/etc/opendr/consumer/server.toml
/etc/opendr/consumer/log4rs.yml
/etc/opendr/consumer/aci.toml
/etc/opendr/consumer/certs/consumer.crt
/etc/opendr/consumer/certs/consumer.key
/etc/opendr/consumer/certs/ca.crt
/run/secrets/opendr-consumer-root-password-hash
/run/secrets/opendr-replication-bind-password
/var/lib/opendr/consumer/data
/var/lib/opendr/consumer/replication_state
/var/log/opendr/consumer.log
/var/log/opendr/consumer-audit.log
```

## Configuration Baseline

Use a hardened config as the starting point:

- `security.profile = "production"`.
- `tls.enabled = true` with readable certificate, key, and CA paths.
- `root_password_file` or `root_password_env`; never inline production root
  secrets in `server.toml`.
- `[audit].enabled = true`, with authentication, authorization, modification,
  and connection events enabled.
- `[access_control].enabled = true`, `default_policy = "deny"`, and a reviewed
  ACI rules file.
- `[rate_limit].enabled = true`, with bind, search, and write limits sized for
  the expected traffic.
- LMDB data directories on persistent storage with backup capacity at least the
  data volume plus one full backup.
- `replication.state_storage_path` on persistent storage for provider changelog
  and consumer cookies.
- `replication.provider_url` uses `ldaps://` whenever replication bind
  credentials are configured. The development-only
  `allow_insecure_provider_bind` option is rejected under
  `security.profile = "production"`.
- The provider certificate chain is installed in the consumer host trust store
  or signed by a CA already trusted by the consumer host.

## First Deployment

1. Install the release binary and record the SHA:

   ```bash
   opendr --version || true
   git rev-parse HEAD
   ```

2. Create role-specific directories:

   ```bash
   install -d -m 0750 /etc/opendr/provider /etc/opendr/consumer
   install -d -m 0750 /var/lib/opendr/provider/data /var/lib/opendr/provider/replication_state
   install -d -m 0750 /var/lib/opendr/consumer/data /var/lib/opendr/consumer/replication_state
   install -d -m 0750 /var/log/opendr /var/backups/opendr/provider
   ```

3. Install secrets and TLS material using your secret manager. Confirm file
   ownership allows only the OpenDR service account to read secret files.

4. Write provider and consumer configs. Start from
   `config/examples/replication/provider.toml` and
   `config/examples/replication/consumer.toml`, then apply the hardening baseline
   above.

5. Start the provider:

   ```bash
   opendr --config /etc/opendr/provider/server.toml \
     --log-config /etc/opendr/provider/log4rs.yml
   ```

6. Validate provider health:

   ```bash
   ldapsearch -LLL -o ldif-wrap=no -x -H ldaps://provider.example.com:1636 \
     -D "cn=manager,dc=example,dc=org" -y /run/secrets/provider-root-password \
     -b "" -s base "(objectClass=*)" namingContexts supportedLDAPVersion supportedSASLMechanisms

   ldapsearch -LLL -o ldif-wrap=no -x -H ldaps://provider.example.com:1636 \
     -D "cn=manager,dc=example,dc=org" -y /run/secrets/provider-root-password \
     -b "dc=example,dc=org" -s base "(objectClass=*)"
   ```

7. Start the consumer:

   ```bash
   opendr --config /etc/opendr/consumer/server.toml \
     --log-config /etc/opendr/consumer/log4rs.yml
   ```

8. Validate consumer full refresh and live replication:

   ```bash
   ldapadd -x -H ldaps://provider.example.com:1636 \
     -D "cn=manager,dc=example,dc=org" -y /run/secrets/provider-root-password <<'LDIF'
   dn: uid=deployment-smoke,ou=people,dc=example,dc=org
   objectClass: top
   objectClass: person
   objectClass: organizationalPerson
   objectClass: inetOrgPerson
   cn: Deployment Smoke
   sn: Smoke
   uid: deployment-smoke
   mail: deployment-smoke@example.org
   LDIF

   ldapsearch -LLL -o ldif-wrap=no -x -H ldaps://consumer.example.com:2636 \
     -D "cn=manager,dc=example,dc=org" -y /run/secrets/consumer-root-password \
     -b "dc=example,dc=org" "(uid=deployment-smoke)" dn uid mail
   ```

9. Confirm logs have no bind failures, replay gaps, TLS errors, or unexpected
   consumer disconnects.

## Backup Before Upgrade

Take and inspect a provider full backup before replacing binaries, configs,
schema, ACLs, indexes, or TLS material:

```bash
BACKUP_DIR=/var/backups/opendr/provider/full-$(date -u +%Y%m%dT%H%M%SZ)

opendr-backup --config /etc/opendr/provider/server.toml --json full \
  --target "${BACKUP_DIR}" | tee "${BACKUP_DIR}.json"

opendr-backup --config /etc/opendr/provider/server.toml --json inspect \
  --backup "${BACKUP_DIR}" | tee "${BACKUP_DIR}.inspect.json"
```

Copy the backup to remote storage and run `opendr-backup inspect` again on the
copied artifact. Record the backup ID and checkpoint CSN in the change ticket.

## Upgrade Procedure

1. Confirm the readiness gates for the release candidate are attached to the
   change ticket.
2. Stop or drain consumer traffic if the deployment has external read routing.
3. Take the provider backup described above.
4. Stop the consumer.
5. Stop the provider.
6. Replace the provider binary and config artifacts.
7. Start the provider and run the provider health checks.
8. Replace the consumer binary and config artifacts.
9. Start the consumer and validate full refresh or cookie resume.
10. Run the smoke replication add/search from the first deployment section.
11. Keep the previous binary, config directory, data directory, replication
    state directory, and backup artifact until the rollback window closes.

## Rollback Procedure

Use this path when an upgrade or deployment writes bad data, changes schema or
indexes incorrectly, or leaves the provider in an unknown state.

1. Stop consumers first to prevent more replay attempts:

   ```bash
   systemctl stop opendr-consumer
   ```

2. Stop the provider:

   ```bash
   systemctl stop opendr-provider
   ```

3. Move failed state aside. Do not delete it during incident response:

   ```bash
   mv /var/lib/opendr/provider/data /var/lib/opendr/provider/data.failed-$(date -u +%Y%m%dT%H%M%SZ)
   mv /var/lib/opendr/provider/replication_state /var/lib/opendr/provider/replication_state.failed-$(date -u +%Y%m%dT%H%M%SZ)
   install -d -m 0750 /var/lib/opendr/provider/data /var/lib/opendr/provider/replication_state
   ```

4. Restore the provider backup:

   ```bash
   opendr-restore --backup "${BACKUP_DIR}" \
     --target-data-dir /var/lib/opendr/provider/data
   ```

5. Restore the previous binary and config if the rollback is caused by code or
   config, then start the provider.

6. Validate provider bind/search and confirm bad deployment marker entries are
   absent.

7. Rebootstrap each consumer when the provider data has been rolled back behind
   the consumer cookie:

   ```bash
   systemctl stop opendr-consumer
   mv /var/lib/opendr/consumer/data /var/lib/opendr/consumer/data.failed-$(date -u +%Y%m%dT%H%M%SZ)
   mv /var/lib/opendr/consumer/replication_state /var/lib/opendr/consumer/replication_state.failed-$(date -u +%Y%m%dT%H%M%SZ)
   install -d -m 0750 /var/lib/opendr/consumer/data /var/lib/opendr/consumer/replication_state
   systemctl start opendr-consumer
   ```

8. Validate consumer full refresh and post-rollback live replication.

9. Attach provider logs, consumer logs, backup inspect output, restore output,
   and validation LDIF to the incident/change ticket.

## Rollback Drill

Run this drill before a release is considered production-ready and after any
material change to deployment, backup, restore, or replication behavior:

```bash
DEPLOYMENT_DRILL_OUTPUT_DIR=target/deployment-rollback-drill/readiness-smoke \
./scripts/deployment_rollback_drill.sh
```

Release-candidate evidence should use the release binary profile and retained
artifacts:

```bash
DEPLOYMENT_DRILL_MODE=release \
DEPLOYMENT_DRILL_OUTPUT_DIR=target/deployment-rollback-drill/release-candidate \
./scripts/deployment_rollback_drill.sh
```

The drill fails non-zero if any step fails. It validates:

- provider startup and root bind
- provider backup, inspect, and restore dry-run
- consumer initial refresh
- live replication before rollback
- failed deployment marker replication before rollback
- provider restore from backup with the failed marker absent
- consumer rebootstrap from the restored provider
- live replication after rollback

Retain `summary.md`, command logs, server logs, backup manifests, failed data
directories, and validation LDIF files from the drill artifact directory.

## Incident Checklist

Replication lag:

- Check provider and consumer logs for disconnects and replay errors.
- Check monitoring fields documented in
  [`REPLICATION_PRODUCTION_GUARANTEES.md`](./REPLICATION_PRODUCTION_GUARANTEES.md).
- Confirm the provider changelog window covers the lag duration.
- Avoid deleting consumer state until logs and cookies are captured.

Stale consumer cookie:

- Save `<consumer state>/replication_cookie.txt`.
- Save provider `provider_changelog.json` metadata.
- Delete only the consumer cookie to force a full refresh when provider data is
  authoritative and changelog replay is no longer possible.

Changelog gap after restore:

- Treat it as expected when provider data is restored without a matching
  provider changelog window.
- Move consumer data and replication state aside, then rebootstrap from the
  restored provider.

TLS failure:

- Confirm certificate expiry, SANs, key permissions, and CA bundle.
- Run the rotation procedure from [`TLS_ROTATION.md`](./TLS_ROTATION.md).
- Restart OpenDR after replacing cert/key files; hot reload is not supported.

Failed binds:

- Confirm the client is using LDAPS or StartTLS under the production profile.
- Verify the bind DN is canonical and under the expected base DN.
- Confirm the secret source file contains the intended password or hash.
- Check audit logs for authentication and authorization denial context.

Backup or restore failure:

- Run `opendr-backup inspect` on the source and copied backup.
- Confirm the restore target directory is empty.
- Keep failed target directories intact until the incident is reviewed.
