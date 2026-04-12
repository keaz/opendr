# Management Console

OpenDR serves a read-only management console from the monitoring HTTP listener.
Use it to inspect the running instance without attaching an LDAP client or
scraping Prometheus output directly.

## Enable The Console

The console is available when monitoring is enabled and `console_enabled` is
true:

```toml
[monitoring]
enabled = true
metrics_address = "127.0.0.1"
metrics_port = 9090
metrics_path = "/metrics"
health_path = "/health"
console_enabled = true
console_path = "/console"
console_session_ttl_secs = 3600
```

Open the console at:

```bash
open http://127.0.0.1:9090/console
```

Keep the monitoring listener bound to loopback or another trusted interface. If
the console must be reachable from another host, put network controls or a
trusted reverse proxy in front of the monitoring port.

## Login

The console accepts only the configured root account. When `root_user_dn` is an
RDN, OpenDR combines it with `base_dn` for console login.

For this server config:

```toml
[server]
base_dn = "dc=example,dc=com"
root_user_dn = "cn=admin"
```

log in as:

```text
cn=admin,dc=example,dc=com
```

Sessions are process-local and expire on restart or after
`console_session_ttl_secs`. The session cookie is HttpOnly, SameSite Strict, and
scoped to `console_path`.

## Routes

| Route | Method | Purpose |
| --- | --- | --- |
| `/console` | `GET` | Static browser console |
| `/console/login` | `POST` | Root DN/password login |
| `/console/logout` | `POST` | Session logout |
| `/console/api/overview` | `GET` | Authenticated JSON status snapshot |

Use `console_path` to change the route prefix. For example, with
`console_path = "/ops"`, the overview endpoint becomes `/ops/api/overview`.

## Overview Data

The overview response includes:

- process uptime and timestamp
- health component states
- connection counts and limits
- operation counters
- backend resource and auth-cache counters when exposed by the runtime
- FSM state counters
- replication mode, provider state, consumer state, active provider sessions,
  persisted cookie status, and latest replication error when replication is
  configured

The console does not mutate directory entries, replication state, or runtime
configuration.

## Troubleshooting

If the page does not load, check `[monitoring] enabled`, `metrics_address`,
`metrics_port`, `console_enabled`, and `console_path`. If login fails, use the
full root DN and the same password accepted by LDAP simple bind for the root
account.
