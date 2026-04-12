# OpenDR Architecture Overview

OpenDR is a Rust LDAPv3 server with two listener runtimes behind the same
`opendr` binary:

- `fsm`, the default and recommended runtime.
- `legacy`, the older runtime retained for compatibility and targeted behavior
  comparison.

The server entrypoint is `src/main.rs`. It loads configuration, initializes the
backend, starts replication services, starts monitoring, builds TLS state, and
dispatches LDAP and LDAPS listeners based on `server.runtime`.

## Startup Flow

```mermaid
flowchart TD
    A["opendr binary"] --> B["Parse --config and --log-config"]
    B --> C["Initialize log4rs"]
    C --> D["Load ServerConfig from TOML and OPENDR_* overrides"]
    D --> E["Validate config and runtime compatibility"]
    E --> F["Resolve root password source"]
    F --> G["Initialize LMDB or memory backend"]
    G --> H{"Replication mode"}
    H -->|"provider or both"| I["Wrap backend with changelog support"]
    H -->|"disabled or consumer"| J["Use backend directly"]
    I --> K["Create replication service"]
    J --> K
    K --> L["Start provider task when configured"]
    L --> M["Start consumer task when configured"]
    M --> N["Start monitoring HTTP runtime when enabled"]
    N --> O["Build rustls handler when TLS is enabled"]
    O --> P["Start LDAP listener"]
    P --> Q["Start LDAPS listener when TLS is enabled"]
    Q --> R["Drain and stop on shutdown signal"]
```

## Request Flow

```mermaid
flowchart LR
    A["LDAP client"] --> B["TCP or TLS listener"]
    B --> C["Connection pool and resource limits"]
    C --> D["Rate-limit checks"]
    D --> E["BER decoder"]
    E --> F["LDAP parser"]
    F --> G["Control validation"]
    G --> H{"Operation"}
    H -->|"Bind"| I["Auth FSM"]
    H -->|"Search"| J["Search FSM"]
    H -->|"Add, modify, delete, ModifyDN"| K["Write FSM"]
    H -->|"Compare"| L["Compare FSM"]
    H -->|"StartTLS, WhoAmI, Password Modify, Cancel"| M["Extended operation FSM"]
    J --> N["DirectoryBackend"]
    K --> N
    L --> N
    I --> N
    M --> N
    N --> O["LMDB or in-memory backend"]
    O --> P["LDAP response encoder"]
    P --> A
```

The FSM runtime creates a connection-level `ConnectionFsmSet` that owns:

- connection transport state
- BER decoder state
- authentication state
- operation FSMs correlated by LDAP message ID

Search, write, compare, and extended operations are independent FSM
implementations. Provider replication streams are served as LDAP Sync search
requests over the same server path.

## Runtime Composition

```mermaid
flowchart TB
    subgraph Entry["src/main.rs"]
        A["Load and validate ServerConfig"]
        B{"server.runtime"}
    end

    A --> B
    B -->|"fsm"| C["src/fsm_server.rs"]
    B -->|"legacy"| D["src/server.rs"]

    subgraph FSM["FSM runtime"]
        C --> E["ConnectionFsmSet"]
        E --> F["ConnectionFsmImpl"]
        E --> G["BerDecoderFsmImpl"]
        E --> H["AuthenticationFsm"]
        E --> I["Operation registry keyed by LDAP message ID"]
        I --> J["SearchFsmImpl"]
        I --> K["WriteFsmImpl"]
        I --> L["CompareFsmImpl"]
        I --> M["ExtendedOpFsmImpl"]
    end

    subgraph Shared["Shared services"]
        N["DirectoryBackend"]
        O["Schema validator"]
        P["TLS handler"]
        R["Metrics and audit"]
    end

    C --> N
    D --> N
    E --> O
    E --> P
    C --> R
    D --> R
```

## Main Components

| Component | Files | Responsibility |
| --- | --- | --- |
| Entrypoint | `src/main.rs` | Runtime selection, backend setup, replication task startup, TLS, monitoring, shutdown |
| Configuration | `src/config.rs` | TOML/env loading, validation, defaults, secret resolution |
| Setup | `src/setup.rs`, `src/bin/setup.rs` | Interactive and non-interactive first-time setup |
| FSM listener | `src/fsm_server.rs`, `src/fsm_runtime.rs`, `src/fsm.rs` | Current listener path and operation FSM composition |
| Legacy listener | `src/server.rs` | Older listener path and shared protocol helpers |
| Backend | `src/backend.rs`, `src/backend_lmdb.rs` | Backend trait, in-memory test backend, LMDB backend |
| TLS | `src/tls.rs`, `src/connection_fsm.rs` | LDAPS and StartTLS transport upgrade |
| Replication | `src/replication*.rs`, `src/backend_changelog_wrapper.rs` | Provider changelog, LDAP Sync provider sessions, consumer state |
| Backup | `src/backup.rs`, `src/bin/opendr_backup.rs`, `src/bin/opendr_restore.rs` | LMDB full backup, changelog incremental backup, offline restore |
| Monitoring | `src/monitoring_runtime.rs`, `src/metrics.rs` | Prometheus metrics, JSON health, read-only console UI, and overview API |
| Audit and ACI | `src/audit.rs`, `src/aci.rs` | Security event logging and access-control engine |

## Runtime Selection

```toml
[server]
runtime = "fsm"
```

Use `fsm` for new deployments. It integrates shutdown, connection pooling,
resource limits, rate limiting, metrics, audit, TLS, and operation FSMs.

Use `legacy` only for compatibility checks or legacy-specific debugging. The
shipped binary rejects non-default `rate_limit.burst_size` when using `legacy`.

## Storage

The production backend is LMDB. It stores entries, password hashes, normalized
DN lookup, context metadata, and configured attribute indexes in separate LMDB
databases. Reads use LMDB multi-reader behavior and exact-DN entry/auth
credential caches. Writes use a backend write lock.

The in-memory backend is useful for tests and local experiments. It is not a
durable backend.

## Replication

OpenDR replication is listener-based LDAP Sync replication:

1. Provider writes are recorded through `ChangelogBackendWrapper`.
2. The provider stores a bounded changelog and broadcasts live changes.
3. A consumer performs an initial refresh from the provider.
4. The consumer persists a replication cookie.
5. The consumer keeps a refresh-and-persist search open for live updates.

Provider state is persisted in:

```text
<replication.state_storage_path>/provider_changelog.json
```

Consumer state is persisted in:

```text
<replication.state_storage_path>/replication_cookie.txt
```

Poll-based consumer replication has been removed. Consumer and both modes
require `enable_change_listening = true`.

```mermaid
sequenceDiagram
    participant Writer as LDAP writer
    participant Provider as Provider runtime
    participant Wrapper as ChangelogBackendWrapper
    participant Store as LMDB backend
    participant Changelog as provider_changelog.json
    participant Consumer as Consumer runtime task
    participant Cookie as replication_cookie.txt

    Consumer->>Provider: LDAP Sync refresh request with optional cookie
    Provider->>Store: Search entries under base DN
    Store-->>Provider: Current entries with entryUUID and entryCSN
    Provider-->>Consumer: Present or add sync state controls
    Consumer->>Store: Apply refreshed entries locally
    Consumer->>Cookie: Persist refreshed cookie
    Consumer->>Provider: Refresh-and-persist LDAP Sync search
    Writer->>Provider: Add, modify, delete, or rename
    Provider->>Wrapper: Commit write through provider wrapper
    Wrapper->>Store: Persist directory change
    Wrapper->>Changelog: Append bounded changelog entry
    Wrapper-->>Provider: Broadcast live change
    Provider-->>Consumer: Stream sync state control
    Consumer->>Store: Apply live change
    Consumer->>Cookie: Persist new cookie
```

## Operational Attributes

Backend writes maintain operational attributes such as:

- `entryCSN`
- `entryUUID`
- create and modify timestamps
- creators and modifiers names
- `contextCSN`

Operational attributes are hidden from normal search results unless the client
requests `+` or explicit operational attribute names.

## Known Implementation Boundaries

- FSM runtime simple bind, anonymous bind, and SASL PLAIN over confidential
  transport are wired. Other SASL mechanisms are not production-enabled.
- `access_control.rules_file` is parsed but not loaded by the shipped startup
  path.
- `performance.indexing_enabled` and `performance.cache_size` are wired into
  startup; other performance fields are parsed for forward compatibility.
- Restore applies incrementals with default LMDB index configuration; keep the
  runtime config aligned and allow startup index backfill for custom indexes.
- General multi-master conflict resolution is not implemented.
