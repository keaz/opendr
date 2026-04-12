export const startupFlowDiagram = `
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
`;

export const requestFlowDiagram = `
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
`;

export const runtimeCompositionDiagram = `
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
`;

export const replicationFlowDiagram = `
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
`;

export const storageIndexDiagram = `
flowchart LR
    A["LDAP write"] --> B["Schema and ACI checks"]
    B --> C["LMDB write transaction"]
    C --> D["entries database"]
    C --> E["DN lookup index"]
    C --> F["operational metadata"]
    C --> G["configured attribute indexes"]
    G --> H["equality"]
    G --> I["presence"]
    G --> J["substring tokens"]
    G --> K["ordering keys"]
    L["Startup"] --> M{"index metadata changed?"}
    M -->|"yes"| N["Backfill configured indexes"]
    M -->|"no"| O["Open backend normally"]
`;

export const architectureDiagrams = [
  startupFlowDiagram,
  requestFlowDiagram,
  runtimeCompositionDiagram,
  replicationFlowDiagram,
  storageIndexDiagram,
];
