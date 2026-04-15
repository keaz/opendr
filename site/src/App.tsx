import { useEffect, useId, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import perfComparisonMarkdown from "../../docs/PERFORMANCE_COMPARISON.md?raw";
import {
  replicationFlowDiagram,
  requestFlowDiagram,
  runtimeCompositionDiagram,
  startupFlowDiagram,
  storageIndexDiagram,
} from "./diagrams";

type ChapterNavItem = {
  id: string;
  number: string;
  label: string;
};

type ReferenceItem = {
  title: string;
  intro: string;
  snippet: string;
  options: [string, string][];
};

type ChartSeries = {
  label: string;
  values: number[];
  color: string;
};

type BarChartDatum = {
  label: string;
  value: number;
  color: string;
};

type ExpandedChart =
  | {
      kind: "grouped";
      title: string;
      description: string;
      labels: string[];
      series: ChartSeries[];
      unit: string;
    }
  | {
      kind: "simple";
      title: string;
      description: string;
      data: BarChartDatum[];
      unit: string;
    };

type ExpandedDiagram = {
  title: string;
  description: string;
  chart: string;
};

const chapters: ChapterNavItem[] = [
  { id: "overview", number: "0", label: "Overview" },
  { id: "quickstart", number: "1", label: "Quickstart" },
  { id: "build-source", number: "2", label: "Build From Source" },
  { id: "architecture", number: "3", label: "Architecture" },
  { id: "runtimes", number: "4", label: "Runtimes" },
  { id: "performance", number: "5", label: "Performance Results" },
  { id: "setup", number: "6", label: "Setup Command" },
  { id: "configuration", number: "7", label: "Configuration" },
  { id: "tls", number: "8", label: "TLS" },
  { id: "replication", number: "9", label: "Replication" },
  { id: "indexing", number: "10", label: "Indexing" },
  { id: "backup", number: "11", label: "Backup and Restore" },
  { id: "operations", number: "12", label: "Operations" },
  { id: "troubleshooting", number: "13", label: "Troubleshooting" },
  { id: "pages", number: "14", label: "GitHub Pages" },
];

const runtimeRows = [
  {
    runtime: "`fsm`",
    use: "New deployments, active listener development, standard testing.",
    notes:
      "Integrates shutdown, connection pool, rate limiter, metrics, audit, TLS, and operation FSMs.",
  },
  {
    runtime: "`legacy`",
    use: "Compatibility checks and focused debugging against the older server path.",
    notes:
      "Keep `rate_limit.burst_size` at the default. SASL PLAIN over secure transport is covered here.",
  },
];

const configItems: ReferenceItem[] = [
  {
    title: "`[server]`",
    intro: "Listener identity, naming context, root account, runtime choice, and connection-level server limits.",
    snippet: `[server]
bind_address = "127.0.0.1"
ldap_port = 1389
ldaps_port = 1636
hostname = "localhost"
runtime = "fsm"
replica_id = 1
base_dn = "dc=example,dc=com"
root_user_dn = "cn=admin"
root_password_file = "/run/secrets/opendr-root-password-hash"
organization_name = "Example Organization"
read_buffer_size = 4096
operation_timeout_secs = 300
cleanup_interval_secs = 60
max_concurrent_operations = 100`,
    options: [
      ["bind_address", "Host or IP to bind. Do not include a port; ports come from ldap_port and ldaps_port."],
      ["ldap_port", "Plain LDAP listener port. It must be non-zero and different from ldaps_port."],
      ["ldaps_port", "LDAPS listener port used when TLS is enabled. It must differ from ldap_port."],
      ["hostname", "Server hostname used by generated config and diagnostics."],
      ["runtime", "Use fsm for normal development and deployments; use legacy only for compatibility debugging."],
      ["replica_id", "Non-zero replica identifier used in generated CSNs. Keep it unique for replicated nodes."],
      ["base_dn", "Base naming context that OpenDR initializes and serves."],
      ["root_user_dn", "Root user RDN or DN prefix used with base_dn during initialization and binds."],
      ["root_password", "Inline root secret. Useful only for local testing; prefer root_password_env or root_password_file."],
      ["root_password_env", "Name of an environment variable containing the root secret."],
      ["root_password_file", "Path to a file containing the root secret. For LMDB, store the full {SSHA512} hash."],
      ["organization_name", "Value used when setup/server initialization creates the base organization entry."],
      ["read_buffer_size", "Socket read buffer size in bytes for incoming LDAP traffic."],
      ["operation_timeout_secs", "Maximum time allowed for an LDAP operation before timeout handling."],
      ["cleanup_interval_secs", "Interval for runtime cleanup work such as stale connection state."],
      ["max_concurrent_operations", "Per-connection cap for active LDAP operations."],
    ],
  },
  {
    title: "`[backend]`",
    intro: "Persistence engine, LMDB sizing, sample-data flag, and index configuration.",
    snippet: `[backend]
backend_type = "lmdb"
data_directory = "./data"
lmdb_max_size = 10737418240
lmdb_max_readers = 256
import_sample_data = false
indexed_attributes = ["cn", "uid", "mail", "objectClass"]

[[backend.indexes]]
attribute = "cn"
types = ["substring"]

[[backend.indexes]]
attribute = "exampleScore"
types = ["equality", "ordering"]`,
    options: [
      ["backend_type", "Use lmdb for persistent runtime data. memory is useful for tests and temporary experiments."],
      ["data_directory", "Directory that stores LMDB files for persistent backends."],
      ["lmdb_max_size", "LMDB map size in bytes. Size it above expected database growth because LMDB maps a fixed address range."],
      ["lmdb_max_readers", "Maximum concurrent LMDB reader slots. Raise it for high bind/search concurrency."],
      ["import_sample_data", "Parsed by runtime; setup can write sample.ldif, but server startup does not import it automatically."],
      ["indexed_attributes", "Legacy shortcut: each listed attribute receives equality and presence indexes."],
      ["indexes.attribute", "Attribute name for typed index configuration."],
      ["indexes.types", "Index types for the attribute: equality, presence, substring, or ordering. Short aliases eq, pres, sub, and ord are accepted. Equality, substring, and ordering indexes are validated against the loaded schema matching rules."],
    ],
  },
  {
    title: "`[tls]`",
    intro: "LDAPS and StartTLS are enabled together through rustls when tls.enabled is true.",
    snippet: `[tls]
enabled = true
cert_file = "/etc/opendr/certs/server.crt"
key_file = "/etc/opendr/certs/server.key"
ca_file = "/etc/opendr/certs/ca.crt"
require_client_cert = false
min_tls_version = "1.2"`,
    options: [
      ["enabled", "Starts the LDAPS listener and allows StartTLS upgrades on the plain LDAP listener."],
      ["cert_file", "Path to the server certificate. Startup validates that it exists when TLS is enabled."],
      ["key_file", "Path to the private key. Startup validates that it exists when TLS is enabled."],
      ["ca_file", "Optional CA bundle path. Required when require_client_cert is true."],
      ["require_client_cert", "Set true for mutual TLS; clients must present certificates trusted by ca_file."],
      ["min_tls_version", "Minimum protocol version. Valid values are 1.2 and 1.3."],
    ],
  },
  {
    title: "`[replication]`",
    intro: "LDAP Sync provider, consumer, or both-mode replication with persisted changelog and cookies.",
    snippet: `[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:1389"
bind_dn = "cn=replication,dc=example,dc=com"
bind_password_file = "/run/secrets/opendr-replication-bind-password"
changelog_capacity = 10000
changelog_enabled = true
max_batch_size = 100
sync_interval_secs = 60
max_retry_attempts = 3
retry_delay_secs = 5
enable_change_listening = true
enable_streaming = true
heartbeat_interval_secs = 30
max_concurrent_consumers = 10
consumer_timeout_secs = 300
provider_timeout_secs = 30
state_persistence_timeout_secs = 10
change_buffer_size = 1000
state_storage_path = "./data/replication_state"
stream_port = 0`,
    options: [
      ["enabled", "Turns replication services on. Leave false for standalone servers."],
      ["mode", "provider serves changes, consumer follows a provider, and both enables bidirectional node behavior."],
      ["provider_url", "LDAP URL for the upstream provider. Required for consumer and both modes."],
      ["bind_dn", "Bind DN used by a consumer when connecting to the provider."],
      ["bind_password", "Inline replication bind secret. Prefer bind_password_env or bind_password_file."],
      ["bind_password_env", "Name of an environment variable containing the replication bind secret."],
      ["bind_password_file", "Path to a file containing the replication bind secret."],
      ["changelog_capacity", "Maximum retained provider changelog entries. Size it for expected outage and backup windows."],
      ["changelog_enabled", "Keeps provider changelog recording active for provider and both modes."],
      ["max_batch_size", "Maximum entries returned per replication batch."],
      ["sync_interval_secs", "Compatibility field; current consumer replication is listener-based, not poll-based."],
      ["max_retry_attempts", "Number of consumer reconnect attempts before failing the cycle."],
      ["retry_delay_secs", "Delay between consumer reconnect attempts."],
      ["enable_change_listening", "Required for consumer and both modes because poll-based replication has been removed."],
      ["enable_streaming", "Enables provider-side live refresh-and-persist streaming."],
      ["heartbeat_interval_secs", "Heartbeat cadence for long-lived replication listening sessions."],
      ["max_concurrent_consumers", "Provider-side cap on active consumer sessions."],
      ["consumer_timeout_secs", "Provider-side timeout for consumer sessions."],
      ["provider_timeout_secs", "Consumer-side timeout for provider requests."],
      ["state_persistence_timeout_secs", "Timeout while persisting consumer replication state."],
      ["change_buffer_size", "Consumer-side live change buffer size."],
      ["state_storage_path", "Directory for provider changelog state and consumer cookies."],
      ["stream_port", "Reserved or derived replication stream port. Use 0 unless you are testing explicit stream port validation."],
    ],
  },
  {
    title: "`[resources]`",
    intro: "Runtime safety limits enforced around connections, operations, memory, and idle sessions.",
    snippet: `[resources]
max_connections = 512
max_connections_per_ip = 256
max_operations_per_connection = 200
max_memory_per_connection = 10485760
max_total_memory = 2147483648
connection_idle_timeout_secs = 600`,
    options: [
      ["max_connections", "Total concurrent connection cap. Must be greater than zero."],
      ["max_connections_per_ip", "Per-source-IP connection cap. It cannot exceed max_connections."],
      ["max_operations_per_connection", "Per-connection active operation cap."],
      ["max_memory_per_connection", "Byte budget per connection."],
      ["max_total_memory", "Byte budget across runtime connection state."],
      ["connection_idle_timeout_secs", "Idle duration before connection cleanup can close stale sessions."],
    ],
  },
  {
    title: "`[rate_limit]`",
    intro: "Global, per-client, and per-operation request budgets for the runtime limiter.",
    snippet: `[rate_limit]
enabled = true
global_requests_per_second = 1000
per_client_requests_per_second = 100
burst_size = 50
window_duration_secs = 1
adaptive_enabled = true
adaptive_threshold = 0.8
adaptive_multiplier = 0.5
auto_ban_threshold = 100
auto_ban_duration_secs = 300
blacklist = []
whitelist = []

[rate_limit.operation_limits]
bind = 10
search = 50
modify = 20
add = 20
delete = 10
modifydn = 10
compare = 30
extended = 20`,
    options: [
      ["enabled", "Turns rate limiting on or off."],
      ["global_requests_per_second", "Cluster-wide process limit for requests per second."],
      ["per_client_requests_per_second", "Per-client request rate limit."],
      ["burst_size", "Allowed short burst above the steady rate. Keep default when server.runtime is legacy."],
      ["window_duration_secs", "Sliding-window duration used by the limiter."],
      ["adaptive_enabled", "Enables adaptive reduction when the configured threshold is reached."],
      ["adaptive_threshold", "Utilization threshold from 0.0 to 1.0 that triggers adaptive behavior."],
      ["adaptive_multiplier", "Multiplier from 0.0 to 1.0 applied during adaptive limiting."],
      ["auto_ban_threshold", "Violation count before an address is automatically banned."],
      ["auto_ban_duration_secs", "Duration for automatic bans."],
      ["blacklist", "List of IP addresses that should be rejected."],
      ["whitelist", "List of IP addresses exempted from rate limiting."],
      ["operation_limits.bind", "Per-operation limit for bind requests."],
      ["operation_limits.search", "Per-operation limit for search requests."],
      ["operation_limits.modify", "Per-operation limit for modify requests."],
      ["operation_limits.add", "Per-operation limit for add requests."],
      ["operation_limits.delete", "Per-operation limit for delete requests."],
      ["operation_limits.modifydn", "Per-operation limit for ModifyDN requests."],
      ["operation_limits.compare", "Per-operation limit for compare requests."],
      ["operation_limits.extended", "Per-operation limit for extended operation requests."],
    ],
  },
  {
    title: "`[monitoring]`",
    intro: "HTTP endpoints for Prometheus metrics, JSON health, and the read-only management console.",
    snippet: `[monitoring]
enabled = true
metrics_address = "127.0.0.1"
metrics_port = 9090
metrics_path = "/metrics"
health_path = "/health"
console_enabled = true
console_path = "/console"
console_session_ttl_secs = 3600`,
    options: [
      ["enabled", "Starts or disables the monitoring HTTP endpoint."],
      ["metrics_address", "Address the monitoring server binds to."],
      ["metrics_port", "Port for monitoring HTTP traffic."],
      ["metrics_path", "Prometheus text endpoint path."],
      ["health_path", "JSON health endpoint path."],
      ["console_enabled", "Serves the read-only management console from the monitoring listener."],
      ["console_path", "Browser console base path."],
      ["console_session_ttl_secs", "Process-local console session timeout in seconds."],
    ],
  },
  {
    title: "`[audit]`",
    intro: "Security and operations audit log path, format, level, and category toggles.",
    snippet: `[audit]
enabled = true
log_file = "./logs/audit.log"
format = "json"
level = "info"
log_authentication = true
log_authorization = true
log_modifications = true
log_connections = true`,
    options: [
      ["enabled", "Turns audit logging on or off."],
      ["log_file", "Path for audit output when file-backed logging is used."],
      ["format", "Audit output format: json, syslog, or text."],
      ["level", "Minimum audit level: debug, info, warning, error, or critical."],
      ["log_authentication", "Logs bind and authentication events."],
      ["log_authorization", "Logs authorization decisions."],
      ["log_modifications", "Logs write operations that modify directory data."],
      ["log_connections", "Logs connection lifecycle events."],
    ],
  },
  {
    title: "`[access_control]`",
    intro: "ACI engine policy and startup-loaded rule file.",
    snippet: `[access_control]
enabled = true
default_policy = "deny"
rules_file = "/etc/opendr/aci.toml"`,
    options: [
      ["enabled", "Enables construction of the access-control engine."],
      ["default_policy", "Default decision when no rule allows the request. Use deny unless you are doing local bring-up."],
      ["rules_file", "TOML rule file loaded at startup when access control is enabled."],
    ],
  },
  {
    title: "`[performance]`",
    intro: "Performance tuning fields. The current startup path actively wires indexing and cache size.",
    snippet: `[performance]
worker_threads = 0
schema_validation = true
indexing_enabled = true
cache_size = 1000
query_optimization = true`,
    options: [
      ["worker_threads", "Parsed for forward compatibility. A value of 0 means automatic sizing."],
      ["schema_validation", "Parsed for compatibility; active schema behavior is configured in `[schema]`."],
      ["indexing_enabled", "Controls whether configured runtime indexes are maintained."],
      ["cache_size", "Entry/auth cache sizing used by current startup wiring."],
      ["query_optimization", "Parsed for forward compatibility."],
    ],
  },
  {
    title: "`[schema]`",
    intro: "Schema registry loading, validation, and subschema publication.",
    snippet: `[schema]
enabled = true
schema_dir = "config/schema"
load_builtin = ["core"]
strict_validation = true
allow_online_updates = false`,
    options: [
      ["enabled", "Loads the built-in and external LDAP schema registry at startup."],
      ["schema_dir", "Directory for RFC-style LDIF schema files with `.ldif`, `.schema`, or `.conf` extensions."],
      ["load_builtin", "Built-in schema bundle names loaded before external files."],
      ["strict_validation", "Treats malformed schema files as startup errors."],
      ["allow_online_updates", "Allows authenticated Modify requests on `cn=Subschema` to persist safe schema changes into the configured schema directory."],
    ],
  },
];

const aciRulesExample = `[[rules]]
name = "operators-search"
effect = "grant"
priority = 50
permissions = ["search"]
target = { subtree = "dc=example,dc=com" }
subject = { group = "cn=directory-operators,ou=groups,dc=example,dc=com" }

[[rules]]
name = "operators-read-visible-attrs"
effect = "grant"
priority = 40
permissions = ["read"]
target = { subtree = "dc=example,dc=com", attributes = ["cn", "mail", "objectClass"] }
subject = { group = "cn=directory-operators,ou=groups,dc=example,dc=com" }

[[rules]]
name = "hide-passwords"
effect = "deny"
priority = 100
permissions = ["read"]
target = { subtree = "dc=example,dc=com", attributes = ["userPassword"] }
subject = { all_authenticated = true }`;

const schemaDefinitionExample = `dn: cn=schema
matchingRules: ( 1.3.6.1.4.1.55555.20.7 NAME 'exampleEmployeeNumberMatch' DESC 'Example employee number equality' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
matchingRuleUse: ( 1.3.6.1.4.1.55555.20.7 NAME 'exampleEmployeeNumberMatchUse' APPLIES exampleEmployeeNumber )
attributeTypes: ( 1.3.6.1.4.1.55555.20.1 NAME 'exampleEmployeeNumber' DESC 'Example employee number' EQUALITY exampleEmployeeNumberMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.2 NAME 'exampleAccessCode' DESC 'Example access code' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.3 NAME 'exampleStartTime' DESC 'Example start timestamp' EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.6 NAME 'exampleScore' DESC 'Example integer score' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.8 NAME 'exampleExactCode' DESC 'Example case exact code' EQUALITY caseExactMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
objectClasses: ( 1.3.6.1.4.1.55555.20.100 NAME 'exampleEmployee' DESC 'Example employee entry' SUP inetOrgPerson STRUCTURAL MUST ( exampleEmployeeNumber $ exampleAccessCode ) MAY ( exampleStartTime $ exampleScore $ exampleExactCode ) )
nameForms: ( 1.3.6.1.4.1.55555.20.101 NAME 'exampleEmployeeNameForm' OC exampleEmployee MUST cn )
dITStructureRules: ( 555201 NAME 'exampleEmployeeStructureRule' FORM exampleEmployeeNameForm )`;

const schemaRecordExample = `dn: cn=Schema Example One,ou=people,dc=example,dc=org
objectClass: top
objectClass: exampleEmployee
cn: Schema Example One
sn: One
uid: schemaexample1
mail: schemaexample1@example.org
exampleEmployeeNumber: 1001
exampleAccessCode: blue
exampleStartTime: 20260413010101Z
exampleScore: 010
exampleExactCode: CaseToken`;

const operationsRows = [
  ["LDAP operations", "Simple bind, anonymous bind, search, add, modify, delete, ModifyDN, compare, abandon, and unbind."],
  ["Extended operations", "StartTLS, Password Modify, WhoAmI, and Cancel are wired in the FSM server path."],
  ["Controls", "Paged results, server-side sort, ManageDsaIT, and LDAP Sync controls are supported."],
  ["Schema", "Built-in, external LDIF, and authorized online schema definitions publish through `cn=Subschema` and validate add, modify, and ModifyDN writes."],
  ["ACI", "Startup loads TOML ACI rules, then applies operation-level and attribute-level checks for search and write paths."],
  ["Monitoring", "Prometheus metrics, JSON health, and the read-only management console are served from the configured monitoring listener."],
];

const troubleshootingRows = [
  ["Startup exits before listener", "Config path, log4rs path, secret source exclusivity, TLS file existence, and port conflicts."],
  ["LMDB root bind fails", "`root_password_file` must contain the full `{SSHA512}` hash, and the bind DN includes the base DN."],
  ["StartTLS bind fails", "Bind again after StartTLS because authentication state is reset."],
  ["Search misses operational attributes", "Request `+` or explicit names such as `entryCSN`, `entryUUID`, `lastSuccessfulLogin`, and `failedLoginCount`."],
  ["Replication stalls", "Provider changelog, consumer cookie, provider URL, bind credentials, listener mode, and retry logs."],
  ["Incremental backup fails", "Provider or both mode, persistent changelog path, changelog capacity, and parent checkpoint."],
];

const fsmVsOpenDjRuntime = {
  labels: ["Light", "Moderate", "Heavy", "Stress"],
  series: [
    { label: "OpenDR FSM", values: [371.562, 541.61, 876.78, 1990.305], color: "#7ce8c8" },
    { label: "OpenDJ", values: [928.909, 1273.73, 1781.491, 4399.629], color: "#f2b26d" },
  ],
};

const fsmVsOpenDjSubtreeSearch = {
  labels: ["Light", "Moderate", "Heavy", "Stress"],
  series: [
    { label: "OpenDR FSM", values: [0.592, 2.538, 4.459, 10.488], color: "#7ce8c8" },
    { label: "OpenDJ", values: [4.081, 15.649, 24.809, 46.323], color: "#f2b26d" },
  ],
};

const fsmVsOpenDjMemory = {
  labels: ["Light", "Moderate", "Heavy", "Stress"],
  series: [
    { label: "OpenDR FSM", values: [3.34, 4.09, 6.39, 7.72], color: "#7ce8c8" },
    { label: "OpenDJ", values: [813.2, 818.95, 812.95, 987.33], color: "#f2b26d" },
  ],
};

const concurrentBindThroughput: BarChartDatum[] = [
  { label: "OpenDR FSM", value: 45826.68, color: "#7ce8c8" },
  { label: "OpenDJ", value: 29087.05, color: "#f2b26d" },
];

const saslPlainBindLatency = {
  labels: ["SASL-auth"],
  series: [
    { label: "OpenDR FSM", values: [0.04], color: "#7ce8c8" },
    { label: "OpenDJ", values: [0.226], color: "#f2b26d" },
  ],
};

const saslPlainBindThroughput: BarChartDatum[] = [
  { label: "OpenDR FSM", value: 139135.46, color: "#7ce8c8" },
  { label: "OpenDJ", value: 16600.31, color: "#f2b26d" },
];

const indexSearchLatency = {
  labels: ["uid eq", "mail present", "desc substring", "benchmarkOrder >=", "benchmarkOrder <="],
  series: [
    { label: "OpenDR FSM", values: [0.103, 5.944, 1.268, 3.187, 3.183], color: "#7ce8c8" },
    { label: "OpenDJ", values: [0.275, 15.062, 4.228, 8.436, 8.548], color: "#f2b26d" },
  ],
};

const millionOpenDrRows = [
  ["Preloaded users", "1,000,000"],
  ["Records after setup", "1,000,005"],
  ["OpenDR cache size", "1,000 entries"],
  ["LMDB data directory", "3.20 GiB"],
  ["Serial subtree search mean", "10,749.753 ms"],
  ["Serial base search mean", "141.304 ms"],
  ["Simple-bind concurrency peak", "17,008.19 ops/s"],
  ["Simple-bind max 0% failure clients", "128"],
  ["SASL PLAIN concurrency peak", "48,469.70 ops/s"],
  ["SASL PLAIN max 0% failure clients", "128"],
  ["Sampled peak server memory", "3.75 GiB"],
];

const ldapConTenMillionRows = [
  ["Search", "96", "960,000", "118,520.69", "31,674.02", "+274.2%", "1.882 ms", "0"],
  ["Auth", "84", "840,000", "172,020.69", "16,941.98", "+915.3%", "0.898 ms", "0"],
  ["Modify", "8", "80,000", "8,100.10", "5,760.04", "+40.6%", "1.105 ms", "0"],
  ["Mixed search", "96", "768,000", "33,248.74", "25,399.99", "+30.9%", "0.116 ms", "0"],
  ["Mixed modify", "96", "192,000", "8,312.19", "1,652.35", "+403.0%", "12.935 ms", "0"],
];

const ldapConHighConcurrencyRows = [
  ["Search", "192", "1,920,000", "114,359.60", "4.418 ms", "0"],
  ["Auth", "168", "1,680,000", "172,343.45", "1.784 ms", "0"],
  ["Modify", "8", "80,000", "5,793.40", "36.623 ms", "0"],
  ["Mixed search", "192", "1,536,000", "22,171.45", "0.118 ms", "0"],
  ["Mixed modify", "192", "384,000", "5,542.86", "142.131 ms", "0"],
];

const physicalHostResourceRows = [
  ["OpenLDAP-shaped runtime", "46.34 seconds"],
  ["OpenLDAP-shaped CPU avg / max", "370.10% / 857.90%"],
  ["OpenLDAP-shaped RSS avg / max", "6.49 GiB / 7.51 GiB"],
  ["High-concurrency runtime", "110.37 seconds"],
  ["High-concurrency CPU avg / max", "300.81% / 854.50%"],
  ["High-concurrency RSS avg / max", "8.67 GiB / 9.87 GiB"],
  ["Clean host data.mdb", "17,739,038,720 bytes"],
  ["data.mdb after high-concurrency run", "17,753,178,112 bytes"],
];

const ldapConTenMillionThroughput = {
  labels: ["Search", "Auth", "Modify", "Mixed search", "Mixed modify"],
  series: [
    { label: "OpenDR host", values: [118520.69, 172020.69, 8100.1, 33248.74, 8312.19], color: "#7ce8c8" },
    { label: "OpenDR high concurrency", values: [114359.6, 172343.45, 5793.4, 22171.45, 5542.86], color: "#8fb7ff" },
    { label: "OpenLDAP LMDB 2013", values: [31674.02, 16941.98, 5760.04, 25399.99, 1652.35], color: "#f2b26d" },
  ],
};

const millionConcurrentThroughput: BarChartDatum[] = [
  { label: "Simple bind", value: 17008.19, color: "#7ce8c8" },
  { label: "SASL PLAIN", value: 48469.7, color: "#f2b26d" },
];

const docsHref = (file: string) => `${import.meta.env.BASE_URL}${file}`;
const assetHref = (file: string) => `${import.meta.env.BASE_URL}${file}`;

function markdownHref(href?: string) {
  if (!href) {
    return undefined;
  }

  if (href.startsWith("#") || /^(https?:|mailto:|tel:)/i.test(href)) {
    return href;
  }

  const normalized = href.replace(/^\.\//, "").replace(/^docs\//, "");
  if (normalized.endsWith(".md") || normalized.endsWith(".mmd")) {
    return docsHref(normalized);
  }

  return href;
}

type MermaidApi = typeof import("mermaid")["default"];

let mermaidApi: Promise<MermaidApi> | null = null;

function loadMermaid() {
  mermaidApi ??= import("mermaid").then(({ default: mermaid }) => {
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      themeVariables: {
        background: "#06111f",
        primaryColor: "#102033",
        primaryTextColor: "#eef3ff",
        primaryBorderColor: "#7ce8c8",
        lineColor: "#9fb0c9",
        secondaryColor: "#1d2b42",
        tertiaryColor: "#111f33",
        noteBkgColor: "#1d2b42",
        noteTextColor: "#eef3ff",
        noteBorderColor: "#f2b26d",
        fontFamily: "Manrope, ui-sans-serif, system-ui",
      },
    });
    return mermaid;
  });

  return mermaidApi;
}

function App() {
  const [expandedChart, setExpandedChart] = useState<ExpandedChart | null>(null);
  const [expandedDiagram, setExpandedDiagram] = useState<ExpandedDiagram | null>(null);

  useEffect(() => {
    if (!expandedChart && !expandedDiagram) {
      return;
    }

    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setExpandedChart(null);
        setExpandedDiagram(null);
      }
    };

    window.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [expandedChart, expandedDiagram]);

  return (
    <>
      <a className="skip-link" href="#main">Skip to content</a>

      <header className="topbar">
        <a className="brand" href="#overview" aria-label="OpenDR documentation home">
          <img className="brand-mark" src={assetHref("opendr-icon.svg")} alt="" />
          <span className="brand-copy">
            <strong>OpenDR</strong>
            <small>LDAP Server Manual</small>
          </span>
        </a>
        <nav aria-label="Top navigation">
          <a href={docsHref("DEVELOPER_GUIDE.md")}>Developer Guide</a>
          <a href={docsHref("CONFIGURATION.md")}>Configuration</a>
          <a href={docsHref("MANAGEMENT_CONSOLE.md")}>Management Console</a>
          <a href={docsHref("TROUBLESHOOTING.md")}>Troubleshooting</a>
          <a className="topbar-cta" href="https://github.com/keaz/opendr">GitHub</a>
        </nav>
      </header>

      <div className="book-layout">
        <aside className="book-sidebar" aria-label="Manual chapters">
          <div className="sidebar-title">OpenDR Book</div>
          <nav>
            {chapters.map((chapter) => (
              <a key={chapter.id} href={`#${chapter.id}`} className={chapter.id === "overview" ? "active" : undefined}>
                <span>{chapter.number}</span>
                {chapter.label}
              </a>
            ))}
          </nav>
        </aside>

        <main className="book-main" id="main">
          <article className="book-page">
            <section className="chapter hero-chapter" id="overview" aria-labelledby="overview-title">
              <div className="chapter-kicker">Rust LDAPv3 directory server</div>
              <h1 id="overview-title">OpenDR LDAP Server</h1>
              <p className="lead">
                A developer manual for building, configuring, operating, and
                diagnosing OpenDR. The layout is structured like a book so each
                runtime concern can be read in order or used as a reference
                during troubleshooting.
              </p>

              <div className="hero-media">
                <img
                  src="https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1600&q=80"
                  alt="Network equipment and server cables"
                />
                <div className="hero-summary" aria-label="Current implementation facts">
                  <dl>
                    <div>
                      <dt>Default runtime</dt>
                      <dd>FSM</dd>
                    </div>
                    <div>
                      <dt>Persistent backend</dt>
                      <dd>LMDB</dd>
                    </div>
                    <div>
                      <dt>Replication</dt>
                      <dd>LDAP Sync listener</dd>
                    </div>
                    <div>
                      <dt>Published site</dt>
                      <dd>keaz.github.io/opendr</dd>
                    </div>
                  </dl>
                </div>
              </div>

              <div className="chapter-links">
                <a href={docsHref("DEVELOPER_GUIDE.md")}>Open full developer guide</a>
                <a href={docsHref("CONFIGURATION.md")}>Open configuration reference</a>
                <a href={docsHref("MANAGEMENT_CONSOLE.md")}>Open management console guide</a>
                <a href={docsHref("TROUBLESHOOTING.md")}>Open troubleshooting guide</a>
              </div>
            </section>

            <section className="chapter" id="quickstart" aria-labelledby="quickstart-title">
              <p className="chapter-label">Chapter 1</p>
              <h2 id="quickstart-title">Quickstart</h2>
              <p>
                Use the setup command first. This path assumes the OpenDR
                binaries are already installed or available on <code>PATH</code>;
                building from source is covered in the next chapter.
              </p>

              <div className="command-list">
                <section>
                  <h3>Prepare a working directory</h3>
                  <pre><code>{`mkdir -p ./config ./logs`}</code></pre>
                </section>
                <section>
                  <h3>Run setup</h3>
                  <pre><code>{`opendr-setup --config-dir ./config interactive`}</code></pre>
                  <p>
                    The wizard writes <code>server.toml</code>, setup state,
                    LDIF scaffolding, and the configured data directories.
                  </p>
                </section>
                <section>
                  <h3>Start OpenDR</h3>
                  <pre><code>{`opendr --config ./config/server.toml --log-config ./config/log4rs.yml`}</code></pre>
                  <p>
                    Point <code>--log-config</code> at the packaged log4rs YAML
                    file or copy the repository <code>config/log4rs.yml</code>{" "}
                    beside the generated server config.
                  </p>
                </section>
                <section>
                  <h3>Verify the directory</h3>
                  <pre><code>{`ldapsearch -x -H ldap://127.0.0.1:1389 \\
  -D "cn=admin,dc=example,dc=com" -w "$OPENDR_ADMIN_PASSWORD" \\
  -b "dc=example,dc=com" "(objectClass=*)"`}</code></pre>
                </section>
              </div>

              <div className="callout">
                <strong>Quick check:</strong> use the root DN, base DN, and LDAP
                port selected during setup. If setup is rerun, use{" "}
                <code>opendr-setup --config-dir ./config status</code> first so
                you do not accidentally reset data.
              </div>
            </section>

            <section className="chapter" id="build-source" aria-labelledby="build-source-title">
              <p className="chapter-label">Chapter 2</p>
              <h2 id="build-source-title">Build From Source</h2>
              <p>
                Use this path when you are developing OpenDR itself or testing a
                local branch. Runtime setup still goes through{" "}
                <code>opendr-setup</code>; the only difference is that the
                binaries come from <code>target/release</code>.
              </p>

              <div className="command-list">
                <section>
                  <h3>Build release binaries</h3>
                  <pre><code>{`git clone https://github.com/keaz/opendr.git
cd opendr
cargo build --release`}</code></pre>
                </section>
                <section>
                  <h3>Run setup from the built binary</h3>
                  <pre><code>{`./target/release/opendr-setup --config-dir ./config interactive`}</code></pre>
                </section>
                <section>
                  <h3>Start the built server</h3>
                  <pre><code>{`./target/release/opendr \\
  --config ./config/server.toml \\
  --log-config ./config/log4rs.yml`}</code></pre>
                </section>
              </div>
            </section>

            <section className="chapter" id="architecture" aria-labelledby="architecture-title">
              <p className="chapter-label">Chapter 3</p>
              <h2 id="architecture-title">Architecture</h2>
              <p>
                The shared entrypoint validates configuration, creates the
                backend, wraps it for replication when required, starts
                monitoring, and then launches LDAP and optional LDAPS listeners.
                Runtime selection decides whether connection handling flows
                through <code>src/fsm_server.rs</code> or the older path in{" "}
                <code>src/server.rs</code>.
              </p>

              <div className="pipeline" role="img" aria-label="OpenDR request pipeline">
                <span>TCP or TLS listener</span>
                <span>Connection limits</span>
                <span>BER decoder</span>
                <span>LDAP parser</span>
                <span>Operation dispatch</span>
                <span>DirectoryBackend</span>
                <span>LMDB or memory</span>
              </div>

              <div className="diagram-grid">
                <MermaidDiagram
                  title="Startup flow"
                  description="How the opendr binary moves from config loading into listeners and shutdown."
                  chart={startupFlowDiagram}
                  onExpand={() => setExpandedDiagram({
                    title: "Startup flow",
                    description: "How the opendr binary moves from config loading into listeners and shutdown.",
                    chart: startupFlowDiagram,
                  })}
                />
                <MermaidDiagram
                  title="Request flow"
                  description="The active request path from LDAP client bytes through FSM dispatch and backend response encoding."
                  chart={requestFlowDiagram}
                  onExpand={() => setExpandedDiagram({
                    title: "Request flow",
                    description: "The active request path from LDAP client bytes through FSM dispatch and backend response encoding.",
                    chart: requestFlowDiagram,
                  })}
                />
                <MermaidDiagram
                  title="Runtime composition"
                  description="How runtime selection maps into the FSM listener, legacy listener, and shared services."
                  chart={runtimeCompositionDiagram}
                  onExpand={() => setExpandedDiagram({
                    title: "Runtime composition",
                    description: "How runtime selection maps into the FSM listener, legacy listener, and shared services.",
                    chart: runtimeCompositionDiagram,
                  })}
                />
                <MermaidDiagram
                  title="Replication flow"
                  description="Provider-owned LDAP Sync refresh-and-persist replication with cookie persistence."
                  chart={replicationFlowDiagram}
                  onExpand={() => setExpandedDiagram({
                    title: "Replication flow",
                    description: "Provider-owned LDAP Sync refresh-and-persist replication with cookie persistence.",
                    chart: replicationFlowDiagram,
                  })}
                />
                <MermaidDiagram
                  title="Storage and indexing"
                  description="LMDB write persistence and configured index maintenance, including startup backfill."
                  chart={storageIndexDiagram}
                  onExpand={() => setExpandedDiagram({
                    title: "Storage and indexing",
                    description: "LMDB write persistence and configured index maintenance, including startup backfill.",
                    chart: storageIndexDiagram,
                  })}
                />
              </div>

              <h3>Core modules</h3>
              <table>
                <thead>
                  <tr>
                    <th>Area</th>
                    <th>Implementation</th>
                    <th>Responsibilities</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Entrypoint</td>
                    <td><code>src/main.rs</code></td>
                    <td>Config loading, runtime selection, TLS, monitoring, replication task startup, and shutdown.</td>
                  </tr>
                  <tr>
                    <td>FSM listener</td>
                    <td><code>src/fsm_server.rs</code></td>
                    <td>Connection state, BER decode, auth state, request validation, operation FSM routing.</td>
                  </tr>
                  <tr>
                    <td>Legacy listener</td>
                    <td><code>src/server.rs</code></td>
                    <td>Older request handler path used for compatibility checks and targeted debugging.</td>
                  </tr>
                  <tr>
                    <td>Backend</td>
                    <td><code>src/backend_lmdb.rs</code></td>
                    <td>Entry persistence, password verification, DN index, metadata, and attribute index maintenance.</td>
                  </tr>
                  <tr>
                    <td>Replication</td>
                    <td><code>src/replication/*</code></td>
                    <td>Provider changelog, consumer state, LDAP Sync cookie handling, and refresh-and-persist streams.</td>
                  </tr>
                </tbody>
              </table>
            </section>

            <section className="chapter" id="runtimes" aria-labelledby="runtimes-title">
              <p className="chapter-label">Chapter 4</p>
              <h2 id="runtimes-title">Runtimes</h2>
              <p>
                Choose <code>fsm</code> for normal development and new
                deployments. Choose <code>legacy</code> only when comparing
                behavior against the older handler path or isolating a
                compatibility problem.
              </p>

              <table>
                <thead>
                  <tr>
                    <th>Runtime</th>
                    <th>Use it for</th>
                    <th>Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {runtimeRows.map((row) => (
                    <tr key={row.runtime}>
                      <td><code>{row.runtime.replaceAll("`", "")}</code></td>
                      <td>{row.use}</td>
                      <td>{row.notes}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="callout warning">
                <strong>Authentication support:</strong> FSM and legacy
                runtimes support simple bind, anonymous bind, and SASL PLAIN
                over LDAPS or StartTLS. Other SASL mechanisms are not
                production-enabled. User bind metadata is recorded through
                server-managed operational attributes including{" "}
                <code>lastSuccessfulLogin</code>, <code>lastFailedLogin</code>,
                and <code>failedLoginCount</code>.
              </div>
            </section>

            <section className="chapter" id="performance" aria-labelledby="performance-title">
              <p className="chapter-label">Chapter 5</p>
              <h2 id="performance-title">Performance Results</h2>
              <p>
                The site includes the complete benchmark report from{" "}
                <code>docs/PERFORMANCE_COMPARISON.md</code>. The current
                results include bounded Docker regression profiles, the OpenDR
                1M-user baseline, and physical-machine 10M-user LDAPCon-style
                OpenDR runs shaped like the public LDAPCon 2013 OpenLDAP LMDB
                single-server benchmark.
              </p>

              <h3>Run the performance matrix</h3>
              <div className="command-list">
                <section>
                  <h3>Full latency run</h3>
                  <pre><code>{`./scripts/perf_docker_matrix.sh \\
  --profile-set full \\
  --products opendr,opendj \\
  --opendr-runtime fsm \\
  --benchmark-timeout 240 \\
  --output-dir target/perf/full-rerun-20260414-091948`}</code></pre>
                </section>
                <section>
                  <h3>Simple bind concurrency run</h3>
                  <pre><code>{`./scripts/perf_docker_matrix.sh \\
  --profile-set concurrency \\
  --products opendr,opendj \\
  --opendr-runtime fsm \\
  --benchmark-timeout 240 \\
  --concurrent-bind-clients 1,4,8,10,12,16,32,64,128 \\
  --concurrent-bind-iterations 20 \\
  --concurrent-bind-warmup-iterations 1 \\
  --concurrent-bind-operation-timeout-ms 5000 \\
  --output-dir target/perf/concurrency-coalesced-20260414-091023`}</code></pre>
                </section>
                <section>
                  <h3>SASL PLAIN comparison run</h3>
                  <pre><code>{`./scripts/perf_docker_matrix.sh \\
  --profile-set sasl \\
  --products opendr,opendj \\
  --opendr-runtime fsm \\
  --benchmark-timeout 600 \\
  --concurrent-bind-clients 1,4,8,16,32,64,128 \\
  --concurrent-bind-iterations 20 \\
  --concurrent-bind-warmup-iterations 1 \\
  --concurrent-bind-operation-timeout-ms 5000 \\
  --sasl-plain-authcid-format rdn-value \\
  --skip-sasl-plain-admin-benchmark \\
  --perf-client-image opendr:docker-perf-client \\
  --output-dir target/perf/sasl-guarded-20260414-090609`}</code></pre>
                </section>
                <section>
                  <h3>Index-type comparison run</h3>
                  <pre><code>{`./scripts/perf_docker_matrix.sh \\
  --profile-set index \\
  --products opendr,opendj \\
  --opendr-runtime fsm \\
  --benchmark-timeout 600 \\
  --concurrent-index-search-clients 1,4,8,16,32 \\
  --concurrent-index-search-iterations 20 \\
  --concurrent-index-search-warmup-iterations 1 \\
  --concurrent-index-search-operation-timeout-ms 5000 \\
  --perf-client-image opendr:docker-perf-client \\
  --output-dir target/perf/index-guarded-both-20260414-091425`}</code></pre>
                </section>
                <section>
                  <h3>1M OpenDR preload run</h3>
                  <pre><code>{`./scripts/perf_docker_matrix.sh \\
  --profile-set million \\
  --products opendr \\
  --opendr-runtime fsm \\
  --opendr-lmdb-max-size 17179869184 \\
  --benchmark-timeout 7200 \\
  --sample-interval 5 \\
  --perf-client-image opendr:docker-perf-client \\
  --output-dir target/perf/opendr-million-16g-20260414-103048`}</code></pre>
                </section>
                <section>
                  <h3>10M LDAPCon OpenLDAP-like run</h3>
                  <pre><code>{`./scripts/perf_docker_matrix.sh \\
  --products opendr \\
  --profile-set ldapcon-openldap-ten-million \\
  --output-dir target/perf/opendr-ldapcon-openldap-10m-12cpu-30g \\
  --cpu 12 \\
  --memory 30g \\
  --benchmark-timeout 7200 \\
  --preload-workers 12 \\
  --opendr-lmdb-max-size 343597383680 \\
  --opendr-lmdb-max-readers 4096 \\
  --opendr-max-connections 4096 \\
  --opendr-max-connections-per-ip 4096 \\
  --opendr-worker-threads 12 \\
  --opendr-cache-size 10000000 \\
  --opendr-auth-metadata-update-mode async_coalesced \\
  --opendr-auth-metadata-queue-capacity 2000000 \\
  --opendr-auth-metadata-flush-interval-ms 50 \\
  --opendr-auth-metadata-batch-size 5000 \\
  --opendr-build-profile perf \\
  --opendr-build-rustflags "-C target-cpu=native" \\
  --opendr-bulk-fixture-load \\
  --sample-interval 5`}</code></pre>
                </section>
              </div>

              <div className="callout warning">
                Run the matrix from the repository root with Docker available.
                The compact comparison profiles use bounded 2 CPU and 4 GiB
                container limits. The 10M LDAPCon-style profile uses a larger
                30 GiB envelope, an optimized <code>perf</code> build, and a
                generated 10M LMDB fixture.
              </div>

              <h3>10M physical-machine LDAPCon result</h3>
              <p>
                The public OpenLDAP LMDB rows are single-server results. Their
                published clients and threads are SLAMD load-generator settings:
                search uses 96 effective workers, auth uses 84, and modify
                uses 8. OpenDR uses the same operation-specific concurrency
                shape for the comparison below, running directly on the
                physical machine with 12 OpenDR worker threads and 10000
                LDAPCon operations per client.
              </p>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Operation</th>
                      <th>Concurrency</th>
                      <th>Attempts</th>
                      <th>OpenDR ops/s</th>
                      <th>OpenLDAP LMDB ops/s</th>
                      <th>Gap</th>
                      <th>P99</th>
                      <th>Failures</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ldapConTenMillionRows.map(([operation, concurrency, attempts, opendr, openldap, gap, p99, failures]) => (
                      <tr key={operation}>
                        <td>{operation}</td>
                        <td>{concurrency}</td>
                        <td>{attempts}</td>
                        <td>{opendr}</td>
                        <td>{openldap}</td>
                        <td>{gap}</td>
                        <td>{p99}</td>
                        <td>{failures}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <h3>10M high-concurrency diagnostic</h3>
              <p>
                This run doubled search, auth, and mixed concurrency while
                keeping modify at 8 clients. It is a saturation diagnostic, not
                the public OpenLDAP-shaped comparison row.
              </p>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Operation</th>
                      <th>Concurrency</th>
                      <th>Attempts</th>
                      <th>OpenDR ops/s</th>
                      <th>P99</th>
                      <th>Failures</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ldapConHighConcurrencyRows.map(([operation, concurrency, attempts, opendr, p99, failures]) => (
                      <tr key={operation}>
                        <td>{operation}</td>
                        <td>{concurrency}</td>
                        <td>{attempts}</td>
                        <td>{opendr}</td>
                        <td>{p99}</td>
                        <td>{failures}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <h3>Physical-machine resource profile</h3>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {physicalHostResourceRows.map(([metric, value]) => (
                      <tr key={metric}>
                        <td>{metric}</td>
                        <td>{value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <h3>1M OpenDR baseline</h3>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {millionOpenDrRows.map(([metric, value]) => (
                      <tr key={metric}>
                        <td>{metric}</td>
                        <td>{value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <h3>Performance charts</h3>
              <div className="chart-grid">
                <GroupedBarChart
                  title="10M LDAPCon throughput"
                  description="Higher is better. Physical-machine OpenDR runs compared with the public single-server OpenLDAP LMDB LDAPCon 2013 rows."
                  labels={ldapConTenMillionThroughput.labels}
                  series={ldapConTenMillionThroughput.series}
                  unit="ops/s"
                  onExpand={() => setExpandedChart({
                    kind: "grouped",
                    title: "10M LDAPCon throughput",
                    description: "Higher is better. Physical-machine OpenDR runs compared with the public single-server OpenLDAP LMDB LDAPCon 2013 rows.",
                    labels: ldapConTenMillionThroughput.labels,
                    series: ldapConTenMillionThroughput.series,
                    unit: "ops/s",
                  })}
                />
                <GroupedBarChart
                  title="Total runtime"
                  description="Lower is better. Measured in milliseconds across the full Docker profile run."
                  labels={fsmVsOpenDjRuntime.labels}
                  series={fsmVsOpenDjRuntime.series}
                  unit="ms"
                  onExpand={() => setExpandedChart({
                    kind: "grouped",
                    title: "Total runtime",
                    description: "Lower is better. Measured in milliseconds across the full Docker profile run.",
                    labels: fsmVsOpenDjRuntime.labels,
                    series: fsmVsOpenDjRuntime.series,
                    unit: "ms",
                  })}
                />
                <GroupedBarChart
                  title="Subtree search mean"
                  description="Lower is better. Mean subtree search latency by load profile."
                  labels={fsmVsOpenDjSubtreeSearch.labels}
                  series={fsmVsOpenDjSubtreeSearch.series}
                  unit="ms"
                  onExpand={() => setExpandedChart({
                    kind: "grouped",
                    title: "Subtree search mean",
                    description: "Lower is better. Mean subtree search latency by load profile.",
                    labels: fsmVsOpenDjSubtreeSearch.labels,
                    series: fsmVsOpenDjSubtreeSearch.series,
                    unit: "ms",
                  })}
                />
                <GroupedBarChart
                  title="Average memory"
                  description="Lower is better. Average container memory during the same Docker profiles."
                  labels={fsmVsOpenDjMemory.labels}
                  series={fsmVsOpenDjMemory.series}
                  unit="MiB"
                  onExpand={() => setExpandedChart({
                    kind: "grouped",
                    title: "Average memory",
                    description: "Lower is better. Average container memory during the same Docker profiles.",
                    labels: fsmVsOpenDjMemory.labels,
                    series: fsmVsOpenDjMemory.series,
                    unit: "MiB",
                  })}
                />
                <SimpleBarChart
                  title="Peak successful bind throughput"
                  description="Higher is better. Guarded auth-concurrency profile across all tested rows; see the report for failure rates by client level."
                  data={concurrentBindThroughput}
                  unit="ops/s"
                  onExpand={() => setExpandedChart({
                    kind: "simple",
                    title: "Peak successful bind throughput",
                    description: "Higher is better. Guarded auth-concurrency profile across all tested rows; see the report for failure rates by client level.",
                    data: concurrentBindThroughput,
                    unit: "ops/s",
                  })}
                />
                <GroupedBarChart
                  title="SASL PLAIN bind mean"
                  description="Lower is better. Fixture-user SASL PLAIN bind latency from the guarded sasl-auth profile."
                  labels={saslPlainBindLatency.labels}
                  series={saslPlainBindLatency.series}
                  unit="ms"
                  onExpand={() => setExpandedChart({
                    kind: "grouped",
                    title: "SASL PLAIN bind mean",
                    description: "Lower is better. Fixture-user SASL PLAIN bind latency from the guarded sasl-auth profile.",
                    labels: saslPlainBindLatency.labels,
                    series: saslPlainBindLatency.series,
                    unit: "ms",
                  })}
                />
                <SimpleBarChart
                  title="Peak SASL PLAIN throughput"
                  description="Higher is better. Peak fixture-user SASL PLAIN successful binds from the sasl-auth profile."
                  data={saslPlainBindThroughput}
                  unit="ops/s"
                  onExpand={() => setExpandedChart({
                    kind: "simple",
                    title: "Peak SASL PLAIN throughput",
                    description: "Higher is better. Peak fixture-user SASL PLAIN successful binds from the sasl-auth profile.",
                    data: saslPlainBindThroughput,
                    unit: "ops/s",
                  })}
                />
                <GroupedBarChart
                  title="Indexed search latency"
                  description="Lower is better. Mean latency for equality, presence, substring, and benchmarkOrder ordering probes."
                  labels={indexSearchLatency.labels}
                  series={indexSearchLatency.series}
                  unit="ms"
                  onExpand={() => setExpandedChart({
                    kind: "grouped",
                    title: "Indexed search latency",
                    description: "Lower is better. Mean latency for equality, presence, substring, and benchmarkOrder ordering probes.",
                    labels: indexSearchLatency.labels,
                    series: indexSearchLatency.series,
                    unit: "ms",
                  })}
                />
                <SimpleBarChart
                  title="1M OpenDR auth concurrency"
                  description="Higher is better. OpenDR-only 1M fixture with 0% failures through 128 clients."
                  data={millionConcurrentThroughput}
                  unit="ops/s"
                  onExpand={() => setExpandedChart({
                    kind: "simple",
                    title: "1M OpenDR auth concurrency",
                    description: "Higher is better. OpenDR-only 1M fixture with 0% failures through 128 clients.",
                    data: millionConcurrentThroughput,
                    unit: "ops/s",
                  })}
                />
              </div>

              <h3>Complete benchmark report</h3>
              <div className="markdown-doc perf-results">
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  components={{
                    table: ({ node: _node, children, ...props }) => (
                      <div className="table-scroll">
                        <table {...props}>{children}</table>
                      </div>
                    ),
                    a: ({ node: _node, children, href, ...props }) => {
                      const resolvedHref = markdownHref(href);
                      const isExternal = Boolean(resolvedHref && /^(https?:|mailto:|tel:)/i.test(resolvedHref));
                      return (
                        <a
                          {...props}
                          href={resolvedHref}
                          target={isExternal ? "_blank" : undefined}
                          rel={isExternal ? "noreferrer" : undefined}
                        >
                          {children}
                        </a>
                      );
                    },
                  }}
                >
                  {perfComparisonMarkdown}
                </ReactMarkdown>
              </div>
            </section>

            <section className="chapter" id="setup" aria-labelledby="setup-title">
              <p className="chapter-label">Chapter 6</p>
              <h2 id="setup-title">Setup Command</h2>
              <p>
                <code>opendr-setup</code> is the supported first-run path. It
                writes runtime configuration, setup state, LDIF scaffolding, and
                filesystem directories. The server initializes base entries when
                the base DN is not present.
              </p>

              <pre><code>{`opendr-setup interactive
opendr-setup non-interactive --config setup-config.toml
opendr-setup generate-config --output setup-config.toml
opendr-setup status
opendr-setup reset --force
opendr-setup hash-password 'StrongPass123'`}</code></pre>

              <h3>Generated artifacts</h3>
              <ul>
                <li><code>server.toml</code> with canonical runtime fields.</li>
                <li><code>setup.state</code> to block accidental reconfiguration.</li>
                <li><code>admin.ldif</code>, <code>base.ldif</code>, and optional <code>sample.ldif</code>.</li>
                <li>Data and replication state directories.</li>
              </ul>
            </section>

            <section className="chapter" id="configuration" aria-labelledby="configuration-title">
              <p className="chapter-label">Chapter 7</p>
              <h2 id="configuration-title">Configuration</h2>
              <p>
                Runtime configuration is TOML plus optional <code>OPENDR_*</code>{" "}
                environment overrides. Use double underscores for nested fields,
                such as <code>OPENDR_REPLICATION__MODE=provider</code>. Each
                section below includes a copyable snippet and the purpose of
                every option parsed by the current runtime config.
              </p>

              <div className="config-sections">
                {configItems.map((item) => (
                  <section className="config-section" key={item.title}>
                    <h3><code>{item.title.replaceAll("`", "")}</code></h3>
                    <p>{item.intro}</p>
                    <pre><code>{item.snippet}</code></pre>
                    <KeyValueTable headings={["Option", "How to configure it"]} rows={item.options} />
                  </section>
                ))}
                <section className="config-section">
                  <h3><code>aci.toml</code></h3>
                  <p>
                    Rules grant or deny permissions by priority, target, and
                    subject. Attribute targets limit which values are returned
                    by search or accepted by writes.
                  </p>
                  <pre><code>{aciRulesExample}</code></pre>
                </section>
                <section className="config-section">
                  <h3><code>config/schema/10-example-employee.ldif</code></h3>
                  <p>
                    Schema files use <code>dn: cn=schema</code> and RFC-style
                    subschema attributes. Place attribute definitions before
                    object classes, and validate the file before restart.
                  </p>
                  <pre><code>{schemaDefinitionExample}</code></pre>
                  <pre><code>{`opendr --config config/server.toml schema validate
opendr --config config/server.toml schema explain exampleEmployeeNumber`}</code></pre>
                  <p>
                    After startup, LDAP clients can write entries that use the
                    custom object class and attributes.
                  </p>
                  <pre><code>{schemaRecordExample}</code></pre>
                </section>
              </div>

              <a className="text-link" href={docsHref("CONFIGURATION.md")}>Read the complete configuration reference</a>
            </section>

            <section className="chapter" id="tls" aria-labelledby="tls-title">
              <p className="chapter-label">Chapter 8</p>
              <h2 id="tls-title">TLS</h2>
              <p>
                LDAPS and StartTLS share the rustls handler. TLS 1.2 and TLS 1.3
                minimum versions are accepted. LDAPS starts on{" "}
                <code>server.ldaps_port</code> when TLS is enabled.
              </p>

              <pre><code>{`[tls]
enabled = true
cert_file = "/etc/opendr/certs/server.crt"
key_file = "/etc/opendr/certs/server.key"
ca_file = "/etc/opendr/certs/ca.crt"
require_client_cert = false
min_tls_version = "1.2"`}</code></pre>

              <ul>
                <li>StartTLS upgrades a plain LDAP connection, then resets authentication state.</li>
                <li>Mutual TLS requires <code>require_client_cert = true</code> and a valid <code>ca_file</code>.</li>
                <li>Startup fails before binding the listener if certificate paths are missing or unreadable.</li>
              </ul>
            </section>

            <section className="chapter" id="replication" aria-labelledby="replication-title">
              <p className="chapter-label">Chapter 9</p>
              <h2 id="replication-title">Replication</h2>
              <p>
                OpenDR uses provider-owned LDAP Sync streams. A consumer performs
                an initial refresh, persists a cookie, and then keeps a
                long-lived refresh-and-persist search open for live changes.
              </p>

              <h3>Provider</h3>
              <pre><code>{`[replication]
enabled = true
mode = "provider"
changelog_enabled = true
changelog_capacity = 100000
state_storage_path = "/var/lib/opendr/provider/replication_state"`}</code></pre>

              <h3>Consumer</h3>
              <pre><code>{`[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:1389"
bind_dn = "cn=replication,dc=example,dc=com"
bind_password_file = "/run/secrets/opendr-replication-bind-password"
enable_change_listening = true`}</code></pre>

              <div className="callout">
                <code>sync_interval_secs</code> remains as a compatibility field,
                not a polling cadence. <code>enable_change_listening = false</code>
                is invalid for consumer and both modes.
              </div>
            </section>

            <section className="chapter" id="indexing" aria-labelledby="indexing-title">
              <p className="chapter-label">Chapter 10</p>
              <h2 id="indexing-title">Indexing</h2>
              <p>
                LMDB indexes are configured by attribute and index type. Startup
                validates index types against schema matching rules and backfills
                when configured index metadata or resolved matching-rule OIDs change.
              </p>

              <pre><code>{`[backend]
indexed_attributes = ["cn", "uid", "mail", "objectClass", "ou"]

[[backend.indexes]]
attribute = "cn"
types = ["substring"]

[[backend.indexes]]
attribute = "exampleScore"
types = ["ordering"]`}</code></pre>

              <ul>
                <li>Legacy attributes receive equality and presence indexes.</li>
                <li>Typed indexes support equality, presence, substring, and ordering.</li>
                <li>Equality keys use the attribute equality matching rule.</li>
                <li>Substring indexes use 3-character tokens from the substring matching rule.</li>
                <li>Ordering indexes use ordering-rule keys, including numeric order for integer attributes.</li>
              </ul>
            </section>

            <section className="chapter" id="backup" aria-labelledby="backup-title">
              <p className="chapter-label">Chapter 11</p>
              <h2 id="backup-title">Backup and Restore</h2>
              <p>
                Full backups are online LMDB environment copies with manifests.
                Restores are offline and should target an empty directory first.
                Incremental backups require retained provider changelog entries.
              </p>

              <div className="command-list">
                <section>
                  <h3>Full backup</h3>
                  <pre><code>{`opendr-backup --config /etc/opendr/server.toml full \\
  --target /var/backups/opendr/full-20260412`}</code></pre>
                </section>
                <section>
                  <h3>Incremental backup</h3>
                  <pre><code>{`opendr-backup --config /etc/opendr/server.toml incremental \\
  --parent /var/backups/opendr/full-20260412 \\
  --target /var/backups/opendr/inc-20260412-01`}</code></pre>
                </section>
                <section>
                  <h3>Inspect backup</h3>
                  <pre><code>{`opendr-backup inspect \\
  --backup /var/backups/opendr/full-20260412`}</code></pre>
                </section>
                <section>
                  <h3>Restore dry run</h3>
                  <pre><code>{`opendr-restore \\
  --backup /var/backups/opendr/full-20260412 \\
  --target-data-dir /var/lib/opendr/data-restored \\
  --dry-run`}</code></pre>
                </section>
              </div>

              <a className="text-link" href={docsHref("BACKUP_RESTORE.md")}>Read the backup and restore runbook</a>
            </section>

            <section className="chapter" id="operations" aria-labelledby="operations-title">
              <p className="chapter-label">Chapter 12</p>
              <h2 id="operations-title">Operations Surface</h2>
              <p>
                These are the current server capabilities developers should know
                before writing tests, diagnosing client behavior, or extending
                the protocol layer.
              </p>

              <KeyValueTable headings={["Area", "Current behavior"]} rows={operationsRows} />
              <p>
                The management console is available at <code>/console</code> by
                default on the monitoring port and requires the configured root
                DN and password.
              </p>
              <a className="text-link" href={docsHref("MANAGEMENT_CONSOLE.md")}>Read the management console runbook</a>
            </section>

            <section className="chapter" id="troubleshooting" aria-labelledby="troubleshooting-title">
              <p className="chapter-label">Chapter 13</p>
              <h2 id="troubleshooting-title">Troubleshooting</h2>
              <p>
                Start from the failing boundary. Most failures are caused by
                config path mismatches, stale setup state, secret source
                conflicts, TLS file errors, replication cookies, or changelog
                retention.
              </p>

              <KeyValueTable headings={["Symptom", "Check first"]} rows={troubleshootingRows} />

              <a className="text-link" href={docsHref("TROUBLESHOOTING.md")}>Read the troubleshooting runbook</a>
            </section>

            <section className="chapter" id="pages" aria-labelledby="pages-title">
              <p className="chapter-label">Chapter 14</p>
              <h2 id="pages-title">GitHub Pages</h2>
              <p>
                The documentation website is a React and Vite app in{" "}
                <code>site/</code>. The GitHub Actions workflow builds the app to{" "}
                <code>build/</code>, copies the Markdown runbooks into that
                artifact, and deploys the artifact through GitHub Pages.
              </p>

              <pre><code>{`pnpm install
pnpm dev
pnpm build
pnpm preview`}</code></pre>
              <p>
                Once published, the project site is available at{" "}
                <code>https://keaz.github.io/opendr/</code>.
              </p>

              <a className="text-link" href={docsHref("GITHUB_PAGES.md")}>Read the deployment notes</a>
            </section>
          </article>
        </main>

      </div>

      {expandedChart ? (
        <div className="chart-modal-backdrop" role="presentation" onClick={() => setExpandedChart(null)}>
          <div
            className="chart-modal"
            role="dialog"
            aria-modal="true"
            aria-label={`${expandedChart.title} expanded chart`}
            onClick={(event) => event.stopPropagation()}
          >
            <button className="chart-modal-close" type="button" onClick={() => setExpandedChart(null)}>
              Close chart
            </button>
            {expandedChart.kind === "grouped" ? (
              <GroupedBarChart
                title={expandedChart.title}
                description={expandedChart.description}
                labels={expandedChart.labels}
                series={expandedChart.series}
                unit={expandedChart.unit}
                expanded
              />
            ) : (
              <SimpleBarChart
                title={expandedChart.title}
                description={expandedChart.description}
                data={expandedChart.data}
                unit={expandedChart.unit}
                expanded
              />
            )}
          </div>
        </div>
      ) : null}

      {expandedDiagram ? (
        <div className="chart-modal-backdrop" role="presentation" onClick={() => setExpandedDiagram(null)}>
          <div
            className="chart-modal diagram-modal"
            role="dialog"
            aria-modal="true"
            aria-label={`${expandedDiagram.title} expanded diagram`}
            onClick={(event) => event.stopPropagation()}
          >
            <button className="chart-modal-close" type="button" onClick={() => setExpandedDiagram(null)}>
              Close diagram
            </button>
            <MermaidDiagram
              title={expandedDiagram.title}
              description={expandedDiagram.description}
              chart={expandedDiagram.chart}
              expanded
            />
          </div>
        </div>
      ) : null}

      <footer className="site-footer">
        <span>OpenDR LDAP Server</span>
        <nav aria-label="Footer navigation">
          <a href={docsHref("DEVELOPER_GUIDE.md")}>Developer Guide</a>
          <a href={docsHref("CONFIGURATION.md")}>Configuration</a>
          <a href={docsHref("MANAGEMENT_CONSOLE.md")}>Management Console</a>
          <a href={docsHref("BACKUP_RESTORE.md")}>Backup Restore</a>
          <a href={docsHref("REPLICATION_GUIDE.md")}>Replication</a>
        </nav>
      </footer>
    </>
  );
}

function KeyValueTable({ headings, rows }: { headings: [string, string]; rows: string[][] }) {
  return (
    <table>
      <thead>
        <tr>
          <th>{headings[0]}</th>
          <th>{headings[1]}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(([left, right]) => (
          <tr key={left}>
            <td>{left}</td>
            <td>{right}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function GroupedBarChart({
  title,
  description,
  labels,
  series,
  unit,
  onExpand,
  expanded = false,
}: {
  title: string;
  description: string;
  labels: string[];
  series: ChartSeries[];
  unit: string;
  onExpand?: () => void;
  expanded?: boolean;
}) {
  const width = expanded ? 1120 : 760;
  const height = expanded ? 500 : 320;
  const left = expanded ? 86 : 64;
  const right = 24;
  const top = 30;
  const bottom = expanded ? 108 : 82;
  const chartWidth = width - left - right;
  const chartHeight = height - top - bottom;
  const maxValue = Math.max(...series.flatMap((item) => item.values));
  const groupWidth = chartWidth / labels.length;
  const barWidth = Math.min(expanded ? 52 : 34, (groupWidth - 18) / series.length);

  return (
    <figure className={`chart-card${expanded ? " chart-card-expanded" : ""}`}>
      <figcaption>
        <span className="chart-caption-copy">
          <strong>{title}</strong>
          <span>{description}</span>
        </span>
        {onExpand ? (
          <button className="chart-expand-button" type="button" onClick={onExpand}>
            Expand chart
          </button>
        ) : null}
      </figcaption>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${title}: ${description}`}>
        <line x1={left} y1={top + chartHeight} x2={width - right} y2={top + chartHeight} className="chart-axis" />
        {[0, 0.25, 0.5, 0.75, 1].map((tick) => {
          const y = top + chartHeight - tick * chartHeight;
          return (
            <g key={tick}>
              <line x1={left} y1={y} x2={width - right} y2={y} className="chart-gridline" />
              <text x={left - 10} y={y + 4} textAnchor="end" className="chart-tick">
                {formatChartValue(maxValue * tick)}
              </text>
            </g>
          );
        })}
        {labels.map((label, labelIndex) => {
          const groupX = left + labelIndex * groupWidth;
          return (
            <g key={label}>
              {series.map((item, seriesIndex) => {
                const value = item.values[labelIndex];
                const barHeight = maxValue === 0 ? 0 : (value / maxValue) * chartHeight;
                const x = groupX + (groupWidth - barWidth * series.length) / 2 + seriesIndex * barWidth;
                const y = top + chartHeight - barHeight;
                return (
                  <g key={item.label}>
                    <rect x={x} y={y} width={barWidth - 3} height={barHeight} fill={item.color} rx="3" />
                    <title>{`${item.label} ${label}: ${formatChartValue(value)} ${unit}`}</title>
                  </g>
                );
              })}
              <text x={groupX + groupWidth / 2} y={height - (expanded ? 68 : 48)} textAnchor="middle" className="chart-label">
                {label}
              </text>
            </g>
          );
        })}
        <text x={left} y={height - 22} className="chart-unit">{unit}</text>
        {series.map((item, index) => (
          <g key={item.label} transform={`translate(${left + 70 + index * 170} ${height - 28})`}>
            <rect width="12" height="12" fill={item.color} rx="2" />
            <text x="18" y="10" className="chart-legend">{item.label}</text>
          </g>
        ))}
      </svg>
    </figure>
  );
}

function SimpleBarChart({
  title,
  description,
  data,
  unit,
  onExpand,
  expanded = false,
}: {
  title: string;
  description: string;
  data: BarChartDatum[];
  unit: string;
  onExpand?: () => void;
  expanded?: boolean;
}) {
  const maxValue = Math.max(...data.map((item) => item.value));

  return (
    <figure className={`chart-card${expanded ? " chart-card-expanded" : ""}`}>
      <figcaption>
        <span className="chart-caption-copy">
          <strong>{title}</strong>
          <span>{description}</span>
        </span>
        {onExpand ? (
          <button className="chart-expand-button" type="button" onClick={onExpand}>
            Expand chart
          </button>
        ) : null}
      </figcaption>
      <div className="horizontal-bars" role="img" aria-label={`${title}: ${description}`}>
        {data.map((item) => (
          <div className="horizontal-bar-row" key={item.label}>
            <span>{item.label}</span>
            <div className="horizontal-bar-track">
              <div
                className="horizontal-bar-fill"
                style={{ width: `${maxValue === 0 ? 0 : (item.value / maxValue) * 100}%`, background: item.color }}
              />
            </div>
            <strong>{formatChartValue(item.value)} {unit}</strong>
          </div>
        ))}
      </div>
    </figure>
  );
}

function formatChartValue(value: number) {
  if (value >= 1000) {
    return Math.round(value).toLocaleString("en-US");
  }

  if (value >= 100) {
    return value.toFixed(0);
  }

  if (value >= 10) {
    return value.toFixed(1);
  }

  return value.toFixed(2);
}

function MermaidDiagram({
  title,
  description,
  chart,
  onExpand,
  expanded = false,
}: {
  title: string;
  description: string;
  chart: string;
  onExpand?: () => void;
  expanded?: boolean;
}) {
  const id = useId().replaceAll(":", "");
  const diagramRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    setError(null);
    loadMermaid()
      .then((mermaid) => mermaid.render(`opendr-${id}`, chart))
      .then(({ svg, bindFunctions }) => {
        if (cancelled || !diagramRef.current) {
          return;
        }
        diagramRef.current.innerHTML = svg;
        bindFunctions?.(diagramRef.current);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
        }
      });

    return () => {
      cancelled = true;
    };
  }, [chart, id]);

  return (
    <figure className={`diagram-card${expanded ? " diagram-card-expanded" : ""}`}>
      <figcaption>
        <span className="chart-caption-copy">
          <strong>{title}</strong>
          <span>{description}</span>
        </span>
        {onExpand ? (
          <button className="chart-expand-button" type="button" onClick={onExpand}>
            Expand diagram
          </button>
        ) : null}
      </figcaption>
      <div className="mermaid-frame" ref={diagramRef} aria-label={title}>
        {error ? <pre><code>{error}</code></pre> : <span className="diagram-loading">Rendering diagram</span>}
      </div>
    </figure>
  );
}

export default App;
