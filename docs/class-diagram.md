# OpenDR Runtime Composition Diagram

This diagram reflects the current shipped runtime shape. The `opendr` binary
selects either the FSM listener or the legacy listener. The FSM listener owns
connection-local transport, BER decoding, authentication, and operation FSMs.
Replication is not stored inside `ConnectionFsmSet`; provider streaming is served
as LDAP Sync search traffic, while the consumer runs as a replication service
task.

```mermaid
classDiagram
    class ServerConfig {
        +server.runtime
        +backend.type
        +tls.enabled
        +replication.mode
        +monitoring.enabled
    }

    class MainEntrypoint {
        +load_config()
        +init_backend()
        +start_replication_tasks()
        +start_monitoring()
        +start_listeners()
    }

    class FsmServer {
        +serve_ldap()
        +serve_ldaps()
        +handle_sync_search_request()
    }

    class LegacyServer {
        +serve_ldap()
        +serve_ldaps()
        +handle_sync_search_request()
        +handle_sasl_plain_bind()
    }

    class ConnectionFsmSet {
        -connection: ConnectionFsmImpl
        -decoder: BerDecoderFsmImpl
        -auth: AuthenticationFsm
        -operations: FsmOperationRegistry
        -backend: DirectoryBackend
        -schema_validator: SchemaValidator
    }

    class AuthenticationFsm {
        <<enum>>
        Simple(AuthFsmImpl)
        Sasl(SaslFsmImpl)
    }

    class OperationFsm {
        <<enum>>
        Search(SearchFsmImpl)
        Write(WriteFsmImpl)
        Compare(CompareFsmImpl)
        Extended(ExtendedOpFsmImpl)
    }

    class DirectoryBackend {
        <<trait>>
        +authenticate()
        +get_entry()
        +search_entries()
        +add_entry()
        +modify_entry()
        +delete_entry()
        +compare_attribute()
        +rename_entry()
    }

    class LmdbBackend {
        +entry databases
        +DN lookup index
        +attribute indexes
        +operational metadata
    }

    class ChangelogBackendWrapper {
        +record_provider_writes()
        +append_changelog_entry()
        +broadcast_live_change()
    }

    class ReplicationService {
        +start_provider()
        +start_consumer()
    }

    class ReplicationConsumerFsmImpl {
        +StartConsumption
        +BatchReceived
        +StatePersisted
        +ChangeReceived
        +ProviderDisconnected
    }

    ServerConfig --> MainEntrypoint
    MainEntrypoint --> FsmServer : runtime=fsm
    MainEntrypoint --> LegacyServer : runtime=legacy
    MainEntrypoint --> ReplicationService
    FsmServer --> ConnectionFsmSet
    ConnectionFsmSet --> AuthenticationFsm
    ConnectionFsmSet --> OperationFsm
    ConnectionFsmSet --> DirectoryBackend
    DirectoryBackend <|.. LmdbBackend
    DirectoryBackend <|.. ChangelogBackendWrapper
    ChangelogBackendWrapper --> LmdbBackend
    ReplicationService --> ChangelogBackendWrapper : provider mode
    ReplicationService --> ReplicationConsumerFsmImpl : consumer mode
    FsmServer --> ChangelogBackendWrapper : LDAP Sync search stream
    LegacyServer --> ChangelogBackendWrapper : LDAP Sync search stream
```
