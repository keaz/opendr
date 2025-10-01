# LDAP Server Architecture Overview

This document provides a high-level architectural overview of the opendr LDAP server, focusing on the FSM-based design and component relationships.

## System Architecture Layers

```mermaid
graph TB
    subgraph "Client Layer"
        C[LDAP Client]
    end

    subgraph "Transport Layer"
        CF[ConnectionFsm<br/>TCP/TLS Management]
        BF[BerDecoderFsm<br/>Message Parsing]
    end

    subgraph "Authentication Layer"
        AF[AuthFsm<br/>Simple Bind]
        SF[SaslFsm<br/>SASL Mechanisms]
    end

    subgraph "Operation Layer"
        SeF[SearchFsm<br/>Search Operations]
        WF[WriteFsm<br/>Add/Modify/Delete]
        CoF[CompareFsm<br/>Compare Operations]
        EF[ExtendedOpFsm<br/>Extended Operations]
        RF[ReferralFsm<br/>Referral Handling]
    end

    subgraph "Replication Layer"
        RPF[ReplicationProviderFsm<br/>RFC 4533 Provider]
        RCF[ReplicationConsumerFsm<br/>RFC 4533 Consumer]
    end

    subgraph "Storage Layer"
        BTF[BackendTxnFsm<br/>Transaction Management]
        DB[DirectoryBackend<br/>Data Storage]
        FB[FileBackend<br/>Disk-backed Implementation]
    end

    C --> CF
    CF --> BF
    BF --> AF
    BF --> SF
    BF --> SeF
    BF --> WF
    BF --> CoF
    BF --> EF
    BF --> RF
    SeF --> BTF
    WF --> BTF
    CoF --> BTF
    BTF --> DB
    DB --> FB
    SeF --> RPF
    SeF --> RCF

    classDef transport fill:#e1f5fe
    classDef auth fill:#f3e5f5
    classDef operation fill:#e8f5e8
    classDef replication fill:#fff3e0
    classDef storage fill:#fce4ec

    class CF,BF transport
    class AF,SF auth
    class SeF,WF,CoF,EF,RF operation
    class RPF,RCF replication
    class BTF,DB,FB storage
```

## Connection Lifecycle and FSM Management

```mermaid
graph LR
    subgraph "Single LDAP Connection"
        CFS[ConnectionFsmSet]
        
        subgraph "Core FSMs (1 each)"
            CF[ConnectionFsm]
            BF[BerDecoderFsm]
            AUTH[AuthenticationFsm]
        end
        
        subgraph "Operation FSMs (N parallel)"
            OP1[SearchFsm #1]
            OP2[WriteFsm #1]
            OP3[SearchFsm #2]
            OPN[... more operations]
        end
        
        subgraph "Optional Replication (≤2)"
            REP1[ReplicationProviderFsm]
            REP2[ReplicationConsumerFsm]
        end
    end

    CFS --> CF
    CFS --> BF
    CFS --> AUTH
    CFS --> OP1
    CFS --> OP2
    CFS --> OP3
    CFS --> OPN
    CFS --> REP1
    CFS --> REP2

    AUTH --> AF[AuthFsm]
    AUTH --> SF[SaslFsm]
```

## FSM State Transition Example - Search Operation

The Search FSM (`SearchFsmImpl`) demonstrates the comprehensive state management used throughout the system:

```mermaid
stateDiagram-v2
    [*] --> Initializing : StartSearch Event
    
    Initializing --> FindingCandidates : Parameters Validated
    
    FindingCandidates --> Iterating : CandidatesFound(>0)
    FindingCandidates --> Completed : CandidatesFound(0)
    
    Iterating --> EmittingEntries : EntryFound
    Iterating --> Completed : All Candidates Processed
    Iterating --> Abandoned : Abandon Event
    Iterating --> TimeLimitExceeded : TimeLimit Event
    Iterating --> SizeLimitExceeded : SizeLimit Event
    
    EmittingEntries --> Iterating : EntryEmitted
    EmittingEntries --> Abandoned : Abandon Event
    EmittingEntries --> TimeLimitExceeded : TimeLimit Event
    EmittingEntries --> SizeLimitExceeded : SizeLimit Event
    
    Completed --> [*] : SearchComplete Event
    Abandoned --> [*] : Operation Cancelled
    TimeLimitExceeded --> [*] : Timeout Response Sent
    SizeLimitExceeded --> [*] : Limit Response Sent

    note right of Iterating
        The Search FSM implements:
        - Base/OneLevel/Subtree scopes
        - Complex LDAP filter evaluation
        - Size and time limit enforcement
        - Batch candidate processing
        - Performance metrics collection
    end note
```

## Concurrent Operation Flow

```mermaid
sequenceDiagram
    participant Client
    participant Server as LDAP Server
    participant Op1 as Search FSM #1
    participant Op2 as Write FSM #1
    participant Op3 as Search FSM #2
    participant Backend

    Note over Client,Backend: Multiple operations can run concurrently

    Client->>Server: Search Request #1 (msgId=1)
    Server->>Op1: Create SearchFsm
    Op1->>Backend: Query candidates
    
    Client->>Server: Add Request (msgId=2)
    Server->>Op2: Create WriteFsm
    Op2->>Backend: Begin transaction
    
    Client->>Server: Search Request #2 (msgId=3)
    Server->>Op3: Create SearchFsm
    Op3->>Backend: Query candidates
    
    Backend-->>Op2: Transaction started
    Op2->>Client: Add Response (msgId=2)
    
    Backend-->>Op1: Candidates found
    Op1->>Client: Search Entries (msgId=1)
    Op1->>Client: Search Done (msgId=1)
    
    Backend-->>Op3: Candidates found
    Op3->>Client: Search Entries (msgId=3)
    Op3->>Client: Search Done (msgId=3)
```

## Key Design Principles

### 1. **Separation of Concerns**
- **Transport**: Handle TCP/TLS and message framing
- **Authentication**: Manage session identity and authorization
- **Operations**: Execute LDAP protocol operations independently
- **Storage**: Provide transactional data access

The `FileBackend` implementation persists directory entries to disk while keeping an in-memory snapshot for fast read paths. The storage snapshot is flushed after every mutating operation, which keeps the design ready for a future read-through cache layer without changing the `DirectoryBackend` trait contract.

### 2. **Concurrency Model**
- Each operation is an independent FSM instance
- Shared transport and authentication state
- Parallel operation execution with message ID correlation
- Backend transaction isolation

### 3. **State Management**
- Explicit state transitions through events
- Timeout and abandonment support
- Error state handling and recovery
- Terminal state enforcement

### 4. **Extensibility**
- Plugin architecture for new FSM types
- Backend abstraction for different storage engines
- Extended operation framework
- Replication protocol support

### 5. **Type Safety**
- Rust trait system ensures compile-time correctness
- Associated types for state/event/error specifications
- Dynamic dispatch through trait objects
- Memory safety without garbage collection

## Implementation Status

The FSM architecture has been progressively implemented with a focus on completeness and production readiness:

### ✅ **Implemented FSMs**

1. **Connection FSM** (`connection_fsm.rs`)
   - TCP/TLS connection management
   - Network error handling and recovery
   - Connection state tracking

2. **BER Decoder FSM** (`ber_decoder_fsm.rs`)
   - LDAP message parsing and validation
   - Incremental message assembly
   - Buffer management and overflow protection

3. **Authentication FSM** (`auth_fsm.rs`)
   - Simple bind authentication
   - Anonymous bind support
   - User credential validation

4. **SASL FSM** (`sasl_fsm.rs`)
   - SASL mechanism framework
   - Multi-step authentication flows
   - Credential verification abstractions

5. **Search FSM** (`search_fsm.rs`)
   - Complete LDAP search functionality
   - All search scopes (base, onelevel, subtree)
   - Size and time limits with enforcement
   - Complex filter evaluation support
   - Entry formatting and attribute projection
   - Performance metrics and monitoring
   - Comprehensive error handling and abandonment

6. **Write FSM** (`write_fsm.rs`) 
   - Complete LDAP write operations (Add, Modify, ModifyDN, Delete)
   - Schema validation and compliance checking
   - Access Control Information (ACI) evaluation
   - Transaction management with commit/rollback
   - Entry validation and constraint checking
   - Comprehensive error handling and audit logging
   - Performance metrics and monitoring

7. **Compare FSM** (`compare_fsm.rs`) ⭐ **Latest Implementation**
   - Complete LDAP compare operations
   - Lightweight entry retrieval with attribute filtering
   - Binary-safe and case-insensitive attribute comparisons
   - Multi-value attribute handling (true if any value matches)
   - Access control integration for compare permissions
   - Performance monitoring and comprehensive error handling
   - Support for operational attribute restrictions

### 🚧 **Planned FSMs**

- **Extended Operation FSM**: Custom LDAP extensions
- **Referral FSM**: LDAP referral handling
- **Replication Provider FSM**: RFC 4533 replication
- **Replication Consumer FSM**: Replication client
- **Backend Transaction FSM**: Transaction management

### 🏗️ **Architecture Benefits Realized**

The implemented FSMs demonstrate the architecture's key benefits:
- **Type Safety**: Compile-time correctness through Rust's trait system
- **Testability**: Comprehensive mock implementations and >90% test coverage
- **Concurrency**: Independent FSM instances for parallel operations
- **Extensibility**: Trait abstractions enable different implementations
- **Error Handling**: Robust error propagation and recovery mechanisms
- **Performance**: Efficient state management and resource utilization

This architecture provides a solid foundation for implementing a production-ready LDAP server with enterprise features like replication, extended operations, and high concurrency.
