# Push-Based Replication Architecture Diagrams

Visual guide to understanding the push-based replication architecture.

---

## High-Level Architecture

### Current: Pull-Based Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Provider Server                       │
│                                                          │
│  ┌────────────┐        ┌─────────────┐                 │
│  │ Directory  │───────►│  Changelog  │                 │
│  │  Backend   │        │   Tracker   │                 │
│  └────────────┘        └─────────────┘                 │
│                                                          │
│                        ┌─────────────┐                  │
│                        │  Provider   │                  │
│                        │     FSM     │                  │
│                        └──────┬──────┘                  │
└───────────────────────────────┼──────────────────────────┘
                                │
                          (Passive - Waits)
                                │
                   ┌────────────┴────────────┐
                   ↓                         ↓
      ┌────────────────────┐    ┌────────────────────┐
      │  Consumer A        │    │  Consumer B        │
      │                    │    │                    │
      │  ┌──────────┐      │    │  ┌──────────┐      │
      │  │  Timer   │      │    │  │  Timer   │      │
      │  │  (30s)   │      │    │  │  (30s)   │      │
      │  └────┬─────┘      │    │  └────┬─────┘      │
      │       ↓            │    │       ↓            │
      │  Poll Provider ────┼────┼──► Poll Provider   │
      │                    │    │                    │
      └────────────────────┘    └────────────────────┘
           (Active)                  (Active)
```

### Target: Push-Based Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Provider Server                       │
│                                                          │
│  ┌────────────┐        ┌─────────────┐                 │
│  │ Directory  │───────►│  Changelog  │                 │
│  │  Backend   │        │   Tracker   │                 │
│  └─────┬──────┘        └──────┬──────┘                 │
│        │                      │                         │
│        │                      ↓                         │
│        │               ┌─────────────┐                 │
│        └──────────────►│   Change    │                 │
│                        │  Observer   │                 │
│                        └──────┬──────┘                 │
│                               │                         │
│                               ↓                         │
│                        ┌─────────────┐                 │
│                        │    Push     │                 │
│                        │   Manager   │                 │
│                        └──────┬──────┘                 │
│                               │                         │
│                        ┌──────┴──────┐                 │
└────────────────────────┼─────────────┼─────────────────┘
                         │             │
                    (Active - Pushes)  │
                         │             │
         ┌───────────────┘             └──────────────┐
         ↓                                            ↓
┌────────────────────┐                    ┌────────────────────┐
│  Consumer A        │                    │  Consumer B        │
│                    │                    │                    │
│  ┌──────────┐      │                    │  ┌──────────┐      │
│  │Persistent│      │                    │  │Persistent│      │
│  │Connection│      │                    │  │Connection│      │
│  └────┬─────┘      │                    │  └────┬─────┘      │
│       ↓            │                    │       ↓            │
│  Apply Changes ◄───┼────────────────────┼───► Apply Changes  │
│                    │                    │                    │
└────────────────────┘                    └────────────────────┘
      (Passive)                                (Passive)
```

---

## Component Interaction Flow

### Pull-Based: Request-Response Cycle

```
Consumer                Provider
   │                       │
   │ 1. Connect()          │
   ├──────────────────────►│
   │                       │
   │ 2. Request(cookie)    │
   ├──────────────────────►│
   │                       │
   │                       │ 3. Query Backend
   │                       ├────────┐
   │                       │        │
   │                       │◄───────┘
   │                       │
   │ 4. Return Entries     │
   │◄──────────────────────┤
   │                       │
   │ 5. Process            │
   ├────┐                  │
   │    │                  │
   │◄───┘                  │
   │                       │
   │ 6. Save Cookie        │
   ├────┐                  │
   │    │                  │
   │◄───┘                  │
   │                       │
   │ 7. Disconnect()       │
   ├──────────────────────►│
   │                       │
   │ 8. Wait 30s           │
   ├────┐                  │
   │    │                  │
   │◄───┘                  │
   │                       │
   │ 9. Repeat             │
   │                       │

Total Latency: 30+ seconds
```

### Push-Based: Persistent Connection

```
Consumer                Provider              ChangeObserver
   │                       │                        │
   │ 1. Connect()          │                        │
   ├──────────────────────►│                        │
   │                       │                        │
   │ 2. Subscribe(cookie)  │                        │
   ├──────────────────────►│                        │
   │                       │                        │
   │ 3. Initial Content    │                        │
   │◄──────────────────────┤                        │
   │                       │                        │
   │ 4. Process            │                        │
   ├────┐                  │                        │
   │◄───┘                  │                        │
   │                       │                        │
   │ 5. RefreshDone        │                        │
   │◄──────────────────────┤                        │
   │                       │                        │
   │ ═══════════════════════════════════════════════│
   │      Connection Persists - Waiting for Changes │
   │ ═══════════════════════════════════════════════│
   │                       │                        │
   │                       │  6. Directory Change   │
   │                       │◄───────────────────────┤
   │                       │                        │
   │                       │  7. Notify PushManager │
   │                       ├────┐                   │
   │                       │◄───┘                   │
   │                       │                        │
   │ 8. Push Entry         │                        │
   │◄──────────────────────┤                        │
   │                       │                        │
   │ 9. Apply Change       │                        │
   ├────┐                  │                        │
   │◄───┘                  │                        │
   │                       │                        │
   │ 10. Ack               │                        │
   ├──────────────────────►│                        │
   │                       │                        │
   │ ═══════════════════════════════════════════════│
   │      Continue listening for more changes...    │
   │ ═══════════════════════════════════════════════│

Total Latency: < 1 second
```

---

## Multi-Master Topology

### 3-Node Full Mesh

```
         ┌─────────────────┐
         │    Master A     │
         │  Replica ID: 1  │
         │                 │
         │  Push Manager   │
         │       +         │
         │ Consumer (B,C)  │
         └────────┬────────┘
                  │
         ┌────────┴────────┐
         │                 │
         ↓                 ↓
┌─────────────────┐   ┌─────────────────┐
│    Master B     │   │    Master C     │
│  Replica ID: 2  │◄─►│  Replica ID: 3  │
│                 │   │                 │
│  Push Manager   │   │  Push Manager   │
│       +         │   │       +         │
│ Consumer (A,C)  │   │ Consumer (A,B)  │
└─────────────────┘   └─────────────────┘

Each master:
- Pushes its local changes to other masters
- Receives pushes from other masters
- Maintains 2 outbound persistent connections
- Maintains 2 inbound persistent connections
```

### Change Propagation Example

```
Step 1: User updates entry on Master A
┌─────────────────┐
│    Master A     │  Change: user1.email = "new@email.com"
│   CSN: 1000001  │  Replica ID: 1
└────────┬────────┘  Timestamp: T0
         │
         │ < 500ms
         │
         ├──────────────────┐
         │                  │
         ↓                  ↓
┌─────────────────┐   ┌─────────────────┐
│    Master B     │   │    Master C     │
│ Received: T0+500│   │ Received: T0+500│
│ Applied: T0+600 │   │ Applied: T0+600 │
└─────────────────┘   └─────────────────┘

Total propagation time: ~600ms
All nodes consistent within 1 second
```

### Conflict Scenario

```
Step 1: Concurrent updates at T=0
┌─────────────────┐         ┌─────────────────┐
│    Master A     │         │    Master B     │
│ user1.email =   │         │ user1.email =   │
│ "alice@a.com"   │         │ "alice@b.com"   │
│ CSN: 1000001    │         │ CSN: 1000002    │
└────────┬────────┘         └────────┬────────┘
         │                           │
         │ T0+500                    │ T0+500
         │                           │
         ├──────────┐       ┌────────┤
         │          │       │        │
         ↓          ↓       ↓        ↓
┌─────────────────┐   ┌─────────────────┐
│    Master B     │   │    Master A     │
│ CONFLICT!       │   │ CONFLICT!       │
│                 │   │                 │
│ Local CSN:      │   │ Local CSN:      │
│   1000002       │   │   1000001       │
│ Remote CSN:     │   │ Remote CSN:     │
│   1000001       │   │   1000002       │
│                 │   │                 │
│ Resolution:     │   │ Resolution:     │
│ CSN 1000002 >   │   │ CSN 1000002 >   │
│ CSN 1000001     │   │ CSN 1000001     │
│ Keep Local ✓    │   │ Accept Remote ✓ │
└─────────────────┘   └─────────────────┘

Step 2: After conflict resolution (T0+1s)
All masters have: user1.email = "alice@b.com"
Winner: Master B (CSN 1000002)
```

---

## Component Architecture

### Provider Server Components

```
┌──────────────────────────────────────────────────────────┐
│                    Provider Server                        │
│                                                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │              Backend Layer                         │  │
│  │                                                    │  │
│  │  ┌──────────────┐    ┌────────────────────┐      │  │
│  │  │  Directory   │    │ Changelog Backend  │      │  │
│  │  │   Backend    │───►│     Wrapper        │      │  │
│  │  │   (LMDB)     │    │                    │      │  │
│  │  └──────────────┘    └─────────┬──────────┘      │  │
│  └────────────────────────────────┼──────────────────┘  │
│                                    │                     │
│                                    ↓                     │
│  ┌─────────────────────────────────────────────────┐    │
│  │           Change Observer                       │    │
│  │                                                 │    │
│  │  - Monitors backend changes                    │    │
│  │  - Notifies registered callbacks               │    │
│  │  - Thread-safe callback registry               │    │
│  └────────────────┬────────────────────────────────┘    │
│                   │                                      │
│                   ↓                                      │
│  ┌─────────────────────────────────────────────────┐    │
│  │           Changelog Tracker                     │    │
│  │                                                 │    │
│  │  - Stores recent changes (CSN-indexed)         │    │
│  │  - Generates CSNs                              │    │
│  │  - Manages contextCSN                          │    │
│  └────────────────┬────────────────────────────────┘    │
│                   │                                      │
│                   ↓                                      │
│  ┌─────────────────────────────────────────────────┐    │
│  │           Push Manager                          │    │
│  │                                                 │    │
│  │  ┌─────────────────────────────────────────┐   │    │
│  │  │  Consumer Registry                      │   │    │
│  │  │  - Tracks persistent consumers          │   │    │
│  │  │  - Connection handles                   │   │    │
│  │  │  - Sync mode (refresh/persist)          │   │    │
│  │  └─────────────────────────────────────────┘   │    │
│  │                                                 │    │
│  │  ┌─────────────────────────────────────────┐   │    │
│  │  │  Change Router                          │   │    │
│  │  │  - Routes changes to consumers          │   │    │
│  │  │  - Applies filters                      │   │    │
│  │  │  - Batching logic                       │   │    │
│  │  └─────────────────────────────────────────┘   │    │
│  │                                                 │    │
│  │  ┌─────────────────────────────────────────┐   │    │
│  │  │  Persistent Connection Manager          │   │    │
│  │  │  - Maintains LDAP connections           │   │    │
│  │  │  - Heartbeat mechanism                  │   │    │
│  │  │  - Health checks                        │   │    │
│  │  └─────────────────────────────────────────┘   │    │
│  └─────────────────┬───────────────────────────────┘    │
│                    │                                     │
│                    ↓                                     │
│  ┌─────────────────────────────────────────────────┐    │
│  │         Replication Provider FSM                │    │
│  │                                                 │    │
│  │  States:                                        │    │
│  │  - Idle                                         │    │
│  │  - Refreshing (initial content)                │    │
│  │  - Persisting (push mode)                      │    │
│  └─────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

### Consumer Server Components

```
┌──────────────────────────────────────────────────────────┐
│                    Consumer Server                        │
│                                                           │
│  ┌─────────────────────────────────────────────────┐     │
│  │      Replication Consumer FSM                   │     │
│  │                                                 │     │
│  │  States:                                        │     │
│  │  - Idle                                         │     │
│  │  - Connecting                                   │     │
│  │  - RefreshStage (receiving initial content)    │     │
│  │  - PersistStage (listening for pushes)         │     │
│  │  - ApplyingChanges                              │     │
│  └────────────────┬────────────────────────────────┘     │
│                   │                                       │
│                   ↓                                       │
│  ┌─────────────────────────────────────────────────┐     │
│  │      Provider Connection Handler                │     │
│  │                                                 │     │
│  │  - Persistent LDAP connection                  │     │
│  │  - Message reception                           │     │
│  │  - Reconnection logic                          │     │
│  │  - Heartbeat handling                          │     │
│  └────────────────┬────────────────────────────────┘     │
│                   │                                       │
│                   ↓                                       │
│  ┌─────────────────────────────────────────────────┐     │
│  │         Batch Processor                         │     │
│  │                                                 │     │
│  │  - Deserializes entries                        │     │
│  │  - Applies changes to backend                  │     │
│  │  - Updates contextCSN                          │     │
│  └────────────────┬────────────────────────────────┘     │
│                   │                                       │
│                   ↓                                       │
│  ┌─────────────────────────────────────────────────┐     │
│  │         Conflict Resolver                       │     │
│  │                                                 │     │
│  │  - Detects conflicts                           │     │
│  │  - Applies resolution strategy                 │     │
│  │  - Logs conflicts                              │     │
│  └────────────────┬────────────────────────────────┘     │
│                   │                                       │
│                   ↓                                       │
│  ┌─────────────────────────────────────────────────┐     │
│  │         State Manager                           │     │
│  │                                                 │     │
│  │  - Persists cookie to disk                     │     │
│  │  - Loads cookie on startup                     │     │
│  │  - Atomic writes                               │     │
│  └────────────────┬────────────────────────────────┘     │
│                   │                                       │
│                   ↓                                       │
│  ┌─────────────────────────────────────────────────┐     │
│  │         Backend Layer                           │     │
│  │                                                 │     │
│  │  ┌──────────────┐    ┌────────────────────┐    │     │
│  │  │  Directory   │    │      contextCSN    │    │     │
│  │  │   Backend    │◄───┤      Tracker       │    │     │
│  │  │   (LMDB)     │    │                    │    │     │
│  │  └──────────────┘    └────────────────────┘    │     │
│  └─────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────┘
```

---

## Message Flow Diagrams

### Refresh Stage (Initial Sync)

```
Consumer              Provider              Backend
   │                     │                     │
   │ SearchRequest       │                     │
   │ mode=persist        │                     │
   │ cookie=null         │                     │
   ├────────────────────►│                     │
   │                     │                     │
   │                     │ Query All Entries   │
   │                     ├────────────────────►│
   │                     │                     │
   │                     │ Return Entries      │
   │                     │◄────────────────────┤
   │                     │                     │
   │ SearchResultEntry   │                     │
   │ + SyncStateControl  │                     │
   │ (state=add)         │                     │
   │◄────────────────────┤                     │
   │                     │                     │
   │ SearchResultEntry   │                     │
   │ + SyncStateControl  │                     │
   │ (state=add)         │                     │
   │◄────────────────────┤                     │
   │                     │                     │
   │ ... (more entries)  │                     │
   │◄────────────────────┤                     │
   │                     │                     │
   │ SyncInfoMessage     │                     │
   │ (refreshDone=TRUE)  │                     │
   │ cookie=csn-XXX      │                     │
   │◄────────────────────┤                     │
   │                     │                     │
   │ ═══════════════════════════════════════════
   │     Now in PERSIST stage                  │
   │ ═══════════════════════════════════════════
```

### Persist Stage (Real-time Push)

```
Backend            ChangeObserver      PushManager       Consumer
   │                     │                  │                │
   │ Directory Change    │                  │                │
   │ (user1.email)       │                  │                │
   ├────────────────────►│                  │                │
   │                     │                  │                │
   │                     │ Notify Change    │                │
   │                     ├─────────────────►│                │
   │                     │                  │                │
   │                     │                  │ Filter by      │
   │                     │                  │ Consumer       │
   │                     │                  ├────┐           │
   │                     │                  │◄───┘           │
   │                     │                  │                │
   │                     │                  │ SearchResult   │
   │                     │                  │ Entry +        │
   │                     │                  │ SyncState      │
   │                     │                  │ (state=modify) │
   │                     │                  │ cookie=csn-YYY │
   │                     │                  ├───────────────►│
   │                     │                  │                │
   │                     │                  │ Ack            │
   │                     │                  │◄───────────────┤
   │                     │                  │                │

Time: < 1 second from directory change to consumer application
```

---

## Conflict Resolution Flow

```
Master A                    Master B
   │                           │
   │ T=0: Update user1.email   │ T=0: Update user1.email
   │ = "alice@a.com"           │ = "alice@b.com"
   │ CSN: 1000001              │ CSN: 1000002
   │                           │
   │ T=0.5s: Push to B ────────┼──►
   │                           │   Receive Remote Change
   │                           │   CSN: 1000001
   │                           │
   │                           │   Compare CSNs:
   │                           │   Local:  1000002
   │                           │   Remote: 1000001
   │                           │
   │                           │   Decision:
   │                           │   1000002 > 1000001
   │                           │   → Keep Local Change
   │                           │   → Discard Remote
   │                           │
   │ ◄──────────────────────── │ T=0.5s: Push to A
   │ Receive Remote Change     │
   │ CSN: 1000002              │
   │                           │
   │ Compare CSNs:             │
   │ Local:  1000001           │
   │ Remote: 1000002           │
   │                           │
   │ Decision:                 │
   │ 1000002 > 1000001         │
   │ → Accept Remote           │
   │ → Discard Local           │
   │                           │
   │ Apply: "alice@b.com"      │
   │                           │
   ↓                           ↓
Both converged to: "alice@b.com" (CSN: 1000002)
Time to convergence: ~1 second
```

---

## State Diagrams

### Provider FSM States

```
                    ┌─────────┐
                    │  Idle   │
                    └────┬────┘
                         │
           Consumer connects with mode=persist
                         │
                         ↓
                  ┌──────────────┐
                  │  Refreshing  │
                  │              │
                  │ - Query backend    │
                  │ - Send all entries │
                  └──────┬──────┘
                         │
               Send SyncInfo(refreshDone=TRUE)
                         │
                         ↓
                  ┌──────────────┐
                  │  Persisting  │◄────┐
                  │              │     │
                  │ - Listen for changes│
                  │ - Push to consumer  │
                  └──────┬──────┘      │
                         │             │
                    Change occurs      │
                         │             │
                    Push change ───────┘
                         │
                    Consumer disconnects
                         │
                         ↓
                    ┌─────────┐
                    │  Idle   │
                    └─────────┘
```

### Consumer FSM States

```
                    ┌─────────┐
                    │  Idle   │
                    └────┬────┘
                         │
                  Start replication
                         │
                         ↓
                  ┌──────────────┐
                  │ Connecting   │
                  └──────┬──────┘
                         │
                 Connection established
                         │
                         ↓
                  ┌──────────────┐
                  │RefreshStage  │
                  │              │
                  │ - Receive initial content │
                  │ - Apply entries           │
                  └──────┬──────┘
                         │
           Receive SyncInfo(refreshDone=TRUE)
                         │
                         ↓
                  ┌──────────────┐
                  │PersistStage  │◄────┐
                  │              │     │
                  │ - Listen for pushes│
                  │ - Apply changes     │
                  └──────┬──────┘      │
                         │             │
                  Receive change       │
                         │             │
                         ↓             │
                  ┌──────────────┐    │
                  │ Applying     │    │
                  │ Changes      │────┘
                  └──────┬──────┘
                         │
                  Connection lost
                         │
                         ↓
                  ┌──────────────┐
                  │ Connecting   │
                  │ (Reconnect)  │
                  └──────────────┘
```

---

## Deployment Architecture

### Single Data Center

```
┌─────────────────────────────────────────────────┐
│              Data Center                        │
│                                                 │
│  ┌──────────────┐                               │
│  │  Master A    │                               │
│  │  (Provider)  │                               │
│  └──────┬───────┘                               │
│         │                                        │
│         │ Push changes                          │
│         │                                        │
│         ├────────────┬────────────┬──────────┐  │
│         │            │            │          │  │
│         ↓            ↓            ↓          ↓  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│  │Consumer 1│ │Consumer 2│ │Consumer 3│ │Consumer N│
│  │(Replica) │ │(Replica) │ │(Replica) │ │(Replica) │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘
│                                                 │
└─────────────────────────────────────────────────┘
```

### Multi Data Center (Multi-Master)

```
┌─────────────────────────┐     ┌─────────────────────────┐
│     Data Center 1       │     │     Data Center 2       │
│                         │     │                         │
│  ┌──────────────┐       │     │  ┌──────────────┐       │
│  │  Master A    │◄──────┼─────┼─►│  Master B    │       │
│  │ (Provider +  │       │ WAN │  │ (Provider +  │       │
│  │  Consumer)   │       │     │  │  Consumer)   │       │
│  └──────┬───────┘       │     │  └──────┬───────┘       │
│         │               │     │         │               │
│         ↓               │     │         ↓               │
│  ┌──────────┐           │     │  ┌──────────┐           │
│  │Consumer 1│           │     │  │Consumer 1│           │
│  └──────────┘           │     │  └──────────┘           │
│                         │     │                         │
└─────────────────────────┘     └─────────────────────────┘
           ↑                                    ↑
           │                                    │
           │            WAN                     │
           │                                    │
           └──────────────┬─────────────────────┘
                          │
              ┌───────────────────────┐
              │   Data Center 3       │
              │                       │
              │  ┌──────────────┐     │
              │  │  Master C    │     │
              │  │ (Provider +  │     │
              │  │  Consumer)   │     │
              │  └──────┬───────┘     │
              │         │             │
              │         ↓             │
              │  ┌──────────┐         │
              │  │Consumer 1│         │
              │  └──────────┘         │
              │                       │
              └───────────────────────┘
```

---

**Legend:**
- `─────►` : Pull (request-response)
- `═════►` : Push (persistent connection)
- `◄────►` : Bidirectional (multi-master)
- `┌─────┐`: Component/Server
- `│     │`: Boundary

---

**Last Updated:** October 8, 2025  
**Version:** 1.0
