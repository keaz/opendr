# Pull vs Push Replication: Quick Reference

**Last Updated:** October 8, 2025

---

## Overview

| Aspect | Pull-Based (Current) | Push-Based (Target) |
|--------|---------------------|---------------------|
| **RFC Mode** | refreshOnly | refreshAndPersist |
| **Initiator** | Consumer | Provider |
| **Connection** | Temporary | Persistent |
| **Latency** | 30s (configurable) | < 1s (real-time) |
| **Network Overhead** | High (repeated polls) | Low (single connection) |
| **Multi-Master** | Difficult | Natural fit |
| **Complexity** | Simple | Moderate |
| **RFC 4533 Compliance** | Partial | Full |

---

## Current Pull-Based Architecture

### How It Works
```
1. Consumer wakes up (timer: 30s)
2. Consumer connects to provider
3. Consumer sends: "Give me changes since cookie X"
4. Provider returns: Batch of changes
5. Consumer applies changes
6. Consumer saves new cookie
7. Consumer disconnects
8. Sleep 30s, repeat
```

### Pros ✅
- Simple to implement
- Consumer controls timing
- Works with any LDAP server
- Low server-side complexity

### Cons ❌
- High latency (30s default)
- Wastes resources (polls even when no changes)
- Repeated connection overhead
- Not suitable for multi-master
- Delayed conflict detection

---

## Target Push-Based Architecture

### How It Works
```
1. Consumer connects to provider ONCE
2. Consumer sends: "Subscribe to changes, mode=persist"
3. Provider returns: Initial content (refresh stage)
4. Provider sends: "Refresh done, entering persist stage"
5. CONNECTION STAYS OPEN
6. When change occurs:
   - Provider immediately pushes change to consumer
   - Consumer applies change
   - Consumer acknowledges
7. Heartbeat keeps connection alive
8. On disconnect: Reconnect and resume
```

### Pros ✅
- Real-time replication (< 1s)
- Efficient (no polling)
- RFC 4533 fully compliant
- Perfect for multi-master
- Immediate conflict detection
- Lower network overhead

### Cons ❌
- More complex implementation
- Requires persistent connections
- Server must track consumers
- More server-side state

---

## Multi-Master Comparison

### Pull-Based Multi-Master (Current - Problematic)

```
Master A ←--poll--→ Master B
   ↑                  ↑
   |                  |
   poll              poll
   |                  |
   ↓                  ↓
Master C ←--poll--→ Master C

Problems:
- Delayed propagation (up to 30s × hops)
- Conflicts detected late
- Update A→B→C takes 60s+
- Cascade issues
```

**Example Conflict Scenario:**
```
T=0:   User1 updates entry on Master A
T=0:   User2 updates same entry on Master B
T=30:  Master A polls Master B (conflict!)
T=30:  Master B polls Master A (conflict!)
T=60:  Both realize conflict, but which change wins?
```

### Push-Based Multi-Master (Target - Optimal)

```
Master A ⟺ Master B
   ⟺        ⟺
Master C ⟺ Master C

Benefits:
- Immediate propagation (< 1s)
- Fast conflict detection
- Update A→B→C takes < 2s
- Natural topology
```

**Example Conflict Scenario:**
```
T=0.0s: User1 updates entry on Master A (CSN: 1000001)
T=0.0s: User2 updates entry on Master B (CSN: 1000002)
T=0.5s: Master A pushes to B (detects conflict immediately)
T=0.5s: Master B pushes to A (detects conflict immediately)
T=0.5s: Both use CSN comparison → CSN 1000002 wins
T=1.0s: All masters converged to winning value
```

---

## RFC 4533 Compliance

### refreshOnly Mode (Pull)

**RFC Section:** 3.3

**Provider Behavior:**
```
1. Receive SearchRequest with mode=refreshOnly
2. Return matching entries
3. Include Sync State Control (state=add/modify/delete)
4. Send SearchResultDone with Sync Done Control
5. Close operation
```

**Consumer Behavior:**
```
1. Send SearchRequest periodically
2. Process returned entries
3. Save cookie from Sync Done Control
4. Disconnect
5. Repeat
```

### refreshAndPersist Mode (Push)

**RFC Section:** 3.4

**Provider Behavior:**
```
1. Receive SearchRequest with mode=refreshAndPersist
2. REFRESH STAGE:
   - Return initial content
   - Include Sync State Control for each entry
3. Send Sync Info Message (refreshDone=TRUE)
4. PERSIST STAGE:
   - Keep connection open
   - Monitor directory for changes
   - Push changes immediately with Sync State Control
   - Send periodic Sync Info Messages (new cookies)
5. Continue until canceled or error
```

**Consumer Behavior:**
```
1. Send SearchRequest once (mode=refreshAndPersist)
2. REFRESH STAGE:
   - Receive and process initial content
   - Build local copy
3. Wait for Sync Info Message (refreshDone=TRUE)
4. PERSIST STAGE:
   - Keep connection open
   - Receive pushed changes in real-time
   - Apply changes immediately
   - Update cookie on each change
5. Handle disconnects → reconnect with latest cookie
```

---

## Implementation Comparison

### Current Consumer Code (Pull)
```rust
loop {
    // Wait for timer
    sleep(Duration::from_secs(30)).await;
    
    // Connect
    provider.connect(url).await?;
    
    // Request changes
    let entries = provider.request_from_cookie(cookie).await?;
    
    // Apply changes
    for entry in entries {
        batch_processor.apply_entry(&entry).await?;
    }
    
    // Save cookie
    state_manager.save_cookie(&new_cookie).await?;
    
    // Disconnect
    provider.disconnect().await?;
}
```

### Target Consumer Code (Push)
```rust
// Connect once
provider.connect(url).await?;

// Request persistent sync
provider.request_persistent_sync(cookie).await?;

// Enter listen loop
loop {
    select! {
        // Receive pushed change
        Ok(entry) = provider.receive_change() => {
            batch_processor.apply_entry(&entry).await?;
            state_manager.save_cookie(&entry.cookie).await?;
        }
        
        // Heartbeat timer
        _ = heartbeat_timer.tick() => {
            provider.send_heartbeat().await?;
        }
        
        // Connection check
        _ = connection_check.tick() => {
            if !provider.is_connected().await? {
                // Reconnect with latest cookie
                provider.connect(url).await?;
                provider.request_persistent_sync(latest_cookie).await?;
            }
        }
    }
}
```

---

## Configuration Comparison

### Current Configuration (Pull)
```toml
[replication]
role = "consumer"
provider_url = "ldap://provider:389"
sync_interval_secs = 30  # Poll every 30 seconds
max_retry_attempts = 3
```

### Target Configuration (Push)
```toml
[replication]
role = "consumer"
provider_url = "ldap://provider:389"
sync_mode = "persist"  # NEW: Use push mode
heartbeat_interval_secs = 60
connection_timeout_secs = 300
auto_reconnect = true
```

### Multi-Master Configuration (Push Only)
```toml
[replication]
role = "both"  # Act as both provider and consumer
provider_urls = [
    "ldap://master1:389",
    "ldap://master2:389",
    "ldap://master3:389"
]
sync_mode = "persist"
conflict_resolution = "last_write_wins"
topology = "full_mesh"  # or "star", "ring"
```

---

## Performance Comparison

### Latency

| Metric | Pull | Push |
|--------|------|------|
| **Best Case** | 30s | < 1s |
| **Worst Case** | 60s | 2s |
| **Average** | 30s | 0.5s |
| **Multi-Master (3 hops)** | 90s+ | 2-3s |

### Network Overhead

**Pull-Based:**
```
Polls per hour: 120 (every 30s)
Changes per hour: 10 (example)
Wasted polls: 110
Connection overhead: 120 × TCP handshake
Data transfer: All entries every time (filtered by CSN)
```

**Push-Based:**
```
Connections per hour: 1 (persistent)
Changes pushed: 10 (exactly what changed)
Wasted activity: 0
Connection overhead: 1 × TCP handshake + heartbeats
Data transfer: Only changed entries
```

### Resource Usage

| Resource | Pull | Push |
|----------|------|------|
| **Connections/hour** | 120 | 1 |
| **Server memory** | Low | Medium (tracks consumers) |
| **Client CPU** | Periodic spikes | Steady low |
| **Network bandwidth** | High | Low |

---

## Migration Path

### Step 1: Deploy Push-Capable Provider
```bash
# Update provider configuration
[replication]
role = "provider"
changelog_enabled = true
persist_mode_enabled = true  # NEW
max_persistent_consumers = 100
```

### Step 2: Gradual Consumer Migration
```bash
# Old consumers continue polling (backward compatible)
# New consumers use push

# Consumer A (old - still works)
sync_mode = "refresh_only"

# Consumer B (new - push)
sync_mode = "persist"
```

### Step 3: Monitor and Validate
```bash
# Monitor both modes
# Verify push consumers get updates faster
# Check for any issues
```

### Step 4: Full Migration
```bash
# Switch all consumers to push
# Remove old polling code (optional)
```

---

## Decision Matrix: When to Use Each

### Use Pull (refreshOnly) When:
- ✅ Simple setup required
- ✅ Infrequent updates (hourly/daily)
- ✅ Network is unreliable
- ✅ Latency not critical
- ✅ Single provider, few consumers

### Use Push (refreshAndPersist) When:
- ✅ Real-time updates required
- ✅ Multi-master topology
- ✅ Many consumers
- ✅ Frequent updates
- ✅ Network is stable
- ✅ Need RFC 4533 full compliance

---

## Key Takeaways

1. **Push is better for multi-master** - Natural fit for bidirectional replication
2. **Push reduces latency** - From 30s to < 1s
3. **Push reduces overhead** - Persistent connections vs repeated polls
4. **Push is RFC compliant** - refreshAndPersist is the standard way
5. **Push requires more complexity** - But worth it for production multi-master

---

## Next Steps

1. ✅ Read design document: `PUSH_BASED_REPLICATION_DESIGN.md`
2. ✅ Review implementation tasks: `PUSH_REPLICATION_PROGRESS.md`
3. ⬜ Assign developers to Phase 1 tasks
4. ⬜ Begin implementation
5. ⬜ Track progress weekly

---

**References:**
- RFC 4533: https://datatracker.ietf.org/doc/html/rfc4533
- Design Doc: `PUSH_BASED_REPLICATION_DESIGN.md`
- Progress Tracker: `PUSH_REPLICATION_PROGRESS.md`
