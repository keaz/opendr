# Replication CSN Filtering Fix

## Date: 2025-10-07

## Problem
Consumer was receiving ALL entries on every sync cycle, even though it was:
1. Loading the replication cookie correctly
2. Sending the cookie to the provider  
3. Claiming to do "incremental sync"

Result: ~900 "AlreadyExists" errors on every sync.

## Root Cause

The provider's `request_from_cookie()` method had two code paths:

1. **Local changelog path** (no LDAP connection): 
   - ✅ Correctly used `get_changelog_since(cookie, 100)` to filter by cookie
   
2. **LDAP remote sync path** (with connection):
   - ❌ Completely ignored the cookie parameter
   - ❌ Always did full sync with `(objectClass=*)` filter
   - ❌ Returned ALL entries regardless of CSN

See lines 569-622 in `src/replication.rs`:

```rust
// Query remote provider via LDAP
// For now, we'll do a full sync by searching all entries
// TODO: Implement proper RFC 4533 Content Synchronization
```

The TODO comment indicated this was known incomplete functionality.

## Solution

Added client-side CSN filtering in the LDAP sync path:

### Step 1: Parse Cookie CSN
```rust
let cookie_csn = if let Some(cookie_str) = cookie {
    if let Some(csn_str) = cookie_str.strip_prefix("csn-") {
        Some(csn_str.to_string())
    } else {
        None
    }
} else {
    None
};
```

### Step 2: Request entryCSN Attribute
```rust
let (rs, _res) = ldap
    .search(
        base_dn,
        Scope::Subtree,
        filter,
        vec!["*", "entryCSN"], // Added entryCSN
    )
```

### Step 3: Filter Entries by CSN
```rust
if let Some(ref cookie_csn_str) = cookie_csn {
    if let Some(entry_csn_values) = search_entry.attrs.get("entrycsn") {
        if let Some(entry_csn_str) = entry_csn_values.first() {
            // Compare as strings (both use same format: timestamp#replica#seq#mod)
            if entry_csn_str <= cookie_csn_str {
                return None;  // Skip - already replicated
            }
        }
    }
}
```

## CSN Format

Both cookie and entryCSN use the same format, making string comparison valid:

```
timestamp#replica_id#sequence#mod_number
1759856306700260#001#000000#000000
```

Format is lexicographically sortable because:
- Timestamp is numeric and left-padded
- All components are # separated
- Comparison follows RFC 4533 CSN ordering

## Expected Behavior After Fix

### Initial Sync (no cookie):
```
INFO  | Requesting changelog entries from remote provider (cookie: None)
INFO  | Retrieved 1000 entries from provider  
INFO  | Prepared 1000 entries for replication
```

### Incremental Sync (with cookie, no changes):
```
INFO  | Requesting changelog entries from remote provider (cookie: Some("csn-1759856306700260#001#000000#000000"))
INFO  | Retrieved 1000 entries from provider
INFO  | CSN compare: entry='uid=user0001,ou=People,dc=example,dc=com' entryCSN='1759856306700260#001#000000#000000' vs cookie='1759856306700260#001#000000#000000'
INFO  | (repeated for all entries - all filtered out)
INFO  | Prepared 0 entries for replication
```

### Incremental Sync (with cookie, 10 new entries):
```
INFO  | Requesting changelog entries from remote provider (cookie: Some("csn-1759856306700260#001#000000#000000"))
INFO  | Retrieved 1010 entries from provider
INFO  | (1000 entries skipped - CSN <= cookie)
INFO  | Including new entry: uid=user1001,ou=People,dc=example,dc=com
INFO  | ...
INFO  | Prepared 10 entries for replication
```

## Limitations

1. **Not RFC 4533 compliant**: This is a client-side workaround, not a proper Sync Request Control
2. **Performance**: Still fetches all entries from provider, filters on consumer
3. **Deletions not handled**: Only handles ADD operations (no MODIFY/DELETE tracking)
4. **String comparison**: Works but not as robust as proper CSN parsing

## Future Improvements

1. Implement RFC 4533 Sync Request Control on provider
2. Add server-side CSN filtering (indexed entryCSN queries)
3. Support MODIFY and DELETE operations in incremental sync
4. Add CSN parsing/comparison using `Csn::parse()` and `Ord` trait

## Testing

To verify the fix:

```bash
# 1. Start provider with data
cd svr_1 && cargo run --release &

# 2. Start consumer (will do initial sync)
cargo run --release &

# 3. Wait for first sync, check logs:
grep "Prepared.*entries for replication" consumer.log

# 4. Wait 30 seconds for next sync
# Should see: "Prepared 0 entries for replication"

# 5. Add entries to provider
# 6. Wait for next sync
# Should see: "Prepared N entries for replication" (only new entries)
```

Expected log pattern:
- First sync: `Prepared 1000 entries`
- Second sync: `Prepared 0 entries` (if no changes)
- No "AlreadyExists" warnings after first sync

## Files Changed

- `src/replication.rs`: 
  - Lines 569-680: Added CSN parsing and filtering logic
  - Lines 635-655: Added entryCSN comparison with debug logging

## Related Issues

- Fixes: Consumer repeatedly getting all data (Task 8.6)
- Addresses: TODO at line 571 about RFC 4533 implementation
- Related to: REPLICATION_COOKIE_FIX_SUMMARY.md (cookie persistence fix)
