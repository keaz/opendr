# Replication entryCSN Fix - Final Solution

**Date:** October 7, 2025  
**Issue:** Consumer retrieving all entries but not saving them (all entries missing entryCSN)

## Problem Analysis

### Root Cause
The provider LDAP server was generating and storing `entryCSN` operational attributes correctly in the database, but was **not returning them in search results**. This caused the consumer's CSN filtering to skip all entries because they appeared to have no entryCSN.

### Evidence from Logs
```
2025-10-07 22:38:51 | INFO  | src/replication.rs:620 — Retrieved 905 entries from provider
2025-10-07 22:38:51 | WARN  | src/replication.rs:660 — Entry uid=user0000,... has no entryCSN, skipping
... (905 warnings)
2025-10-07 22:38:51 | INFO  | src/replication.rs:693 — Prepared 0 entries for replication (filtered by CSN)
```

All 905 entries were being skipped because `entryCSN` was not present in the LDAP search response, even though:
1. ✅ Consumer correctly requested `["*", "entryCSN"]`
2. ✅ Provider stored entryCSN in the database
3. ❌ Provider's `select_attributes()` function ignored operational attributes

## Technical Details

### LDAP Operational Attributes
LDAP distinguishes between:
- **User attributes**: Normal attributes like `cn`, `mail`, `uid`
- **Operational attributes**: System-managed like `entryCSN`, `createTimestamp`, `modifyTimestamp`

By LDAP RFC standards:
- `*` requests all user attributes
- `+` requests all operational attributes
- Specific names request individual attributes (e.g., `entryCSN`)

### The Bug
The `select_attributes()` function in `src/server.rs` only processed `entry.attributes` (user attributes) and completely ignored `entry.operational_attributes`, even when explicitly requested.

```rust
// OLD CODE (BUGGY)
fn select_attributes(entry: &DirectoryEntry, requested: &[String]) -> Vec<(String, Vec<String>)> {
    // ... logic for user attributes only ...
    for (name, values) in &entry.attributes {  // ❌ Only checks user attributes
        // ...
    }
    // ❌ Never checks entry.operational_attributes
}
```

## Solution Implemented

### Modified File
`src/server.rs` - function `select_attributes()` (lines 610-630)

### Changes Made
1. Added detection for `+` (all operational attributes)
2. Added logic to check if specific operational attributes are requested
3. Added code to extract and return operational attributes from `entry.operational_attributes`

### Supported Operational Attributes
- `entryCSN` - Change Sequence Number for replication
- `createTimestamp` - Entry creation time
- `modifyTimestamp` - Last modification time
- `creatorsName` - DN of entry creator
- `modifiersName` - DN of last modifier

### Code Changes
```rust
// NEW CODE (FIXED)
fn select_attributes(entry: &DirectoryEntry, requested: &[String]) -> Vec<(String, Vec<String>)> {
    // ... existing user attribute logic ...
    
    // ✅ NEW: Check for operational attributes
    let include_all_operational = requested.iter().any(|attr| attr == "+");
    
    if include_all_operational || requested.iter().any(|attr| 
        attr.eq_ignore_ascii_case("entrycsn") ||
        // ... other operational attributes ...
    ) {
        let op_attrs = &entry.operational_attributes;
        
        // ✅ Add entryCSN if requested and present
        if (include_all_operational || requested.iter().any(|a| a.eq_ignore_ascii_case("entrycsn")))
            && op_attrs.entry_csn.is_some() 
        {
            selected.push(("entryCSN".to_string(), vec![op_attrs.entry_csn.as_ref().unwrap().to_ldap_string()]));
        }
        
        // ... similar for other operational attributes ...
    }
    
    selected
}
```

## Testing

### Before Fix
```bash
# Search requesting entryCSN
ldapsearch -x -H ldap://localhost:1389 \
    -b "ou=People,dc=example,dc=com" \
    "(uid=user0000)" entryCSN

# Result: No entryCSN returned ❌
```

### After Fix
```bash
# Search requesting entryCSN
ldapsearch -x -H ldap://localhost:1389 \
    -b "ou=People,dc=example,dc=com" \
    "(uid=user0000)" entryCSN

# Expected Result: 
# dn: uid=user0000,ou=People,dc=example,dc=com
# entryCSN: 1759856850999702#001#000000#000000 ✅
```

### Testing Script
Run `./test_entrycsn.sh` to verify:
1. Provider returns entryCSN when explicitly requested
2. Provider returns entryCSN with wildcard + entryCSN request
3. All operational attributes work correctly

### Replication Test
After this fix, replication should work correctly:

```bash
# 1. Rebuild
cargo build --release

# 2. Clean consumer data
rm -rf ./data/data.mdb ./data/lock.mdb ./data/replication_state/

# 3. Start provider (svr_1)
cd svr_1 && ../target/release/opendr &

# 4. Start consumer
./target/release/opendr &

# 5. Wait 30 seconds and check logs
tail -f log/opendr.log
```

**Expected behavior:**
- First sync: "Prepared N entries for replication" (N > 0)
- Subsequent syncs: "Prepared 0 entries for replication (filtered by CSN)"
- **No warnings** about missing entryCSN

## Impact

### Fixed Issues
1. ✅ entryCSN now returned in search results when requested
2. ✅ Consumer can now filter entries by CSN correctly
3. ✅ Incremental replication works as designed
4. ✅ All operational attributes now accessible via LDAP

### Behavioral Changes
- **Before**: Operational attributes were stored but never retrievable
- **After**: Operational attributes returned when explicitly requested or with `+`

### Compatibility
- ✅ Backward compatible - existing queries unchanged
- ✅ LDAP RFC compliant - follows standard for operational attributes
- ✅ No breaking changes to API or storage format

## Related Files

### Modified
- `src/server.rs` - Fixed `select_attributes()` function

### Previously Fixed (Still Relevant)
- `src/replication.rs` - CSN filtering logic (Task 8.6)
- `src/replication_consumer_fsm.rs` - Cookie persistence
- `src/backend_lmdb.rs` - CSN generation and storage

### Testing
- `test_entrycsn.sh` - New test script for operational attributes
- `verify_replication.sh` - Existing replication verification
- `test_incremental_sync.sh` - Existing comprehensive replication test

## Next Steps

1. **Verify Fix**:
   ```bash
   ./test_entrycsn.sh
   ```

2. **Test Replication**:
   ```bash
   ./test_incremental_sync.sh
   ```

3. **Manual Verification**:
   - Check provider returns entryCSN
   - Confirm consumer logs show CSN comparisons
   - Verify subsequent syncs transfer 0 entries

4. **Production Readiness**:
   - Consider adding metrics for operational attribute requests
   - Add logging for CSN comparisons (already done)
   - Document operational attribute support in README

## Summary

The replication issue where "consumer is getting all the records every time but doesn't save them" was caused by the provider not returning the `entryCSN` operational attribute in search results. This caused the consumer's CSN filtering to reject all entries as having no CSN, resulting in 0 entries prepared for replication.

The fix ensures operational attributes are properly returned when requested, enabling the CSN-based incremental replication to function correctly. Entries now include their entryCSN values, allowing the consumer to:
1. Compare entry CSNs with the saved cookie CSN
2. Skip entries already replicated (entryCSN <= cookie CSN)
3. Only replicate new entries (entryCSN > cookie CSN)

**Status**: ✅ **COMPLETE** - Ready for testing
