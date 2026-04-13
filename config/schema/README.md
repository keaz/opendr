# LDAP Schema Directory

OpenDR loads RFC-style schema LDIF files from this directory at startup when
`[schema].enabled` is true. Files are read in lexical order when their extension
is `.ldif`, `.schema`, or `.conf`.

Supported subschema attributes include:

- `attributeTypes`
- `objectClasses`
- `ldapSyntaxes`
- `matchingRules`
- `matchingRuleUse`
- `dITContentRules`
- `nameForms`
- `dITStructureRules`

Use numeric OIDs for custom definitions and keep dependencies ordered or present
in the same file.

Recommended file pattern:

1. Allocate a private OID branch for your organization or deployment.
2. Define custom `matchingRules` and `matchingRuleUse` entries only when a
   built-in rule is not enough for the new attribute semantics.
3. Define `attributeTypes` with `NAME`, `DESC`, an LDAP syntax OID, matching
   rules when needed, and `SINGLE-VALUE` when only one value is valid.
4. Define `objectClasses` with `SUP`, `STRUCTURAL` or `AUXILIARY`, and the
   `MUST`/`MAY` attributes allowed on entries.
5. Add `dITContentRules`, `nameForms`, and `dITStructureRules` when the schema
   needs content restrictions or RDN naming rules.
6. Run `opendr --config config/server.toml schema validate` before restart.
7. Run `opendr --config config/server.toml schema explain <name-or-oid>` to
   inspect the effective definition.

If `[schema].allow_online_updates = true`, accepted LDAP Modify operations
against `cn=Subschema` are persisted here in `99-online.ldif`. Keep that file
under the same operational controls as other schema files.
