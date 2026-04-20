# LDAP RFC Compliance and Alignment Matrix

This matrix is the release-tracking source for OpenDR LDAP RFC support. It
tracks the current, non-obsoleted LDAP RFCs that affect a generic LDAP server:
LDAPv3 core protocol behavior, Root DSE advertising, controls, extended
operations, server features, operational attributes, LDIF handling, and LDAP
schema bundles that OpenDR ships or deliberately does not ship.

The RFC set was reviewed against the RFC Editor index on 2026-04-19. Obsolete
LDAPv2 and pre-LDAPbis RFCs are represented by their replacement rows, primarily
the RFC 4510 LDAPv3 technical specification. Non-server or application-specific
LDAP RFCs are listed separately so release claims stay precise.

Status values are:

- `Supported`: implemented, advertised when appropriate, and covered by tests.
- `Partial`: implemented for the documented subset; gaps are explicit.
- `Aligned`: reflected in policy, docs, registry behavior, or release gates,
  but not a standalone protocol feature.
- `Unsupported`: not implemented and not advertised.
- `Not bundled`: not shipped as a built-in schema bundle; compatible
  deployments may still load custom schema where the schema engine can parse it.
- `Out of scope`: not an OpenDR LDAP server compatibility claim.
- `Intentionally unsupported`: deliberately rejected or omitted for safety.
- `Untested`: behavior exists or is planned, but the release gate does not yet
  prove it.

Production releases must keep this file, `ROOT_DSE_CAPABILITIES.md`, and the
readiness checklist in sync with code changes.

## Source of Truth

| Source | Role in this matrix | OpenDR alignment |
| --- | --- | --- |
| RFC 4510 | LDAPv3 technical specification roadmap. It identifies RFC 4511 through RFC 4519 as the LDAPv3 core and applies RFC 4520 and RFC 4521 extension guidance. | The core rows below are mandatory for any LDAPv3 server claim. |
| RFC Editor index | Current RFC status, obsoleted-by metadata, and publication category. | Obsoleted LDAP RFCs are not listed as separate current support targets unless a replacement row references them. |
| Root DSE runtime output | Client-visible capability claims through `supportedControl`, `supportedExtension`, `supportedFeatures`, `supportedSASLMechanisms`, and `supportedLDAPVersion`. | `tests/rfc_compliance_matrix_integration.rs` checks advertised OIDs against this document and `ROOT_DSE_CAPABILITIES.md`. |

## LDAPv3 Core RFCs

| RFC | Area | Status | Implementation and docs | Coverage and gate | Notes |
| --- | --- | --- | --- | --- | --- |
| RFC 4510 | LDAPv3 roadmap | Supported | This matrix links the RFC 4511-4519 rows that make up the LDAPv3 profile. | `cargo test --workspace --no-fail-fast`; `scripts/ldap_interop_gate.sh` | Roadmap RFC only; no protocol surface by itself. |
| RFC 4511 | Protocol operations, BER messages, controls, result codes | Partial | `src/server.rs`, `src/fsm_server.rs`, `src/ber_decoder_fsm.rs`, `src/parser.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_4511_protocol_integration.rs`, `tests/ldap_ops_client_integration.rs`, `tests/paged_results_integration.rs`, `tests/server_side_sort_integration.rs`, `fuzz/fuzz_targets/ber_decoder.rs`, `fuzz/fuzz_targets/ldap_request_handler.rs` | Bind, Search, Add, Modify, Delete, ModifyDN, Compare, Abandon, Unbind, extended ops, and known controls are covered. Arbitrary client behavior still requires the interop and fuzz gates. |
| RFC 4512 | Directory information model, Root DSE, subschema | Partial | `src/schema.rs`, `src/search_protocol.rs`, `docs/schema_integration.md`, `docs/ROOT_DSE_CAPABILITIES.md`; advanced schema rule enforcement completed under GitHub issue #190 | `tests/rfc_4512_directory_model_integration.rs`, `tests/schema_integration.rs`, `tests/schema_adapter_integration.rs`, `tests/operational_attrs_server_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs`, `tests/server_handlers.rs`, `scripts/ldap_interop_gate.sh` | Core schema publication and validation are present, including DIT content rules, name forms, structure rules, and dependency checks. The row remains Partial until the full RFC 4512 surface is validated through the release interop gate. |
| RFC 4513 | Authentication and security mechanisms | Partial | `src/auth_fsm.rs`, `src/security_layer.rs`, `src/sasl_mechanisms.rs`, `src/tls.rs`, `docs/PRODUCTION_SECURITY_PROFILE.md` | `tests/rfc_4513_auth_security_integration.rs`, `tests/legacy_runtime_security_integration.rs`, `tests/tls_runtime_integration.rs`, `tests/security_integration.rs`, `scripts/ldap_interop_gate.sh` | Simple bind, anonymous policy controls, StartTLS/LDAPS, SASL PLAIN over confidential transports, centralized effective security state, and SASL EXTERNAL over verified mutual TLS are covered. The interop gate validates cleartext-bind rejection, SASL PLAIN over StartTLS/LDAPS, malformed SASL PLAIN rejection, Root DSE SASL visibility, and SASL EXTERNAL mTLS bind/WhoAmI. SASL PLAIN accepts empty authzid plus self `dn:` and `u:` forms. SASL EXTERNAL accepts empty authzid plus self `dn:` authzid mapped from the verified client certificate. Proxy authorization and multi-step challenge mechanisms remain unsupported. |
| RFC 4514 | DN string representation | Supported | `src/dn.rs`, `docs/LDAP_REFERRAL_ALIAS_SUPPORT.md` | `dn::tests::*`, `tests/referral_integration.rs` | DN parsing and canonicalization are shared by scope matching, ACI, referrals, and ModifyDN validation. |
| RFC 4515 | Search filter string representation | Partial | `src/parser.rs`, `src/ldap_filter_eval.rs`, `src/search_adapters/` | `tests/rfc_4515_filter_integration.rs`, `tests/search_adapters_integration.rs`, `tests/indexing_integration.rs`, `tests/real_time_propagation_tests.rs` | Common equality, presence, substring, ordering, approximate, extensible, and boolean filters are covered. RFC 4526 absolute true and false filters are tracked separately. |
| RFC 4516 | LDAP URL format | Supported | `src/ldap_url.rs`, `docs/LDAP_REFERRAL_ALIAS_SUPPORT.md` | `tests/rfc_4516_ldap_url_referral_integration.rs`, `ldap_url::*` unit tests, `tests/referral_integration.rs`, `scripts/referral_alias_interop.sh` | LDAP and LDAPS URLs are parsed, validated, rendered, and used by referral handling. |
| RFC 4517 | Syntaxes and matching rules | Supported | File-backed core schema bundle in `resources/schema/core/rfc4517.ldif`, matching-rule execution and syntax validation in `src/schema.rs`, `docs/LDAP_SYNTAX_MATCHING_SUPPORT.md`; full RFC 4517 registry completed under GitHub issue #191 and migrated toward GitHub issue #200 | `tests/rfc_4517_4518_syntax_matching_integration.rs`, `tests/schema_integration.rs`, `tests/config_integration.rs`, `tests/indexing_integration.rs`, `tests/setup_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs` | The RFC 4517 syntax and matching-rule registry is advertised from bundled LDIF and executable where applicable. Internationalized string preparation details remain tracked under the separate RFC 4518 row. |
| RFC 4518 | Internationalized string preparation | Supported | `src/schema.rs`, `docs/LDAP_SYNTAX_MATCHING_SUPPORT.md`; full stringprep completed under GitHub issue #192 | `tests/rfc_4517_4518_syntax_matching_integration.rs`, `tests/schema_integration.rs`, `tests/indexing_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs` | Directory String, Numeric String, Telephone Number, and related matching rules apply X.520/RFC 4518 preparation, Unicode compatibility normalization, prohibited-code-point checks, and insignificant character handling. |
| RFC 4519 | User application schema | Supported | File-backed core schema bundle in `resources/schema/core/rfc4519.ldif`, schema validation in `src/schema.rs`, `docs/schema_integration.md`, `docs/schema_alignment.md`; full parity completed under GitHub issue #193 and migrated toward GitHub issue #200 | `tests/schema_integration.rs`, `tests/setup_integration.rs`, `tests/schema_adapter_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs`, `e2e_tests/test_schema_management.sh` | RFC 4519 user attributes and object classes are registered and validated from bundled LDIF, including strict `groupOfNames`, `uniqueMemberMatch` semantics, and generated schema-file loading. |

## Extension Governance, LDIF, and Discovery RFCs

| RFC | Area | Status | Implementation and docs | Coverage and gate | Notes |
| --- | --- | --- | --- | --- | --- |
| RFC 4520 | LDAP IANA registration policy | Aligned | `src/fsm_request.rs`, `src/search_protocol.rs`, `docs/ROOT_DSE_CAPABILITIES.md`, this matrix | `tests/rfc_compliance_matrix_integration.rs`, `tests/rfc_controls_extensions_integration.rs` | OpenDR treats public LDAP OIDs as registered protocol mechanisms and keeps Root DSE advertising tied to implemented request-usable capabilities. |
| RFC 4521 | LDAP extension design considerations | Aligned | `src/ldap_controls.rs`, `src/fsm_request.rs`, `src/extended_ops.rs`, `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | `tests/rfc_controls_extensions_integration.rs`, `tests/rfc_compliance_matrix_integration.rs` | Criticality semantics, request/response control separation, and Root DSE truthfulness follow the extension guidance. |
| RFC 2849 | LDIF technical specification | Partial | Startup entry import in `src/main.rs`, schema LDIF loading in `src/schema.rs`, setup LDIF generation in `src/setup.rs`, `docs/schema_integration.md`, `docs/CONFIGURATION.md` | `tests/setup_integration.rs`, `tests/schema_integration.rs`, `tests/schema_adapter_integration.rs`, `main::tests::test_initialize_base_structure_imports_config_ldif_files` | OpenDR supports the LDIF forms used for startup entries and schema definitions, including folded and base64 values. Full LDIF changerecord processing and URL values are not supported. |
| RFC 3045 | Vendor information in Root DSE | Unsupported | `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_4512_directory_model_integration.rs` | `vendorName` and `vendorVersion` are not currently published. |
| RFC 3384 | LDAPv3 replication requirements | Aligned | `docs/REPLICATION_GUIDE.md`, `docs/REPLICATION_PRODUCTION_GUARANTEES.md`, `src/replication*` | `tests/replication_e2e.rs`, `tests/replication_integration.rs`, `tests/rfc_4533_content_sync_integration.rs` | Informational requirements are represented by the RFC 4533 implementation and replication production guarantees. |

## Application and Directory Schema RFCs

| RFC | Area | Status | Implementation and docs | Coverage and gate | Notes |
| --- | --- | --- | --- | --- | --- |
| RFC 2247 | Domain names in LDAP/X.500 DNs | Supported | `resources/schema/core/rfc4519.ldif`, optional `resources/schema/cosine/rfc4524.ldif`, setup DN scaffolding in `src/setup.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs`, `tests/setup_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs` | Current `dc`, `dcObject`, and `domain` definitions are supplied through RFC 4519 and RFC 4524, which update RFC 2247. |
| RFC 2798 | `inetOrgPerson` object class | Supported | File-backed core schema bundle in `resources/schema/core/rfc2798.ldif`, schema validation in `src/schema.rs`, `docs/schema_integration.md`, `docs/schema_alignment.md`; full parity completed under GitHub issue #194 and migrated toward issue #200 | `tests/schema_integration.rs`, `tests/rfc_4517_4518_syntax_matching_integration.rs`, `tests/setup_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs` | The full RFC 2798 MAY attribute set is registered and validated from bundled LDIF, including audio/photo, X.509 certificate syntax, binary `;binary` attributes, `x500UniqueIdentifier`, generated schema-file loading, and `preferredLanguage` constraints. |
| RFC 2307 | POSIX/NIS account and group schema | Supported | Optional `posix` built-in schema bundle backed by `resources/schema/posix/rfc2307.ldif`, `src/schema.rs`, `docs/schema_integration.md`, `docs/schema_alignment.md`; full parity completed under GitHub issue #195 | `tests/schema_integration.rs`, `tests/config_integration.rs`, `tests/setup_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs` | The full RFC 2307 object class and attribute set is registered and validated, including shadow accounts, hosts, networks, services, protocols, RPCs, netgroups, NIS maps, IEEE 802 devices, bootable devices, custom netgroup/boot syntaxes, generated schema-file loading, and host/network/MAC semantic checks. |
| RFC 3112 | LDAP Authentication Password schema | Unsupported | `resources/schema/core/rfc4519.ldif`, `src/backend_lmdb.rs`, `docs/PRODUCTION_SECURITY_PROFILE.md` | `tests/schema_integration.rs`, `tests/backend_lmdb_integration.rs`, `tests/legacy_runtime_security_integration.rs` | OpenDR stores and verifies `userPassword` values and SSHA512 root credentials. It does not register or process the RFC 3112 `authPassword` schema. |
| RFC 3671 | Collective attributes | Supported | File-backed core schema bundle in `resources/schema/core/rfc3671.ldif`, collective projection runtime in `src/collective_attrs.rs`, schema validation in `src/schema.rs`, search and compare integration in `src/server.rs` and `src/fsm_server.rs`; completed under GitHub issue #196 | `collective_attrs::tests::*`, `schema::tests::rfc3671_*`, `server::tests::collective_attributes_are_projected_for_search_results_and_filters`, `server::tests::collective_attributes_are_projected_for_compare`, `fsm_server::tests::handle_connection_projects_collective_attributes_for_compare`, `tests/schema_rfc_conformance_roadmap.rs` | OpenDR registers `collectiveAttributeSubentry`, `collectiveAttributeSubentries`, `collectiveExclusions`, and the RFC 3671 collective attribute types. Collective attributes are stored on collective subentries, projected virtually into applicable search results and Compare operations, usable in filters, excluded with `collectiveExclusions`, and not persisted on target entries. Schema loading rejects single-valued collective attributes, non-collective subtypes of collective attributes, and object classes that list collective attributes. |
| RFC 3672 | LDAP subentries | Supported | File-backed core schema bundle in `resources/schema/core/rfc3672.ldif`, subtreeSpecification parser in `src/schema.rs`, Subentries request control in `src/search_controls.rs`, search visibility in `src/server.rs` and `src/fsm_server.rs`, `docs/ROOT_DSE_CAPABILITIES.md`; completed under GitHub issue #197 | `schema::tests::core_schema_loads_file_backed_rfc3671_and_rfc3672_definitions`, `schema::tests::subtree_specification_parser_*`, `server::tests::subentries_*`, `tests/schema_rfc_conformance_roadmap.rs`, `tests/rfc_controls_extensions_integration.rs` | OpenDR registers `subentry`, `administrativeRole`, `subtreeSpecification`, validates Subtree Specification syntax, requires subentries to sit below administrative entries, and applies RFC 3672 search visibility. Role-specific subentry classes from other RFCs remain tracked in their own rows. |
| RFC 3687 | LDAP and X.500 component matching rules | Partial | X.509 component matching execution in `src/schema.rs` and `src/ldap_filter_eval.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs`, `tests/rfc_4517_4518_syntax_matching_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs` | OpenDR implements component-style matching for the RFC 4523 X.509 schema surface. It does not expose a generic component assertion engine for arbitrary ASN.1 syntaxes. |
| RFC 3698 | Additional LDAP matching rules | Aligned | `resources/schema/core/rfc4517.ldif`, `src/schema.rs`, `docs/LDAP_SYNTAX_MATCHING_SUPPORT.md` | `tests/rfc_4517_4518_syntax_matching_integration.rs`, `tests/schema_integration.rs` | RFC 4517 updates and incorporates the current matching-rule surface; OpenDR tracks it through the RFC 4517 row. |
| RFC 3703 | Policy Core LDAP schema | Not bundled | Custom schema loading in `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Not shipped as a built-in bundle. |
| RFC 4104 | Policy Core Extension LDAP schema | Not bundled | Custom schema loading in `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Not shipped as a built-in bundle. |
| RFC 4522 | Binary encoding option | Partial | Attribute-option handling in `src/schema.rs`, X.509 and `inetOrgPerson` schema docs | `tests/schema_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs` | `;binary` is accepted and validated for the shipped certificate-related schema attributes. OpenDR does not claim a generic BER-valued binary option for every possible syntax. |
| RFC 4523 | X.509 certificate schema | Supported | Optional `x509` built-in schema bundle backed by `resources/schema/x509/rfc4523.ldif`, DER-backed value validation, exact GSER assertion matching, component matching-rule execution, X.509 matching-rule applicability in `src/schema.rs`, search/compare use through `src/ldap_filter_eval.rs`, `docs/schema_integration.md`, `docs/schema_alignment.md`; completed under GitHub issue #198 | `schema::tests::x509_schema_loads_file_backed_rfc4523_definitions`, `schema::tests::rfc4523_x400_address_common_built_in_fields_render_rfc2156_string`, `schema::tests::rfc4523_x400_extension_attributes_render_rfc2156_string`, `schema::tests::rfc4523_x400_psap_address_renders_rfc1278_presentation_address`, `schema::tests::rfc4523_other_name_known_constructed_values_match_der`, `ldap_filter_eval::tests::schema_filter_and_compare_use_rfc4523_certificate_exact_match`, `backend_lmdb::tests::test_schema_index_plan_rejects_partial_certificate_pair_matching_rule`, `tests/schema_integration.rs`, `tests/config_integration.rs`, `tests/setup_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs` | The RFC 4523 syntax, matching-rule, attribute, and object-class definitions are registered, and certificate, CRL, certificate-pair, and supported-algorithm values are validated as DER, PEM, or base64 DER. `certificateExactMatch` executes serial-number and issuer GSER assertions; `certificateListExactMatch` executes issuer and `thisUpdate` assertions; `certificatePairExactMatch` executes issued-to and issued-by certificate exact assertions without equality-index support; `algorithmIdentifierMatch` executes algorithm OID assertions with absent or NULL parameters. Component matching covers certificate, CRL, certificate-pair, algorithm, name constraint, GeneralSubtree, `otherName`, Kerberos, X.400, and distribution-point assertions documented in `schema_integration.md`. TLS runtime support is separate from certificate attribute/object class schema support. |
| RFC 4524 | COSINE LDAP/X.500 schema | Supported | Optional `cosine` built-in schema bundle backed by `resources/schema/cosine/rfc4524.ldif`, duplicate standard definition merging in `src/schema.rs`, `docs/schema_integration.md`, `docs/schema_alignment.md`; full parity completed under GitHub issue #199 | `schema::tests::cosine_schema_loads_file_backed_rfc4524_definitions`, `tests/schema_integration.rs`, `tests/config_integration.rs`, `tests/setup_integration.rs`, `tests/schema_rfc_conformance_roadmap.rs` | The full RFC 4524 attribute and object class set is registered and validated, including account, document, document series, domain, domain-related objects, friendly country, RFC 822 local part, room, simple security object, historic descriptor aliases, generated schema-file loading, and syntax-bound validation. |
| RFC 4530 | `entryUUID` operational attribute | Partial | `src/backend.rs`, `src/backend_lmdb.rs`, `src/operational_attrs.rs`, `docs/TROUBLESHOOTING.md` | `tests/rfc_4512_directory_model_integration.rs`, `tests/operational_attrs_server_integration.rs`, `tests/operational_attrs_search_integration.rs`, `tests/replication_integration.rs` | Entries receive stable UUID values and return them when requested as operational attributes. RFC 4530-specific UUID syntax and matching-rule schema are not yet registered as first-class schema definitions. |
| RFC 5020 | `entryDN` operational attribute | Partial | Virtual attribute projection in `src/backend.rs`, `src/backend_adapters/search.rs`, `src/search_adapters.rs`, `docs/TROUBLESHOOTING.md` | `tests/rfc_4512_directory_model_integration.rs`, `tests/operational_attrs_server_integration.rs`, `fsm_server::tests::*entryDN*`, `server::tests::*entryDN*` | `entryDN` is returned by name or through `+` operational selection. RFC 5020-specific matching rule registration remains a schema gap. |
| RFC 5803 | SCRAM secret storage schema | Unsupported | `src/sasl_mechanisms.rs`, `src/backend_lmdb.rs`, `docs/PRODUCTION_SECURITY_PROFILE.md` | `tests/rfc_4513_auth_security_integration.rs`, `tests/legacy_runtime_security_integration.rs` | SASL PLAIN and SASL EXTERNAL are supported over qualifying confidential transports; SCRAM mechanisms and RFC 5803 `authPassword` storage are not implemented. |

## Advertised Controls, Extensions, and Features

Every `Yes` row in `docs/ROOT_DSE_CAPABILITIES.md` must have a row here and a
release-gate test.

| RFC | Capability | OID | Root DSE attribute | Status | Implementation and docs | Coverage and gate |
| --- | --- | --- | --- | --- | --- | --- |
| RFC 2696 | Simple Paged Results request control | `1.2.840.113556.1.4.319` | `supportedControl` | Supported | `src/search_controls.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_controls_extensions_integration.rs`, `tests/paged_results_integration.rs`, `server::tests::paged_search_*`, `scripts/ldap_interop_gate.sh` |
| RFC 2891 | Server-Side Sort request control | `1.2.840.113556.1.4.473` | `supportedControl` | Supported | `src/server.rs`, `src/fsm_server.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_controls_extensions_integration.rs`, `tests/server_side_sort_integration.rs`, `scripts/ldap_interop_gate.sh` |
| RFC 3296 | ManageDsaIT request control | `2.16.840.1.113730.3.4.2` | `supportedControl` | Supported | `src/ldap_controls.rs`, `src/referral.rs`, `docs/LDAP_REFERRAL_ALIAS_SUPPORT.md` | `tests/rfc_controls_extensions_integration.rs`, `tests/referral_integration.rs`, `scripts/referral_alias_interop.sh` |
| RFC 3672 | Subentries request control | `1.3.6.1.4.1.4203.1.10.1` | `supportedControl` | Supported | `src/search_controls.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_controls_extensions_integration.rs`, `server::tests::subentries_*` |
| RFC 3673 | All Operational Attributes feature | `1.3.6.1.4.1.4203.1.5.1` | `supportedFeatures` | Partial | `src/operational_attrs.rs`, `src/backend.rs`, `src/search_adapters.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_4512_directory_model_integration.rs`, `tests/operational_attrs_search_integration.rs`, `tests/operational_attrs_server_integration.rs` |
| RFC 3909 | Cancel extended operation | `1.3.6.1.1.8` | `supportedExtension` | Supported | `src/extended_ops.rs`, `src/server.rs`, `src/fsm_server.rs` | `tests/rfc_controls_extensions_integration.rs`, `tests/security_integration.rs`, `server::tests::cancel_*`, `fsm_server::tests::cancel_*` |
| RFC 4511 / RFC 4513 | StartTLS extended operation | `1.3.6.1.4.1.1466.20037` | `supportedExtension` | Supported | `src/tls.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/PRODUCTION_SECURITY_PROFILE.md`, `docs/TLS_ROTATION.md` | `tests/rfc_controls_extensions_integration.rs`, `tests/tls_runtime_integration.rs`, `scripts/ldap_interop_gate.sh`, `scripts/tls_rotation_gate.sh` |
| RFC 4525 | Modify-Increment feature | `1.3.6.1.1.14` | `supportedFeatures` | Supported | `src/backend.rs`, `src/backend_lmdb.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | `tests/rfc_controls_extensions_integration.rs`, `server::tests::modify_increment_*`, `tests/backend_lmdb_integration.rs` |
| RFC 4527 | Pre-Read request control | `1.3.6.1.1.13.1` | `supportedControl` | Supported | `src/read_entry_controls.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/ROOT_DSE_CAPABILITIES.md`, `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | `read_entry_controls::tests::*`, `server::tests::modify_with_pre_read_returns_prior_entry_control`, `server::tests::malformed_pre_read_modify_is_rejected_without_mutating_entry`, `tests/rfc_controls_extensions_integration.rs`, `tests/rfc_4512_directory_model_integration.rs` |
| RFC 4527 | Post-Read request control | `1.3.6.1.1.13.2` | `supportedControl` | Supported | `src/read_entry_controls.rs`, `src/server.rs`, `src/fsm_request.rs`, `src/fsm_server.rs`, `docs/ROOT_DSE_CAPABILITIES.md`, `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | `read_entry_controls::tests::*`, `server::tests::add_with_post_read_returns_added_entry_control`, `server::tests::modify_with_pre_and_post_read_returns_prior_and_current_entry_controls`, `server::tests::moddn_with_post_read_returns_renamed_entry_control`, `fsm_server::tests::handle_connection_processes_*_with_post_read_control`, `tests/rfc_controls_extensions_integration.rs`, `tests/rfc_4512_directory_model_integration.rs` |
| RFC 4528 | Assertion request control | `1.3.6.1.1.12` | `supportedControl` | Unsupported | `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | `tests/rfc_controls_extensions_integration.rs`; critical/non-critical behavior covered by `server::tests::unsupported_expected_controls_follow_generic_criticality_semantics` |
| RFC 4529 | Request attributes by object class | `1.3.6.1.4.1.4203.1.5.2` | `supportedFeatures` | Supported | `src/search_protocol.rs`, `src/schema.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | `search_protocol::tests::expands_rfc4529_object_class_attribute_selectors`, `tests/server_handlers.rs`, `tests/rfc_controls_extensions_integration.rs`, `tests/rfc_4512_directory_model_integration.rs` |
| RFC 4532 | WhoAmI extended operation | `1.3.6.1.4.1.4203.1.11.3` | `supportedExtension` | Supported | `src/extended_ops.rs`, `src/server.rs`, `src/fsm_server.rs` | `tests/rfc_controls_extensions_integration.rs`, `tests/ldap_ops_client_integration.rs`, `tests/legacy_runtime_security_integration.rs`, `tests/tls_runtime_integration.rs` |
| RFC 4533 | Content Sync request control | `1.3.6.1.4.1.4203.1.9.1.1` | `supportedControl` | Partial | `src/sync_controls.rs`, `src/replication_*`, `docs/REPLICATION_PRODUCTION_GUARANTEES.md` | `tests/rfc_4533_content_sync_integration.rs`, `tests/replication_e2e.rs`, `tests/replication_integration.rs`, `tests/replication_consumer_integration.rs` |
| RFC 4533 | Content Sync state response control | `1.3.6.1.4.1.4203.1.9.1.2` | response-only | Supported for response encoding | `src/sync_controls.rs`, `src/server.rs`, `src/fsm_server.rs` | `tests/rfc_4533_content_sync_integration.rs`, `tests/replication_e2e.rs`, sync-control unit tests |
| RFC 4533 | Content Sync done response control | `1.3.6.1.4.1.4203.1.9.1.3` | response-only | Supported for response encoding | `src/sync_controls.rs`, `src/server.rs`, `src/fsm_server.rs` | `tests/rfc_4533_content_sync_integration.rs`, `tests/replication_e2e.rs`, sync-control unit tests |
| RFC 3062 | Password Modify extended operation | `1.3.6.1.4.1.4203.1.11.1` | `supportedExtension` | Supported | `src/extended_ops.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/PRODUCTION_SECURITY_PROFILE.md` | `tests/rfc_controls_extensions_integration.rs`, `tests/ldap_ops_client_integration.rs`, `tests/legacy_runtime_security_integration.rs` |

RFC 3673 is marked Partial because OpenDR accepts `+` and returns operational
attributes when requested, but does not yet publish the RFC 3673 feature OID in
`supportedFeatures`.

## Approved LDAP Server Extensions Not Advertised

These current RFCs define LDAP server controls, extended operations, filters, or
protocol services that OpenDR does not advertise. Unknown critical controls are
rejected and unknown non-critical controls are ignored per RFC 4511 generic
control semantics unless a row above registers explicit support.

| RFC | Area | Status | Implementation and docs | Coverage and gate | Notes |
| --- | --- | --- | --- | --- | --- |
| RFC 2589 | Dynamic directory services and Dynamic Refresh extended operation | Unsupported | `src/extended_ops.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_controls_extensions_integration.rs` | `dynamicObject`, `entryTtl`, `dynamicSubtrees`, and Dynamic Refresh are not registered or advertised. |
| RFC 2649 | Signed operation control and schema | Unsupported | `src/ldap_controls.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_controls_extensions_integration.rs` | OpenDR does not implement operation-signature controls or signed-journal schema. |
| RFC 3829 | Authorization Identity request and response controls | Unsupported | `src/ldap_controls.rs`, `src/extended_ops.rs` | `tests/rfc_controls_extensions_integration.rs`, `tests/ldap_ops_client_integration.rs` | Use RFC 4532 WhoAmI for the supported authorization identity query. |
| RFC 3866 | Language tags and ranges in LDAP attribute options | Unsupported | `src/schema.rs`, `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | `tests/schema_integration.rs` | OpenDR validates RFC 2798 `preferredLanguage` values, but does not implement language-range attribute option selection such as `cn;lang-en`. |
| RFC 3876 | Matched Values control | Unsupported | `src/ldap_controls.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_controls_extensions_integration.rs` | Attribute values are not filtered through `valuesReturnFilter` request controls. |
| RFC 3928 | LDAP Client Update Protocol | Unsupported | `src/replication*`, `docs/REPLICATION_GUIDE.md` | `tests/rfc_4533_content_sync_integration.rs`, `tests/replication_e2e.rs` | OpenDR uses RFC 4533 Content Sync instead of LCUP. |
| RFC 4370 | Proxied Authorization control | Unsupported | `src/aci.rs`, `src/ldap_controls.rs`, `docs/PRODUCTION_SECURITY_PROFILE.md` | `tests/security_integration.rs`, `tests/rfc_controls_extensions_integration.rs` | Per-operation authorization identity substitution is not implemented or advertised. |
| RFC 4373 | LDAP Bulk Update/Replication Protocol | Unsupported | `src/replication*`, `docs/REPLICATION_GUIDE.md` | `tests/rfc_4533_content_sync_integration.rs`, `tests/replication_e2e.rs` | OpenDR uses provider-owned Content Sync replication and backup/restore tooling instead of LBURP. |
| RFC 4526 | Absolute True and False filters | Unsupported | `src/ldap_filter_eval.rs`, `src/parser.rs` | `tests/rfc_4515_filter_integration.rs` | Search filters cover the RFC 4515 surface OpenDR parses today. Absolute true and false filter encodings are not accepted as a separate feature. |
| RFC 4531 | LDAP Turn operation | Unsupported | `src/extended_ops.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_controls_extensions_integration.rs` | OpenDR does not reverse client/server roles on an established LDAP session. |
| RFC 5805 | LDAP Transactions | Unsupported | Per-entry transactions in `src/write_fsm.rs`, backend write transactions in `src/backend_lmdb.rs` | `tests/backend_lmdb_integration.rs`, `tests/rfc_controls_extensions_integration.rs` | OpenDR write operations are transactional internally, but the RFC 5805 multi-operation transaction extended operations are not implemented. |
| RFC 6171 | Don't Use Copy control | Unsupported | `src/ldap_controls.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/rfc_controls_extensions_integration.rs` | OpenDR does not advertise or evaluate `dontUseCopy`; referrals and ManageDsaIT behavior are tracked separately. |

## Approved LDAP Schema RFCs Not Bundled

OpenDR ships only the core, POSIX, COSINE, and X.509 schema bundles listed
above. The schema engine can load additional RFC-style LDIF definitions when
they fit the supported subschema grammar, but these RFCs are not bundled or
claimed as release-ready compatibility surfaces.

| RFC | Area | Status | Implementation and docs | Coverage and gate | Notes |
| --- | --- | --- | --- | --- | --- |
| RFC 2164 | MIXER address mapping schema | Not bundled | `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Application-specific schema. |
| RFC 2713 | Java object schema | Not bundled | `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Application-specific schema. |
| RFC 2714 | CORBA object-reference schema | Not bundled | `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Application-specific schema. |
| RFC 2739 | Calendar attributes for vCard and LDAP | Not bundled | `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Application-specific schema. |
| RFC 2927 | MIME directory profile for LDAP schema | Out of scope | `docs/schema_integration.md` | - | Interchange profile for carrying schema, not an LDAP server runtime feature. |
| RFC 2985 | PKCS #9 selected object classes and attributes | Not bundled | `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Application-specific PKCS schema. |
| RFC 3088 | OpenLDAP Root Service referral service | Out of scope | `src/referral.rs`, `docs/LDAP_REFERRAL_ALIAS_SUPPORT.md` | `tests/referral_integration.rs` | OpenDR supports LDAP referrals but does not claim the experimental OpenLDAP root referral service. |
| RFC 3663 | Domain administrative data in LDAP | Not bundled | `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Application-specific schema. |
| RFC 4403 | UDDIv3 LDAP schema | Not bundled | `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Application-specific schema. |
| RFC 4876 | LDAP-based agent configuration profile schema | Not bundled | `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | DUA configuration schema, not a generic server built-in. |
| RFC 7612 | Printer services schema | Not bundled | `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Application-specific printer schema. |
| RFC 8284 | XMPP white-pages schema | Not bundled | `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs` | Application-specific schema. |

## Non-Server LDAP-Related RFCs

These RFCs are current and LDAP-related, but they do not define a generic LDAP
server feature that OpenDR should advertise or bundle.

| RFC | Area | Status | Reason |
| --- | --- | --- | --- |
| RFC 1823 | C LDAP API | Out of scope | Client library API. |
| RFC 2820 | Access control requirements for LDAP | Aligned | Informational requirements are represented by OpenDR ACI docs and tests, not a protocol capability. |
| RFC 2926 | LDAP schema to and from SLP templates | Out of scope | Conversion procedure for SLP templates. |
| RFC 3254 | Directory terminology | Aligned | Informational terminology reference. |
| RFC 3352 | CLDAP to Historic status | Out of scope | Confirms CLDAP is historic; OpenDR is LDAP over TCP/TLS. |
| RFC 3494 | LDAPv2 to Historic status | Aligned | OpenDR advertises LDAP version 3 only. |
| RFC 3642 | Common GSER encoding elements | Aligned | Used indirectly by schema-specific GSER assertions such as RFC 4523. |
| RFC 3727 | ASN.1 module for component matching rules | Aligned | Tracked through the RFC 3687 and RFC 4523 rows. |
| RFC 3944 | H.350 directory services | Out of scope | Application profile. |
| RFC 6134 | Sieve externally stored lists | Out of scope | Sieve client/server behavior that may query LDAP, not LDAP server behavior. |
| RFC 6880 | Kerberos information model | Out of scope | Kerberos information model; OpenDR only validates referenced X.509 `otherName` values where used by RFC 4523 matching. |

## Release Gate

A release can only claim production readiness for the supported rows above when
these gates pass and their artifacts are retained:

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. `cargo test --workspace --no-fail-fast`
4. `cargo test --doc --quiet`
5. `cargo test --test rfc_compliance_matrix_integration`
6. `scripts/ldap_interop_gate.sh`
7. `scripts/referral_alias_interop.sh` against a fixture with referral and alias entries
8. `TLS_ROTATION_ARTIFACT_DIR=target/tls-rotation-gate/release-candidate ./scripts/tls_rotation_gate.sh`
9. `FUZZ_GATE_MODE=release FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/release-candidate ./scripts/fuzz_gate.sh`
10. Retain `target/fuzz-gate/release-candidate` logs, corpora, dictionaries, and crash artifacts
11. `PERF_GATE_MODE=release PERF_GATE_BASELINE_JSON=target/perf/regression-baseline/opendr/regression-100k/ldap-benchmark-results.json PERF_GATE_OUTPUT_DIR=target/perf/regression-candidate ./scripts/perf_regression_gate.sh`

The manual GitHub workflow `Production Readiness Gate` runs the CI-friendly
subset and documents the longer fuzz and soak commands that must be executed
before a production-ready release is cut.
