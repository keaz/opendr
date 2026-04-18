use std::collections::HashMap;

use opendr::backend::MockBackend;
use opendr::fsm_request::active_fsm_control_registry;
use opendr::search_protocol::build_root_dse_attributes;

const RFC_MATRIX: &str = include_str!("../docs/LDAP_RFC_COMPLIANCE_MATRIX.md");
const ROOT_DSE_CAPABILITIES: &str = include_str!("../docs/ROOT_DSE_CAPABILITIES.md");

#[derive(Debug)]
struct TableRow {
    header: Vec<String>,
    cells: Vec<String>,
    line_number: usize,
}

#[derive(Debug)]
struct ComplianceRow {
    oid: Option<String>,
    status: String,
    coverage: String,
}

#[derive(Debug)]
struct RootDseCapability {
    name: String,
    oid: String,
    root_dse_attribute: String,
    advertised: String,
    line_number: usize,
}

impl RootDseCapability {
    fn is_advertised(&self) -> bool {
        let advertised = self.advertised.to_ascii_lowercase();
        advertised.starts_with("yes") || advertised.starts_with("only when")
    }

    fn is_unsupported_or_deferred(&self) -> bool {
        let advertised = self.advertised.to_ascii_lowercase();
        advertised.contains("unsupported") || advertised.contains("deferred")
    }
}

#[test]
fn supported_rfc_rows_have_release_gate_coverage() {
    let rows = compliance_rows();
    assert!(!rows.is_empty(), "expected RFC compliance rows");

    let missing_coverage: Vec<_> = rows
        .iter()
        .filter(|row| row.status.starts_with("Supported"))
        .filter(|row| row.coverage.trim().is_empty() || row.coverage.trim() == "-")
        .collect();

    assert!(
        missing_coverage.is_empty(),
        "supported RFC compliance rows must name release-gate coverage: {missing_coverage:#?}"
    );
}

#[test]
fn root_dse_advertised_oids_are_tracked_by_the_rfc_matrix() {
    let capabilities = root_dse_capabilities();
    assert!(
        !capabilities.is_empty(),
        "expected Root DSE capability rows"
    );

    for capability in capabilities
        .iter()
        .filter(|capability| capability.is_advertised())
    {
        assert!(
            RFC_MATRIX.contains(&capability.oid),
            "Root DSE capability `{}` advertises OID `{}` on line {}, but the RFC compliance matrix does not track it",
            capability.name,
            capability.oid,
            capability.line_number
        );
    }
}

#[test]
fn unsupported_root_dse_capabilities_are_not_marked_advertised() {
    let incorrectly_advertised: Vec<_> = root_dse_capabilities()
        .into_iter()
        .filter(|capability| capability.is_unsupported_or_deferred())
        .filter(|capability| capability.is_advertised())
        .collect();

    assert!(
        incorrectly_advertised.is_empty(),
        "unsupported or deferred Root DSE capabilities must not be advertised: {incorrectly_advertised:#?}"
    );
}

#[test]
fn unsupported_root_dse_oids_have_unsupported_matrix_rows() {
    let matrix_rows = compliance_rows();
    let unsupported_oids: Vec<_> = root_dse_capabilities()
        .into_iter()
        .filter(|capability| capability.is_unsupported_or_deferred())
        .collect();

    for capability in unsupported_oids {
        let matching_row = matrix_rows
            .iter()
            .find(|row| row.oid.as_deref() == Some(capability.oid.as_str()));

        assert!(
            matching_row
                .map(|row| row.status == "Unsupported")
                .unwrap_or(false),
            "Root DSE capability `{}` marks OID `{}` as unsupported/deferred on line {}, but the RFC matrix does not have a matching Unsupported row",
            capability.name,
            capability.oid,
            capability.line_number
        );
    }
}

#[tokio::test]
async fn documented_root_dse_advertising_matches_runtime_capabilities() {
    let backend = MockBackend::new();
    let registry = active_fsm_control_registry();
    let attributes = build_root_dse_attributes(
        &backend,
        &["dc=example,dc=org".to_string()],
        "cn=Subschema",
        false,
        true,
        &registry.root_dse_supported_control_oids(),
        &[],
    )
    .await
    .unwrap();
    let attributes = attributes.into_iter().collect::<HashMap<_, _>>();

    for attribute_name in [
        "supportedControl",
        "supportedExtension",
        "supportedFeatures",
    ] {
        let mut documented_oids = documented_advertised_oids(attribute_name);
        let mut runtime_oids = attributes.get(attribute_name).cloned().unwrap_or_default();
        documented_oids.sort();
        runtime_oids.sort();

        assert_eq!(
            runtime_oids, documented_oids,
            "Root DSE `{attribute_name}` runtime advertising must match docs/ROOT_DSE_CAPABILITIES.md"
        );
    }
}

#[tokio::test]
async fn starttls_is_not_advertised_when_the_connection_is_already_secure() {
    const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";

    let backend = MockBackend::new();
    let attributes = build_root_dse_attributes(&backend, &[], "cn=Subschema", true, true, &[], &[])
        .await
        .unwrap();
    let attributes = attributes.into_iter().collect::<HashMap<_, _>>();

    assert!(
        !attributes
            .get("supportedExtension")
            .unwrap()
            .contains(&START_TLS_OID.to_string()),
        "StartTLS must not be advertised after the connection is already secure"
    );
}

fn compliance_rows() -> Vec<ComplianceRow> {
    markdown_table_rows(RFC_MATRIX)
        .into_iter()
        .filter_map(|row| {
            let status_index = find_header_index(&row.header, "Status")?;
            let coverage_index = row
                .header
                .iter()
                .position(|header| header.to_ascii_lowercase().contains("coverage"))?;

            let oid = find_header_index(&row.header, "OID")
                .and_then(|index| row.cells.get(index))
                .and_then(|cell| extract_first_oid(cell));

            Some(ComplianceRow {
                oid,
                status: row.cells.get(status_index)?.trim().to_string(),
                coverage: row.cells.get(coverage_index)?.trim().to_string(),
            })
        })
        .collect()
}

fn root_dse_capabilities() -> Vec<RootDseCapability> {
    markdown_table_rows(ROOT_DSE_CAPABILITIES)
        .into_iter()
        .filter_map(|row| {
            let root_dse_attribute = root_dse_attribute_for_header(row.header.first()?)?;
            let oid_index = find_header_index(&row.header, "OID")?;
            let advertised_index = find_header_index(&row.header, "Advertised")?;
            let name = row.cells.first()?.trim().to_string();
            let oid = row
                .cells
                .get(oid_index)
                .and_then(|cell| extract_first_oid(cell))?;
            let advertised = row.cells.get(advertised_index)?.trim().to_string();

            Some(RootDseCapability {
                name,
                oid,
                root_dse_attribute,
                advertised,
                line_number: row.line_number,
            })
        })
        .collect()
}

fn documented_advertised_oids(root_dse_attribute: &str) -> Vec<String> {
    root_dse_capabilities()
        .into_iter()
        .filter(|capability| capability.root_dse_attribute == root_dse_attribute)
        .filter(|capability| capability.is_advertised())
        .map(|capability| capability.oid)
        .collect()
}

fn root_dse_attribute_for_header(header: &str) -> Option<String> {
    match header {
        "Control" => Some("supportedControl".to_string()),
        "Extension" => Some("supportedExtension".to_string()),
        "Feature" => Some("supportedFeatures".to_string()),
        _ => None,
    }
}

fn markdown_table_rows(markdown: &str) -> Vec<TableRow> {
    let mut rows = Vec::new();
    let mut header: Option<Vec<String>> = None;
    let mut has_separator = false;

    for (index, line) in markdown.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            header = None;
            has_separator = false;
            continue;
        }

        let cells = split_markdown_row(trimmed);
        if cells.is_empty() {
            continue;
        }

        if is_separator_row(&cells) {
            has_separator = header.is_some();
            continue;
        }

        if !has_separator {
            header = Some(cells);
            continue;
        }

        if let Some(current_header) = &header {
            rows.push(TableRow {
                header: current_header.clone(),
                cells,
                line_number: index + 1,
            });
        }
    }

    rows
}

fn split_markdown_row(line: &str) -> Vec<String> {
    line.trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect()
}

fn is_separator_row(cells: &[String]) -> bool {
    cells.iter().all(|cell| {
        !cell.is_empty()
            && cell
                .chars()
                .all(|character| matches!(character, '-' | ':' | ' '))
    })
}

fn find_header_index(header: &[String], expected: &str) -> Option<usize> {
    header
        .iter()
        .position(|cell| cell.trim().eq_ignore_ascii_case(expected))
}

fn extract_first_oid(cell: &str) -> Option<String> {
    for backtick_part in cell.split('`').skip(1).step_by(2) {
        if looks_like_oid(backtick_part) {
            return Some(backtick_part.to_string());
        }
    }

    cell.split_whitespace()
        .find(|part| {
            looks_like_oid(part.trim_matches(|character| character == ',' || character == '.'))
        })
        .map(|part| {
            part.trim_matches(|character| character == ',' || character == '.')
                .to_string()
        })
}

fn looks_like_oid(value: &str) -> bool {
    let mut saw_dot = false;
    let mut previous_was_dot = false;

    for character in value.chars() {
        match character {
            '0'..='9' => previous_was_dot = false,
            '.' if !previous_was_dot => {
                saw_dot = true;
                previous_was_dot = true;
            }
            _ => return false,
        }
    }

    saw_dot && !previous_was_dot
}
