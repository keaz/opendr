use crate::backend::DirectoryEntry;
use crate::replication::RenameChange;
use crate::replication_provider_fsm::{ChangeType, ChangelogEntry};
use lber::common::TagClass;
use lber::structures::Tag;
use ldap3::parse_filter;
use ldap_parser::filter::{Filter, Substring};

const AND_FILTER: u64 = 0;
const OR_FILTER: u64 = 1;
const NOT_FILTER: u64 = 2;
const EQUALITY_MATCH: u64 = 3;
const SUBSTRINGS_MATCH: u64 = 4;
const GREATER_OR_EQUAL: u64 = 5;
const LESS_OR_EQUAL: u64 = 6;
const PRESENT_MATCH: u64 = 7;
const APPROX_MATCH: u64 = 8;
const EXTENSIBLE_MATCH: u64 = 9;

const SUBSTRING_INITIAL: u64 = 0;
const SUBSTRING_ANY: u64 = 1;
const SUBSTRING_FINAL: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompiledLdapFilter {
    And(Vec<CompiledLdapFilter>),
    Or(Vec<CompiledLdapFilter>),
    Not(Box<CompiledLdapFilter>),
    Equality {
        attribute: String,
        value: String,
    },
    Substrings {
        attribute: String,
        parts: Vec<SubstringPart>,
    },
    GreaterOrEqual {
        attribute: String,
        value: String,
    },
    LessOrEqual {
        attribute: String,
        value: String,
    },
    Present {
        attribute: String,
    },
    ApproxMatch {
        attribute: String,
        value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubstringPart {
    Initial(String),
    Any(String),
    Final(String),
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedChange {
    change_type: ChangeType,
    scope_dns: Vec<String>,
    entry: Option<DirectoryEntry>,
    dn: String,
}

pub(crate) fn compile_filter(filter: &str) -> Result<CompiledLdapFilter, String> {
    let tag = parse_filter(filter).map_err(|_| format!("invalid LDAP filter syntax: {filter}"))?;
    CompiledLdapFilter::from_tag(&tag)
}

pub(crate) fn matches_search_filter(entry: &DirectoryEntry, filter: &Filter<'_>) -> bool {
    CompiledLdapFilter::from_search_filter(filter)
        .map(|compiled| compiled.matches(entry))
        .unwrap_or(false)
}

pub(crate) fn prepare_change(
    change: &ChangelogEntry,
    require_entry_snapshot: bool,
) -> Result<PreparedChange, String> {
    match change.change_type {
        ChangeType::Add | ChangeType::Modify | ChangeType::Delete => {
            let entry = if require_entry_snapshot {
                Some(deserialize_entry(change)?)
            } else {
                None
            };

            Ok(PreparedChange {
                change_type: change.change_type.clone(),
                scope_dns: vec![change.dn.clone()],
                entry,
                dn: change.dn.clone(),
            })
        }
        ChangeType::Rename => {
            let rename = serde_json::from_slice::<RenameChange>(&change.change_data)
                .map_err(|e| format!("invalid rename change payload for {}: {}", change.dn, e))?;
            let target_dn =
                rename_target_dn(&change.dn, &rename.new_rdn, rename.new_superior.as_deref());

            Ok(PreparedChange {
                change_type: ChangeType::Rename,
                scope_dns: vec![change.dn.clone(), target_dn],
                entry: None,
                dn: change.dn.clone(),
            })
        }
    }
}

pub(crate) fn is_dn_in_scope(dn: &str, base_dn: &str) -> bool {
    if dn == base_dn {
        return true;
    }

    let dn_lower = dn.to_lowercase();
    let base_dn_lower = base_dn.to_lowercase();

    if dn_lower.ends_with(&base_dn_lower) {
        let prefix_len = dn_lower.len() - base_dn_lower.len();
        if prefix_len > 0 {
            return &dn_lower[prefix_len - 1..prefix_len] == ",";
        }
    }

    false
}

impl PreparedChange {
    pub(crate) fn matches(
        &self,
        base_dn: &str,
        filter: Option<&CompiledLdapFilter>,
    ) -> Result<bool, String> {
        if !self.scope_dns.iter().any(|dn| is_dn_in_scope(dn, base_dn)) {
            return Ok(false);
        }

        match filter {
            None => Ok(true),
            Some(filter) => match self.change_type {
                ChangeType::Rename => Err(format!(
                    "rename change for {} cannot evaluate attribute filters without an entry snapshot",
                    self.dn
                )),
                ChangeType::Add | ChangeType::Modify | ChangeType::Delete => self
                    .entry
                    .as_ref()
                    .map(|entry| filter.matches(entry))
                    .ok_or_else(|| {
                        format!(
                            "{} change for {} is missing an entry snapshot for filter evaluation",
                            change_type_label(&self.change_type),
                            self.dn
                        )
                    }),
            },
        }
    }
}

impl CompiledLdapFilter {
    fn from_search_filter(filter: &Filter<'_>) -> Result<Self, String> {
        match filter {
            Filter::And(filters) => filters
                .iter()
                .map(Self::from_search_filter)
                .collect::<Result<Vec<_>, _>>()
                .map(Self::And),
            Filter::Or(filters) => filters
                .iter()
                .map(Self::from_search_filter)
                .collect::<Result<Vec<_>, _>>()
                .map(Self::Or),
            Filter::Not(filter) => Ok(Self::Not(Box::new(Self::from_search_filter(filter)?))),
            Filter::EqualityMatch(ava) => Ok(Self::Equality {
                attribute: ava.attribute_desc.0.to_ascii_lowercase(),
                value: bytes_to_string(ava.assertion_value),
            }),
            Filter::Substrings(substring) => Ok(Self::Substrings {
                attribute: substring.filter_type.0.to_ascii_lowercase(),
                parts: substring
                    .substrings
                    .iter()
                    .map(convert_search_substring)
                    .collect(),
            }),
            Filter::GreaterOrEqual(ava) => Ok(Self::GreaterOrEqual {
                attribute: ava.attribute_desc.0.to_ascii_lowercase(),
                value: bytes_to_string(ava.assertion_value),
            }),
            Filter::LessOrEqual(ava) => Ok(Self::LessOrEqual {
                attribute: ava.attribute_desc.0.to_ascii_lowercase(),
                value: bytes_to_string(ava.assertion_value),
            }),
            Filter::Present(attribute) => Ok(Self::Present {
                attribute: attribute.0.to_ascii_lowercase(),
            }),
            Filter::ApproxMatch(ava) => Ok(Self::ApproxMatch {
                attribute: ava.attribute_desc.0.to_ascii_lowercase(),
                value: bytes_to_string(ava.assertion_value),
            }),
            Filter::ExtensibleMatch(_) => {
                Err("extensibleMatch filters are not supported".to_string())
            }
        }
    }

    fn from_tag(tag: &Tag) -> Result<Self, String> {
        match tag {
            Tag::Sequence(sequence)
                if sequence.class == TagClass::Context && sequence.id == AND_FILTER =>
            {
                sequence
                    .inner
                    .iter()
                    .map(Self::from_tag)
                    .collect::<Result<Vec<_>, _>>()
                    .map(Self::And)
            }
            Tag::Sequence(sequence)
                if sequence.class == TagClass::Context && sequence.id == OR_FILTER =>
            {
                sequence
                    .inner
                    .iter()
                    .map(Self::from_tag)
                    .collect::<Result<Vec<_>, _>>()
                    .map(Self::Or)
            }
            Tag::ExplicitTag(explicit)
                if explicit.class == TagClass::Context && explicit.id == NOT_FILTER =>
            {
                Ok(Self::Not(Box::new(Self::from_tag(
                    explicit.inner.as_ref(),
                )?)))
            }
            Tag::Sequence(sequence)
                if sequence.class == TagClass::Context && sequence.id == EQUALITY_MATCH =>
            {
                let [attribute, value] = expect_octet_pair(&sequence.inner, "equalityMatch")?;
                Ok(Self::Equality { attribute, value })
            }
            Tag::Sequence(sequence)
                if sequence.class == TagClass::Context && sequence.id == SUBSTRINGS_MATCH =>
            {
                let (attribute, parts) = parse_substrings_sequence(sequence)?;
                Ok(Self::Substrings { attribute, parts })
            }
            Tag::Sequence(sequence)
                if sequence.class == TagClass::Context && sequence.id == GREATER_OR_EQUAL =>
            {
                let [attribute, value] = expect_octet_pair(&sequence.inner, "greaterOrEqual")?;
                Ok(Self::GreaterOrEqual { attribute, value })
            }
            Tag::Sequence(sequence)
                if sequence.class == TagClass::Context && sequence.id == LESS_OR_EQUAL =>
            {
                let [attribute, value] = expect_octet_pair(&sequence.inner, "lessOrEqual")?;
                Ok(Self::LessOrEqual { attribute, value })
            }
            Tag::OctetString(octet)
                if octet.class == TagClass::Context && octet.id == PRESENT_MATCH =>
            {
                Ok(Self::Present {
                    attribute: octet_string_value(octet).to_ascii_lowercase(),
                })
            }
            Tag::Sequence(sequence)
                if sequence.class == TagClass::Context && sequence.id == APPROX_MATCH =>
            {
                let [attribute, value] = expect_octet_pair(&sequence.inner, "approxMatch")?;
                Ok(Self::ApproxMatch { attribute, value })
            }
            Tag::Sequence(sequence)
                if sequence.class == TagClass::Context && sequence.id == EXTENSIBLE_MATCH =>
            {
                let _ = sequence;
                Err("extensibleMatch filters are not supported".to_string())
            }
            other => Err(format!("unsupported LDAP filter tag: {:?}", other)),
        }
    }

    fn matches(&self, entry: &DirectoryEntry) -> bool {
        match self {
            Self::And(filters) => filters.iter().all(|filter| filter.matches(entry)),
            Self::Or(filters) => filters.iter().any(|filter| filter.matches(entry)),
            Self::Not(filter) => !filter.matches(entry),
            Self::Equality { attribute, value } => attribute_values(entry, attribute)
                .map(|values| values.iter().any(|candidate| candidate == value))
                .unwrap_or(false),
            Self::Substrings { attribute, parts } => attribute_values(entry, attribute)
                .map(|values| matches_substrings(values, parts))
                .unwrap_or(false),
            Self::GreaterOrEqual { attribute, value } => attribute_values(entry, attribute)
                .map(|values| values.iter().any(|candidate| candidate >= value))
                .unwrap_or(false),
            Self::LessOrEqual { attribute, value } => attribute_values(entry, attribute)
                .map(|values| values.iter().any(|candidate| candidate <= value))
                .unwrap_or(false),
            Self::Present { attribute } => attribute_values(entry, attribute).is_some(),
            Self::ApproxMatch { attribute, value } => attribute_values(entry, attribute)
                .map(|values| {
                    values
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(value))
                })
                .unwrap_or(false),
        }
    }
}

fn change_type_label(change_type: &ChangeType) -> &'static str {
    match change_type {
        ChangeType::Add => "add",
        ChangeType::Modify => "modify",
        ChangeType::Delete => "delete",
        ChangeType::Rename => "rename",
    }
}

fn deserialize_entry(change: &ChangelogEntry) -> Result<DirectoryEntry, String> {
    if change.change_data.is_empty() {
        return Err(format!(
            "{} change for {} is missing change_data",
            change_type_label(&change.change_type),
            change.dn
        ));
    }

    serde_json::from_slice::<DirectoryEntry>(&change.change_data).map_err(|e| {
        format!(
            "failed to deserialize {} change snapshot for {}: {}",
            change_type_label(&change.change_type),
            change.dn,
            e
        )
    })
}

fn rename_target_dn(dn: &str, new_rdn: &str, new_superior: Option<&str>) -> String {
    if let Some(superior) = new_superior {
        format!("{new_rdn},{superior}")
    } else if let Some((_, rest)) = dn.split_once(',') {
        format!("{new_rdn},{rest}")
    } else {
        new_rdn.to_string()
    }
}

fn parse_substrings_sequence(
    sequence: &lber::structures::Sequence,
) -> Result<(String, Vec<SubstringPart>), String> {
    if sequence.inner.len() != 2 {
        return Err("substring filter must contain attribute and substrings".to_string());
    }

    let attribute =
        expect_octet_string(&sequence.inner[0], "substring attribute")?.to_ascii_lowercase();
    let Tag::Sequence(parts) = &sequence.inner[1] else {
        return Err("substring filter must encode substring parts as a sequence".to_string());
    };

    let compiled_parts = parts
        .inner
        .iter()
        .map(parse_substring_part)
        .collect::<Result<Vec<_>, _>>()?;

    Ok((attribute, compiled_parts))
}

fn parse_substring_part(tag: &Tag) -> Result<SubstringPart, String> {
    let Tag::OctetString(octet) = tag else {
        return Err("substring part must be encoded as an octet string".to_string());
    };

    let value = octet_string_value(octet);
    match (octet.class, octet.id) {
        (TagClass::Context, SUBSTRING_INITIAL) => Ok(SubstringPart::Initial(value)),
        (TagClass::Context, SUBSTRING_ANY) => Ok(SubstringPart::Any(value)),
        (TagClass::Context, SUBSTRING_FINAL) => Ok(SubstringPart::Final(value)),
        _ => Err("unsupported substring part".to_string()),
    }
}

fn convert_search_substring(substring: &Substring<'_>) -> SubstringPart {
    match substring {
        Substring::Initial(segment) => SubstringPart::Initial(bytes_to_string(segment.0.as_ref())),
        Substring::Any(segment) => SubstringPart::Any(bytes_to_string(segment.0.as_ref())),
        Substring::Final(segment) => SubstringPart::Final(bytes_to_string(segment.0.as_ref())),
    }
}

fn expect_octet_pair(tags: &[Tag], label: &str) -> Result<[String; 2], String> {
    if tags.len() != 2 {
        return Err(format!(
            "{label} filter must contain exactly two octet strings"
        ));
    }

    Ok([
        expect_octet_string(&tags[0], label)?.to_ascii_lowercase(),
        expect_octet_string(&tags[1], label)?,
    ])
}

fn expect_octet_string(tag: &Tag, label: &str) -> Result<String, String> {
    let Tag::OctetString(octet) = tag else {
        return Err(format!("{label} must be encoded as an octet string"));
    };
    Ok(octet_string_value(octet))
}

fn octet_string_value(octet: &lber::structures::OctetString) -> String {
    bytes_to_string(octet.inner.as_slice())
}

fn matches_substrings(values: &[String], parts: &[SubstringPart]) -> bool {
    if parts.is_empty() {
        return values.iter().any(|value| value.is_empty());
    }

    values.iter().any(|value| substring_matches(value, parts))
}

fn substring_matches(value: &str, parts: &[SubstringPart]) -> bool {
    let mut remainder = value;

    for part in parts {
        match part {
            SubstringPart::Initial(segment) => {
                if !remainder.starts_with(segment) {
                    return false;
                }
                remainder = &remainder[segment.len()..];
            }
            SubstringPart::Any(segment) => {
                if segment.is_empty() {
                    continue;
                }
                if let Some(index) = remainder.find(segment) {
                    remainder = &remainder[index + segment.len()..];
                } else {
                    return false;
                }
            }
            SubstringPart::Final(segment) => return remainder.ends_with(segment),
        }
    }

    true
}

fn attribute_values<'a>(entry: &'a DirectoryEntry, attribute: &str) -> Option<&'a Vec<String>> {
    entry.attributes.get(attribute)
}

fn bytes_to_string(value: &[u8]) -> String {
    String::from_utf8_lossy(value).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csn::Csn;
    use std::collections::HashMap;

    fn test_entry(dn: &str, object_class: &str, cn: &str) -> DirectoryEntry {
        let mut attributes = HashMap::new();
        attributes.insert("objectclass".to_string(), vec![object_class.to_string()]);
        attributes.insert("cn".to_string(), vec![cn.to_string()]);
        DirectoryEntry::new(dn, attributes)
    }

    fn change_with_entry(
        change_type: ChangeType,
        dn: &str,
        entry: &DirectoryEntry,
    ) -> ChangelogEntry {
        ChangelogEntry::new(
            Csn::new(1),
            change_type,
            dn.to_string(),
            serde_json::to_vec(entry).unwrap(),
        )
    }

    #[test]
    fn compile_filter_parses_and_matches_compound_filters() {
        let filter = compile_filter("(&(objectClass=person)(cn=Alice*))").unwrap();
        let entry = test_entry("cn=alice,dc=example,dc=com", "person", "Alice Adams");
        let other = test_entry("cn=bob,dc=example,dc=com", "group", "Bob");

        assert!(filter.matches(&entry));
        assert!(!filter.matches(&other));
    }

    #[test]
    fn compile_filter_rejects_invalid_and_unsupported_filters() {
        assert!(compile_filter("(objectClass=person").is_err());
        assert!(compile_filter("(cn:caseExactMatch:=Alice)").is_err());
    }

    #[test]
    fn prepare_change_uses_entry_snapshots_for_attribute_filters() {
        let entry = test_entry("cn=alice,dc=example,dc=com", "person", "Alice");
        let change = change_with_entry(ChangeType::Add, &entry.dn, &entry);
        let compiled = compile_filter("(objectClass=person)").unwrap();
        let prepared = prepare_change(&change, true).unwrap();

        assert!(prepared
            .matches("dc=example,dc=com", Some(&compiled))
            .unwrap());
    }

    #[test]
    fn prepare_change_uses_delete_snapshot_and_scope() {
        let entry = test_entry("cn=stale,dc=example,dc=com", "person", "Stale");
        let change = change_with_entry(ChangeType::Delete, &entry.dn, &entry);
        let compiled = compile_filter("(cn=Stale)").unwrap();
        let prepared = prepare_change(&change, true).unwrap();

        assert!(prepared
            .matches("dc=example,dc=com", Some(&compiled))
            .unwrap());
        assert!(!prepared.matches("dc=other,dc=com", None).unwrap());
    }

    #[test]
    fn prepare_change_handles_rename_scope_and_rejects_attribute_filters() {
        let rename = RenameChange {
            new_rdn: "cn=alice".to_string(),
            delete_old: true,
            new_superior: Some("ou=people,dc=example,dc=com".to_string()),
            actor_dn: None,
        };
        let change = ChangelogEntry::new(
            Csn::new(1),
            ChangeType::Rename,
            "cn=alice,ou=staging,dc=example,dc=com".to_string(),
            serde_json::to_vec(&rename).unwrap(),
        );
        let prepared = prepare_change(&change, false).unwrap();

        assert!(prepared
            .matches("ou=people,dc=example,dc=com", None)
            .unwrap());
        assert!(prepared
            .matches(
                "dc=example,dc=com",
                Some(&compile_filter("(cn=alice)").unwrap())
            )
            .is_err());
    }
}
