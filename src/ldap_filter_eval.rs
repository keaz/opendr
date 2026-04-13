use crate::backend::{DirectoryEntry, SearchCandidateHint, SearchSubstringPart};
use crate::replication::RenameChange;
use crate::replication_provider_fsm::{ChangeType, ChangelogEntry};
use crate::schema::{LdapSchema, MatchingRuleError, ResolvedMatchingRule};
use crate::search_fsm::SearchEntry;
use lber::common::TagClass;
use lber::structures::Tag;
use ldap_parser::filter::{Filter, Substring};
use ldap3::parse_filter;
use std::cmp::Ordering as CmpOrdering;
use std::collections::{HashMap, HashSet};

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
const SUBSTRING_INDEX_MIN_CHARS: usize = 3;

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
    Extensible {
        attribute: Option<String>,
        matching_rule: Option<String>,
        value: String,
        dn_attributes: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PreparedLdapFilter {
    And(Vec<PreparedLdapFilter>),
    Or(Vec<PreparedLdapFilter>),
    Not(Box<PreparedLdapFilter>),
    Equality {
        attribute: String,
        rule: ResolvedMatchingRule,
        normalized_value: String,
    },
    Substrings {
        attribute: String,
        rule: ResolvedMatchingRule,
        normalized_parts: Vec<SubstringPart>,
    },
    GreaterOrEqual {
        attribute: String,
        rule: ResolvedMatchingRule,
        normalized_value: String,
        ordering_key: String,
    },
    LessOrEqual {
        attribute: String,
        rule: ResolvedMatchingRule,
        normalized_value: String,
        ordering_key: String,
    },
    Present {
        attribute: String,
    },
    Extensible {
        attribute: Option<String>,
        rule: ResolvedMatchingRule,
        normalized_value: String,
        dn_attributes: bool,
        applicable_attributes: Option<HashSet<String>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubstringPart {
    Initial(String),
    Any(String),
    Final(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FilterSchemaError {
    UndefinedAttribute(String),
    InappropriateMatching(String),
    InvalidAttributeSyntax(String),
    InvalidFilter(String),
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedChange {
    change_type: ChangeType,
    scope_dns: Vec<String>,
    entry: Option<DirectoryEntry>,
    dn: String,
}

impl std::fmt::Display for FilterSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UndefinedAttribute(message) => write!(f, "undefined attribute type: {}", message),
            Self::InappropriateMatching(message) => {
                write!(f, "inappropriate matching: {}", message)
            }
            Self::InvalidAttributeSyntax(message) => {
                write!(f, "invalid attribute syntax: {}", message)
            }
            Self::InvalidFilter(message) => write!(f, "invalid filter: {}", message),
        }
    }
}

impl std::error::Error for FilterSchemaError {}

impl From<MatchingRuleError> for FilterSchemaError {
    fn from(error: MatchingRuleError) -> Self {
        match error {
            MatchingRuleError::AttributeNotFound(attribute) => Self::UndefinedAttribute(attribute),
            MatchingRuleError::InvalidSyntax { .. } => {
                Self::InvalidAttributeSyntax(error.to_string())
            }
            MatchingRuleError::NoMatchingRule { .. }
            | MatchingRuleError::UnsupportedRule(_)
            | MatchingRuleError::MatchingRuleNotFound(_)
            | MatchingRuleError::InapplicableRule { .. } => {
                Self::InappropriateMatching(error.to_string())
            }
            MatchingRuleError::MissingDependency(message) => Self::InvalidFilter(message),
        }
    }
}

pub(crate) fn compile_filter(filter: &str) -> Result<CompiledLdapFilter, String> {
    let tag = parse_filter(filter).map_err(|_| format!("invalid LDAP filter syntax: {filter}"))?;
    CompiledLdapFilter::from_tag(&tag)
}

#[cfg(test)]
pub(crate) fn extract_search_candidate_hint(filter: &Filter<'_>) -> Option<SearchCandidateHint> {
    CompiledLdapFilter::from_search_filter(filter)
        .ok()
        .and_then(|compiled| compiled.search_candidate_hint())
}

pub(crate) fn extract_search_candidate_hint_from_str(filter: &str) -> Option<SearchCandidateHint> {
    compile_filter(filter)
        .ok()
        .and_then(|compiled| compiled.search_candidate_hint())
}

#[cfg(test)]
pub(crate) fn matches_search_filter(entry: &DirectoryEntry, filter: &Filter<'_>) -> bool {
    CompiledLdapFilter::from_search_filter(filter)
        .map(|compiled| compiled.matches(entry))
        .unwrap_or(false)
}

pub(crate) fn validate_search_filter(
    schema: &LdapSchema,
    filter: &Filter<'_>,
) -> Result<(), FilterSchemaError> {
    prepare_search_filter_with_schema(schema, filter).map(|_| ())
}

pub(crate) fn matches_search_filter_with_schema(
    entry: &DirectoryEntry,
    filter: &Filter<'_>,
    schema: &LdapSchema,
) -> Result<bool, FilterSchemaError> {
    CompiledLdapFilter::from_search_filter(filter)
        .map_err(FilterSchemaError::InvalidFilter)?
        .prepare_with_schema(schema)?
        .matches_entry(entry)
}

pub(crate) fn prepare_search_filter_with_schema(
    schema: &LdapSchema,
    filter: &Filter<'_>,
) -> Result<PreparedLdapFilter, FilterSchemaError> {
    CompiledLdapFilter::from_search_filter(filter)
        .map_err(FilterSchemaError::InvalidFilter)?
        .prepare_with_schema(schema)
}

pub(crate) fn compare_attribute_with_schema(
    schema: &LdapSchema,
    _dn: &str,
    attributes: &HashMap<String, Vec<String>>,
    attribute: &str,
    assertion: &str,
) -> Result<bool, FilterSchemaError> {
    schema.resolve_attribute_matching_profile(attribute)?;
    let attribute_key = attribute.to_ascii_lowercase();
    let Some(values) = attribute_values(attributes, &attribute_key) else {
        return Ok(false);
    };
    validate_compare_assertion(schema, attribute, assertion)?;
    let rule = schema.equality_rule_for_attribute(attribute)?;
    for candidate in values {
        if rule.values_equal(candidate, assertion)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn validate_compare_assertion(
    schema: &LdapSchema,
    attribute: &str,
    assertion: &str,
) -> Result<(), FilterSchemaError> {
    let rule = schema.equality_rule_for_attribute(attribute)?;
    ensure_supported_rule(&rule)?;
    rule.normalize_value(assertion)?;
    Ok(())
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
    fn search_candidate_hint(&self) -> Option<SearchCandidateHint> {
        match self {
            Self::And(filters) => filters.iter().find_map(Self::search_candidate_hint),
            Self::Equality { attribute, value } => Some(SearchCandidateHint::Equality {
                attribute: attribute.clone(),
                value: value.clone(),
            }),
            Self::Present { attribute } => Some(SearchCandidateHint::Present {
                attribute: attribute.clone(),
            }),
            Self::Substrings { attribute, parts }
                if parts.iter().any(|part| {
                    substring_part_value(part).chars().count() >= SUBSTRING_INDEX_MIN_CHARS
                }) =>
            {
                Some(SearchCandidateHint::Substring {
                    attribute: attribute.clone(),
                    parts: parts.iter().map(SearchSubstringPart::from).collect(),
                })
            }
            Self::GreaterOrEqual { attribute, value } => {
                Some(SearchCandidateHint::GreaterOrEqual {
                    attribute: attribute.clone(),
                    value: value.clone(),
                })
            }
            Self::LessOrEqual { attribute, value } => Some(SearchCandidateHint::LessOrEqual {
                attribute: attribute.clone(),
                value: value.clone(),
            }),
            Self::ApproxMatch { attribute, value } => Some(SearchCandidateHint::Equality {
                attribute: attribute.clone(),
                value: value.clone(),
            }),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn validate_with_schema(
        &self,
        schema: &LdapSchema,
    ) -> Result<(), FilterSchemaError> {
        match self {
            Self::And(filters) | Self::Or(filters) => {
                for filter in filters {
                    filter.validate_with_schema(schema)?;
                }
                Ok(())
            }
            Self::Not(filter) => filter.validate_with_schema(schema),
            Self::Equality { attribute, value } => {
                let rule = schema.equality_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                rule.normalize_value(value)?;
                Ok(())
            }
            Self::Substrings { attribute, parts } => {
                let rule = schema.substring_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                for part in parts {
                    normalize_substring_part_for_rule(part, &rule)?;
                }
                Ok(())
            }
            Self::GreaterOrEqual { attribute, value } | Self::LessOrEqual { attribute, value } => {
                let rule = schema.ordering_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                rule.ordering_key(value)?;
                Ok(())
            }
            Self::Present { attribute } => {
                schema.resolve_attribute_matching_profile(attribute)?;
                Ok(())
            }
            Self::ApproxMatch { attribute, .. } => {
                schema.resolve_attribute_matching_profile(attribute)?;
                Err(FilterSchemaError::InappropriateMatching(format!(
                    "approximate matching is not supported for {}",
                    attribute
                )))
            }
            Self::Extensible {
                attribute,
                matching_rule,
                value,
                ..
            } => {
                let rule = match (attribute.as_deref(), matching_rule.as_deref()) {
                    (Some(attribute), Some(matching_rule)) => {
                        schema.matching_rule_applies_to_attribute(matching_rule, attribute)?
                    }
                    (Some(attribute), None) => schema.equality_rule_for_attribute(attribute)?,
                    (None, Some(matching_rule)) => schema.resolve_matching_rule(matching_rule)?,
                    (None, None) => {
                        return Err(FilterSchemaError::InvalidFilter(
                            "extensible match requires an attribute or matching rule".to_string(),
                        ));
                    }
                };
                ensure_supported_rule(&rule)?;
                rule.normalize_value(value)?;
                Ok(())
            }
        }
    }

    pub(crate) fn prepare_with_schema(
        &self,
        schema: &LdapSchema,
    ) -> Result<PreparedLdapFilter, FilterSchemaError> {
        match self {
            Self::And(filters) => filters
                .iter()
                .map(|filter| filter.prepare_with_schema(schema))
                .collect::<Result<Vec<_>, _>>()
                .map(PreparedLdapFilter::And),
            Self::Or(filters) => filters
                .iter()
                .map(|filter| filter.prepare_with_schema(schema))
                .collect::<Result<Vec<_>, _>>()
                .map(PreparedLdapFilter::Or),
            Self::Not(filter) => filter
                .prepare_with_schema(schema)
                .map(Box::new)
                .map(PreparedLdapFilter::Not),
            Self::Equality { attribute, value } => {
                let rule = schema.equality_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                let normalized_value = rule.normalize_value(value)?;
                Ok(PreparedLdapFilter::Equality {
                    attribute: attribute.clone(),
                    rule,
                    normalized_value,
                })
            }
            Self::Substrings { attribute, parts } => {
                let rule = schema.substring_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                let normalized_parts = parts
                    .iter()
                    .map(|part| normalize_substring_part_for_rule(part, &rule))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PreparedLdapFilter::Substrings {
                    attribute: attribute.clone(),
                    rule,
                    normalized_parts,
                })
            }
            Self::GreaterOrEqual { attribute, value } => {
                let rule = schema.ordering_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                let normalized_value = rule.normalize_value(value)?;
                let ordering_key = rule.ordering_key(value)?;
                Ok(PreparedLdapFilter::GreaterOrEqual {
                    attribute: attribute.clone(),
                    rule,
                    normalized_value,
                    ordering_key,
                })
            }
            Self::LessOrEqual { attribute, value } => {
                let rule = schema.ordering_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                let normalized_value = rule.normalize_value(value)?;
                let ordering_key = rule.ordering_key(value)?;
                Ok(PreparedLdapFilter::LessOrEqual {
                    attribute: attribute.clone(),
                    rule,
                    normalized_value,
                    ordering_key,
                })
            }
            Self::Present { attribute } => {
                schema.resolve_attribute_matching_profile(attribute)?;
                Ok(PreparedLdapFilter::Present {
                    attribute: attribute.clone(),
                })
            }
            Self::ApproxMatch { attribute, .. } => {
                schema.resolve_attribute_matching_profile(attribute)?;
                Err(FilterSchemaError::InappropriateMatching(format!(
                    "approximate matching is not supported for {}",
                    attribute
                )))
            }
            Self::Extensible {
                attribute,
                matching_rule,
                value,
                dn_attributes,
            } => {
                let (rule, applicable_attributes) =
                    match (attribute.as_deref(), matching_rule.as_deref()) {
                        (Some(attribute), Some(matching_rule)) => (
                            schema.matching_rule_applies_to_attribute(matching_rule, attribute)?,
                            None,
                        ),
                        (Some(attribute), None) => {
                            (schema.equality_rule_for_attribute(attribute)?, None)
                        }
                        (None, Some(matching_rule)) => (
                            schema.resolve_matching_rule(matching_rule)?,
                            Some(applicable_attribute_names_for_rule(schema, matching_rule)),
                        ),
                        (None, None) => {
                            return Err(FilterSchemaError::InvalidFilter(
                                "extensible match requires an attribute or matching rule"
                                    .to_string(),
                            ));
                        }
                    };
                ensure_supported_rule(&rule)?;
                let normalized_value = rule.normalize_value(value)?;
                Ok(PreparedLdapFilter::Extensible {
                    attribute: attribute.clone(),
                    rule,
                    normalized_value,
                    dn_attributes: *dn_attributes,
                    applicable_attributes,
                })
            }
        }
    }

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
                value: bytes_to_string(&ava.assertion_value),
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
                value: bytes_to_string(&ava.assertion_value),
            }),
            Filter::LessOrEqual(ava) => Ok(Self::LessOrEqual {
                attribute: ava.attribute_desc.0.to_ascii_lowercase(),
                value: bytes_to_string(&ava.assertion_value),
            }),
            Filter::Present(attribute) => Ok(Self::Present {
                attribute: attribute.0.to_ascii_lowercase(),
            }),
            Filter::ApproxMatch(ava) => Ok(Self::ApproxMatch {
                attribute: ava.attribute_desc.0.to_ascii_lowercase(),
                value: bytes_to_string(&ava.assertion_value),
            }),
            Filter::ExtensibleMatch(assertion) => Ok(Self::Extensible {
                attribute: assertion
                    .rule_type
                    .as_ref()
                    .map(|attribute| attribute.0.to_ascii_lowercase()),
                matching_rule: assertion
                    .matching_rule
                    .as_ref()
                    .map(|rule| rule.0.to_ascii_lowercase()),
                value: bytes_to_string(assertion.assertion_value.0.as_ref()),
                dn_attributes: assertion.dn_attributes.unwrap_or(false),
            }),
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
                parse_extensible_match_sequence(sequence)
            }
            other => Err(format!("unsupported LDAP filter tag: {:?}", other)),
        }
    }

    fn matches(&self, entry: &DirectoryEntry) -> bool {
        self.matches_attributes(&entry.dn, &entry.attributes)
    }

    #[cfg(test)]
    fn matches_with_schema(
        &self,
        entry: &DirectoryEntry,
        schema: &LdapSchema,
    ) -> Result<bool, FilterSchemaError> {
        self.matches_attributes_with_schema(schema, &entry.dn, &entry.attributes)
    }

    pub(crate) fn matches_search_entry(&self, entry: &SearchEntry) -> bool {
        self.matches_attributes(&entry.dn, &entry.attributes)
    }

    fn matches_attributes(&self, dn: &str, attributes: &HashMap<String, Vec<String>>) -> bool {
        match self {
            Self::And(filters) => filters
                .iter()
                .all(|filter| filter.matches_attributes(dn, attributes)),
            Self::Or(filters) => filters
                .iter()
                .any(|filter| filter.matches_attributes(dn, attributes)),
            Self::Not(filter) => !filter.matches_attributes(dn, attributes),
            Self::Equality { attribute, value } => attribute_values(attributes, attribute)
                .map(|values| values.iter().any(|candidate| candidate == value))
                .unwrap_or(false),
            Self::Substrings { attribute, parts } => attribute_values(attributes, attribute)
                .map(|values| matches_substrings(values, parts))
                .unwrap_or(false),
            Self::GreaterOrEqual { attribute, value } => attribute_values(attributes, attribute)
                .map(|values| values.iter().any(|candidate| candidate >= value))
                .unwrap_or(false),
            Self::LessOrEqual { attribute, value } => attribute_values(attributes, attribute)
                .map(|values| values.iter().any(|candidate| candidate <= value))
                .unwrap_or(false),
            Self::Present { attribute } => attribute_values(attributes, attribute).is_some(),
            Self::ApproxMatch { attribute, value } => attribute_values(attributes, attribute)
                .map(|values| {
                    values
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(value))
                })
                .unwrap_or(false),
            Self::Extensible {
                attribute,
                matching_rule,
                value,
                dn_attributes,
            } => matches_extensible(
                dn,
                attributes,
                attribute.as_deref(),
                matching_rule.as_deref(),
                value,
                *dn_attributes,
            ),
        }
    }

    #[cfg(test)]
    fn matches_attributes_with_schema(
        &self,
        schema: &LdapSchema,
        dn: &str,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<bool, FilterSchemaError> {
        match self {
            Self::And(filters) => {
                for filter in filters {
                    if !filter.matches_attributes_with_schema(schema, dn, attributes)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::Or(filters) => {
                for filter in filters {
                    if filter.matches_attributes_with_schema(schema, dn, attributes)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::Not(filter) => {
                Ok(!filter.matches_attributes_with_schema(schema, dn, attributes)?)
            }
            Self::Equality { attribute, value } => {
                let rule = schema.equality_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                Ok(attribute_values(attributes, attribute)
                    .map(|values| values_match_rule(values, value, &rule))
                    .transpose()?
                    .unwrap_or(false))
            }
            Self::Substrings { attribute, parts } => {
                let rule = schema.substring_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                let normalized_parts = parts
                    .iter()
                    .map(|part| normalize_substring_part_for_rule(part, &rule))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(attribute_values(attributes, attribute)
                    .map(|values| matches_substrings_with_rule(values, &normalized_parts, &rule))
                    .transpose()?
                    .unwrap_or(false))
            }
            Self::GreaterOrEqual { attribute, value } => {
                let rule = schema.ordering_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                Ok(attribute_values(attributes, attribute)
                    .map(|values| values_compare_rule(values, value, &rule, CmpExpectation::Ge))
                    .transpose()?
                    .unwrap_or(false))
            }
            Self::LessOrEqual { attribute, value } => {
                let rule = schema.ordering_rule_for_attribute(attribute)?;
                ensure_supported_rule(&rule)?;
                Ok(attribute_values(attributes, attribute)
                    .map(|values| values_compare_rule(values, value, &rule, CmpExpectation::Le))
                    .transpose()?
                    .unwrap_or(false))
            }
            Self::Present { attribute } => {
                schema.resolve_attribute_matching_profile(attribute)?;
                Ok(attribute_values(attributes, attribute).is_some())
            }
            Self::ApproxMatch { attribute, .. } => {
                schema.resolve_attribute_matching_profile(attribute)?;
                Err(FilterSchemaError::InappropriateMatching(format!(
                    "approximate matching is not supported for {}",
                    attribute
                )))
            }
            Self::Extensible {
                attribute,
                matching_rule,
                value,
                dn_attributes,
            } => matches_extensible_with_schema(
                schema,
                dn,
                attributes,
                attribute.as_deref(),
                matching_rule.as_deref(),
                value,
                *dn_attributes,
            ),
        }
    }
}

impl PreparedLdapFilter {
    pub(crate) fn search_candidate_hint(&self) -> Option<SearchCandidateHint> {
        match self {
            Self::And(filters) => filters.iter().find_map(Self::search_candidate_hint),
            Self::Equality {
                attribute,
                normalized_value,
                ..
            } => Some(SearchCandidateHint::Equality {
                attribute: attribute.clone(),
                value: normalized_value.clone(),
            }),
            Self::Present { attribute } => Some(SearchCandidateHint::Present {
                attribute: attribute.clone(),
            }),
            Self::Substrings {
                attribute,
                normalized_parts,
                ..
            } if normalized_parts.iter().any(|part| {
                substring_part_value(part).chars().count() >= SUBSTRING_INDEX_MIN_CHARS
            }) =>
            {
                Some(SearchCandidateHint::Substring {
                    attribute: attribute.clone(),
                    parts: normalized_parts
                        .iter()
                        .map(SearchSubstringPart::from)
                        .collect(),
                })
            }
            Self::GreaterOrEqual {
                attribute,
                normalized_value,
                ..
            } => Some(SearchCandidateHint::GreaterOrEqual {
                attribute: attribute.clone(),
                value: normalized_value.clone(),
            }),
            Self::LessOrEqual {
                attribute,
                normalized_value,
                ..
            } => Some(SearchCandidateHint::LessOrEqual {
                attribute: attribute.clone(),
                value: normalized_value.clone(),
            }),
            _ => None,
        }
    }

    pub(crate) fn exact_index_coverage_hint(&self) -> Option<SearchCandidateHint> {
        match self {
            Self::Equality {
                attribute,
                normalized_value,
                ..
            } => Some(SearchCandidateHint::Equality {
                attribute: attribute.clone(),
                value: normalized_value.clone(),
            }),
            Self::Present { attribute } => Some(SearchCandidateHint::Present {
                attribute: attribute.clone(),
            }),
            Self::GreaterOrEqual {
                attribute,
                normalized_value,
                ..
            } => Some(SearchCandidateHint::GreaterOrEqual {
                attribute: attribute.clone(),
                value: normalized_value.clone(),
            }),
            Self::LessOrEqual {
                attribute,
                normalized_value,
                ..
            } => Some(SearchCandidateHint::LessOrEqual {
                attribute: attribute.clone(),
                value: normalized_value.clone(),
            }),
            _ => None,
        }
    }

    pub(crate) fn matches_entry(&self, entry: &DirectoryEntry) -> Result<bool, FilterSchemaError> {
        self.matches_attributes(&entry.dn, &entry.attributes)
    }

    pub(crate) fn matches_search_entry(
        &self,
        entry: &SearchEntry,
    ) -> Result<bool, FilterSchemaError> {
        self.matches_attributes(&entry.dn, &entry.attributes)
    }

    fn matches_attributes(
        &self,
        dn: &str,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<bool, FilterSchemaError> {
        match self {
            Self::And(filters) => {
                for filter in filters {
                    if !filter.matches_attributes(dn, attributes)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::Or(filters) => {
                for filter in filters {
                    if filter.matches_attributes(dn, attributes)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::Not(filter) => Ok(!filter.matches_attributes(dn, attributes)?),
            Self::Equality {
                attribute,
                rule,
                normalized_value,
            } => Ok(attribute_values(attributes, attribute)
                .map(|values| values_match_normalized_rule(values, normalized_value, rule))
                .transpose()?
                .unwrap_or(false)),
            Self::Substrings {
                attribute,
                rule,
                normalized_parts,
            } => Ok(attribute_values(attributes, attribute)
                .map(|values| matches_substrings_with_rule(values, normalized_parts, rule))
                .transpose()?
                .unwrap_or(false)),
            Self::GreaterOrEqual {
                attribute,
                rule,
                ordering_key,
                ..
            } => Ok(attribute_values(attributes, attribute)
                .map(|values| {
                    values_compare_ordering_key(values, ordering_key, rule, CmpExpectation::Ge)
                })
                .transpose()?
                .unwrap_or(false)),
            Self::LessOrEqual {
                attribute,
                rule,
                ordering_key,
                ..
            } => Ok(attribute_values(attributes, attribute)
                .map(|values| {
                    values_compare_ordering_key(values, ordering_key, rule, CmpExpectation::Le)
                })
                .transpose()?
                .unwrap_or(false)),
            Self::Present { attribute } => Ok(attribute_values(attributes, attribute).is_some()),
            Self::Extensible {
                attribute,
                rule,
                normalized_value,
                dn_attributes,
                applicable_attributes,
            } => matches_prepared_extensible(
                dn,
                attributes,
                attribute.as_deref(),
                rule,
                normalized_value,
                *dn_attributes,
                applicable_attributes.as_ref(),
            ),
        }
    }
}

impl From<&SubstringPart> for SearchSubstringPart {
    fn from(part: &SubstringPart) -> Self {
        match part {
            SubstringPart::Initial(value) => Self::Initial(value.clone()),
            SubstringPart::Any(value) => Self::Any(value.clone()),
            SubstringPart::Final(value) => Self::Final(value.clone()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CmpExpectation {
    Ge,
    Le,
}

fn ensure_supported_rule(rule: &ResolvedMatchingRule) -> Result<(), FilterSchemaError> {
    if rule.is_supported() {
        Ok(())
    } else {
        Err(FilterSchemaError::InappropriateMatching(format!(
            "unsupported matching rule {}",
            rule.primary_name
        )))
    }
}

fn normalize_substring_part_for_rule(
    part: &SubstringPart,
    rule: &ResolvedMatchingRule,
) -> Result<SubstringPart, FilterSchemaError> {
    let value = rule.normalize_substring_fragment(substring_part_value(part))?;
    Ok(match part {
        SubstringPart::Initial(_) => SubstringPart::Initial(value),
        SubstringPart::Any(_) => SubstringPart::Any(value),
        SubstringPart::Final(_) => SubstringPart::Final(value),
    })
}

#[cfg(test)]
fn values_match_rule(
    values: &[String],
    assertion: &str,
    rule: &ResolvedMatchingRule,
) -> Result<bool, FilterSchemaError> {
    for candidate in values {
        if rule.values_equal(candidate, assertion)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn values_match_normalized_rule(
    values: &[String],
    normalized_assertion: &str,
    rule: &ResolvedMatchingRule,
) -> Result<bool, FilterSchemaError> {
    for candidate in values {
        if rule.normalize_value(candidate)? == normalized_assertion {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
fn values_compare_rule(
    values: &[String],
    assertion: &str,
    rule: &ResolvedMatchingRule,
    expectation: CmpExpectation,
) -> Result<bool, FilterSchemaError> {
    for candidate in values {
        let ordering = rule.compare_values(candidate, assertion)?;
        let matched = match expectation {
            CmpExpectation::Ge => matches!(ordering, CmpOrdering::Greater | CmpOrdering::Equal),
            CmpExpectation::Le => matches!(ordering, CmpOrdering::Less | CmpOrdering::Equal),
        };
        if matched {
            return Ok(true);
        }
    }
    Ok(false)
}

fn values_compare_ordering_key(
    values: &[String],
    assertion_key: &str,
    rule: &ResolvedMatchingRule,
    expectation: CmpExpectation,
) -> Result<bool, FilterSchemaError> {
    for candidate in values {
        let candidate_key = rule.ordering_key(candidate)?;
        let ordering = candidate_key.as_str().cmp(assertion_key);
        let matched = match expectation {
            CmpExpectation::Ge => matches!(ordering, CmpOrdering::Greater | CmpOrdering::Equal),
            CmpExpectation::Le => matches!(ordering, CmpOrdering::Less | CmpOrdering::Equal),
        };
        if matched {
            return Ok(true);
        }
    }
    Ok(false)
}

fn matches_substrings_with_rule(
    values: &[String],
    normalized_parts: &[SubstringPart],
    rule: &ResolvedMatchingRule,
) -> Result<bool, FilterSchemaError> {
    for value in values {
        let normalized_value = rule.normalize_value(value)?;
        if substring_matches(&normalized_value, normalized_parts) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn matches_prepared_extensible(
    dn: &str,
    attributes: &HashMap<String, Vec<String>>,
    attribute: Option<&str>,
    rule: &ResolvedMatchingRule,
    normalized_value: &str,
    dn_attributes: bool,
    applicable_attributes: Option<&HashSet<String>>,
) -> Result<bool, FilterSchemaError> {
    if let Some(attribute) = attribute {
        if attribute_values(attributes, attribute)
            .map(|values| values_match_normalized_rule(values, normalized_value, rule))
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(true);
        }

        return if dn_attributes {
            values_match_normalized_rule(
                &dn_attribute_values(dn, Some(attribute)),
                normalized_value,
                rule,
            )
        } else {
            Ok(false)
        };
    }

    for (attribute, values) in attributes {
        if applicable_attributes
            .map(|attributes| attributes.contains(attribute.as_str()))
            .unwrap_or(true)
            && values_match_normalized_rule(values, normalized_value, rule)?
        {
            return Ok(true);
        }
    }

    if dn_attributes {
        for value in dn_attribute_values(dn, None) {
            if rule.normalize_value(&value)? == normalized_value {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn applicable_attribute_names_for_rule(
    schema: &LdapSchema,
    matching_rule: &str,
) -> HashSet<String> {
    let mut applicable = HashSet::new();
    for attribute in schema.attribute_types_unique_sorted() {
        if schema
            .matching_rule_applies_to_attribute(matching_rule, &attribute.oid)
            .is_ok()
        {
            applicable.insert(attribute.oid.to_ascii_lowercase());
            for name in attribute.names {
                applicable.insert(name.to_ascii_lowercase());
            }
        }
    }
    applicable
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

fn parse_extensible_match_sequence(
    sequence: &lber::structures::Sequence,
) -> Result<CompiledLdapFilter, String> {
    let mut matching_rule = None;
    let mut attribute = None;
    let mut value = None;
    let mut dn_attributes = false;

    for tag in &sequence.inner {
        match tag {
            Tag::OctetString(octet) if octet.class == TagClass::Context && octet.id == 1 => {
                matching_rule = Some(octet_string_value(octet).to_ascii_lowercase());
            }
            Tag::OctetString(octet) if octet.class == TagClass::Context && octet.id == 2 => {
                attribute = Some(octet_string_value(octet).to_ascii_lowercase());
            }
            Tag::OctetString(octet) if octet.class == TagClass::Context && octet.id == 3 => {
                value = Some(octet_string_value(octet));
            }
            Tag::Boolean(boolean) if boolean.class == TagClass::Context && boolean.id == 4 => {
                dn_attributes = boolean.inner;
            }
            _ => return Err("unsupported extensibleMatch assertion component".to_string()),
        }
    }

    if attribute.is_none() && matching_rule.is_none() {
        return Err("extensibleMatch requires an attribute or matching rule".to_string());
    }

    Ok(CompiledLdapFilter::Extensible {
        attribute,
        matching_rule,
        value: value.ok_or_else(|| "extensibleMatch requires an assertion value".to_string())?,
        dn_attributes,
    })
}

fn convert_search_substring(substring: &Substring<'_>) -> SubstringPart {
    match substring {
        Substring::Initial(segment) => SubstringPart::Initial(bytes_to_string(segment.0.as_ref())),
        Substring::Any(segment) => SubstringPart::Any(bytes_to_string(segment.0.as_ref())),
        Substring::Final(segment) => SubstringPart::Final(bytes_to_string(segment.0.as_ref())),
    }
}

fn substring_part_value(part: &SubstringPart) -> &str {
    match part {
        SubstringPart::Initial(value) | SubstringPart::Any(value) | SubstringPart::Final(value) => {
            value
        }
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

fn matches_extensible(
    dn: &str,
    attributes: &HashMap<String, Vec<String>>,
    attribute: Option<&str>,
    matching_rule: Option<&str>,
    assertion: &str,
    dn_attributes: bool,
) -> bool {
    if let Some(attribute) = attribute {
        if attribute_values(attributes, attribute)
            .map(|values| {
                values
                    .iter()
                    .any(|value| extensible_value_matches(value, assertion, matching_rule))
            })
            .unwrap_or(false)
        {
            return true;
        }

        return dn_attributes
            && dn_attribute_values(dn, Some(attribute))
                .iter()
                .any(|value| extensible_value_matches(value, assertion, matching_rule));
    }

    if attributes.values().any(|values| {
        values
            .iter()
            .any(|value| extensible_value_matches(value, assertion, matching_rule))
    }) {
        return true;
    }

    dn_attributes
        && dn_attribute_values(dn, None)
            .iter()
            .any(|value| extensible_value_matches(value, assertion, matching_rule))
}

#[cfg(test)]
fn matches_extensible_with_schema(
    schema: &LdapSchema,
    dn: &str,
    attributes: &HashMap<String, Vec<String>>,
    attribute: Option<&str>,
    matching_rule: Option<&str>,
    assertion: &str,
    dn_attributes: bool,
) -> Result<bool, FilterSchemaError> {
    match (attribute, matching_rule) {
        (Some(attribute), Some(matching_rule)) => {
            let rule = schema.matching_rule_applies_to_attribute(matching_rule, attribute)?;
            ensure_supported_rule(&rule)?;
            if attribute_values(attributes, attribute)
                .map(|values| values_match_rule(values, assertion, &rule))
                .transpose()?
                .unwrap_or(false)
            {
                return Ok(true);
            }
            if dn_attributes {
                return values_match_rule(
                    &dn_attribute_values(dn, Some(attribute)),
                    assertion,
                    &rule,
                );
            }
            Ok(false)
        }
        (Some(attribute), None) => {
            let rule = schema.equality_rule_for_attribute(attribute)?;
            ensure_supported_rule(&rule)?;
            if attribute_values(attributes, attribute)
                .map(|values| values_match_rule(values, assertion, &rule))
                .transpose()?
                .unwrap_or(false)
            {
                return Ok(true);
            }
            if dn_attributes {
                return values_match_rule(
                    &dn_attribute_values(dn, Some(attribute)),
                    assertion,
                    &rule,
                );
            }
            Ok(false)
        }
        (None, Some(matching_rule)) => {
            let rule = schema.resolve_matching_rule(matching_rule)?;
            ensure_supported_rule(&rule)?;
            for (attribute, values) in attributes {
                if schema
                    .matching_rule_applies_to_attribute(matching_rule, attribute)
                    .is_ok()
                    && values_match_rule(values, assertion, &rule)?
                {
                    return Ok(true);
                }
            }
            if dn_attributes {
                for value in dn_attribute_values(dn, None) {
                    if rule.values_equal(&value, assertion)? {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        (None, None) => Err(FilterSchemaError::InvalidFilter(
            "extensible match requires an attribute or matching rule".to_string(),
        )),
    }
}

fn extensible_value_matches(candidate: &str, assertion: &str, matching_rule: Option<&str>) -> bool {
    match matching_rule {
        None | Some("caseexactmatch") | Some("2.5.13.5") => candidate == assertion,
        Some("caseignorematch") | Some("2.5.13.2") => {
            candidate.to_lowercase() == assertion.to_lowercase()
        }
        Some("distinguishednamematch") | Some("2.5.13.1") => {
            normalize_dn_value(candidate) == normalize_dn_value(assertion)
        }
        Some("integermatch") | Some("2.5.13.14") => {
            let candidate = candidate.trim().parse::<i64>();
            let assertion = assertion.trim().parse::<i64>();
            matches!((candidate, assertion), (Ok(candidate), Ok(assertion)) if candidate == assertion)
        }
        Some("booleanmatch")
        | Some("2.5.13.13")
        | Some("objectidentifiermatch")
        | Some("2.5.13.0") => candidate.eq_ignore_ascii_case(assertion),
        Some(_) => false,
    }
}

fn dn_attribute_values(dn: &str, attribute: Option<&str>) -> Vec<String> {
    dn.split(',')
        .flat_map(|rdn| rdn.split('+'))
        .filter_map(|ava| {
            let (name, value) = ava.split_once('=')?;
            match attribute {
                Some(attribute) if !name.trim().eq_ignore_ascii_case(attribute) => None,
                _ => Some(value.trim().to_string()),
            }
        })
        .collect()
}

fn normalize_dn_value(value: &str) -> String {
    value
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(",")
        .to_ascii_lowercase()
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

fn attribute_values<'a>(
    attributes: &'a HashMap<String, Vec<String>>,
    attribute: &str,
) -> Option<&'a Vec<String>> {
    attributes.get(attribute)
}

fn bytes_to_string(value: &[u8]) -> String {
    String::from_utf8_lossy(value).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csn::Csn;
    use crate::schema::LdapSchema;
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
    fn compile_filter_rejects_invalid_filters() {
        assert!(compile_filter("(objectClass=person").is_err());
        assert!(compile_filter("(:=Alice)").is_err());
    }

    #[test]
    fn compile_filter_parses_extensible_match_filters() {
        let exact = compile_filter("(cn:=Alice)").unwrap();
        let ignore_case = compile_filter("(cn:caseIgnoreMatch:=ALICE)").unwrap();
        let dn_attribute = compile_filter("(cn:dn:caseIgnoreMatch:=alice)").unwrap();
        let unsupported_rule = compile_filter("(cn:unknownRule:=Alice)").unwrap();
        let entry = test_entry("cn=alice,dc=example,dc=com", "person", "Alice");

        assert!(exact.matches(&entry));
        assert!(ignore_case.matches(&entry));
        assert!(dn_attribute.matches(&entry));
        assert!(!unsupported_rule.matches(&entry));
    }

    #[test]
    fn compile_filter_extracts_substring_and_ordering_hints() {
        assert_eq!(
            extract_search_candidate_hint_from_str("(cn=Ali*)"),
            Some(SearchCandidateHint::Substring {
                attribute: "cn".to_string(),
                parts: vec![SearchSubstringPart::Initial("Ali".to_string())],
            })
        );
        assert_eq!(
            extract_search_candidate_hint_from_str("(entryCSN>=020)"),
            Some(SearchCandidateHint::GreaterOrEqual {
                attribute: "entrycsn".to_string(),
                value: "020".to_string(),
            })
        );
        assert_eq!(
            extract_search_candidate_hint_from_str("(entryCSN<=020)"),
            Some(SearchCandidateHint::LessOrEqual {
                attribute: "entrycsn".to_string(),
                value: "020".to_string(),
            })
        );
        assert_eq!(
            extract_search_candidate_hint_from_str("(cn~=Alice)"),
            Some(SearchCandidateHint::Equality {
                attribute: "cn".to_string(),
                value: "Alice".to_string(),
            })
        );
        assert_eq!(extract_search_candidate_hint_from_str("(cn=Al*)"), None);
    }

    #[test]
    fn schema_filter_matching_uses_attribute_matching_rules() {
        let schema = LdapSchema::with_core_schema();
        let filter = compile_filter("(cn=  ALICE   SMITH )").unwrap();
        let entry = test_entry("cn=alice,dc=example,dc=com", "person", "Alice Smith");

        assert!(filter.matches_with_schema(&entry, &schema).unwrap());
    }

    #[test]
    fn prepared_schema_filter_matches_existing_schema_evaluator() {
        let mut schema = LdapSchema::with_core_schema();
        schema
            .load_ldif_str(
                "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.60.1 NAME 'exampleNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
",
            )
            .unwrap();

        let filter = compile_filter("(&(cn=  ALICE   SMITH )(exampleNumber>=0020))").unwrap();
        let prepared = filter.prepare_with_schema(&schema).unwrap();
        let mut matching = test_entry("cn=alice,dc=example,dc=com", "person", "Alice Smith");
        matching
            .attributes
            .insert("examplenumber".to_string(), vec!["42".to_string()]);
        let mut non_matching = test_entry("cn=alice,dc=example,dc=com", "person", "Alice Smith");
        non_matching
            .attributes
            .insert("examplenumber".to_string(), vec!["9".to_string()]);

        assert_eq!(
            prepared.matches_entry(&matching).unwrap(),
            filter.matches_with_schema(&matching, &schema).unwrap()
        );
        assert_eq!(
            prepared.matches_entry(&non_matching).unwrap(),
            filter.matches_with_schema(&non_matching, &schema).unwrap()
        );
    }

    #[test]
    fn prepared_schema_filter_reuses_normalized_substring_and_extensible_assertions() {
        let schema = LdapSchema::with_core_schema();
        let substring_filter = compile_filter("(cn=*ALICE*)").unwrap();
        let extensible_filter = compile_filter("(:caseIgnoreMatch:=  ALICE   SMITH )").unwrap();
        let substring_plan = substring_filter.prepare_with_schema(&schema).unwrap();
        let extensible_plan = extensible_filter.prepare_with_schema(&schema).unwrap();
        let entry = test_entry("cn=alice,dc=example,dc=com", "person", "Alice Smith");

        assert!(substring_plan.matches_entry(&entry).unwrap());
        assert!(extensible_plan.matches_entry(&entry).unwrap());
    }

    #[test]
    fn prepared_schema_filter_exposes_normalized_index_hints() {
        let mut schema = LdapSchema::with_core_schema();
        schema
            .load_ldif_str(
                "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.60.1 NAME 'exampleNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
",
            )
            .unwrap();

        let ordering_plan = compile_filter("(exampleNumber>=00042)")
            .unwrap()
            .prepare_with_schema(&schema)
            .unwrap();
        assert_eq!(
            ordering_plan.search_candidate_hint(),
            Some(SearchCandidateHint::GreaterOrEqual {
                attribute: "examplenumber".to_string(),
                value: "42".to_string(),
            })
        );

        let equality_plan = compile_filter("(cn=  ALICE   SMITH )")
            .unwrap()
            .prepare_with_schema(&schema)
            .unwrap();
        assert_eq!(
            equality_plan.search_candidate_hint(),
            Some(SearchCandidateHint::Equality {
                attribute: "cn".to_string(),
                value: "alice smith".to_string(),
            })
        );
        assert_eq!(
            equality_plan.exact_index_coverage_hint(),
            equality_plan.search_candidate_hint()
        );

        let compound_plan = compile_filter("(&(cn=Alice)(sn=Smith))")
            .unwrap()
            .prepare_with_schema(&schema)
            .unwrap();
        assert_eq!(compound_plan.exact_index_coverage_hint(), None);
    }

    #[test]
    fn schema_filter_validation_rejects_illegal_or_unknown_comparisons() {
        let schema = LdapSchema::with_core_schema();

        let unknown = compile_filter("(missingAttribute=value)").unwrap();
        assert!(matches!(
            unknown.validate_with_schema(&schema),
            Err(FilterSchemaError::UndefinedAttribute(_))
        ));

        let no_ordering = compile_filter("(cn>=Alice)").unwrap();
        assert!(matches!(
            no_ordering.validate_with_schema(&schema),
            Err(FilterSchemaError::InappropriateMatching(_))
        ));
    }

    #[test]
    fn schema_filter_validation_rejects_invalid_assertion_syntax() {
        let mut schema = LdapSchema::with_core_schema();
        schema
            .load_ldif_str(
                "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.60.1 NAME 'exampleNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
",
            )
            .unwrap();

        let invalid_integer = compile_filter("(exampleNumber>=not-an-int)").unwrap();
        assert!(matches!(
            invalid_integer.validate_with_schema(&schema),
            Err(FilterSchemaError::InvalidAttributeSyntax(_))
        ));
    }

    #[test]
    fn prepare_change_uses_entry_snapshots_for_attribute_filters() {
        let entry = test_entry("cn=alice,dc=example,dc=com", "person", "Alice");
        let change = change_with_entry(ChangeType::Add, &entry.dn, &entry);
        let compiled = compile_filter("(objectClass=person)").unwrap();
        let prepared = prepare_change(&change, true).unwrap();

        assert!(
            prepared
                .matches("dc=example,dc=com", Some(&compiled))
                .unwrap()
        );
    }

    #[test]
    fn prepare_change_uses_delete_snapshot_and_scope() {
        let entry = test_entry("cn=stale,dc=example,dc=com", "person", "Stale");
        let change = change_with_entry(ChangeType::Delete, &entry.dn, &entry);
        let compiled = compile_filter("(cn=Stale)").unwrap();
        let prepared = prepare_change(&change, true).unwrap();

        assert!(
            prepared
                .matches("dc=example,dc=com", Some(&compiled))
                .unwrap()
        );
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

        assert!(
            prepared
                .matches("ou=people,dc=example,dc=com", None)
                .unwrap()
        );
        assert!(
            prepared
                .matches(
                    "dc=example,dc=com",
                    Some(&compile_filter("(cn=alice)").unwrap())
                )
                .is_err()
        );
    }
}
