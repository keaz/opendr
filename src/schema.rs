// LDAP Schema Validation (RFC 4512)
// Implements schema enforcement for entries and attributes

use base64::{Engine as _, engine::general_purpose};
use chrono::{
    DateTime, Datelike, Duration, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, TimeZone,
    Timelike, Utc,
};
use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::dn::{canonicalize_dn, parse_rdn};

/// LDAP Schema containing attribute types and object classes
#[derive(Debug, Clone)]
pub struct LdapSchema {
    attribute_types: HashMap<String, AttributeType>,
    attribute_types_by_oid: HashMap<String, AttributeType>,
    attribute_metadata_by_oid: HashMap<String, AttributeTypeMetadata>,
    object_classes: HashMap<String, ObjectClass>,
    object_classes_by_oid: HashMap<String, ObjectClass>,
    object_class_metadata_by_oid: HashMap<String, SchemaElementMetadata>,
    ldap_syntaxes: HashMap<String, LdapSyntax>,
    matching_rules: HashMap<String, MatchingRule>,
    matching_rules_by_oid: HashMap<String, MatchingRule>,
    matching_rule_uses: HashMap<String, MatchingRuleUse>,
    matching_rule_uses_by_oid: HashMap<String, MatchingRuleUse>,
    dit_content_rules: HashMap<String, DitContentRule>,
    name_forms: HashMap<String, NameForm>,
    name_forms_by_oid: HashMap<String, NameForm>,
    dit_structure_rules: HashMap<u32, DitStructureRule>,
}

/// Attribute type definition
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeType {
    pub oid: String,
    pub names: Vec<String>,
    pub description: Option<String>,
    pub equality: Option<String>,
    pub syntax: String,
    pub single_value: bool,
}

/// Additional RFC 4512 attribute type fields kept outside [`AttributeType`] for
/// backward compatibility with older tests and call sites.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttributeTypeMetadata {
    pub obsolete: bool,
    pub superior: Option<String>,
    pub ordering: Option<String>,
    pub substring: Option<String>,
    pub collective: bool,
    pub no_user_modification: bool,
    pub usage: Option<String>,
    pub syntax_length: Option<usize>,
    pub extensions: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchemaElementMetadata {
    pub description: Option<String>,
    pub obsolete: bool,
    pub extensions: BTreeMap<String, Vec<String>>,
}

/// Object class definition
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectClass {
    pub oid: String,
    pub names: Vec<String>,
    pub sup: Vec<String>, // Superior object classes
    pub kind: ObjectClassKind,
    pub must: Vec<String>, // Required attributes
    pub may: Vec<String>,  // Optional attributes
}

/// Object class type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectClassKind {
    Abstract,
    Structural,
    Auxiliary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapSyntax {
    pub oid: String,
    pub description: Option<String>,
    pub obsolete: bool,
    pub extensions: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchingRule {
    pub oid: String,
    pub names: Vec<String>,
    pub description: Option<String>,
    pub obsolete: bool,
    pub syntax: String,
    pub extensions: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchingRuleUse {
    pub oid: String,
    pub names: Vec<String>,
    pub description: Option<String>,
    pub obsolete: bool,
    pub applies: Vec<String>,
    pub extensions: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DitContentRule {
    pub oid: String,
    pub names: Vec<String>,
    pub description: Option<String>,
    pub obsolete: bool,
    pub auxiliary: Vec<String>,
    pub must: Vec<String>,
    pub may: Vec<String>,
    pub not: Vec<String>,
    pub extensions: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameForm {
    pub oid: String,
    pub names: Vec<String>,
    pub description: Option<String>,
    pub obsolete: bool,
    pub object_class: String,
    pub must: Vec<String>,
    pub may: Vec<String>,
    pub extensions: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DitStructureRule {
    pub rule_id: u32,
    pub names: Vec<String>,
    pub description: Option<String>,
    pub obsolete: bool,
    pub name_form: String,
    pub superior_rules: Vec<u32>,
    pub extensions: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeMatchingUse {
    Equality,
    Ordering,
    Substring,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMatchingRule {
    pub oid: String,
    pub names: Vec<String>,
    pub primary_name: String,
    pub syntax: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeMatchingProfile {
    pub oid: String,
    pub names: Vec<String>,
    pub syntax_oid: String,
    pub syntax_length: Option<usize>,
    pub single_value: bool,
    pub obsolete: bool,
    pub no_user_modification: bool,
    pub superior_chain: Vec<String>,
    pub equality: Option<ResolvedMatchingRule>,
    pub ordering: Option<ResolvedMatchingRule>,
    pub substring: Option<ResolvedMatchingRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchingRuleError {
    AttributeNotFound(String),
    MatchingRuleNotFound(String),
    NoMatchingRule {
        attribute: String,
        use_kind: AttributeMatchingUse,
    },
    UnsupportedRule(String),
    InvalidSyntax {
        rule: String,
        value: String,
        reason: String,
    },
    InapplicableRule {
        rule: String,
        attribute: String,
    },
    MissingDependency(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAttributeType {
    attribute_type: AttributeType,
    metadata: AttributeTypeMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedObjectClass {
    object_class: ObjectClass,
    metadata: SchemaElementMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectiveAttributeType {
    oid: String,
    names: Vec<String>,
    syntax_oid: String,
    syntax_length: Option<usize>,
    single_value: bool,
    obsolete: bool,
    no_user_modification: bool,
    equality: Option<String>,
    ordering: Option<String>,
    substring: Option<String>,
    superior_chain: Vec<String>,
}

/// Schema validation error
#[derive(Debug, Clone, PartialEq)]
pub enum SchemaError {
    ObjectClassNotFound(String),
    AttributeNotFound(String),
    MissingRequiredAttribute(String),
    AttributeNotAllowed(String),
    InvalidStructuralChain,
    MultipleStructuralClasses,
    SingleValueViolation(String),
    InvalidSyntax(String, String),
    NoStructuralClass,
    DuplicateOid(String),
    DuplicateName(String),
    MissingDependency(String),
    ObsoleteObjectClass(String),
    ObsoleteAttributeType(String),
    NoUserModification(String),
    DitContentRuleViolation(String),
    NamingViolation(String),
    StructureRuleViolation(String),
    ParseError(String),
    IoError(String),
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::ObjectClassNotFound(name) => write!(f, "Object class not found: {}", name),
            SchemaError::AttributeNotFound(name) => write!(f, "Attribute type not found: {}", name),
            SchemaError::MissingRequiredAttribute(name) => {
                write!(f, "Missing required attribute: {}", name)
            }
            SchemaError::AttributeNotAllowed(name) => {
                write!(f, "Attribute not allowed by entry schema: {}", name)
            }
            SchemaError::InvalidStructuralChain => {
                write!(f, "Invalid structural object class chain")
            }
            SchemaError::MultipleStructuralClasses => {
                write!(f, "Multiple structural object classes")
            }
            SchemaError::SingleValueViolation(name) => {
                write!(f, "Single-value violation for attribute: {}", name)
            }
            SchemaError::InvalidSyntax(attr, reason) => {
                write!(f, "Invalid syntax for {}: {}", attr, reason)
            }
            SchemaError::NoStructuralClass => write!(f, "No structural object class defined"),
            SchemaError::DuplicateOid(oid) => write!(f, "Duplicate schema OID: {}", oid),
            SchemaError::DuplicateName(name) => write!(f, "Duplicate schema name: {}", name),
            SchemaError::MissingDependency(message) => {
                write!(f, "Missing schema dependency: {}", message)
            }
            SchemaError::ObsoleteObjectClass(name) => {
                write!(f, "Obsolete object class cannot be used: {}", name)
            }
            SchemaError::ObsoleteAttributeType(name) => {
                write!(f, "Obsolete attribute type cannot be used: {}", name)
            }
            SchemaError::NoUserModification(name) => {
                write!(f, "Attribute is not user modifiable: {}", name)
            }
            SchemaError::DitContentRuleViolation(message) => {
                write!(f, "DIT content rule violation: {}", message)
            }
            SchemaError::NamingViolation(message) => write!(f, "Naming violation: {}", message),
            SchemaError::StructureRuleViolation(message) => {
                write!(f, "DIT structure rule violation: {}", message)
            }
            SchemaError::ParseError(message) => write!(f, "Schema parse error: {}", message),
            SchemaError::IoError(message) => write!(f, "Schema I/O error: {}", message),
        }
    }
}

impl std::error::Error for SchemaError {}

impl std::fmt::Display for AttributeMatchingUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Equality => write!(f, "equality"),
            Self::Ordering => write!(f, "ordering"),
            Self::Substring => write!(f, "substring"),
        }
    }
}

impl std::fmt::Display for MatchingRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AttributeNotFound(attribute) => {
                write!(f, "attribute type not found: {}", attribute)
            }
            Self::MatchingRuleNotFound(rule) => write!(f, "matching rule not found: {}", rule),
            Self::NoMatchingRule {
                attribute,
                use_kind,
            } => write!(f, "{} has no {} matching rule", attribute, use_kind),
            Self::UnsupportedRule(rule) => write!(f, "unsupported matching rule: {}", rule),
            Self::InvalidSyntax {
                rule,
                value,
                reason,
            } => write!(
                f,
                "value {:?} is invalid for matching rule {}: {}",
                value, rule, reason
            ),
            Self::InapplicableRule { rule, attribute } => write!(
                f,
                "matching rule {} does not apply to attribute {}",
                rule, attribute
            ),
            Self::MissingDependency(message) => {
                write!(f, "missing matching dependency: {}", message)
            }
        }
    }
}

impl std::error::Error for MatchingRuleError {}

impl ResolvedMatchingRule {
    pub fn normalize_value(&self, value: &str) -> Result<String, MatchingRuleError> {
        normalize_matching_rule_value(self, value)
    }

    pub fn normalize_substring_fragment(&self, value: &str) -> Result<String, MatchingRuleError> {
        normalize_matching_rule_value(self, value)
    }

    pub fn ordering_key(&self, value: &str) -> Result<String, MatchingRuleError> {
        matching_rule_ordering_key(self, value)
    }

    pub fn values_equal(&self, left: &str, right: &str) -> Result<bool, MatchingRuleError> {
        Ok(self.normalize_value(left)? == self.normalize_value(right)?)
    }

    pub fn compare_values(
        &self,
        left: &str,
        right: &str,
    ) -> Result<CmpOrdering, MatchingRuleError> {
        compare_matching_rule_values(self, left, right)
    }

    pub fn is_supported(&self) -> bool {
        supported_matching_rule_kind(self).is_some()
    }

    fn label(&self) -> &str {
        if self.primary_name.is_empty() {
            &self.oid
        } else {
            &self.primary_name
        }
    }
}

impl AttributeMatchingProfile {
    pub fn rule_for_use(&self, use_kind: AttributeMatchingUse) -> Option<&ResolvedMatchingRule> {
        match use_kind {
            AttributeMatchingUse::Equality => self.equality.as_ref(),
            AttributeMatchingUse::Ordering => self.ordering.as_ref(),
            AttributeMatchingUse::Substring => self.substring.as_ref(),
        }
    }
}

impl LdapSchema {
    /// Create an empty schema
    pub fn new() -> Self {
        Self {
            attribute_types: HashMap::new(),
            attribute_types_by_oid: HashMap::new(),
            attribute_metadata_by_oid: HashMap::new(),
            object_classes: HashMap::new(),
            object_classes_by_oid: HashMap::new(),
            object_class_metadata_by_oid: HashMap::new(),
            ldap_syntaxes: HashMap::new(),
            matching_rules: HashMap::new(),
            matching_rules_by_oid: HashMap::new(),
            matching_rule_uses: HashMap::new(),
            matching_rule_uses_by_oid: HashMap::new(),
            dit_content_rules: HashMap::new(),
            name_forms: HashMap::new(),
            name_forms_by_oid: HashMap::new(),
            dit_structure_rules: HashMap::new(),
        }
    }

    /// Create schema with core LDAP definitions
    pub fn with_core_schema() -> Self {
        let mut schema = Self::new();
        schema.load_core_schema();
        schema
    }

    /// Load core LDAP schema (RFC 4519, 4524)
    fn load_core_schema(&mut self) {
        // Core attribute types
        let core_attributes = vec![
            AttributeType {
                oid: "2.5.4.0".to_string(),
                names: vec!["objectClass".to_string()],
                description: Some("Object class".to_string()),
                equality: Some("objectIdentifierMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.38".to_string(), // OID syntax
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.3".to_string(),
                names: vec!["cn".to_string(), "commonName".to_string()],
                description: Some("Common name".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(), // Directory String
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.4".to_string(),
                names: vec!["sn".to_string(), "surname".to_string()],
                description: Some("Surname".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.10".to_string(),
                names: vec!["o".to_string(), "organizationName".to_string()],
                description: Some("Organization name".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.11".to_string(),
                names: vec!["ou".to_string(), "organizationalUnitName".to_string()],
                description: Some("Organizational unit name".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.1".to_string(),
                names: vec!["uid".to_string(), "userid".to_string()],
                description: Some("User ID".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.3".to_string(),
                names: vec!["mail".to_string(), "rfc822Mailbox".to_string()],
                description: Some("Email address".to_string()),
                equality: Some("caseIgnoreIA5Match".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.26".to_string(), // IA5 String
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.35".to_string(),
                names: vec!["userPassword".to_string()],
                description: Some("User password".to_string()),
                equality: Some("octetStringMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.40".to_string(), // Octet String
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.13".to_string(),
                names: vec!["description".to_string()],
                description: Some("Description".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.42".to_string(),
                names: vec!["givenName".to_string()],
                description: Some("Given name".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.16.840.1.113730.3.1.241".to_string(),
                names: vec!["displayName".to_string()],
                description: Some("Display name".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.25".to_string(),
                names: vec!["dc".to_string(), "domainComponent".to_string()],
                description: Some("Domain component".to_string()),
                equality: Some("caseIgnoreIA5Match".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.26".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.31".to_string(),
                names: vec!["member".to_string()],
                description: Some("Group member".to_string()),
                equality: Some("distinguishedNameMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.12".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.12".to_string(),
                names: vec!["title".to_string()],
                description: Some("Title".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.20".to_string(),
                names: vec!["telephoneNumber".to_string()],
                description: Some("Telephone number".to_string()),
                equality: Some("telephoneNumberMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.50".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.15".to_string(),
                names: vec!["businessCategory".to_string()],
                description: Some("Business category".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
        ];

        for attr in core_attributes {
            self.add_attribute_type(attr);
        }
        for attr_name in [
            "cn",
            "sn",
            "o",
            "ou",
            "uid",
            "mail",
            "description",
            "givenName",
            "displayName",
            "dc",
            "title",
            "businessCategory",
        ] {
            self.set_attribute_substring_rule(attr_name, "caseIgnoreSubstringsMatch");
        }
        self.set_attribute_substring_rule("telephoneNumber", "telephoneNumberSubstringsMatch");

        // Core object classes
        let core_classes = vec![
            ObjectClass {
                oid: "2.5.6.0".to_string(),
                names: vec!["top".to_string()],
                sup: vec![],
                kind: ObjectClassKind::Abstract,
                must: vec!["objectClass".to_string()],
                may: vec![],
            },
            ObjectClass {
                oid: "2.5.6.6".to_string(),
                names: vec!["person".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["sn".to_string(), "cn".to_string()],
                may: vec![
                    "userPassword".to_string(),
                    "telephoneNumber".to_string(),
                    "description".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.7".to_string(),
                names: vec!["organizationalPerson".to_string()],
                sup: vec!["person".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec![],
                may: vec!["ou".to_string(), "mail".to_string()],
            },
            ObjectClass {
                oid: "2.16.840.1.113730.3.2.2".to_string(),
                names: vec!["inetOrgPerson".to_string()],
                sup: vec!["organizationalPerson".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec![],
                may: vec![
                    "uid".to_string(),
                    "givenName".to_string(),
                    "displayName".to_string(),
                    "mail".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.4".to_string(),
                names: vec!["organization".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["o".to_string()],
                may: vec!["description".to_string()],
            },
            ObjectClass {
                oid: "2.5.6.5".to_string(),
                names: vec!["organizationalUnit".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["ou".to_string()],
                may: vec!["description".to_string()],
            },
            ObjectClass {
                oid: "1.3.6.1.4.1.1466.344".to_string(),
                names: vec!["dcObject".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Auxiliary,
                must: vec!["dc".to_string()],
                may: vec![],
            },
            ObjectClass {
                oid: "0.9.2342.19200300.100.4.13".to_string(),
                names: vec!["domain".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["dc".to_string()],
                may: vec!["description".to_string()],
            },
            ObjectClass {
                oid: "2.5.6.9".to_string(),
                names: vec!["groupOfNames".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["cn".to_string(), "member".to_string()],
                may: vec!["businessCategory".to_string(), "description".to_string()],
            },
        ];

        for oc in core_classes {
            self.add_object_class(oc);
        }

        self.load_standard_syntaxes_and_matching_rules();
    }

    fn load_standard_syntaxes_and_matching_rules(&mut self) {
        let syntaxes = [
            ("1.3.6.1.4.1.1466.115.121.1.7", "Boolean"),
            ("1.3.6.1.4.1.1466.115.121.1.12", "DN"),
            ("1.3.6.1.4.1.1466.115.121.1.15", "Directory String"),
            ("1.3.6.1.4.1.1466.115.121.1.24", "Generalized Time"),
            ("1.3.6.1.4.1.1466.115.121.1.26", "IA5 String"),
            ("1.3.6.1.4.1.1466.115.121.1.27", "Integer"),
            ("1.3.6.1.4.1.1466.115.121.1.38", "OID"),
            ("1.3.6.1.4.1.1466.115.121.1.40", "Octet String"),
            ("1.3.6.1.4.1.1466.115.121.1.41", "Postal Address"),
            ("1.3.6.1.4.1.1466.115.121.1.50", "Telephone Number"),
        ];
        for (oid, description) in syntaxes {
            let _ = self.try_add_ldap_syntax(LdapSyntax {
                oid: oid.to_string(),
                description: Some(description.to_string()),
                obsolete: false,
                extensions: BTreeMap::new(),
            });
        }

        let matching_rules = [
            (
                "2.5.13.2",
                "caseIgnoreMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            (
                "2.5.13.5",
                "caseExactMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            (
                "2.5.13.4",
                "caseIgnoreSubstringsMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            (
                "2.5.13.7",
                "caseExactSubstringsMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            ("2.5.13.13", "booleanMatch", "1.3.6.1.4.1.1466.115.121.1.7"),
            ("2.5.13.14", "integerMatch", "1.3.6.1.4.1.1466.115.121.1.27"),
            (
                "2.5.13.15",
                "integerOrderingMatch",
                "1.3.6.1.4.1.1466.115.121.1.27",
            ),
            (
                "2.5.13.27",
                "generalizedTimeMatch",
                "1.3.6.1.4.1.1466.115.121.1.24",
            ),
            (
                "2.5.13.28",
                "generalizedTimeOrderingMatch",
                "1.3.6.1.4.1.1466.115.121.1.24",
            ),
            (
                "2.5.13.1",
                "distinguishedNameMatch",
                "1.3.6.1.4.1.1466.115.121.1.12",
            ),
            (
                "2.5.13.0",
                "objectIdentifierMatch",
                "1.3.6.1.4.1.1466.115.121.1.38",
            ),
            (
                "2.5.13.17",
                "octetStringMatch",
                "1.3.6.1.4.1.1466.115.121.1.40",
            ),
            (
                "1.3.6.1.4.1.1466.109.114.2",
                "caseIgnoreIA5Match",
                "1.3.6.1.4.1.1466.115.121.1.26",
            ),
            (
                "2.5.13.20",
                "telephoneNumberMatch",
                "1.3.6.1.4.1.1466.115.121.1.50",
            ),
            (
                "2.5.13.21",
                "telephoneNumberSubstringsMatch",
                "1.3.6.1.4.1.1466.115.121.1.50",
            ),
        ];
        for (oid, name, syntax) in matching_rules {
            let _ = self.try_add_matching_rule(MatchingRule {
                oid: oid.to_string(),
                names: vec![name.to_string()],
                description: Some(name.to_string()),
                obsolete: false,
                syntax: syntax.to_string(),
                extensions: BTreeMap::new(),
            });
        }
    }

    /// Add an attribute type to the schema
    pub fn add_attribute_type(&mut self, attr: AttributeType) {
        self.add_attribute_type_with_metadata(attr, AttributeTypeMetadata::default());
    }

    fn add_attribute_type_with_metadata(
        &mut self,
        attr: AttributeType,
        metadata: AttributeTypeMetadata,
    ) {
        for name in &attr.names {
            self.attribute_types
                .insert(name.to_lowercase(), attr.clone());
        }
        self.attribute_types_by_oid
            .insert(attr.oid.clone(), attr.clone());
        self.attribute_metadata_by_oid
            .insert(attr.oid.clone(), metadata);
    }

    /// Add an object class to the schema
    pub fn add_object_class(&mut self, oc: ObjectClass) {
        self.add_object_class_with_metadata(oc, SchemaElementMetadata::default());
    }

    fn add_object_class_with_metadata(&mut self, oc: ObjectClass, metadata: SchemaElementMetadata) {
        for name in &oc.names {
            self.object_classes.insert(name.to_lowercase(), oc.clone());
        }
        self.object_classes_by_oid
            .insert(oc.oid.clone(), oc.clone());
        self.object_class_metadata_by_oid
            .insert(oc.oid.clone(), metadata);
    }

    fn set_attribute_substring_rule(&mut self, attr_name: &str, matching_rule: &str) {
        let Some(attribute) = self.get_attribute_type(attr_name) else {
            return;
        };
        let oid = attribute.oid.clone();
        if let Some(metadata) = self.attribute_metadata_by_oid.get_mut(&oid) {
            metadata.substring = Some(matching_rule.to_string());
        }
    }

    /// Get an attribute type by name
    pub fn get_attribute_type(&self, name: &str) -> Option<&AttributeType> {
        self.attribute_types
            .get(&name.to_lowercase())
            .or_else(|| self.attribute_types_by_oid.get(name))
    }

    /// Get an object class by name
    pub fn get_object_class(&self, name: &str) -> Option<&ObjectClass> {
        self.object_classes
            .get(&name.to_lowercase())
            .or_else(|| self.object_classes_by_oid.get(name))
    }

    pub fn get_attribute_metadata(&self, name: &str) -> Option<&AttributeTypeMetadata> {
        self.get_attribute_type(name)
            .and_then(|attribute| self.attribute_metadata_by_oid.get(&attribute.oid))
    }

    pub fn get_matching_rule(&self, name_or_oid: &str) -> Option<&MatchingRule> {
        self.matching_rules
            .get(&name_or_oid.to_lowercase())
            .or_else(|| self.matching_rules_by_oid.get(name_or_oid))
    }

    pub fn resolve_matching_rule(
        &self,
        name_or_oid: &str,
    ) -> Result<ResolvedMatchingRule, MatchingRuleError> {
        self.get_matching_rule(name_or_oid)
            .map(resolved_matching_rule)
            .ok_or_else(|| MatchingRuleError::MatchingRuleNotFound(name_or_oid.to_string()))
    }

    pub fn resolve_attribute_matching_profile(
        &self,
        name_or_oid: &str,
    ) -> Result<AttributeMatchingProfile, MatchingRuleError> {
        let attribute = self
            .get_attribute_type(name_or_oid)
            .ok_or_else(|| MatchingRuleError::AttributeNotFound(name_or_oid.to_string()))?;
        let effective = self.resolve_effective_attribute(attribute, &mut HashSet::new())?;
        Ok(AttributeMatchingProfile {
            oid: effective.oid,
            names: effective.names,
            syntax_oid: effective.syntax_oid,
            syntax_length: effective.syntax_length,
            single_value: effective.single_value,
            obsolete: effective.obsolete,
            no_user_modification: effective.no_user_modification,
            superior_chain: effective.superior_chain,
            equality: effective
                .equality
                .as_deref()
                .map(|rule| self.resolve_matching_rule(rule))
                .transpose()?,
            ordering: effective
                .ordering
                .as_deref()
                .map(|rule| self.resolve_matching_rule(rule))
                .transpose()?,
            substring: effective
                .substring
                .as_deref()
                .map(|rule| self.resolve_matching_rule(rule))
                .transpose()?,
        })
    }

    pub fn matching_rule_for_attribute(
        &self,
        attribute: &str,
        use_kind: AttributeMatchingUse,
    ) -> Result<ResolvedMatchingRule, MatchingRuleError> {
        let profile = self.resolve_attribute_matching_profile(attribute)?;
        profile
            .rule_for_use(use_kind)
            .cloned()
            .ok_or_else(|| MatchingRuleError::NoMatchingRule {
                attribute: attribute.to_string(),
                use_kind,
            })
    }

    pub fn equality_rule_for_attribute(
        &self,
        attribute: &str,
    ) -> Result<ResolvedMatchingRule, MatchingRuleError> {
        self.matching_rule_for_attribute(attribute, AttributeMatchingUse::Equality)
    }

    pub fn ordering_rule_for_attribute(
        &self,
        attribute: &str,
    ) -> Result<ResolvedMatchingRule, MatchingRuleError> {
        self.matching_rule_for_attribute(attribute, AttributeMatchingUse::Ordering)
    }

    pub fn substring_rule_for_attribute(
        &self,
        attribute: &str,
    ) -> Result<ResolvedMatchingRule, MatchingRuleError> {
        self.matching_rule_for_attribute(attribute, AttributeMatchingUse::Substring)
    }

    pub fn matching_rule_applies_to_attribute(
        &self,
        rule_name_or_oid: &str,
        attribute: &str,
    ) -> Result<ResolvedMatchingRule, MatchingRuleError> {
        let rule = self.resolve_matching_rule(rule_name_or_oid)?;
        let profile = self.resolve_attribute_matching_profile(attribute)?;
        if profile
            .rule_for_use(AttributeMatchingUse::Equality)
            .into_iter()
            .chain(profile.rule_for_use(AttributeMatchingUse::Ordering))
            .chain(profile.rule_for_use(AttributeMatchingUse::Substring))
            .any(|candidate| matching_rules_are_same(candidate, &rule))
        {
            return Ok(rule);
        }

        let rule_use_applies = self
            .matching_rule_uses_by_oid
            .get(&rule.oid)
            .or_else(|| {
                rule.names
                    .iter()
                    .find_map(|name| self.matching_rule_uses.get(&name.to_lowercase()))
            })
            .is_some_and(|rule_use| {
                rule_use.applies.iter().any(|applies| {
                    applies.eq_ignore_ascii_case(attribute)
                        || applies.eq_ignore_ascii_case(&profile.oid)
                        || profile
                            .names
                            .iter()
                            .any(|name| applies.eq_ignore_ascii_case(name))
                })
            });
        if rule_use_applies || base_syntax_oid(&rule.syntax) == base_syntax_oid(&profile.syntax_oid)
        {
            return Ok(rule);
        }

        Err(MatchingRuleError::InapplicableRule {
            rule: rule.label().to_string(),
            attribute: attribute.to_string(),
        })
    }

    /// Return unique attribute types keyed by OID, sorted for stable publication.
    pub fn attribute_types_unique_sorted(&self) -> Vec<AttributeType> {
        let mut attributes = self
            .attribute_types_by_oid
            .values()
            .cloned()
            .collect::<Vec<_>>();
        attributes.sort_by(|left, right| left.oid.cmp(&right.oid));
        attributes
    }

    /// Return unique object classes keyed by OID, sorted for stable publication.
    pub fn object_classes_unique_sorted(&self) -> Vec<ObjectClass> {
        let mut object_classes = self
            .object_classes_by_oid
            .values()
            .cloned()
            .collect::<Vec<_>>();
        object_classes.sort_by(|left, right| left.oid.cmp(&right.oid));
        object_classes
    }

    pub fn attribute_type_descriptions_unique_sorted(&self) -> Vec<String> {
        self.attribute_types_unique_sorted()
            .into_iter()
            .map(|attribute| {
                let metadata = self.attribute_metadata_by_oid.get(&attribute.oid);
                attribute.to_schema_description_with_metadata(metadata)
            })
            .collect()
    }

    pub fn object_class_descriptions_unique_sorted(&self) -> Vec<String> {
        self.object_classes_unique_sorted()
            .into_iter()
            .map(|object_class| {
                let metadata = self.object_class_metadata_by_oid.get(&object_class.oid);
                object_class.to_schema_description_with_metadata(metadata)
            })
            .collect()
    }

    pub fn ldap_syntax_descriptions_unique_sorted(&self) -> Vec<String> {
        let mut values = self.ldap_syntaxes.values().collect::<Vec<_>>();
        values.sort_by(|left, right| left.oid.cmp(&right.oid));
        values
            .into_iter()
            .map(LdapSyntax::to_schema_description)
            .collect()
    }

    pub fn matching_rule_descriptions_unique_sorted(&self) -> Vec<String> {
        let mut values = self.matching_rules_by_oid.values().collect::<Vec<_>>();
        values.sort_by(|left, right| left.oid.cmp(&right.oid));
        values
            .into_iter()
            .map(MatchingRule::to_schema_description)
            .collect()
    }

    pub fn matching_rule_use_descriptions_unique_sorted(&self) -> Vec<String> {
        let mut values = self.matching_rule_uses_by_oid.values().collect::<Vec<_>>();
        values.sort_by(|left, right| left.oid.cmp(&right.oid));
        values
            .into_iter()
            .map(MatchingRuleUse::to_schema_description)
            .collect()
    }

    pub fn dit_content_rule_descriptions_unique_sorted(&self) -> Vec<String> {
        let mut values = self.dit_content_rules.values().collect::<Vec<_>>();
        values.sort_by(|left, right| left.oid.cmp(&right.oid));
        values
            .into_iter()
            .map(DitContentRule::to_schema_description)
            .collect()
    }

    pub fn name_form_descriptions_unique_sorted(&self) -> Vec<String> {
        let mut values = self.name_forms_by_oid.values().collect::<Vec<_>>();
        values.sort_by(|left, right| left.oid.cmp(&right.oid));
        values
            .into_iter()
            .map(NameForm::to_schema_description)
            .collect()
    }

    pub fn dit_structure_rule_descriptions_unique_sorted(&self) -> Vec<String> {
        let mut values = self.dit_structure_rules.values().collect::<Vec<_>>();
        values.sort_by_key(|rule| rule.rule_id);
        values
            .into_iter()
            .map(DitStructureRule::to_schema_description)
            .collect()
    }

    pub fn explain(&self, name_or_oid: &str) -> Option<String> {
        self.get_attribute_type(name_or_oid)
            .map(|attribute| {
                attribute.to_schema_description_with_metadata(
                    self.attribute_metadata_by_oid.get(&attribute.oid),
                )
            })
            .or_else(|| {
                self.get_object_class(name_or_oid).map(|object_class| {
                    object_class.to_schema_description_with_metadata(
                        self.object_class_metadata_by_oid.get(&object_class.oid),
                    )
                })
            })
            .or_else(|| {
                self.ldap_syntaxes
                    .get(name_or_oid)
                    .map(LdapSyntax::to_schema_description)
            })
            .or_else(|| {
                self.matching_rules
                    .get(&name_or_oid.to_lowercase())
                    .or_else(|| self.matching_rules_by_oid.get(name_or_oid))
                    .map(MatchingRule::to_schema_description)
            })
            .or_else(|| {
                self.matching_rule_uses
                    .get(&name_or_oid.to_lowercase())
                    .or_else(|| self.matching_rule_uses_by_oid.get(name_or_oid))
                    .map(MatchingRuleUse::to_schema_description)
            })
            .or_else(|| {
                self.dit_content_rules
                    .get(name_or_oid)
                    .map(DitContentRule::to_schema_description)
            })
            .or_else(|| {
                self.name_forms
                    .get(&name_or_oid.to_lowercase())
                    .or_else(|| self.name_forms_by_oid.get(name_or_oid))
                    .map(NameForm::to_schema_description)
            })
            .or_else(|| {
                name_or_oid
                    .parse::<u32>()
                    .ok()
                    .and_then(|rule_id| self.dit_structure_rules.get(&rule_id))
                    .map(DitStructureRule::to_schema_description)
            })
    }

    pub fn load_schema_dir(&mut self, schema_dir: impl AsRef<Path>) -> Result<(), SchemaError> {
        let schema_dir = schema_dir.as_ref();
        if !schema_dir.exists() {
            return Ok(());
        }
        let mut files = fs::read_dir(schema_dir)
            .map_err(|err| SchemaError::IoError(format!("{}: {}", schema_dir.display(), err)))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.is_file()
                    && path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| {
                            extension.eq_ignore_ascii_case("ldif")
                                || extension.eq_ignore_ascii_case("schema")
                                || extension.eq_ignore_ascii_case("conf")
                        })
            })
            .collect::<Vec<PathBuf>>();
        files.sort();

        for file in files {
            self.load_schema_file(&file)?;
        }
        self.validate_schema_dependencies()
    }

    pub fn load_schema_file(&mut self, path: impl AsRef<Path>) -> Result<(), SchemaError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .map_err(|err| SchemaError::IoError(format!("{}: {}", path.display(), err)))?;
        self.load_ldif_str(&contents)
            .map_err(|err| SchemaError::ParseError(format!("{}: {}", path.display(), err)))
    }

    pub fn load_ldif_str(&mut self, contents: &str) -> Result<(), SchemaError> {
        let lines = unfold_ldif_lines(contents)?;
        let mut raw_schema_statement = String::new();

        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.eq_ignore_ascii_case("version: 1")
                || trimmed.to_ascii_lowercase().starts_with("dn:")
            {
                continue;
            }

            if trimmed.starts_with("attributetype ") || trimmed.starts_with("attributeType ") {
                raw_schema_statement = trimmed.to_string();
                if trimmed.ends_with(')') {
                    self.load_schema_statement(&raw_schema_statement)?;
                    raw_schema_statement.clear();
                }
                continue;
            }
            if trimmed.starts_with("objectclass ") || trimmed.starts_with("objectClass ") {
                raw_schema_statement = trimmed.to_string();
                if trimmed.ends_with(')') {
                    self.load_schema_statement(&raw_schema_statement)?;
                    raw_schema_statement.clear();
                }
                continue;
            }
            if !raw_schema_statement.is_empty() {
                raw_schema_statement.push(' ');
                raw_schema_statement.push_str(trimmed);
                if trimmed.ends_with(')') {
                    self.load_schema_statement(&raw_schema_statement)?;
                    raw_schema_statement.clear();
                }
                continue;
            }

            let Some((name, value)) = parse_ldif_attrval(&line)? else {
                continue;
            };
            self.load_schema_attr_value(&name, &value)?;
        }

        if !raw_schema_statement.is_empty() {
            self.load_schema_statement(&raw_schema_statement)?;
        }

        self.validate_schema_dependencies()
    }

    fn load_schema_statement(&mut self, statement: &str) -> Result<(), SchemaError> {
        let Some((name, value)) = statement.split_once(char::is_whitespace) else {
            return Err(SchemaError::ParseError(format!(
                "schema statement has no value: {}",
                statement
            )));
        };
        self.load_schema_attr_value(name, value.trim())
    }

    fn load_schema_attr_value(&mut self, name: &str, value: &str) -> Result<(), SchemaError> {
        let normalized_name = normalize_schema_attr_name(name);
        if canonical_schema_attr_name(name).is_some() && !value.trim_start().starts_with('(') {
            return Ok(());
        }
        match normalized_name.as_str() {
            "attributetypes" | "attributetype" => {
                let parsed = parse_attribute_type_description(value)?;
                self.try_add_attribute_type_with_metadata(parsed.attribute_type, parsed.metadata)
            }
            "objectclasses" | "objectclass" => {
                let parsed = parse_object_class_description(value)?;
                self.try_add_object_class_with_metadata(parsed.object_class, parsed.metadata)
            }
            "ldapsyntaxes" | "ldapsyntax" => {
                self.try_add_ldap_syntax(parse_ldap_syntax_description(value)?)
            }
            "matchingrules" | "matchingrule" => {
                self.try_add_matching_rule(parse_matching_rule_description(value)?)
            }
            "matchingruleuse" | "matchingruleuses" => {
                self.try_add_matching_rule_use(parse_matching_rule_use_description(value)?)
            }
            "ditcontentrules" | "ditcontentrule" => {
                self.try_add_dit_content_rule(parse_dit_content_rule_description(value)?)
            }
            "nameforms" | "nameform" => self.try_add_name_form(parse_name_form_description(value)?),
            "ditstructurerules" | "ditstructurerule" => {
                self.try_add_dit_structure_rule(parse_dit_structure_rule_description(value)?)
            }
            _ => Ok(()),
        }
    }

    pub fn apply_schema_attr_value(&mut self, name: &str, value: &str) -> Result<(), SchemaError> {
        self.load_schema_attr_value(name, value)
    }

    pub fn remove_schema_attr_value(&mut self, name: &str, value: &str) -> Result<(), SchemaError> {
        let Some(canonical_name) = canonical_schema_attr_name(name) else {
            return Err(SchemaError::ParseError(format!(
                "unsupported schema attribute: {}",
                name
            )));
        };
        match canonical_name {
            "attributeTypes" => {
                let parsed = parse_attribute_type_description(value)?;
                let Some(attribute) = self
                    .attribute_types_by_oid
                    .remove(&parsed.attribute_type.oid)
                else {
                    return Err(SchemaError::AttributeNotFound(parsed.attribute_type.oid));
                };
                self.attribute_metadata_by_oid.remove(&attribute.oid);
                for name in attribute.names {
                    self.attribute_types.remove(&name.to_lowercase());
                }
            }
            "objectClasses" => {
                let parsed = parse_object_class_description(value)?;
                let Some(object_class) =
                    self.object_classes_by_oid.remove(&parsed.object_class.oid)
                else {
                    return Err(SchemaError::ObjectClassNotFound(parsed.object_class.oid));
                };
                self.object_class_metadata_by_oid.remove(&object_class.oid);
                for name in object_class.names {
                    self.object_classes.remove(&name.to_lowercase());
                }
            }
            "ldapSyntaxes" => {
                let syntax = parse_ldap_syntax_description(value)?;
                if self.ldap_syntaxes.remove(&syntax.oid).is_none() {
                    return Err(SchemaError::AttributeNotFound(syntax.oid));
                }
            }
            "matchingRules" => {
                let rule = parse_matching_rule_description(value)?;
                let Some(rule) = self.matching_rules_by_oid.remove(&rule.oid) else {
                    return Err(SchemaError::AttributeNotFound(rule.oid));
                };
                for name in rule.names {
                    self.matching_rules.remove(&name.to_lowercase());
                }
            }
            "matchingRuleUse" => {
                let rule_use = parse_matching_rule_use_description(value)?;
                let Some(rule_use) = self.matching_rule_uses_by_oid.remove(&rule_use.oid) else {
                    return Err(SchemaError::AttributeNotFound(rule_use.oid));
                };
                for name in rule_use.names {
                    self.matching_rule_uses.remove(&name.to_lowercase());
                }
            }
            "dITContentRules" => {
                let rule = parse_dit_content_rule_description(value)?;
                if self.dit_content_rules.remove(&rule.oid).is_none() {
                    return Err(SchemaError::AttributeNotFound(rule.oid));
                }
            }
            "nameForms" => {
                let name_form = parse_name_form_description(value)?;
                let Some(name_form) = self.name_forms_by_oid.remove(&name_form.oid) else {
                    return Err(SchemaError::AttributeNotFound(name_form.oid));
                };
                for name in name_form.names {
                    self.name_forms.remove(&name.to_lowercase());
                }
            }
            "dITStructureRules" => {
                let rule = parse_dit_structure_rule_description(value)?;
                if self.dit_structure_rules.remove(&rule.rule_id).is_none() {
                    return Err(SchemaError::AttributeNotFound(rule.rule_id.to_string()));
                }
            }
            _ => unreachable!("schema_definition_key only returns schema attributes"),
        }
        Ok(())
    }

    pub fn parse_schema_ldif_values(
        contents: &str,
    ) -> Result<BTreeMap<String, Vec<String>>, SchemaError> {
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in unfold_ldif_lines(contents)? {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.eq_ignore_ascii_case("version: 1")
                || trimmed.to_ascii_lowercase().starts_with("dn:")
            {
                continue;
            }
            let Some((name, value)) = parse_ldif_attrval(&line)? else {
                continue;
            };
            if let Some(canonical_name) = canonical_schema_attr_name(&name) {
                values
                    .entry(canonical_name.to_string())
                    .or_default()
                    .push(value);
            }
        }
        Ok(values)
    }

    fn try_add_attribute_type_with_metadata(
        &mut self,
        attr: AttributeType,
        metadata: AttributeTypeMetadata,
    ) -> Result<(), SchemaError> {
        if self.attribute_types_by_oid.contains_key(&attr.oid) {
            return Err(SchemaError::DuplicateOid(attr.oid));
        }
        for name in &attr.names {
            let normalized = name.to_lowercase();
            if self.attribute_types.contains_key(&normalized) {
                return Err(SchemaError::DuplicateName(name.clone()));
            }
        }
        self.add_attribute_type_with_metadata(attr, metadata);
        Ok(())
    }

    fn try_add_object_class_with_metadata(
        &mut self,
        object_class: ObjectClass,
        metadata: SchemaElementMetadata,
    ) -> Result<(), SchemaError> {
        if self.object_classes_by_oid.contains_key(&object_class.oid) {
            return Err(SchemaError::DuplicateOid(object_class.oid));
        }
        for name in &object_class.names {
            let normalized = name.to_lowercase();
            if self.object_classes.contains_key(&normalized) {
                return Err(SchemaError::DuplicateName(name.clone()));
            }
        }
        self.add_object_class_with_metadata(object_class, metadata);
        Ok(())
    }

    fn try_add_ldap_syntax(&mut self, syntax: LdapSyntax) -> Result<(), SchemaError> {
        if self.ldap_syntaxes.contains_key(&syntax.oid) {
            return Err(SchemaError::DuplicateOid(syntax.oid));
        }
        self.ldap_syntaxes.insert(syntax.oid.clone(), syntax);
        Ok(())
    }

    fn try_add_matching_rule(&mut self, rule: MatchingRule) -> Result<(), SchemaError> {
        if self.matching_rules_by_oid.contains_key(&rule.oid) {
            return Err(SchemaError::DuplicateOid(rule.oid));
        }
        for name in &rule.names {
            let normalized = name.to_lowercase();
            if self.matching_rules.contains_key(&normalized) {
                return Err(SchemaError::DuplicateName(name.clone()));
            }
        }
        for name in &rule.names {
            self.matching_rules
                .insert(name.to_lowercase(), rule.clone());
        }
        self.matching_rules_by_oid.insert(rule.oid.clone(), rule);
        Ok(())
    }

    fn try_add_matching_rule_use(&mut self, rule_use: MatchingRuleUse) -> Result<(), SchemaError> {
        if self.matching_rule_uses_by_oid.contains_key(&rule_use.oid) {
            return Err(SchemaError::DuplicateOid(rule_use.oid));
        }
        for name in &rule_use.names {
            self.matching_rule_uses
                .insert(name.to_lowercase(), rule_use.clone());
        }
        self.matching_rule_uses_by_oid
            .insert(rule_use.oid.clone(), rule_use);
        Ok(())
    }

    fn try_add_dit_content_rule(&mut self, rule: DitContentRule) -> Result<(), SchemaError> {
        if self.dit_content_rules.contains_key(&rule.oid) {
            return Err(SchemaError::DuplicateOid(rule.oid));
        }
        self.dit_content_rules.insert(rule.oid.clone(), rule);
        Ok(())
    }

    fn try_add_name_form(&mut self, name_form: NameForm) -> Result<(), SchemaError> {
        if self.name_forms_by_oid.contains_key(&name_form.oid) {
            return Err(SchemaError::DuplicateOid(name_form.oid));
        }
        for name in &name_form.names {
            let normalized = name.to_lowercase();
            if self.name_forms.contains_key(&normalized) {
                return Err(SchemaError::DuplicateName(name.clone()));
            }
        }
        for name in &name_form.names {
            self.name_forms
                .insert(name.to_lowercase(), name_form.clone());
        }
        self.name_forms_by_oid
            .insert(name_form.oid.clone(), name_form);
        Ok(())
    }

    fn try_add_dit_structure_rule(&mut self, rule: DitStructureRule) -> Result<(), SchemaError> {
        if self.dit_structure_rules.contains_key(&rule.rule_id) {
            return Err(SchemaError::DuplicateOid(rule.rule_id.to_string()));
        }
        self.dit_structure_rules.insert(rule.rule_id, rule);
        Ok(())
    }

    fn resolve_effective_attribute(
        &self,
        attribute: &AttributeType,
        seen: &mut HashSet<String>,
    ) -> Result<EffectiveAttributeType, MatchingRuleError> {
        if !seen.insert(attribute.oid.clone()) {
            return Err(MatchingRuleError::MissingDependency(format!(
                "cyclic attribute SUP chain at {}",
                attribute
                    .names
                    .first()
                    .map(String::as_str)
                    .unwrap_or(&attribute.oid)
            )));
        }

        let metadata = self
            .attribute_metadata_by_oid
            .get(&attribute.oid)
            .cloned()
            .unwrap_or_default();
        let mut effective = EffectiveAttributeType {
            oid: attribute.oid.clone(),
            names: attribute.names.clone(),
            syntax_oid: attribute.syntax.clone(),
            syntax_length: metadata.syntax_length,
            single_value: attribute.single_value,
            obsolete: metadata.obsolete,
            no_user_modification: metadata.no_user_modification,
            equality: attribute.equality.clone(),
            ordering: metadata.ordering.clone(),
            substring: metadata.substring.clone(),
            superior_chain: Vec::new(),
        };

        if let Some(superior_name) = metadata.superior.as_deref() {
            let superior = self.get_attribute_type(superior_name).ok_or_else(|| {
                MatchingRuleError::MissingDependency(format!(
                    "attribute {} references unknown superior {}",
                    attribute
                        .names
                        .first()
                        .map(String::as_str)
                        .unwrap_or(&attribute.oid),
                    superior_name
                ))
            })?;
            let parent = self.resolve_effective_attribute(superior, seen)?;
            if effective.syntax_oid.is_empty() {
                effective.syntax_oid = parent.syntax_oid;
            }
            if effective.syntax_length.is_none() {
                effective.syntax_length = parent.syntax_length;
            }
            if effective.equality.is_none() {
                effective.equality = parent.equality;
            }
            if effective.ordering.is_none() {
                effective.ordering = parent.ordering;
            }
            if effective.substring.is_none() {
                effective.substring = parent.substring;
            }
            effective.single_value |= parent.single_value;
            effective.no_user_modification |= parent.no_user_modification;
            effective.superior_chain = parent.superior_chain;
            effective.superior_chain.push(superior.oid.clone());
        }

        seen.remove(&attribute.oid);
        Ok(effective)
    }

    pub fn validate_schema_dependencies(&self) -> Result<(), SchemaError> {
        for attribute in self.attribute_types_by_oid.values() {
            if !attribute.syntax.is_empty()
                && !self.ldap_syntaxes.is_empty()
                && !self
                    .ldap_syntaxes
                    .contains_key(base_syntax_oid(&attribute.syntax))
            {
                return Err(SchemaError::MissingDependency(format!(
                    "attribute {} references unknown syntax {}",
                    attribute
                        .names
                        .first()
                        .map(String::as_str)
                        .unwrap_or(&attribute.oid),
                    attribute.syntax
                )));
            }
            let Some(metadata) = self.attribute_metadata_by_oid.get(&attribute.oid) else {
                continue;
            };
            if let Some(superior) = metadata.superior.as_deref()
                && self.get_attribute_type(superior).is_none()
            {
                return Err(SchemaError::MissingDependency(format!(
                    "attribute {} references unknown superior {}",
                    attribute
                        .names
                        .first()
                        .map(String::as_str)
                        .unwrap_or(&attribute.oid),
                    superior
                )));
            }
            for matching_rule in attribute
                .equality
                .iter()
                .chain(metadata.ordering.iter())
                .chain(metadata.substring.iter())
            {
                if self.get_matching_rule(matching_rule).is_none() {
                    return Err(SchemaError::MissingDependency(format!(
                        "attribute {} references unknown matching rule {}",
                        attribute
                            .names
                            .first()
                            .map(String::as_str)
                            .unwrap_or(&attribute.oid),
                        matching_rule
                    )));
                }
            }
        }

        for object_class in self.object_classes_by_oid.values() {
            for superior in &object_class.sup {
                if self.get_object_class(superior).is_none() {
                    return Err(SchemaError::MissingDependency(format!(
                        "object class {} references unknown superior {}",
                        object_class
                            .names
                            .first()
                            .map(String::as_str)
                            .unwrap_or(&object_class.oid),
                        superior
                    )));
                }
            }
            for attribute in object_class.must.iter().chain(object_class.may.iter()) {
                if self.get_attribute_type(attribute).is_none() {
                    return Err(SchemaError::MissingDependency(format!(
                        "object class {} references unknown attribute {}",
                        object_class
                            .names
                            .first()
                            .map(String::as_str)
                            .unwrap_or(&object_class.oid),
                        attribute
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate an entry against the schema
    pub fn validate_entry(
        &self,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<(), SchemaError> {
        // Get object classes
        let object_classes = attributes
            .get("objectclass")
            .or_else(|| attributes.get("objectClass"))
            .ok_or(SchemaError::MissingRequiredAttribute(
                "objectClass".to_string(),
            ))?;

        // Validate object classes exist
        let mut oc_definitions = Vec::new();
        for oc_name in object_classes {
            let oc = self
                .get_object_class(oc_name)
                .ok_or_else(|| SchemaError::ObjectClassNotFound(oc_name.clone()))?;
            if self
                .object_class_metadata_by_oid
                .get(&oc.oid)
                .is_some_and(|metadata| metadata.obsolete)
            {
                return Err(SchemaError::ObsoleteObjectClass(oc_name.clone()));
            }
            oc_definitions.push(oc);
        }

        // Validate structural object class rules
        self.validate_structural_classes(&oc_definitions)?;

        // Collect all required and allowed attributes
        let (must_attrs, may_attrs) = self.collect_attributes(&oc_definitions);

        // Validate required attributes are present
        for must_attr in &must_attrs {
            let attr_lower = must_attr.to_lowercase();
            let found = attributes.keys().any(|k| k.to_lowercase() == attr_lower);
            if !found {
                return Err(SchemaError::MissingRequiredAttribute(must_attr.clone()));
            }
        }

        // Validate all attributes are allowed
        let all_allowed: HashSet<String> = must_attrs
            .iter()
            .chain(may_attrs.iter())
            .map(|s| s.to_lowercase())
            .collect();

        for attr_name in attributes.keys() {
            let attr_lower = attr_name.to_lowercase();
            if !all_allowed.contains(&attr_lower) {
                // Check if attribute exists in schema
                if self.get_attribute_type(attr_name).is_none() {
                    return Err(SchemaError::AttributeNotFound(attr_name.clone()));
                }
                return Err(SchemaError::AttributeNotAllowed(attr_name.clone()));
            }
        }

        // Validate single-value constraints
        for (attr_name, values) in attributes {
            if let Some(attr_type) = self.get_attribute_type(attr_name) {
                if self
                    .attribute_metadata_by_oid
                    .get(&attr_type.oid)
                    .is_some_and(|metadata| metadata.obsolete)
                {
                    return Err(SchemaError::ObsoleteAttributeType(attr_name.clone()));
                }
                if self
                    .attribute_metadata_by_oid
                    .get(&attr_type.oid)
                    .is_some_and(|metadata| metadata.no_user_modification)
                {
                    return Err(SchemaError::NoUserModification(attr_name.clone()));
                }
                if attr_type.single_value && values.len() > 1 {
                    return Err(SchemaError::SingleValueViolation(attr_name.clone()));
                }
                for value in values {
                    self.validate_attribute_syntax(attr_type, attr_name, value)?;
                }
            }
        }

        self.validate_dit_content_rules(&oc_definitions, attributes)?;

        Ok(())
    }

    pub fn validate_modified_entry(
        &self,
        original: &HashMap<String, Vec<String>>,
        modified: &HashMap<String, Vec<String>>,
    ) -> Result<(), SchemaError> {
        self.validate_entry(original)?;
        self.validate_entry(modified)?;

        let original_structural = self.structural_class_names(original)?;
        let modified_structural = self.structural_class_names(modified)?;
        if original_structural != modified_structural {
            return Err(SchemaError::InvalidStructuralChain);
        }

        Ok(())
    }

    pub fn validate_rdn_for_entry(
        &self,
        attributes: &HashMap<String, Vec<String>>,
        new_rdn: &str,
    ) -> Result<(), SchemaError> {
        let rdn = parse_rdn(new_rdn)
            .map_err(|err| SchemaError::NamingViolation(format!("Invalid RDN syntax: {}", err)))?;
        for ava in rdn.avas() {
            if self.get_attribute_type(ava.attribute()).is_none() {
                return Err(SchemaError::AttributeNotFound(ava.attribute().to_string()));
            }
        }
        let rdn_attr = rdn
            .avas()
            .first()
            .map(|ava| ava.attribute())
            .ok_or_else(|| SchemaError::NamingViolation("RDN must not be empty".to_string()))?;

        let object_classes = attributes
            .get("objectclass")
            .or_else(|| attributes.get("objectClass"))
            .ok_or(SchemaError::MissingRequiredAttribute(
                "objectClass".to_string(),
            ))?;
        let structural = self.structural_class_names(attributes)?;
        let Some(leaf_structural) = structural.last() else {
            return Err(SchemaError::NoStructuralClass);
        };

        for name_form in self.name_forms_by_oid.values() {
            if self
                .get_object_class(&name_form.object_class)
                .is_some_and(|object_class| {
                    object_class.names[0].eq_ignore_ascii_case(leaf_structural)
                })
                || object_classes
                    .iter()
                    .any(|object_class| object_class.eq_ignore_ascii_case(&name_form.object_class))
            {
                let rdn_lower = rdn_attr.to_lowercase();
                if !name_form
                    .must
                    .iter()
                    .chain(name_form.may.iter())
                    .any(|candidate| candidate.eq_ignore_ascii_case(&rdn_lower))
                {
                    return Err(SchemaError::NamingViolation(format!(
                        "RDN attribute {} is not allowed by name form {}",
                        rdn_attr,
                        name_form
                            .names
                            .first()
                            .map(String::as_str)
                            .unwrap_or(&name_form.oid)
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate structural object class rules
    fn validate_structural_classes(
        &self,
        oc_definitions: &[&ObjectClass],
    ) -> Result<(), SchemaError> {
        let structural: Vec<_> = oc_definitions
            .iter()
            .filter(|oc| oc.kind == ObjectClassKind::Structural)
            .collect();

        // Must have at least one structural class
        if structural.is_empty() {
            return Err(SchemaError::NoStructuralClass);
        }

        // If multiple structural classes, they must be in a valid inheritance chain
        if structural.len() > 1 {
            // Build inheritance graph
            let mut all_sups = HashSet::new();
            for oc in &structural {
                self.collect_superior_classes(&oc.names[0], &mut all_sups);
            }

            // Each structural class (except one) must be a superior of another
            let mut has_root = false;
            for oc in &structural {
                let is_sup_of_another = structural
                    .iter()
                    .any(|other| oc.names[0] != other.names[0] && all_sups.contains(&oc.names[0]));

                if !is_sup_of_another && !has_root {
                    has_root = true;
                } else if !is_sup_of_another && has_root {
                    return Err(SchemaError::MultipleStructuralClasses);
                }
            }
        }

        Ok(())
    }

    fn structural_class_names(
        &self,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<String>, SchemaError> {
        let object_classes = attributes
            .get("objectclass")
            .or_else(|| attributes.get("objectClass"))
            .ok_or(SchemaError::MissingRequiredAttribute(
                "objectClass".to_string(),
            ))?;

        let mut structural = object_classes
            .iter()
            .filter_map(|object_class| self.get_object_class(object_class))
            .filter(|object_class| object_class.kind == ObjectClassKind::Structural)
            .map(|object_class| object_class.names[0].to_lowercase())
            .collect::<Vec<_>>();
        structural.sort();
        Ok(structural)
    }

    fn validate_dit_content_rules(
        &self,
        oc_definitions: &[&ObjectClass],
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<(), SchemaError> {
        let structural = oc_definitions
            .iter()
            .find(|object_class| object_class.kind == ObjectClassKind::Structural);
        let Some(structural) = structural else {
            return Ok(());
        };
        let Some(rule) = self.dit_content_rules.get(&structural.oid) else {
            return Ok(());
        };
        if rule.obsolete {
            return Err(SchemaError::DitContentRuleViolation(format!(
                "content rule for {} is obsolete",
                structural.names[0]
            )));
        }

        let object_classes = attributes
            .get("objectclass")
            .or_else(|| attributes.get("objectClass"))
            .ok_or(SchemaError::MissingRequiredAttribute(
                "objectClass".to_string(),
            ))?;
        for object_class in object_classes {
            if let Some(definition) = self.get_object_class(object_class)
                && definition.kind == ObjectClassKind::Auxiliary
                && !rule
                    .auxiliary
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(object_class))
            {
                return Err(SchemaError::DitContentRuleViolation(format!(
                    "auxiliary class {} is not allowed by content rule {}",
                    object_class,
                    rule.names.first().map(String::as_str).unwrap_or(&rule.oid)
                )));
            }
        }

        for must_attr in &rule.must {
            let attr_lower = must_attr.to_lowercase();
            if !attributes
                .keys()
                .any(|name| name.to_lowercase() == attr_lower)
            {
                return Err(SchemaError::MissingRequiredAttribute(must_attr.clone()));
            }
        }

        for prohibited in &rule.not {
            let attr_lower = prohibited.to_lowercase();
            if attributes
                .keys()
                .any(|name| name.to_lowercase() == attr_lower)
            {
                return Err(SchemaError::DitContentRuleViolation(format!(
                    "attribute {} is prohibited",
                    prohibited
                )));
            }
        }

        Ok(())
    }

    fn validate_attribute_syntax(
        &self,
        attr_type: &AttributeType,
        attr_name: &str,
        value: &str,
    ) -> Result<(), SchemaError> {
        let effective = self
            .resolve_effective_attribute(attr_type, &mut HashSet::new())
            .map_err(|err| SchemaError::InvalidSyntax(attr_name.to_string(), err.to_string()))?;
        let (declared_syntax_oid, inline_length) =
            parse_syntax_with_optional_length(&effective.syntax_oid)?;
        let syntax_length = effective.syntax_length.or(inline_length);

        if let Some(max_chars) = syntax_length
            && value.chars().count() > max_chars
        {
            return Err(SchemaError::InvalidSyntax(
                attr_name.to_string(),
                format!(
                    "value length {} exceeds syntax bound {} for {}",
                    value.chars().count(),
                    max_chars,
                    effective.syntax_oid
                ),
            ));
        }

        validate_ldap_syntax_value(&declared_syntax_oid, value).map_err(|reason| {
            SchemaError::InvalidSyntax(
                attr_name.to_string(),
                format!(
                    "value does not conform to syntax {}: {}",
                    effective.syntax_oid, reason
                ),
            )
        })
    }

    /// Collect all superior class names recursively
    fn collect_superior_classes(&self, oc_name: &str, result: &mut HashSet<String>) {
        if let Some(oc) = self.get_object_class(oc_name) {
            for sup in &oc.sup {
                result.insert(sup.clone());
                self.collect_superior_classes(sup, result);
            }
        }
    }

    /// Collect all required and optional attributes from object classes
    fn collect_attributes(
        &self,
        oc_definitions: &[&ObjectClass],
    ) -> (HashSet<String>, HashSet<String>) {
        let mut must = HashSet::new();
        let mut may = HashSet::new();

        for oc in oc_definitions {
            // Add direct attributes
            must.extend(oc.must.iter().cloned());
            may.extend(oc.may.iter().cloned());

            // Add attributes from superior classes
            self.collect_superior_attributes(oc, &mut must, &mut may);
        }

        (must, may)
    }

    /// Recursively collect attributes from superior classes
    fn collect_superior_attributes(
        &self,
        oc: &ObjectClass,
        must: &mut HashSet<String>,
        may: &mut HashSet<String>,
    ) {
        for sup_name in &oc.sup {
            if let Some(sup) = self.get_object_class(sup_name) {
                must.extend(sup.must.iter().cloned());
                may.extend(sup.may.iter().cloned());
                self.collect_superior_attributes(sup, must, may);
            }
        }
    }
}

impl AttributeType {
    pub fn to_schema_description(&self) -> String {
        self.to_schema_description_with_metadata(None)
    }

    pub fn to_schema_description_with_metadata(
        &self,
        metadata: Option<&AttributeTypeMetadata>,
    ) -> String {
        let mut parts = vec![format!("( {}", self.oid)];

        if !self.names.is_empty() {
            parts.push(format!("NAME {}", format_name_list(&self.names)));
        }
        if let Some(description) = &self.description {
            parts.push(format!("DESC '{}'", escape_schema_value(description)));
        }
        if metadata.is_some_and(|metadata| metadata.obsolete) {
            parts.push("OBSOLETE".to_string());
        }
        if let Some(superior) = metadata.and_then(|metadata| metadata.superior.as_ref()) {
            parts.push(format!("SUP {}", superior));
        }
        if let Some(equality) = &self.equality {
            parts.push(format!("EQUALITY {}", equality));
        }
        if let Some(ordering) = metadata.and_then(|metadata| metadata.ordering.as_ref()) {
            parts.push(format!("ORDERING {}", ordering));
        }
        if let Some(substring) = metadata.and_then(|metadata| metadata.substring.as_ref()) {
            parts.push(format!("SUBSTR {}", substring));
        }
        parts.push(format!("SYNTAX {}", self.syntax));
        if self.single_value {
            parts.push("SINGLE-VALUE".to_string());
        }
        if metadata.is_some_and(|metadata| metadata.collective) {
            parts.push("COLLECTIVE".to_string());
        }
        if metadata.is_some_and(|metadata| metadata.no_user_modification) {
            parts.push("NO-USER-MODIFICATION".to_string());
        }
        if let Some(usage) = metadata.and_then(|metadata| metadata.usage.as_ref()) {
            parts.push(format!("USAGE {}", usage));
        }
        if let Some(metadata) = metadata {
            append_extensions(&mut parts, &metadata.extensions);
        }

        parts.push(")".to_string());
        parts.join(" ")
    }
}

impl ObjectClass {
    pub fn to_schema_description(&self) -> String {
        self.to_schema_description_with_metadata(None)
    }

    pub fn to_schema_description_with_metadata(
        &self,
        metadata: Option<&SchemaElementMetadata>,
    ) -> String {
        let mut parts = vec![format!("( {}", self.oid)];

        if !self.names.is_empty() {
            parts.push(format!("NAME {}", format_name_list(&self.names)));
        }
        if let Some(description) = metadata.and_then(|metadata| metadata.description.as_ref()) {
            parts.push(format!("DESC '{}'", escape_schema_value(description)));
        }
        if metadata.is_some_and(|metadata| metadata.obsolete) {
            parts.push("OBSOLETE".to_string());
        }
        if !self.sup.is_empty() {
            parts.push(format!("SUP {}", format_schema_list(&self.sup)));
        }
        parts.push(match self.kind {
            ObjectClassKind::Abstract => "ABSTRACT".to_string(),
            ObjectClassKind::Structural => "STRUCTURAL".to_string(),
            ObjectClassKind::Auxiliary => "AUXILIARY".to_string(),
        });
        if !self.must.is_empty() {
            parts.push(format!("MUST {}", format_schema_list(&self.must)));
        }
        if !self.may.is_empty() {
            parts.push(format!("MAY {}", format_schema_list(&self.may)));
        }
        if let Some(metadata) = metadata {
            append_extensions(&mut parts, &metadata.extensions);
        }

        parts.push(")".to_string());
        parts.join(" ")
    }
}

impl LdapSyntax {
    pub fn to_schema_description(&self) -> String {
        let mut parts = vec![format!("( {}", self.oid)];
        if let Some(description) = &self.description {
            parts.push(format!("DESC '{}'", escape_schema_value(description)));
        }
        if self.obsolete {
            parts.push("OBSOLETE".to_string());
        }
        append_extensions(&mut parts, &self.extensions);
        parts.push(")".to_string());
        parts.join(" ")
    }
}

impl MatchingRule {
    pub fn to_schema_description(&self) -> String {
        let mut parts = vec![format!("( {}", self.oid)];
        if !self.names.is_empty() {
            parts.push(format!("NAME {}", format_name_list(&self.names)));
        }
        if let Some(description) = &self.description {
            parts.push(format!("DESC '{}'", escape_schema_value(description)));
        }
        if self.obsolete {
            parts.push("OBSOLETE".to_string());
        }
        parts.push(format!("SYNTAX {}", self.syntax));
        append_extensions(&mut parts, &self.extensions);
        parts.push(")".to_string());
        parts.join(" ")
    }
}

impl MatchingRuleUse {
    pub fn to_schema_description(&self) -> String {
        let mut parts = vec![format!("( {}", self.oid)];
        if !self.names.is_empty() {
            parts.push(format!("NAME {}", format_name_list(&self.names)));
        }
        if let Some(description) = &self.description {
            parts.push(format!("DESC '{}'", escape_schema_value(description)));
        }
        if self.obsolete {
            parts.push("OBSOLETE".to_string());
        }
        if !self.applies.is_empty() {
            parts.push(format!("APPLIES {}", format_schema_list(&self.applies)));
        }
        append_extensions(&mut parts, &self.extensions);
        parts.push(")".to_string());
        parts.join(" ")
    }
}

impl DitContentRule {
    pub fn to_schema_description(&self) -> String {
        let mut parts = vec![format!("( {}", self.oid)];
        append_common_schema_parts(
            &mut parts,
            &self.names,
            self.description.as_deref(),
            self.obsolete,
        );
        if !self.auxiliary.is_empty() {
            parts.push(format!("AUX {}", format_schema_list(&self.auxiliary)));
        }
        if !self.must.is_empty() {
            parts.push(format!("MUST {}", format_schema_list(&self.must)));
        }
        if !self.may.is_empty() {
            parts.push(format!("MAY {}", format_schema_list(&self.may)));
        }
        if !self.not.is_empty() {
            parts.push(format!("NOT {}", format_schema_list(&self.not)));
        }
        append_extensions(&mut parts, &self.extensions);
        parts.push(")".to_string());
        parts.join(" ")
    }
}

impl NameForm {
    pub fn to_schema_description(&self) -> String {
        let mut parts = vec![format!("( {}", self.oid)];
        append_common_schema_parts(
            &mut parts,
            &self.names,
            self.description.as_deref(),
            self.obsolete,
        );
        parts.push(format!("OC {}", self.object_class));
        if !self.must.is_empty() {
            parts.push(format!("MUST {}", format_schema_list(&self.must)));
        }
        if !self.may.is_empty() {
            parts.push(format!("MAY {}", format_schema_list(&self.may)));
        }
        append_extensions(&mut parts, &self.extensions);
        parts.push(")".to_string());
        parts.join(" ")
    }
}

impl DitStructureRule {
    pub fn to_schema_description(&self) -> String {
        let mut parts = vec![format!("( {}", self.rule_id)];
        append_common_schema_parts(
            &mut parts,
            &self.names,
            self.description.as_deref(),
            self.obsolete,
        );
        parts.push(format!("FORM {}", self.name_form));
        if !self.superior_rules.is_empty() {
            let values = self
                .superior_rules
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>();
            parts.push(format!("SUP {}", format_schema_list(&values)));
        }
        append_extensions(&mut parts, &self.extensions);
        parts.push(")".to_string());
        parts.join(" ")
    }
}

fn format_name_list(values: &[String]) -> String {
    if values.len() == 1 {
        format!("'{}'", escape_schema_value(&values[0]))
    } else {
        format!(
            "( {} )",
            values
                .iter()
                .map(|value| format!("'{}'", escape_schema_value(value)))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

fn format_schema_list(values: &[String]) -> String {
    if values.len() == 1 {
        values[0].clone()
    } else {
        format!("( {} )", values.join(" $ "))
    }
}

fn append_common_schema_parts(
    parts: &mut Vec<String>,
    names: &[String],
    description: Option<&str>,
    obsolete: bool,
) {
    if !names.is_empty() {
        parts.push(format!("NAME {}", format_name_list(names)));
    }
    if let Some(description) = description {
        parts.push(format!("DESC '{}'", escape_schema_value(description)));
    }
    if obsolete {
        parts.push("OBSOLETE".to_string());
    }
}

fn append_extensions(parts: &mut Vec<String>, extensions: &BTreeMap<String, Vec<String>>) {
    for (name, values) in extensions {
        parts.push(format!("{} {}", name, format_name_list(values)));
    }
}

fn escape_schema_value(value: &str) -> String {
    value.replace('\'', "\\27")
}

fn normalize_schema_attr_name(name: &str) -> String {
    name.chars()
        .filter(|ch| *ch != '-')
        .collect::<String>()
        .to_ascii_lowercase()
}

pub fn canonical_schema_attr_name(name: &str) -> Option<&'static str> {
    match normalize_schema_attr_name(name).as_str() {
        "attributetypes" | "attributetype" => Some("attributeTypes"),
        "objectclasses" | "objectclass" => Some("objectClasses"),
        "ldapsyntaxes" | "ldapsyntax" => Some("ldapSyntaxes"),
        "matchingrules" | "matchingrule" => Some("matchingRules"),
        "matchingruleuse" | "matchingruleuses" => Some("matchingRuleUse"),
        "ditcontentrules" | "ditcontentrule" => Some("dITContentRules"),
        "nameforms" | "nameform" => Some("nameForms"),
        "ditstructurerules" | "ditstructurerule" => Some("dITStructureRules"),
        _ => None,
    }
}

pub fn schema_definition_key(name: &str, value: &str) -> Result<String, SchemaError> {
    let Some(canonical_name) = canonical_schema_attr_name(name) else {
        return Err(SchemaError::ParseError(format!(
            "unsupported schema attribute: {}",
            name
        )));
    };
    let key = match canonical_name {
        "attributeTypes" => parse_attribute_type_description(value)?.attribute_type.oid,
        "objectClasses" => parse_object_class_description(value)?.object_class.oid,
        "ldapSyntaxes" => parse_ldap_syntax_description(value)?.oid,
        "matchingRules" => parse_matching_rule_description(value)?.oid,
        "matchingRuleUse" => parse_matching_rule_use_description(value)?.oid,
        "dITContentRules" => parse_dit_content_rule_description(value)?.oid,
        "nameForms" => parse_name_form_description(value)?.oid,
        "dITStructureRules" => parse_dit_structure_rule_description(value)?
            .rule_id
            .to_string(),
        _ => unreachable!("canonical schema attribute set is exhaustive"),
    };
    Ok(format!("{}:{}", canonical_name, key))
}

fn base_syntax_oid(syntax: &str) -> &str {
    syntax.split_once('{').map_or(syntax, |(oid, _)| oid)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedSyntaxKind {
    Boolean,
    DistinguishedName,
    DirectoryString,
    GeneralizedTime,
    Ia5String,
    Integer,
    ObjectIdentifier,
    OctetString,
    PostalAddress,
    TelephoneNumber,
}

fn supported_syntax_kind(syntax_oid: &str) -> Option<SupportedSyntaxKind> {
    match syntax_oid {
        "1.3.6.1.4.1.1466.115.121.1.7" => Some(SupportedSyntaxKind::Boolean),
        "1.3.6.1.4.1.1466.115.121.1.12" => Some(SupportedSyntaxKind::DistinguishedName),
        "1.3.6.1.4.1.1466.115.121.1.15" => Some(SupportedSyntaxKind::DirectoryString),
        "1.3.6.1.4.1.1466.115.121.1.24" => Some(SupportedSyntaxKind::GeneralizedTime),
        "1.3.6.1.4.1.1466.115.121.1.26" => Some(SupportedSyntaxKind::Ia5String),
        "1.3.6.1.4.1.1466.115.121.1.27" => Some(SupportedSyntaxKind::Integer),
        "1.3.6.1.4.1.1466.115.121.1.38" => Some(SupportedSyntaxKind::ObjectIdentifier),
        "1.3.6.1.4.1.1466.115.121.1.40" => Some(SupportedSyntaxKind::OctetString),
        "1.3.6.1.4.1.1466.115.121.1.41" => Some(SupportedSyntaxKind::PostalAddress),
        "1.3.6.1.4.1.1466.115.121.1.50" => Some(SupportedSyntaxKind::TelephoneNumber),
        _ => None,
    }
}

fn validate_ldap_syntax_value(syntax_oid: &str, value: &str) -> Result<(), String> {
    let Some(kind) = supported_syntax_kind(syntax_oid) else {
        return Err(format!("unsupported LDAP syntax {}", syntax_oid));
    };

    match kind {
        SupportedSyntaxKind::Boolean => {
            if matches!(value, "TRUE" | "FALSE") {
                Ok(())
            } else {
                Err("boolean values must be TRUE or FALSE".to_string())
            }
        }
        SupportedSyntaxKind::DistinguishedName => canonicalize_dn(value)
            .map(|_| ())
            .map_err(|err| err.to_string()),
        SupportedSyntaxKind::DirectoryString => prepare_directory_string(value).map(|_| ()),
        SupportedSyntaxKind::GeneralizedTime => parse_generalized_time(value).map(|_| ()),
        SupportedSyntaxKind::Ia5String => validate_ia5_string(value),
        SupportedSyntaxKind::Integer => parse_integer_syntax(value).map(|_| ()),
        SupportedSyntaxKind::ObjectIdentifier => {
            if is_valid_oid_or_descriptor(value) {
                Ok(())
            } else {
                Err("value must be a numeric OID or descriptor".to_string())
            }
        }
        SupportedSyntaxKind::OctetString => Ok(()),
        SupportedSyntaxKind::PostalAddress => validate_postal_address(value),
        SupportedSyntaxKind::TelephoneNumber => validate_telephone_number(value),
    }
}

fn resolved_matching_rule(rule: &MatchingRule) -> ResolvedMatchingRule {
    ResolvedMatchingRule {
        oid: rule.oid.clone(),
        names: rule.names.clone(),
        primary_name: rule
            .names
            .first()
            .cloned()
            .unwrap_or_else(|| rule.oid.clone()),
        syntax: rule.syntax.clone(),
    }
}

fn matching_rules_are_same(left: &ResolvedMatchingRule, right: &ResolvedMatchingRule) -> bool {
    left.oid == right.oid
        || left.names.iter().any(|left_name| {
            right
                .names
                .iter()
                .any(|right_name| left_name.eq_ignore_ascii_case(right_name))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedMatchingRuleKind {
    Boolean,
    CaseIgnore,
    CaseExact,
    CaseIgnoreIa5,
    Integer,
    IntegerOrdering,
    GeneralizedTime,
    GeneralizedTimeOrdering,
    DistinguishedName,
    ObjectIdentifier,
    OctetString,
    TelephoneNumber,
    TelephoneNumberSubstring,
    CaseIgnoreSubstring,
    CaseExactSubstring,
}

fn supported_matching_rule_kind(rule: &ResolvedMatchingRule) -> Option<SupportedMatchingRuleKind> {
    let name = rule.primary_name.to_ascii_lowercase();
    match (rule.oid.as_str(), name.as_str()) {
        ("2.5.13.2", _) | (_, "caseignorematch") => Some(SupportedMatchingRuleKind::CaseIgnore),
        ("2.5.13.5", _) | (_, "caseexactmatch") => Some(SupportedMatchingRuleKind::CaseExact),
        ("1.3.6.1.4.1.1466.109.114.2", _) | (_, "caseignoreia5match") => {
            Some(SupportedMatchingRuleKind::CaseIgnoreIa5)
        }
        ("2.5.13.13", _) | (_, "booleanmatch") => Some(SupportedMatchingRuleKind::Boolean),
        ("2.5.13.14", _) | (_, "integermatch") => Some(SupportedMatchingRuleKind::Integer),
        ("2.5.13.15", _) | (_, "integerorderingmatch") => {
            Some(SupportedMatchingRuleKind::IntegerOrdering)
        }
        ("2.5.13.27", _) | (_, "generalizedtimematch") => {
            Some(SupportedMatchingRuleKind::GeneralizedTime)
        }
        ("2.5.13.28", _) | (_, "generalizedtimeorderingmatch") => {
            Some(SupportedMatchingRuleKind::GeneralizedTimeOrdering)
        }
        ("2.5.13.1", _) | (_, "distinguishednamematch") => {
            Some(SupportedMatchingRuleKind::DistinguishedName)
        }
        ("2.5.13.0", _) | (_, "objectidentifiermatch") => {
            Some(SupportedMatchingRuleKind::ObjectIdentifier)
        }
        ("2.5.13.17", _) | (_, "octetstringmatch") => Some(SupportedMatchingRuleKind::OctetString),
        ("2.5.13.20", _) | (_, "telephonenumbermatch") => {
            Some(SupportedMatchingRuleKind::TelephoneNumber)
        }
        ("2.5.13.21", _) | (_, "telephonenumbersubstringsmatch") => {
            Some(SupportedMatchingRuleKind::TelephoneNumberSubstring)
        }
        ("2.5.13.4", _) | (_, "caseignoresubstringsmatch") => {
            Some(SupportedMatchingRuleKind::CaseIgnoreSubstring)
        }
        ("2.5.13.7", _) | (_, "caseexactsubstringsmatch") => {
            Some(SupportedMatchingRuleKind::CaseExactSubstring)
        }
        _ => None,
    }
}

fn normalize_matching_rule_value(
    rule: &ResolvedMatchingRule,
    value: &str,
) -> Result<String, MatchingRuleError> {
    let Some(kind) = supported_matching_rule_kind(rule) else {
        return Err(MatchingRuleError::UnsupportedRule(rule.label().to_string()));
    };
    match kind {
        SupportedMatchingRuleKind::Boolean => {
            validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.7", value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))?;
            Ok(value.to_string())
        }
        SupportedMatchingRuleKind::CaseIgnore | SupportedMatchingRuleKind::CaseIgnoreSubstring => {
            normalize_directory_string_case_ignore(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::CaseExact | SupportedMatchingRuleKind::CaseExactSubstring => {
            normalize_directory_string(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::CaseIgnoreIa5 => normalize_ia5_string_case_ignore(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::Integer | SupportedMatchingRuleKind::IntegerOrdering => {
            parse_integer_for_rule(rule, value).map(|value| value.to_string())
        }
        SupportedMatchingRuleKind::GeneralizedTime
        | SupportedMatchingRuleKind::GeneralizedTimeOrdering => {
            normalize_generalized_time_for_rule(rule, value)
        }
        SupportedMatchingRuleKind::DistinguishedName => normalize_dn_value_for_matching(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::ObjectIdentifier => {
            if !is_valid_oid_or_descriptor(value) {
                return Err(invalid_matching_syntax(
                    rule,
                    value,
                    "value must be a numeric OID or descriptor",
                ));
            }
            Ok(value.to_ascii_lowercase())
        }
        SupportedMatchingRuleKind::OctetString => Ok(value.to_string()),
        SupportedMatchingRuleKind::TelephoneNumber
        | SupportedMatchingRuleKind::TelephoneNumberSubstring => {
            normalize_telephone_number_for_matching(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
    }
}

fn matching_rule_ordering_key(
    rule: &ResolvedMatchingRule,
    value: &str,
) -> Result<String, MatchingRuleError> {
    let Some(kind) = supported_matching_rule_kind(rule) else {
        return Err(MatchingRuleError::UnsupportedRule(rule.label().to_string()));
    };
    match kind {
        SupportedMatchingRuleKind::Integer | SupportedMatchingRuleKind::IntegerOrdering => {
            let value = parse_integer_for_rule(rule, value)?;
            let sortable = (value as u128) ^ (1_u128 << 127);
            Ok(format!("{sortable:032x}"))
        }
        SupportedMatchingRuleKind::GeneralizedTime
        | SupportedMatchingRuleKind::GeneralizedTimeOrdering => {
            generalized_time_ordering_key(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        _ => Err(MatchingRuleError::UnsupportedRule(format!(
            "{} is not an ordering rule",
            rule.label()
        ))),
    }
}

fn compare_matching_rule_values(
    rule: &ResolvedMatchingRule,
    left: &str,
    right: &str,
) -> Result<CmpOrdering, MatchingRuleError> {
    let Some(kind) = supported_matching_rule_kind(rule) else {
        return Err(MatchingRuleError::UnsupportedRule(rule.label().to_string()));
    };
    match kind {
        SupportedMatchingRuleKind::Integer | SupportedMatchingRuleKind::IntegerOrdering => {
            Ok(parse_integer_for_rule(rule, left)?.cmp(&parse_integer_for_rule(rule, right)?))
        }
        SupportedMatchingRuleKind::GeneralizedTime
        | SupportedMatchingRuleKind::GeneralizedTimeOrdering => {
            Ok(matching_rule_ordering_key(rule, left)?
                .cmp(&matching_rule_ordering_key(rule, right)?))
        }
        _ => Ok(normalize_matching_rule_value(rule, left)?
            .cmp(&normalize_matching_rule_value(rule, right)?)),
    }
}

fn normalize_directory_string(value: &str) -> Result<String, String> {
    prepare_directory_string(value)
}

fn normalize_directory_string_case_ignore(value: &str) -> Result<String, String> {
    prepare_directory_string(value).map(|value| rfc4518_case_fold(&value))
}

fn prepare_directory_string(value: &str) -> Result<String, String> {
    let prepared = prepare_unicode_string(value)?;
    if prepared.is_empty() {
        Err("Directory String values must not be empty".to_string())
    } else {
        Ok(prepared)
    }
}

fn prepare_unicode_string(value: &str) -> Result<String, String> {
    let mut mapped = String::with_capacity(value.len());
    for ch in value.chars() {
        if is_prohibited_string_char(ch) {
            return Err(format!(
                "value contains prohibited code point U+{:04X}",
                ch as u32
            ));
        }
        if ch.is_whitespace() {
            mapped.push(' ');
        } else {
            mapped.push(ch);
        }
    }

    Ok(mapped.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn rfc4518_case_fold(value: &str) -> String {
    let mut folded = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\u{00DF}' | '\u{1E9E}' => folded.push_str("ss"),
            '\u{03C2}' => folded.push('\u{03C3}'),
            _ => folded.extend(ch.to_lowercase()),
        }
    }
    folded
}

fn is_prohibited_string_char(ch: char) -> bool {
    matches!(ch, '\u{0000}'..='\u{001F}' | '\u{007F}'..='\u{009F}')
}

fn validate_ia5_string(value: &str) -> Result<(), String> {
    if !value.is_ascii() {
        return Err("IA5 values must contain only ASCII characters".to_string());
    }
    if value.chars().any(is_prohibited_string_char) {
        return Err("IA5 values must not contain control characters".to_string());
    }
    Ok(())
}

fn normalize_ia5_string_case_ignore(value: &str) -> Result<String, String> {
    validate_ia5_string(value)?;
    Ok(value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase())
}

fn parse_integer_for_rule(
    rule: &ResolvedMatchingRule,
    value: &str,
) -> Result<i128, MatchingRuleError> {
    parse_integer_syntax(value).map_err(|reason| invalid_matching_syntax(rule, value, &reason))
}

fn parse_integer_syntax(value: &str) -> Result<i128, String> {
    let digits = if let Some(rest) = value.strip_prefix('-') {
        if rest.is_empty() {
            return Err("integer value is missing digits".to_string());
        }
        if rest == "0" || (rest.len() > 1 && rest.starts_with('0')) {
            return Err("integer values must not contain leading zeroes".to_string());
        }
        rest
    } else {
        if value.is_empty() {
            return Err("integer value is empty".to_string());
        }
        if value.len() > 1 && value.starts_with('0') {
            return Err("integer values must not contain leading zeroes".to_string());
        }
        value
    };

    if !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return Err("value is not a valid integer".to_string());
    }

    value
        .parse::<i128>()
        .map_err(|_| "integer value is outside the supported i128 range".to_string())
}

fn normalize_generalized_time_for_rule(
    rule: &ResolvedMatchingRule,
    value: &str,
) -> Result<String, MatchingRuleError> {
    normalize_generalized_time(value)
        .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
}

fn normalize_generalized_time(value: &str) -> Result<String, String> {
    let time = parse_generalized_time(value)?;
    Ok(format_generalized_time(&time, false))
}

fn generalized_time_ordering_key(value: &str) -> Result<String, String> {
    let time = parse_generalized_time(value)?;
    Ok(format_generalized_time(&time, true))
}

fn parse_generalized_time(value: &str) -> Result<DateTime<Utc>, String> {
    if value.is_empty() {
        return Err("generalized time value is empty".to_string());
    }
    if value.chars().any(char::is_whitespace) {
        return Err("generalized time values must not contain whitespace".to_string());
    }

    let upper = value.to_ascii_uppercase();
    let (time_part, offset_seconds) = if let Some(time_part) = upper.strip_suffix('Z') {
        (time_part, 0)
    } else {
        let Some((offset_start, sign)) = upper
            .char_indices()
            .rev()
            .find(|(_, ch)| matches!(ch, '+' | '-'))
        else {
            return Err("generalized time requires Z or +/-HHMM timezone".to_string());
        };
        let offset = &upper[offset_start + 1..];
        if offset.len() != 4 || !offset.chars().all(|ch| ch.is_ascii_digit()) {
            return Err("timezone offset must use +/-HHMM".to_string());
        }
        let hours = parse_decimal_u32(&offset[..2], "timezone hour")?;
        let minutes = parse_decimal_u32(&offset[2..], "timezone minute")?;
        if hours > 23 || minutes > 59 {
            return Err("timezone offset is out of range".to_string());
        }
        let seconds = (hours as i32 * 3600) + (minutes as i32 * 60);
        let signed_seconds = if sign == '-' { -seconds } else { seconds };
        (&upper[..offset_start], signed_seconds)
    };

    let (time_digits, fraction) = if let Some((digits, fraction)) = time_part.split_once('.') {
        (digits, Some(fraction))
    } else if let Some((digits, fraction)) = time_part.split_once(',') {
        (digits, Some(fraction))
    } else {
        (time_part, None)
    };

    if !matches!(time_digits.len(), 10 | 12 | 14)
        || !time_digits.chars().all(|ch| ch.is_ascii_digit())
    {
        return Err("expected YYYYMMDDHH[MM[SS]] generalized time".to_string());
    }

    let year = parse_decimal_i32(&time_digits[0..4], "year")?;
    let month = parse_decimal_u32(&time_digits[4..6], "month")?;
    let day = parse_decimal_u32(&time_digits[6..8], "day")?;
    let hour = parse_decimal_u32(&time_digits[8..10], "hour")?;
    let minute = if time_digits.len() >= 12 {
        parse_decimal_u32(&time_digits[10..12], "minute")?
    } else {
        0
    };
    let second = if time_digits.len() == 14 {
        parse_decimal_u32(&time_digits[12..14], "second")?
    } else {
        0
    };

    let date = NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| "generalized time date is out of range".to_string())?;
    let time = NaiveTime::from_hms_opt(hour, minute, second)
        .ok_or_else(|| "generalized time clock value is out of range".to_string())?;
    let mut naive = NaiveDateTime::new(date, time);

    if let Some(fraction) = fraction {
        let unit_nanos = match time_digits.len() {
            10 => 3_600_000_000_000_u128,
            12 => 60_000_000_000_u128,
            14 => 1_000_000_000_u128,
            _ => unreachable!("validated generalized time length"),
        };
        let (extra_seconds, extra_nanos) = fractional_duration(fraction, unit_nanos)?;
        naive = naive
            .checked_add_signed(Duration::seconds(extra_seconds))
            .and_then(|value| value.checked_add_signed(Duration::nanoseconds(extra_nanos)))
            .ok_or_else(|| "generalized time fraction overflows date range".to_string())?;
    }

    let offset = FixedOffset::east_opt(offset_seconds)
        .ok_or_else(|| "timezone offset is out of range".to_string())?;
    let local = offset
        .from_local_datetime(&naive)
        .single()
        .ok_or_else(|| "generalized time is ambiguous for timezone".to_string())?;
    Ok(local.with_timezone(&Utc))
}

fn format_generalized_time(time: &DateTime<Utc>, fixed_fraction: bool) -> String {
    let base = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    );
    let nanos = time.nanosecond();
    if fixed_fraction {
        format!("{base}.{nanos:09}Z")
    } else if nanos == 0 {
        format!("{base}Z")
    } else {
        let mut fraction = format!("{nanos:09}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        format!("{base}.{fraction}Z")
    }
}

fn fractional_duration(fraction: &str, unit_nanos: u128) -> Result<(i64, i64), String> {
    if fraction.is_empty() || !fraction.chars().all(|ch| ch.is_ascii_digit()) {
        return Err("generalized time fraction must contain digits".to_string());
    }

    let mut numerator = 0_u128;
    let mut scale = 1_u128;
    for ch in fraction.chars().take(18) {
        numerator = numerator * 10 + u128::from(ch as u8 - b'0');
        scale *= 10;
    }

    let total_nanos = numerator
        .checked_mul(unit_nanos)
        .ok_or_else(|| "generalized time fraction is too large".to_string())?
        / scale;
    Ok((
        (total_nanos / 1_000_000_000) as i64,
        (total_nanos % 1_000_000_000) as i64,
    ))
}

fn parse_decimal_u32(value: &str, label: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("invalid generalized time {}", label))
}

fn parse_decimal_i32(value: &str, label: &str) -> Result<i32, String> {
    value
        .parse::<i32>()
        .map_err(|_| format!("invalid generalized time {}", label))
}

fn validate_postal_address(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("Postal Address values must not be empty".to_string());
    }
    for line in value.split('$') {
        if line.is_empty() {
            return Err("Postal Address lines must not be empty".to_string());
        }
        prepare_directory_string(line)?;
    }
    Ok(())
}

fn validate_telephone_number(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("Telephone Number values must not be empty".to_string());
    }
    if value.chars().all(is_printable_string_char) {
        Ok(())
    } else {
        Err("Telephone Number values must use PrintableString characters".to_string())
    }
}

fn normalize_telephone_number_for_matching(value: &str) -> Result<String, String> {
    validate_telephone_number(value)?;
    let mut normalized = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, ' ' | '-') {
            continue;
        }
        normalized.extend(ch.to_lowercase());
    }
    Ok(normalized)
}

fn is_printable_string_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            ' ' | '\'' | '(' | ')' | '+' | ',' | '-' | '.' | '/' | ':' | '=' | '?'
        )
}

fn normalize_dn_value_for_matching(value: &str) -> Result<String, String> {
    canonicalize_dn(value).map_err(|err| err.to_string())
}

fn invalid_matching_syntax(
    rule: &ResolvedMatchingRule,
    value: &str,
    reason: &str,
) -> MatchingRuleError {
    MatchingRuleError::InvalidSyntax {
        rule: rule.label().to_string(),
        value: value.to_string(),
        reason: reason.to_string(),
    }
}

fn is_valid_oid_or_descriptor(value: &str) -> bool {
    is_valid_numeric_oid(value) || is_valid_descriptor(value)
}

fn is_valid_numeric_oid(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() < 2 {
        return false;
    }
    if parts
        .iter()
        .any(|part| part.is_empty() || !part.chars().all(|ch| ch.is_ascii_digit()))
    {
        return false;
    }
    if parts
        .iter()
        .any(|part| part.len() > 1 && part.starts_with('0'))
    {
        return false;
    }

    let Ok(first) = parts[0].parse::<u32>() else {
        return false;
    };
    let Ok(second) = parts[1].parse::<u32>() else {
        return false;
    };
    if first > 2 {
        return false;
    }
    if first < 2 && second > 39 {
        return false;
    }
    true
}

fn is_valid_descriptor(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic() && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn parse_syntax_with_optional_length(value: &str) -> Result<(String, Option<usize>), SchemaError> {
    if let Some((oid, rest)) = value.split_once('{') {
        let Some(length) = rest.strip_suffix('}') else {
            return Err(SchemaError::ParseError(format!(
                "invalid syntax length bound: {}",
                value
            )));
        };
        let parsed_length = length
            .parse::<usize>()
            .map_err(|_| SchemaError::ParseError(format!("invalid syntax length: {}", value)))?;
        Ok((oid.to_string(), Some(parsed_length)))
    } else {
        Ok((value.to_string(), None))
    }
}

fn unfold_ldif_lines(contents: &str) -> Result<Vec<String>, SchemaError> {
    let mut unfolded: Vec<String> = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(continuation) = line.strip_prefix(' ') {
            let Some(previous) = unfolded.last_mut() else {
                return Err(SchemaError::ParseError(
                    "LDIF continuation line without previous line".to_string(),
                ));
            };
            previous.push_str(continuation);
        } else {
            unfolded.push(line.to_string());
        }
    }
    Ok(unfolded)
}

fn parse_ldif_attrval(line: &str) -> Result<Option<(String, String)>, SchemaError> {
    let Some((name, rest)) = line.split_once(':') else {
        return Ok(None);
    };
    let name = name.trim().to_string();
    if let Some(base64_value) = rest.strip_prefix(':') {
        let decoded = general_purpose::STANDARD
            .decode(base64_value.trim())
            .map_err(|err| SchemaError::ParseError(format!("invalid base64 LDIF value: {err}")))?;
        let value = String::from_utf8(decoded)
            .map_err(|err| SchemaError::ParseError(format!("invalid UTF-8 LDIF value: {err}")))?;
        return Ok(Some((name, value)));
    }
    if rest.trim_start().starts_with('<') {
        return Err(SchemaError::ParseError(
            "LDIF URL values are not supported for schema loading".to_string(),
        ));
    }
    Ok(Some((name, rest.trim_start().to_string())))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SchemaToken {
    LParen,
    RParen,
    Dollar,
    Word(String),
    Quoted(String),
}

fn tokenize_schema_description(input: &str) -> Result<Vec<SchemaToken>, SchemaError> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.peek().copied() {
        match ch {
            '(' => {
                chars.next();
                tokens.push(SchemaToken::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(SchemaToken::RParen);
            }
            '$' => {
                chars.next();
                tokens.push(SchemaToken::Dollar);
            }
            '\'' => {
                chars.next();
                let mut value = String::new();
                let mut closed = false;
                for quoted in chars.by_ref() {
                    if quoted == '\'' {
                        closed = true;
                        break;
                    }
                    value.push(quoted);
                }
                if !closed {
                    return Err(SchemaError::ParseError(
                        "unterminated quoted schema value".to_string(),
                    ));
                }
                tokens.push(SchemaToken::Quoted(value));
            }
            ch if ch.is_whitespace() => {
                chars.next();
            }
            _ => {
                let mut value = String::new();
                while let Some(next) = chars.peek().copied() {
                    if next.is_whitespace() || matches!(next, '(' | ')' | '$' | '\'') {
                        break;
                    }
                    value.push(next);
                    chars.next();
                }
                tokens.push(SchemaToken::Word(value));
            }
        }
    }
    Ok(tokens)
}

struct SchemaParser {
    tokens: Vec<SchemaToken>,
    position: usize,
}

impl SchemaParser {
    fn new(input: &str) -> Result<Self, SchemaError> {
        Ok(Self {
            tokens: tokenize_schema_description(input)?,
            position: 0,
        })
    }

    fn expect_lparen(&mut self) -> Result<(), SchemaError> {
        match self.next() {
            Some(SchemaToken::LParen) => Ok(()),
            other => Err(SchemaError::ParseError(format!(
                "expected '(' but found {:?}",
                other
            ))),
        }
    }

    fn expect_rparen(&mut self) -> Result<(), SchemaError> {
        match self.next() {
            Some(SchemaToken::RParen) => Ok(()),
            other => Err(SchemaError::ParseError(format!(
                "expected ')' but found {:?}",
                other
            ))),
        }
    }

    fn expect_word(&mut self, label: &str) -> Result<String, SchemaError> {
        match self.next() {
            Some(SchemaToken::Word(value)) => Ok(value),
            Some(SchemaToken::Quoted(value)) => Ok(value),
            other => Err(SchemaError::ParseError(format!(
                "expected {} but found {:?}",
                label, other
            ))),
        }
    }

    fn expect_quoted(&mut self, label: &str) -> Result<String, SchemaError> {
        match self.next() {
            Some(SchemaToken::Quoted(value)) => Ok(value),
            other => Err(SchemaError::ParseError(format!(
                "expected quoted {} but found {:?}",
                label, other
            ))),
        }
    }

    fn next_keyword(&mut self) -> Result<Option<String>, SchemaError> {
        match self.peek() {
            Some(SchemaToken::RParen) => Ok(None),
            Some(SchemaToken::Word(_)) => self.expect_word("keyword").map(Some),
            other => Err(SchemaError::ParseError(format!(
                "expected schema keyword but found {:?}",
                other
            ))),
        }
    }

    fn parse_qdescrs(&mut self) -> Result<Vec<String>, SchemaError> {
        if matches!(self.peek(), Some(SchemaToken::LParen)) {
            self.expect_lparen()?;
            let mut values = Vec::new();
            loop {
                match self.peek() {
                    Some(SchemaToken::RParen) => {
                        self.expect_rparen()?;
                        break;
                    }
                    Some(SchemaToken::Quoted(_)) => values.push(self.expect_quoted("NAME")?),
                    other => {
                        return Err(SchemaError::ParseError(format!(
                            "expected quoted descriptor in list but found {:?}",
                            other
                        )));
                    }
                }
            }
            Ok(values)
        } else {
            Ok(vec![self.expect_quoted("NAME")?])
        }
    }

    fn parse_oid_list(&mut self) -> Result<Vec<String>, SchemaError> {
        if matches!(self.peek(), Some(SchemaToken::LParen)) {
            self.expect_lparen()?;
            let mut values = Vec::new();
            loop {
                match self.peek() {
                    Some(SchemaToken::RParen) => {
                        self.expect_rparen()?;
                        break;
                    }
                    Some(SchemaToken::Dollar) => {
                        self.next();
                    }
                    Some(SchemaToken::Word(_)) | Some(SchemaToken::Quoted(_)) => {
                        values.push(self.expect_word("OID")?)
                    }
                    other => {
                        return Err(SchemaError::ParseError(format!(
                            "expected OID in list but found {:?}",
                            other
                        )));
                    }
                }
            }
            Ok(values)
        } else {
            Ok(vec![self.expect_word("OID")?])
        }
    }

    fn parse_extension_values(&mut self) -> Result<Vec<String>, SchemaError> {
        if matches!(self.peek(), Some(SchemaToken::LParen)) {
            self.expect_lparen()?;
            let mut values = Vec::new();
            loop {
                match self.peek() {
                    Some(SchemaToken::RParen) => {
                        self.expect_rparen()?;
                        break;
                    }
                    Some(SchemaToken::Quoted(_)) | Some(SchemaToken::Word(_)) => {
                        values.push(self.expect_word("extension value")?)
                    }
                    other => {
                        return Err(SchemaError::ParseError(format!(
                            "expected extension value but found {:?}",
                            other
                        )));
                    }
                }
            }
            Ok(values)
        } else {
            Ok(vec![self.expect_word("extension value")?])
        }
    }

    fn peek(&self) -> Option<&SchemaToken> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<SchemaToken> {
        let token = self.tokens.get(self.position).cloned();
        if token.is_some() {
            self.position += 1;
        }
        token
    }
}

fn parse_extensions(
    parser: &mut SchemaParser,
    keyword: &str,
    extensions: &mut BTreeMap<String, Vec<String>>,
) -> Result<bool, SchemaError> {
    if keyword.to_ascii_uppercase().starts_with("X-") {
        extensions.insert(keyword.to_string(), parser.parse_extension_values()?);
        Ok(true)
    } else {
        Ok(false)
    }
}

fn parse_attribute_type_description(input: &str) -> Result<ParsedAttributeType, SchemaError> {
    let mut parser = SchemaParser::new(input)?;
    parser.expect_lparen()?;
    let oid = parser.expect_word("attribute type OID")?;
    if !is_valid_numeric_oid(&oid) {
        return Err(SchemaError::ParseError(format!(
            "invalid attribute type OID: {}",
            oid
        )));
    }

    let mut names = Vec::new();
    let mut description = None;
    let mut equality = None;
    let mut syntax = None;
    let mut single_value = false;
    let mut metadata = AttributeTypeMetadata::default();

    while let Some(keyword) = parser.next_keyword()? {
        match keyword.to_ascii_uppercase().as_str() {
            "NAME" => names = parser.parse_qdescrs()?,
            "DESC" => description = Some(parser.expect_quoted("DESC")?),
            "OBSOLETE" => metadata.obsolete = true,
            "SUP" => metadata.superior = Some(parser.expect_word("SUP")?),
            "EQUALITY" => equality = Some(parser.expect_word("EQUALITY")?),
            "ORDERING" => metadata.ordering = Some(parser.expect_word("ORDERING")?),
            "SUBSTR" => metadata.substring = Some(parser.expect_word("SUBSTR")?),
            "SYNTAX" => {
                let (syntax_oid, syntax_length) =
                    parse_syntax_with_optional_length(&parser.expect_word("SYNTAX")?)?;
                syntax = Some(syntax_oid);
                metadata.syntax_length = syntax_length;
            }
            "SINGLE-VALUE" => single_value = true,
            "COLLECTIVE" => metadata.collective = true,
            "NO-USER-MODIFICATION" => metadata.no_user_modification = true,
            "USAGE" => metadata.usage = Some(parser.expect_word("USAGE")?),
            other => {
                if !parse_extensions(&mut parser, other, &mut metadata.extensions)? {
                    return Err(SchemaError::ParseError(format!(
                        "unsupported attribute type token: {}",
                        other
                    )));
                }
            }
        }
    }
    parser.expect_rparen()?;

    let syntax = syntax
        .or_else(|| metadata.superior.as_ref().map(|_| String::new()))
        .ok_or_else(|| {
            SchemaError::ParseError(format!("attribute type {} is missing SYNTAX or SUP", oid))
        })?;
    if names.is_empty() {
        names.push(oid.clone());
    }
    for name in &names {
        if !is_valid_descriptor(name) && !is_valid_numeric_oid(name) {
            return Err(SchemaError::ParseError(format!(
                "invalid attribute descriptor: {}",
                name
            )));
        }
    }

    Ok(ParsedAttributeType {
        attribute_type: AttributeType {
            oid,
            names,
            description,
            equality,
            syntax,
            single_value,
        },
        metadata,
    })
}

fn parse_object_class_description(input: &str) -> Result<ParsedObjectClass, SchemaError> {
    let mut parser = SchemaParser::new(input)?;
    parser.expect_lparen()?;
    let oid = parser.expect_word("object class OID")?;
    if !is_valid_numeric_oid(&oid) {
        return Err(SchemaError::ParseError(format!(
            "invalid object class OID: {}",
            oid
        )));
    }

    let mut names = Vec::new();
    let mut sup = Vec::new();
    let mut kind = ObjectClassKind::Structural;
    let mut must = Vec::new();
    let mut may = Vec::new();
    let mut metadata = SchemaElementMetadata::default();

    while let Some(keyword) = parser.next_keyword()? {
        match keyword.to_ascii_uppercase().as_str() {
            "NAME" => names = parser.parse_qdescrs()?,
            "DESC" => metadata.description = Some(parser.expect_quoted("DESC")?),
            "OBSOLETE" => metadata.obsolete = true,
            "SUP" => sup = parser.parse_oid_list()?,
            "ABSTRACT" => kind = ObjectClassKind::Abstract,
            "STRUCTURAL" => kind = ObjectClassKind::Structural,
            "AUXILIARY" => kind = ObjectClassKind::Auxiliary,
            "MUST" => must = parser.parse_oid_list()?,
            "MAY" => may = parser.parse_oid_list()?,
            other => {
                if !parse_extensions(&mut parser, other, &mut metadata.extensions)? {
                    return Err(SchemaError::ParseError(format!(
                        "unsupported object class token: {}",
                        other
                    )));
                }
            }
        }
    }
    parser.expect_rparen()?;
    if names.is_empty() {
        names.push(oid.clone());
    }
    Ok(ParsedObjectClass {
        object_class: ObjectClass {
            oid,
            names,
            sup,
            kind,
            must,
            may,
        },
        metadata,
    })
}

fn parse_ldap_syntax_description(input: &str) -> Result<LdapSyntax, SchemaError> {
    let mut parser = SchemaParser::new(input)?;
    parser.expect_lparen()?;
    let oid = parser.expect_word("LDAP syntax OID")?;
    let mut description = None;
    let mut obsolete = false;
    let mut extensions = BTreeMap::new();
    while let Some(keyword) = parser.next_keyword()? {
        match keyword.to_ascii_uppercase().as_str() {
            "DESC" => description = Some(parser.expect_quoted("DESC")?),
            "OBSOLETE" => obsolete = true,
            other => {
                if !parse_extensions(&mut parser, other, &mut extensions)? {
                    return Err(SchemaError::ParseError(format!(
                        "unsupported LDAP syntax token: {}",
                        other
                    )));
                }
            }
        }
    }
    parser.expect_rparen()?;
    Ok(LdapSyntax {
        oid,
        description,
        obsolete,
        extensions,
    })
}

fn parse_matching_rule_description(input: &str) -> Result<MatchingRule, SchemaError> {
    let mut parser = SchemaParser::new(input)?;
    parser.expect_lparen()?;
    let oid = parser.expect_word("matching rule OID")?;
    let mut names = Vec::new();
    let mut description = None;
    let mut obsolete = false;
    let mut syntax = None;
    let mut extensions = BTreeMap::new();
    while let Some(keyword) = parser.next_keyword()? {
        match keyword.to_ascii_uppercase().as_str() {
            "NAME" => names = parser.parse_qdescrs()?,
            "DESC" => description = Some(parser.expect_quoted("DESC")?),
            "OBSOLETE" => obsolete = true,
            "SYNTAX" => syntax = Some(parser.expect_word("SYNTAX")?),
            other => {
                if !parse_extensions(&mut parser, other, &mut extensions)? {
                    return Err(SchemaError::ParseError(format!(
                        "unsupported matching rule token: {}",
                        other
                    )));
                }
            }
        }
    }
    parser.expect_rparen()?;
    Ok(MatchingRule {
        oid,
        names,
        description,
        obsolete,
        syntax: syntax.ok_or_else(|| {
            SchemaError::ParseError("matching rule is missing SYNTAX".to_string())
        })?,
        extensions,
    })
}

fn parse_matching_rule_use_description(input: &str) -> Result<MatchingRuleUse, SchemaError> {
    let mut parser = SchemaParser::new(input)?;
    parser.expect_lparen()?;
    let oid = parser.expect_word("matching rule use OID")?;
    let mut names = Vec::new();
    let mut description = None;
    let mut obsolete = false;
    let mut applies = Vec::new();
    let mut extensions = BTreeMap::new();
    while let Some(keyword) = parser.next_keyword()? {
        match keyword.to_ascii_uppercase().as_str() {
            "NAME" => names = parser.parse_qdescrs()?,
            "DESC" => description = Some(parser.expect_quoted("DESC")?),
            "OBSOLETE" => obsolete = true,
            "APPLIES" => applies = parser.parse_oid_list()?,
            other => {
                if !parse_extensions(&mut parser, other, &mut extensions)? {
                    return Err(SchemaError::ParseError(format!(
                        "unsupported matching rule use token: {}",
                        other
                    )));
                }
            }
        }
    }
    parser.expect_rparen()?;
    Ok(MatchingRuleUse {
        oid,
        names,
        description,
        obsolete,
        applies,
        extensions,
    })
}

fn parse_dit_content_rule_description(input: &str) -> Result<DitContentRule, SchemaError> {
    let mut parser = SchemaParser::new(input)?;
    parser.expect_lparen()?;
    let oid = parser.expect_word("DIT content rule OID")?;
    let mut rule = DitContentRule {
        oid,
        names: Vec::new(),
        description: None,
        obsolete: false,
        auxiliary: Vec::new(),
        must: Vec::new(),
        may: Vec::new(),
        not: Vec::new(),
        extensions: BTreeMap::new(),
    };
    while let Some(keyword) = parser.next_keyword()? {
        match keyword.to_ascii_uppercase().as_str() {
            "NAME" => rule.names = parser.parse_qdescrs()?,
            "DESC" => rule.description = Some(parser.expect_quoted("DESC")?),
            "OBSOLETE" => rule.obsolete = true,
            "AUX" => rule.auxiliary = parser.parse_oid_list()?,
            "MUST" => rule.must = parser.parse_oid_list()?,
            "MAY" => rule.may = parser.parse_oid_list()?,
            "NOT" => rule.not = parser.parse_oid_list()?,
            other => {
                if !parse_extensions(&mut parser, other, &mut rule.extensions)? {
                    return Err(SchemaError::ParseError(format!(
                        "unsupported DIT content rule token: {}",
                        other
                    )));
                }
            }
        }
    }
    parser.expect_rparen()?;
    Ok(rule)
}

fn parse_name_form_description(input: &str) -> Result<NameForm, SchemaError> {
    let mut parser = SchemaParser::new(input)?;
    parser.expect_lparen()?;
    let oid = parser.expect_word("name form OID")?;
    let mut rule = NameForm {
        oid,
        names: Vec::new(),
        description: None,
        obsolete: false,
        object_class: String::new(),
        must: Vec::new(),
        may: Vec::new(),
        extensions: BTreeMap::new(),
    };
    while let Some(keyword) = parser.next_keyword()? {
        match keyword.to_ascii_uppercase().as_str() {
            "NAME" => rule.names = parser.parse_qdescrs()?,
            "DESC" => rule.description = Some(parser.expect_quoted("DESC")?),
            "OBSOLETE" => rule.obsolete = true,
            "OC" => rule.object_class = parser.expect_word("OC")?,
            "MUST" => rule.must = parser.parse_oid_list()?,
            "MAY" => rule.may = parser.parse_oid_list()?,
            other => {
                if !parse_extensions(&mut parser, other, &mut rule.extensions)? {
                    return Err(SchemaError::ParseError(format!(
                        "unsupported name form token: {}",
                        other
                    )));
                }
            }
        }
    }
    parser.expect_rparen()?;
    if rule.object_class.is_empty() {
        return Err(SchemaError::ParseError(
            "name form is missing OC".to_string(),
        ));
    }
    if rule.must.is_empty() {
        return Err(SchemaError::ParseError(
            "name form is missing MUST".to_string(),
        ));
    }
    Ok(rule)
}

fn parse_dit_structure_rule_description(input: &str) -> Result<DitStructureRule, SchemaError> {
    let mut parser = SchemaParser::new(input)?;
    parser.expect_lparen()?;
    let rule_id = parser
        .expect_word("DIT structure rule ID")?
        .parse::<u32>()
        .map_err(|_| SchemaError::ParseError("invalid DIT structure rule ID".to_string()))?;
    let mut rule = DitStructureRule {
        rule_id,
        names: Vec::new(),
        description: None,
        obsolete: false,
        name_form: String::new(),
        superior_rules: Vec::new(),
        extensions: BTreeMap::new(),
    };
    while let Some(keyword) = parser.next_keyword()? {
        match keyword.to_ascii_uppercase().as_str() {
            "NAME" => rule.names = parser.parse_qdescrs()?,
            "DESC" => rule.description = Some(parser.expect_quoted("DESC")?),
            "OBSOLETE" => rule.obsolete = true,
            "FORM" => rule.name_form = parser.expect_word("FORM")?,
            "SUP" => {
                rule.superior_rules = parser
                    .parse_oid_list()?
                    .into_iter()
                    .map(|value| {
                        value.parse::<u32>().map_err(|_| {
                            SchemaError::ParseError(format!(
                                "invalid DIT structure rule superior ID: {}",
                                value
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            }
            other => {
                if !parse_extensions(&mut parser, other, &mut rule.extensions)? {
                    return Err(SchemaError::ParseError(format!(
                        "unsupported DIT structure rule token: {}",
                        other
                    )));
                }
            }
        }
    }
    parser.expect_rparen()?;
    if rule.name_form.is_empty() {
        return Err(SchemaError::ParseError(
            "DIT structure rule is missing FORM".to_string(),
        ));
    }
    Ok(rule)
}

impl Default for LdapSchema {
    fn default() -> Self {
        Self::with_core_schema()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_schema_loading() {
        let schema = LdapSchema::with_core_schema();

        // Test attribute types
        assert!(schema.get_attribute_type("cn").is_some());
        assert!(schema.get_attribute_type("sn").is_some());
        assert!(schema.get_attribute_type("mail").is_some());
        assert!(schema.get_attribute_type("uid").is_some());

        // Test object classes
        assert!(schema.get_object_class("top").is_some());
        assert!(schema.get_object_class("person").is_some());
        assert!(schema.get_object_class("inetOrgPerson").is_some());
    }

    #[test]
    fn test_validate_valid_person_entry() {
        let schema = LdapSchema::with_core_schema();

        let mut attributes = HashMap::new();
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        );
        attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
        attributes.insert("sn".to_string(), vec!["Doe".to_string()]);

        assert!(schema.validate_entry(&attributes).is_ok());
    }

    #[test]
    fn test_validate_missing_required_attribute() {
        let schema = LdapSchema::with_core_schema();

        let mut attributes = HashMap::new();
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        );
        attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
        // Missing 'sn' which is required by person

        let result = schema.validate_entry(&attributes);
        assert!(matches!(
            result,
            Err(SchemaError::MissingRequiredAttribute(_))
        ));
    }

    #[test]
    fn test_validate_no_object_class() {
        let schema = LdapSchema::with_core_schema();

        let attributes = HashMap::new();

        let result = schema.validate_entry(&attributes);
        assert!(matches!(
            result,
            Err(SchemaError::MissingRequiredAttribute(_))
        ));
    }

    #[test]
    fn test_validate_unknown_object_class() {
        let schema = LdapSchema::with_core_schema();

        let mut attributes = HashMap::new();
        attributes.insert("objectClass".to_string(), vec!["unknownClass".to_string()]);

        let result = schema.validate_entry(&attributes);
        assert!(matches!(result, Err(SchemaError::ObjectClassNotFound(_))));
    }

    #[test]
    fn test_validate_inetorgperson_with_inheritance() {
        let schema = LdapSchema::with_core_schema();

        let mut attributes = HashMap::new();
        attributes.insert(
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "inetOrgPerson".to_string(),
            ],
        );
        attributes.insert("cn".to_string(), vec!["Jane Smith".to_string()]);
        attributes.insert("sn".to_string(), vec!["Smith".to_string()]);
        attributes.insert("uid".to_string(), vec!["jsmith".to_string()]);
        attributes.insert("mail".to_string(), vec!["jsmith@example.com".to_string()]);

        assert!(schema.validate_entry(&attributes).is_ok());
    }

    #[test]
    fn test_validate_organization() {
        let schema = LdapSchema::with_core_schema();

        let mut attributes = HashMap::new();
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "organization".to_string()],
        );
        attributes.insert("o".to_string(), vec!["Example Corp".to_string()]);

        assert!(schema.validate_entry(&attributes).is_ok());
    }

    #[test]
    fn test_validate_organizational_unit() {
        let schema = LdapSchema::with_core_schema();

        let mut attributes = HashMap::new();
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "organizationalUnit".to_string()],
        );
        attributes.insert("ou".to_string(), vec!["Engineering".to_string()]);

        assert!(schema.validate_entry(&attributes).is_ok());
    }

    #[test]
    fn test_single_value_validation() {
        let mut schema = LdapSchema::with_core_schema();

        // Add a single-value attribute
        schema.add_attribute_type(AttributeType {
            oid: "1.2.3.4".to_string(),
            names: vec!["employeeNumber".to_string()],
            description: Some("Employee number".to_string()),
            equality: Some("caseIgnoreMatch".to_string()),
            syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
            single_value: true,
        });

        // Create a custom object class that allows employeeNumber
        schema.add_object_class(ObjectClass {
            oid: "1.2.3.5".to_string(),
            names: vec!["employee".to_string()],
            sup: vec!["inetOrgPerson".to_string()],
            kind: ObjectClassKind::Auxiliary,
            must: vec![],
            may: vec!["employeeNumber".to_string()],
        });

        let mut attributes = HashMap::new();
        attributes.insert(
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "person".to_string(),
                "inetOrgPerson".to_string(),
                "employee".to_string(),
            ],
        );
        attributes.insert("cn".to_string(), vec!["John".to_string()]);
        attributes.insert("sn".to_string(), vec!["Doe".to_string()]);
        attributes.insert(
            "employeeNumber".to_string(),
            vec!["123".to_string(), "456".to_string()],
        );

        let result = schema.validate_entry(&attributes);
        assert!(matches!(result, Err(SchemaError::SingleValueViolation(_))));
    }

    #[test]
    fn test_no_structural_class() {
        let schema = LdapSchema::with_core_schema();

        let mut attributes = HashMap::new();
        attributes.insert("objectClass".to_string(), vec!["top".to_string()]);
        attributes.insert("objectClass".to_string(), vec!["top".to_string()]); // only abstract

        let result = schema.validate_entry(&attributes);
        assert!(matches!(result, Err(SchemaError::NoStructuralClass)));
    }

    #[test]
    fn test_case_insensitive_attribute_names() {
        let schema = LdapSchema::with_core_schema();

        // Test with various case combinations for attribute names
        let mut attributes = HashMap::new();
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        );
        attributes.insert("CN".to_string(), vec!["John Doe".to_string()]);
        attributes.insert("SN".to_string(), vec!["Doe".to_string()]);

        assert!(schema.validate_entry(&attributes).is_ok());
    }

    #[test]
    fn test_attribute_inheritance_from_superior_classes() {
        let schema = LdapSchema::with_core_schema();

        // inetOrgPerson inherits from organizationalPerson which inherits from person
        // So it should require cn and sn from person
        let mut attributes = HashMap::new();
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "inetOrgPerson".to_string()],
        );
        attributes.insert("cn".to_string(), vec!["Jane".to_string()]);
        // Missing sn - should fail

        let result = schema.validate_entry(&attributes);
        assert!(matches!(
            result,
            Err(SchemaError::MissingRequiredAttribute(_))
        ));
    }

    #[test]
    fn unique_schema_views_deduplicate_aliases() {
        let schema = LdapSchema::with_core_schema();

        let attribute_oids = schema
            .attribute_types_unique_sorted()
            .into_iter()
            .map(|attribute| attribute.oid)
            .collect::<Vec<_>>();
        let object_class_oids = schema
            .object_classes_unique_sorted()
            .into_iter()
            .map(|object_class| object_class.oid)
            .collect::<Vec<_>>();

        assert_eq!(attribute_oids.len(), 16);
        assert_eq!(object_class_oids.len(), 9);
        assert!(attribute_oids.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(object_class_oids.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    #[test]
    fn attribute_type_schema_description_uses_rfc_style_format() {
        let schema = LdapSchema::with_core_schema();
        let description = schema
            .get_attribute_type("cn")
            .unwrap()
            .to_schema_description();

        assert_eq!(
            description,
            "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'Common name' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        );
    }

    #[test]
    fn object_class_schema_description_uses_rfc_style_format() {
        let schema = LdapSchema::with_core_schema();
        let description = schema
            .get_object_class("inetOrgPerson")
            .unwrap()
            .to_schema_description();

        assert_eq!(
            description,
            "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( uid $ givenName $ displayName $ mail ) )"
        );
    }

    #[test]
    fn load_ldif_schema_definitions_with_rfc_descriptions() {
        let mut schema = LdapSchema::with_core_schema();

        schema
            .load_ldif_str(
                "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.9999.1.1 NAME 'employeeNumber' DESC 'Employee number' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
objectClasses: ( 1.3.6.1.4.1.9999.1.2 NAME 'exampleEmployee' DESC 'Example employee' SUP top AUXILIARY MAY employeeNumber )
nameForms: ( 1.3.6.1.4.1.9999.1.3 NAME 'exampleEmployeeNameForm' OC person MUST cn )
dITStructureRules: ( 999 NAME 'exampleEmployeeStructureRule' FORM exampleEmployeeNameForm )
",
            )
            .unwrap();

        let attribute_description = schema.explain("employeeNumber").unwrap();
        let object_class_description = schema.explain("exampleEmployee").unwrap();
        let name_form_description = schema.explain("exampleEmployeeNameForm").unwrap();

        assert!(attribute_description.contains("DESC 'Employee number'"));
        assert!(attribute_description.contains("SINGLE-VALUE"));
        assert!(object_class_description.contains("DESC 'Example employee'"));
        assert!(name_form_description.contains("OC person"));
        assert!(
            schema
                .explain("999")
                .unwrap()
                .contains("FORM exampleEmployeeNameForm")
        );
    }

    #[test]
    fn resolve_matching_profile_inherits_attribute_sup_fields() {
        let mut schema = LdapSchema::with_core_schema();
        schema
            .load_ldif_str(
                "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.30.1 NAME 'exampleBaseNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.30.2 NAME 'exampleChildNumber' SUP exampleBaseNumber )
",
            )
            .unwrap();

        let profile = schema
            .resolve_attribute_matching_profile("exampleChildNumber")
            .unwrap();

        assert_eq!(profile.syntax_oid, "1.3.6.1.4.1.1466.115.121.1.27");
        assert!(profile.single_value);
        assert_eq!(profile.equality.unwrap().primary_name, "integerMatch");
        assert_eq!(
            profile.ordering.unwrap().primary_name,
            "integerOrderingMatch"
        );
        assert_eq!(
            profile.superior_chain,
            vec!["1.3.6.1.4.1.55555.30.1".to_string()]
        );
    }

    #[test]
    fn supported_matching_rules_normalize_values() {
        let schema = LdapSchema::with_core_schema();

        assert_eq!(
            schema
                .resolve_matching_rule("caseIgnoreMatch")
                .unwrap()
                .normalize_value("  Straße   Smith ")
                .unwrap(),
            "strasse smith"
        );
        assert_eq!(
            schema
                .resolve_matching_rule("caseExactMatch")
                .unwrap()
                .normalize_value("  Alice   Smith ")
                .unwrap(),
            "Alice Smith"
        );
        assert_eq!(
            schema
                .resolve_matching_rule("caseIgnoreIA5Match")
                .unwrap()
                .normalize_value(" USER@EXAMPLE.ORG ")
                .unwrap(),
            "user@example.org"
        );
        assert_eq!(
            schema
                .resolve_matching_rule("integerMatch")
                .unwrap()
                .normalize_value("42")
                .unwrap(),
            "42"
        );
        assert!(matches!(
            schema
                .resolve_matching_rule("integerMatch")
                .unwrap()
                .normalize_value("00042"),
            Err(MatchingRuleError::InvalidSyntax { .. })
        ));
        assert_eq!(
            schema
                .resolve_matching_rule("booleanMatch")
                .unwrap()
                .normalize_value("TRUE")
                .unwrap(),
            "TRUE"
        );
        assert_eq!(
            schema
                .resolve_matching_rule("distinguishedNameMatch")
                .unwrap()
                .normalize_value(" CN=Alice , OU=People, DC=Example ")
                .unwrap(),
            "cn=alice,ou=people,dc=example"
        );
        assert_eq!(
            schema
                .resolve_matching_rule("objectIdentifierMatch")
                .unwrap()
                .normalize_value("CN")
                .unwrap(),
            "cn"
        );
        assert_eq!(
            schema
                .resolve_matching_rule("telephoneNumberMatch")
                .unwrap()
                .normalize_value("+1 555-0100")
                .unwrap(),
            "+15550100"
        );
        assert_eq!(
            schema
                .resolve_matching_rule("octetStringMatch")
                .unwrap()
                .normalize_value("Secret")
                .unwrap(),
            "Secret"
        );
    }

    #[test]
    fn supported_matching_rules_generate_ordering_keys() {
        let schema = LdapSchema::with_core_schema();
        let integer_rule = schema
            .resolve_matching_rule("integerOrderingMatch")
            .unwrap();
        let time_rule = schema
            .resolve_matching_rule("generalizedTimeOrderingMatch")
            .unwrap();

        assert!(integer_rule.ordering_key("-1").unwrap() < integer_rule.ordering_key("2").unwrap());
        assert_eq!(
            time_rule.ordering_key("20260102030405Z").unwrap(),
            "20260102030405.000000000Z"
        );
        assert_eq!(
            time_rule.normalize_value("20260102030405+0530").unwrap(),
            "20260101213405Z"
        );
        assert!(
            time_rule
                .compare_values("20250101000000Z", "20260101000000Z")
                .unwrap()
                .is_lt()
        );
    }

    #[test]
    fn rfc4517_syntax_validators_cover_advertised_set() {
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.7", "TRUE").is_ok());
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.7", "true").is_err());
        assert!(
            validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.12", "cn=Alice,dc=example")
                .is_ok()
        );
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.15", "Jorg").is_ok());
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.15", "").is_err());
        assert!(
            validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.24", "20260102030405Z").is_ok()
        );
        assert!(
            validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.24", "20260230030405Z").is_err()
        );
        assert!(
            validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.26", "user@example.org").is_ok()
        );
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.26", "Jorg").is_ok());
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.27", "-42").is_ok());
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.27", "042").is_err());
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.38", "2.5.4.3").is_ok());
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.38", "2.05").is_err());
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.40", "\0").is_ok());
        assert!(
            validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.41", "Line 1$Line 2").is_ok()
        );
        assert!(
            validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.41", "Line 1$$Line 3").is_err()
        );
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.50", "+1 555-0100").is_ok());
        assert!(validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.50", "+1_555").is_err());
        assert!(validate_ldap_syntax_value("1.2.3.4", "anything").is_err());
    }

    #[test]
    fn unsupported_matching_rules_are_explicit() {
        let mut schema = LdapSchema::with_core_schema();
        schema
            .load_ldif_str(
                "
dn: cn=schema
matchingRules: ( 1.3.6.1.4.1.55555.31.1 NAME 'exampleUnsupportedMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
",
            )
            .unwrap();

        let rule = schema
            .resolve_matching_rule("exampleUnsupportedMatch")
            .unwrap();
        assert!(matches!(
            rule.normalize_value("abc"),
            Err(MatchingRuleError::UnsupportedRule(_))
        ));
    }
}
