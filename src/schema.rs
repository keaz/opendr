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
use x509_parser::prelude::FromDer;
use x520_stringprep::{
    x520_stringprep_to_case_exact_string, x520_stringprep_to_case_ignore_string,
};

use crate::dn::{canonicalize_dn, parse_dn, parse_rdn, rdn_attribute_values};

const RFC3671_SCHEMA_LDIF: &str = include_str!("../resources/schema/core/rfc3671.ldif");
const RFC3672_SCHEMA_LDIF: &str = include_str!("../resources/schema/core/rfc3672.ldif");
const RFC2307_SCHEMA_LDIF: &str = include_str!("../resources/schema/posix/rfc2307.ldif");
const RFC4524_SCHEMA_LDIF: &str = include_str!("../resources/schema/cosine/rfc4524.ldif");
const RFC4523_SCHEMA_LDIF: &str = include_str!("../resources/schema/x509/rfc4523.ldif");

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinSchemaFile {
    pub bundle: &'static str,
    pub relative_path: &'static str,
    pub contents: &'static str,
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
        let normalized_assertion = self.normalize_value(right)?;
        self.value_matches_normalized_assertion(left, &normalized_assertion)
    }

    pub fn value_matches_normalized_assertion(
        &self,
        candidate: &str,
        normalized_assertion: &str,
    ) -> Result<bool, MatchingRuleError> {
        value_matches_normalized_assertion(self, candidate, normalized_assertion)
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

    pub fn is_index_supported(&self) -> bool {
        !matches!(
            supported_matching_rule_kind(self),
            None | Some(SupportedMatchingRuleKind::X509Certificate)
                | Some(SupportedMatchingRuleKind::X509CertificateList)
                | Some(SupportedMatchingRuleKind::X509CertificatePair)
                | Some(SupportedMatchingRuleKind::X509CertificatePairExact)
        )
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

pub fn bundled_schema_files(bundle: &str) -> Result<Vec<BuiltinSchemaFile>, SchemaError> {
    match bundle.to_ascii_lowercase().as_str() {
        "core" => Ok(vec![
            BuiltinSchemaFile {
                bundle: "core",
                relative_path: "core/rfc3672.ldif",
                contents: RFC3672_SCHEMA_LDIF,
            },
            BuiltinSchemaFile {
                bundle: "core",
                relative_path: "core/rfc3671.ldif",
                contents: RFC3671_SCHEMA_LDIF,
            },
        ]),
        "posix" => Ok(vec![BuiltinSchemaFile {
            bundle: "posix",
            relative_path: "posix/rfc2307.ldif",
            contents: RFC2307_SCHEMA_LDIF,
        }]),
        "cosine" => Ok(vec![BuiltinSchemaFile {
            bundle: "cosine",
            relative_path: "cosine/rfc4524.ldif",
            contents: RFC4524_SCHEMA_LDIF,
        }]),
        "x509" => Ok(vec![BuiltinSchemaFile {
            bundle: "x509",
            relative_path: "x509/rfc4523.ldif",
            contents: RFC4523_SCHEMA_LDIF,
        }]),
        _ => Err(SchemaError::ParseError(format!(
            "unsupported builtin schema bundle: {}",
            bundle
        ))),
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

    /// Load a named built-in schema bundle into this registry.
    pub fn load_builtin_schema(&mut self, bundle: &str) -> Result<(), SchemaError> {
        match bundle.to_ascii_lowercase().as_str() {
            "core" => {
                self.load_core_schema();
                Ok(())
            }
            "posix" => self.load_posix_schema(),
            "cosine" => self.load_cosine_schema(),
            "x509" => self.load_x509_schema(),
            _ => Err(SchemaError::ParseError(format!(
                "unsupported builtin schema bundle: {}",
                bundle
            ))),
        }
    }

    /// Load core LDAP schema (RFC 4519 and file-backed core extensions).
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
                oid: "2.5.4.41".to_string(),
                names: vec!["name".to_string()],
                description: Some("Name supertype".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(), // Directory String
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
                oid: "2.5.4.5".to_string(),
                names: vec!["serialNumber".to_string()],
                description: Some("Serial number".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.44".to_string(), // Printable String
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.6".to_string(),
                names: vec!["c".to_string(), "countryName".to_string()],
                description: Some("Country name".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.11".to_string(), // Country String
                single_value: true,
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
                oid: "2.5.4.36".to_string(),
                names: vec!["userCertificate".to_string()],
                description: Some("User X.509 certificate".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.8".to_string(), // Certificate
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
                oid: "2.5.4.14".to_string(),
                names: vec!["searchGuide".to_string()],
                description: Some("Search guide".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.25".to_string(), // Guide
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.27".to_string(),
                names: vec!["destinationIndicator".to_string()],
                description: Some("Destination indicator".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.44".to_string(), // Printable String
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.49".to_string(),
                names: vec!["distinguishedName".to_string()],
                description: Some("Distinguished name supertype".to_string()),
                equality: Some("distinguishedNameMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.12".to_string(), // DN
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.46".to_string(),
                names: vec!["dnQualifier".to_string()],
                description: Some("DN qualifier".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.44".to_string(), // Printable String
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.47".to_string(),
                names: vec!["enhancedSearchGuide".to_string()],
                description: Some("Enhanced search guide".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.21".to_string(), // Enhanced Guide
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.23".to_string(),
                names: vec!["facsimileTelephoneNumber".to_string()],
                description: Some("Facsimile telephone number".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.22".to_string(), // Facsimile Telephone Number
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
                oid: "2.5.4.43".to_string(),
                names: vec!["initials".to_string()],
                description: Some("Initials".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.44".to_string(),
                names: vec!["generationQualifier".to_string()],
                description: Some("Generation qualifier".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.51".to_string(),
                names: vec!["houseIdentifier".to_string()],
                description: Some("House identifier".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.25".to_string(),
                names: vec!["internationalISDNNumber".to_string()],
                description: Some("International ISDN number".to_string()),
                equality: Some("numericStringMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.36".to_string(), // Numeric String
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.55".to_string(),
                names: vec!["audio".to_string()],
                description: Some("Audio recording".to_string()),
                equality: Some("octetStringMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.40{250000}".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.16.840.1.113730.3.1.241".to_string(),
                names: vec!["displayName".to_string()],
                description: Some("Display name".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: true,
            },
            AttributeType {
                oid: "2.16.840.1.113730.3.1.1".to_string(),
                names: vec!["carLicense".to_string()],
                description: Some("Vehicle license or registration plate".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.16.840.1.113730.3.1.2".to_string(),
                names: vec!["departmentNumber".to_string()],
                description: Some("Department number".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.16.840.1.113730.3.1.3".to_string(),
                names: vec!["employeeNumber".to_string()],
                description: Some("Employee number".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: true,
            },
            AttributeType {
                oid: "2.16.840.1.113730.3.1.4".to_string(),
                names: vec!["employeeType".to_string()],
                description: Some("Employee type".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.16.840.1.113730.3.1.39".to_string(),
                names: vec!["preferredLanguage".to_string()],
                description: Some("Preferred language".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: true,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.6".to_string(),
                names: vec!["roomNumber".to_string()],
                description: Some("Room number".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.10".to_string(),
                names: vec!["manager".to_string()],
                description: Some("Manager".to_string()),
                equality: Some("distinguishedNameMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.12".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.20".to_string(),
                names: vec!["homePhone".to_string()],
                description: Some("Home telephone number".to_string()),
                equality: Some("telephoneNumberMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.50".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.21".to_string(),
                names: vec!["secretary".to_string()],
                description: Some("Secretary".to_string()),
                equality: Some("distinguishedNameMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.12".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.39".to_string(),
                names: vec!["homePostalAddress".to_string()],
                description: Some("Home postal address".to_string()),
                equality: Some("caseIgnoreListMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.41".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.41".to_string(),
                names: vec!["mobile".to_string()],
                description: Some("Mobile telephone number".to_string()),
                equality: Some("telephoneNumberMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.50".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.42".to_string(),
                names: vec!["pager".to_string()],
                description: Some("Pager telephone number".to_string()),
                equality: Some("telephoneNumberMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.50".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.7".to_string(),
                names: vec!["photo".to_string()],
                description: Some("G3 fax encoded photograph".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.23".to_string(), // Fax
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.60".to_string(),
                names: vec!["jpegPhoto".to_string()],
                description: Some("JPEG photograph".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.28".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.16.840.1.113730.3.1.40".to_string(),
                names: vec!["userSMIMECertificate".to_string()],
                description: Some("PKCS#7 SignedData used to support S/MIME".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.5".to_string(), // Binary
                single_value: false,
            },
            AttributeType {
                oid: "2.16.840.1.113730.3.1.216".to_string(),
                names: vec!["userPKCS12".to_string()],
                description: Some("PKCS #12 PFX PDU".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.5".to_string(), // Binary
                single_value: false,
            },
            AttributeType {
                oid: "1.3.6.1.4.1.250.1.57".to_string(),
                names: vec!["labeledURI".to_string()],
                description: Some("Labeled URI".to_string()),
                equality: Some("caseExactMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "0.9.2342.19200300.100.1.25".to_string(),
                names: vec!["dc".to_string(), "domainComponent".to_string()],
                description: Some("Domain component".to_string()),
                equality: Some("caseIgnoreIA5Match".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.26".to_string(),
                single_value: true,
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
                oid: "2.5.4.21".to_string(),
                names: vec!["telexNumber".to_string()],
                description: Some("Telex number".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.52".to_string(), // Telex Number
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.22".to_string(),
                names: vec!["teletexTerminalIdentifier".to_string()],
                description: Some("Teletex terminal identifier".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.51".to_string(), // Teletex Terminal Identifier
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.24".to_string(),
                names: vec!["x121Address".to_string()],
                description: Some("X.121 address".to_string()),
                equality: Some("numericStringMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.36".to_string(), // Numeric String
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.28".to_string(),
                names: vec!["preferredDeliveryMethod".to_string()],
                description: Some("Preferred delivery method".to_string()),
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.14".to_string(), // Delivery Method
                single_value: true,
            },
            AttributeType {
                oid: "2.5.4.15".to_string(),
                names: vec!["businessCategory".to_string()],
                description: Some("Business category".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.7".to_string(),
                names: vec!["l".to_string(), "localityName".to_string()],
                description: Some("Locality name".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.8".to_string(),
                names: vec!["st".to_string(), "stateOrProvinceName".to_string()],
                description: Some("State or province name".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.9".to_string(),
                names: vec!["street".to_string(), "streetAddress".to_string()],
                description: Some("Street address".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.16".to_string(),
                names: vec!["postalAddress".to_string()],
                description: Some("Postal address".to_string()),
                equality: Some("caseIgnoreListMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.41".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.17".to_string(),
                names: vec!["postalCode".to_string()],
                description: Some("Postal code".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.18".to_string(),
                names: vec!["postOfficeBox".to_string()],
                description: Some("Post office box".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.19".to_string(),
                names: vec!["physicalDeliveryOfficeName".to_string()],
                description: Some("Physical delivery office name".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.26".to_string(),
                names: vec!["registeredAddress".to_string()],
                description: Some("Registered address".to_string()),
                equality: Some("caseIgnoreListMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.41".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.33".to_string(),
                names: vec!["roleOccupant".to_string()],
                description: Some("Role occupant".to_string()),
                equality: Some("distinguishedNameMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.12".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.32".to_string(),
                names: vec!["owner".to_string()],
                description: Some("Owner".to_string()),
                equality: Some("distinguishedNameMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.12".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.34".to_string(),
                names: vec!["seeAlso".to_string()],
                description: Some("See also".to_string()),
                equality: Some("distinguishedNameMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.12".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.50".to_string(),
                names: vec!["uniqueMember".to_string()],
                description: Some("Unique group member".to_string()),
                equality: Some("uniqueMemberMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.34".to_string(),
                single_value: false,
            },
            AttributeType {
                oid: "2.5.4.45".to_string(),
                names: vec!["x500UniqueIdentifier".to_string()],
                description: Some("X.500 unique identifier".to_string()),
                equality: Some("bitStringMatch".to_string()),
                syntax: "1.3.6.1.4.1.1466.115.121.1.6".to_string(),
                single_value: false,
            },
        ];

        for attr in core_attributes {
            self.add_attribute_type(attr);
        }
        for attr_name in [
            "name",
            "cn",
            "sn",
            "serialNumber",
            "c",
            "o",
            "ou",
            "uid",
            "description",
            "destinationIndicator",
            "dnQualifier",
            "givenName",
            "initials",
            "generationQualifier",
            "houseIdentifier",
            "displayName",
            "carLicense",
            "departmentNumber",
            "employeeNumber",
            "employeeType",
            "preferredLanguage",
            "roomNumber",
            "dc",
            "title",
            "businessCategory",
            "l",
            "st",
            "street",
            "postalCode",
            "postOfficeBox",
            "physicalDeliveryOfficeName",
        ] {
            self.set_attribute_substring_rule(attr_name, "caseIgnoreSubstringsMatch");
        }
        self.set_attribute_substring_rule("mail", "caseIgnoreIA5SubstringsMatch");
        self.set_attribute_substring_rule("labeledURI", "caseExactSubstringsMatch");
        self.set_attribute_substring_rule("homePostalAddress", "caseIgnoreListSubstringsMatch");
        self.set_attribute_substring_rule("postalAddress", "caseIgnoreListSubstringsMatch");
        self.set_attribute_substring_rule("registeredAddress", "caseIgnoreListSubstringsMatch");
        self.set_attribute_substring_rule(
            "internationalISDNNumber",
            "numericStringSubstringsMatch",
        );
        self.set_attribute_substring_rule("x121Address", "numericStringSubstringsMatch");
        self.set_attribute_substring_rule("telephoneNumber", "telephoneNumberSubstringsMatch");
        self.set_attribute_substring_rule("homePhone", "telephoneNumberSubstringsMatch");
        self.set_attribute_substring_rule("mobile", "telephoneNumberSubstringsMatch");
        self.set_attribute_substring_rule("pager", "telephoneNumberSubstringsMatch");

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
                    "seeAlso".to_string(),
                    "description".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.7".to_string(),
                names: vec!["organizationalPerson".to_string()],
                sup: vec!["person".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec![],
                may: vec![
                    "title".to_string(),
                    "x121Address".to_string(),
                    "registeredAddress".to_string(),
                    "destinationIndicator".to_string(),
                    "preferredDeliveryMethod".to_string(),
                    "telexNumber".to_string(),
                    "teletexTerminalIdentifier".to_string(),
                    "telephoneNumber".to_string(),
                    "internationalISDNNumber".to_string(),
                    "facsimileTelephoneNumber".to_string(),
                    "street".to_string(),
                    "postOfficeBox".to_string(),
                    "postalCode".to_string(),
                    "postalAddress".to_string(),
                    "physicalDeliveryOfficeName".to_string(),
                    "st".to_string(),
                    "l".to_string(),
                    "ou".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.16.840.1.113730.3.2.2".to_string(),
                names: vec!["inetOrgPerson".to_string()],
                sup: vec!["organizationalPerson".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec![],
                may: vec![
                    "businessCategory".to_string(),
                    "audio".to_string(),
                    "carLicense".to_string(),
                    "departmentNumber".to_string(),
                    "displayName".to_string(),
                    "employeeNumber".to_string(),
                    "employeeType".to_string(),
                    "uid".to_string(),
                    "givenName".to_string(),
                    "homePhone".to_string(),
                    "homePostalAddress".to_string(),
                    "initials".to_string(),
                    "jpegPhoto".to_string(),
                    "labeledURI".to_string(),
                    "mail".to_string(),
                    "manager".to_string(),
                    "mobile".to_string(),
                    "o".to_string(),
                    "pager".to_string(),
                    "photo".to_string(),
                    "preferredLanguage".to_string(),
                    "roomNumber".to_string(),
                    "secretary".to_string(),
                    "userCertificate".to_string(),
                    "x500UniqueIdentifier".to_string(),
                    "userSMIMECertificate".to_string(),
                    "userPKCS12".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.11".to_string(),
                names: vec!["applicationProcess".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["cn".to_string()],
                may: vec![
                    "seeAlso".to_string(),
                    "ou".to_string(),
                    "l".to_string(),
                    "description".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.2".to_string(),
                names: vec!["country".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["c".to_string()],
                may: vec!["searchGuide".to_string(), "description".to_string()],
            },
            ObjectClass {
                oid: "2.5.6.14".to_string(),
                names: vec!["device".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["cn".to_string()],
                may: vec![
                    "serialNumber".to_string(),
                    "seeAlso".to_string(),
                    "owner".to_string(),
                    "ou".to_string(),
                    "o".to_string(),
                    "l".to_string(),
                    "description".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.3".to_string(),
                names: vec!["locality".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec![],
                may: vec![
                    "street".to_string(),
                    "seeAlso".to_string(),
                    "searchGuide".to_string(),
                    "st".to_string(),
                    "l".to_string(),
                    "description".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.4".to_string(),
                names: vec!["organization".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["o".to_string()],
                may: vec![
                    "userPassword".to_string(),
                    "searchGuide".to_string(),
                    "seeAlso".to_string(),
                    "businessCategory".to_string(),
                    "x121Address".to_string(),
                    "registeredAddress".to_string(),
                    "destinationIndicator".to_string(),
                    "preferredDeliveryMethod".to_string(),
                    "telexNumber".to_string(),
                    "teletexTerminalIdentifier".to_string(),
                    "telephoneNumber".to_string(),
                    "internationalISDNNumber".to_string(),
                    "facsimileTelephoneNumber".to_string(),
                    "street".to_string(),
                    "postOfficeBox".to_string(),
                    "postalCode".to_string(),
                    "postalAddress".to_string(),
                    "physicalDeliveryOfficeName".to_string(),
                    "st".to_string(),
                    "l".to_string(),
                    "description".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.8".to_string(),
                names: vec!["organizationalRole".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["cn".to_string()],
                may: vec![
                    "x121Address".to_string(),
                    "registeredAddress".to_string(),
                    "destinationIndicator".to_string(),
                    "preferredDeliveryMethod".to_string(),
                    "telexNumber".to_string(),
                    "teletexTerminalIdentifier".to_string(),
                    "telephoneNumber".to_string(),
                    "internationalISDNNumber".to_string(),
                    "facsimileTelephoneNumber".to_string(),
                    "seeAlso".to_string(),
                    "roleOccupant".to_string(),
                    "street".to_string(),
                    "postOfficeBox".to_string(),
                    "postalCode".to_string(),
                    "postalAddress".to_string(),
                    "physicalDeliveryOfficeName".to_string(),
                    "ou".to_string(),
                    "st".to_string(),
                    "l".to_string(),
                    "description".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.5".to_string(),
                names: vec!["organizationalUnit".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["ou".to_string()],
                may: vec![
                    "businessCategory".to_string(),
                    "description".to_string(),
                    "destinationIndicator".to_string(),
                    "facsimileTelephoneNumber".to_string(),
                    "internationalISDNNumber".to_string(),
                    "l".to_string(),
                    "physicalDeliveryOfficeName".to_string(),
                    "postalAddress".to_string(),
                    "postalCode".to_string(),
                    "postOfficeBox".to_string(),
                    "preferredDeliveryMethod".to_string(),
                    "registeredAddress".to_string(),
                    "searchGuide".to_string(),
                    "seeAlso".to_string(),
                    "st".to_string(),
                    "street".to_string(),
                    "telephoneNumber".to_string(),
                    "teletexTerminalIdentifier".to_string(),
                    "telexNumber".to_string(),
                    "userPassword".to_string(),
                    "x121Address".to_string(),
                ],
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
                must: vec!["member".to_string(), "cn".to_string()],
                may: vec![
                    "businessCategory".to_string(),
                    "seeAlso".to_string(),
                    "owner".to_string(),
                    "ou".to_string(),
                    "o".to_string(),
                    "description".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.17".to_string(),
                names: vec!["groupOfUniqueNames".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["cn".to_string(), "uniqueMember".to_string()],
                may: vec![
                    "businessCategory".to_string(),
                    "seeAlso".to_string(),
                    "owner".to_string(),
                    "description".to_string(),
                    "o".to_string(),
                    "ou".to_string(),
                ],
            },
            ObjectClass {
                oid: "2.5.6.10".to_string(),
                names: vec!["residentialPerson".to_string()],
                sup: vec!["person".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["l".to_string()],
                may: vec![
                    "businessCategory".to_string(),
                    "x121Address".to_string(),
                    "registeredAddress".to_string(),
                    "destinationIndicator".to_string(),
                    "preferredDeliveryMethod".to_string(),
                    "telexNumber".to_string(),
                    "teletexTerminalIdentifier".to_string(),
                    "telephoneNumber".to_string(),
                    "internationalISDNNumber".to_string(),
                    "facsimileTelephoneNumber".to_string(),
                    "street".to_string(),
                    "postOfficeBox".to_string(),
                    "postalCode".to_string(),
                    "postalAddress".to_string(),
                    "physicalDeliveryOfficeName".to_string(),
                    "st".to_string(),
                    "l".to_string(),
                ],
            },
            ObjectClass {
                oid: "1.3.6.1.1.3.1".to_string(),
                names: vec!["uidObject".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Auxiliary,
                must: vec!["uid".to_string()],
                may: vec![],
            },
        ];

        for oc in core_classes {
            self.add_object_class(oc);
        }

        self.load_standard_syntaxes_and_matching_rules();
        self.load_core_schema_files();
    }

    fn load_core_schema_files(&mut self) {
        self.load_ldif_str(RFC3672_SCHEMA_LDIF)
            .expect("bundled RFC 3672 schema must load");
        self.load_ldif_str(RFC3671_SCHEMA_LDIF)
            .expect("bundled RFC 3671 schema must load");
    }

    /// Load RFC 2307 POSIX and NIS schema definitions.
    fn load_posix_schema(&mut self) -> Result<(), SchemaError> {
        if self.get_object_class("top").is_none() {
            self.load_core_schema();
        }

        self.load_ldif_str(RFC2307_SCHEMA_LDIF)
    }

    /// Load RFC 4524 COSINE LDAP/X.500 schema definitions.
    fn load_cosine_schema(&mut self) -> Result<(), SchemaError> {
        if self.get_object_class("top").is_none() {
            self.load_core_schema();
        }

        self.load_ldif_str(RFC4524_SCHEMA_LDIF)
    }

    /// Load RFC 4523 X.509 certificate schema definitions.
    fn load_x509_schema(&mut self) -> Result<(), SchemaError> {
        if self.get_object_class("top").is_none() {
            self.load_core_schema();
        }

        self.load_ldif_str(RFC4523_SCHEMA_LDIF)
    }

    fn load_standard_syntaxes_and_matching_rules(&mut self) {
        let syntaxes = [
            ("1.3.6.1.4.1.1466.115.121.1.3", "Attribute Type Description"),
            ("1.3.6.1.4.1.1466.115.121.1.5", "Binary"),
            ("1.3.6.1.4.1.1466.115.121.1.6", "Bit String"),
            ("1.3.6.1.4.1.1466.115.121.1.7", "Boolean"),
            ("1.3.6.1.4.1.1466.115.121.1.8", "Certificate"),
            ("1.3.6.1.4.1.1466.115.121.1.11", "Country String"),
            ("1.3.6.1.4.1.1466.115.121.1.12", "DN"),
            ("1.3.6.1.4.1.1466.115.121.1.14", "Delivery Method"),
            ("1.3.6.1.4.1.1466.115.121.1.15", "Directory String"),
            (
                "1.3.6.1.4.1.1466.115.121.1.16",
                "DIT Content Rule Description",
            ),
            (
                "1.3.6.1.4.1.1466.115.121.1.17",
                "DIT Structure Rule Description",
            ),
            ("1.3.6.1.4.1.1466.115.121.1.21", "Enhanced Guide"),
            (
                "1.3.6.1.4.1.1466.115.121.1.22",
                "Facsimile Telephone Number",
            ),
            ("1.3.6.1.4.1.1466.115.121.1.23", "Fax"),
            ("1.3.6.1.4.1.1466.115.121.1.24", "Generalized Time"),
            ("1.3.6.1.4.1.1466.115.121.1.25", "Guide"),
            ("1.3.6.1.4.1.1466.115.121.1.26", "IA5 String"),
            ("1.3.6.1.4.1.1466.115.121.1.27", "Integer"),
            ("1.3.6.1.4.1.1466.115.121.1.28", "JPEG"),
            ("1.3.6.1.4.1.1466.115.121.1.30", "Matching Rule Description"),
            (
                "1.3.6.1.4.1.1466.115.121.1.31",
                "Matching Rule Use Description",
            ),
            ("1.3.6.1.4.1.1466.115.121.1.34", "Name And Optional UID"),
            ("1.3.6.1.4.1.1466.115.121.1.35", "Name Form Description"),
            ("1.3.6.1.4.1.1466.115.121.1.36", "Numeric String"),
            ("1.3.6.1.4.1.1466.115.121.1.37", "Object Class Description"),
            ("1.3.6.1.4.1.1466.115.121.1.38", "OID"),
            ("1.3.6.1.4.1.1466.115.121.1.39", "Other Mailbox"),
            ("1.3.6.1.4.1.1466.115.121.1.40", "Octet String"),
            ("1.3.6.1.4.1.1466.115.121.1.41", "Postal Address"),
            ("1.3.6.1.4.1.1466.115.121.1.44", "Printable String"),
            ("1.3.6.1.4.1.1466.115.121.1.50", "Telephone Number"),
            (
                "1.3.6.1.4.1.1466.115.121.1.51",
                "Teletex Terminal Identifier",
            ),
            ("1.3.6.1.4.1.1466.115.121.1.52", "Telex Number"),
            ("1.3.6.1.4.1.1466.115.121.1.53", "UTC Time"),
            ("1.3.6.1.4.1.1466.115.121.1.54", "LDAP Syntax Description"),
            ("1.3.6.1.4.1.1466.115.121.1.58", "Substring Assertion"),
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
                "2.5.13.0",
                "objectIdentifierMatch",
                "1.3.6.1.4.1.1466.115.121.1.38",
            ),
            (
                "2.5.13.1",
                "distinguishedNameMatch",
                "1.3.6.1.4.1.1466.115.121.1.12",
            ),
            (
                "2.5.13.2",
                "caseIgnoreMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            (
                "2.5.13.3",
                "caseIgnoreOrderingMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            (
                "2.5.13.4",
                "caseIgnoreSubstringsMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            (
                "2.5.13.5",
                "caseExactMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            (
                "2.5.13.6",
                "caseExactOrderingMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            (
                "2.5.13.7",
                "caseExactSubstringsMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            (
                "2.5.13.8",
                "numericStringMatch",
                "1.3.6.1.4.1.1466.115.121.1.36",
            ),
            (
                "2.5.13.9",
                "numericStringOrderingMatch",
                "1.3.6.1.4.1.1466.115.121.1.36",
            ),
            (
                "2.5.13.10",
                "numericStringSubstringsMatch",
                "1.3.6.1.4.1.1466.115.121.1.36",
            ),
            (
                "2.5.13.11",
                "caseIgnoreListMatch",
                "1.3.6.1.4.1.1466.115.121.1.41",
            ),
            (
                "2.5.13.12",
                "caseIgnoreListSubstringsMatch",
                "1.3.6.1.4.1.1466.115.121.1.41",
            ),
            ("2.5.13.13", "booleanMatch", "1.3.6.1.4.1.1466.115.121.1.7"),
            ("2.5.13.14", "integerMatch", "1.3.6.1.4.1.1466.115.121.1.27"),
            (
                "2.5.13.15",
                "integerOrderingMatch",
                "1.3.6.1.4.1.1466.115.121.1.27",
            ),
            (
                "2.5.13.16",
                "bitStringMatch",
                "1.3.6.1.4.1.1466.115.121.1.6",
            ),
            (
                "2.5.13.17",
                "octetStringMatch",
                "1.3.6.1.4.1.1466.115.121.1.40",
            ),
            (
                "2.5.13.18",
                "octetStringOrderingMatch",
                "1.3.6.1.4.1.1466.115.121.1.40",
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
            (
                "2.5.13.23",
                "uniqueMemberMatch",
                "1.3.6.1.4.1.1466.115.121.1.34",
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
                "2.5.13.29",
                "integerFirstComponentMatch",
                "1.3.6.1.4.1.1466.115.121.1.27",
            ),
            (
                "2.5.13.30",
                "objectIdentifierFirstComponentMatch",
                "1.3.6.1.4.1.1466.115.121.1.38",
            ),
            (
                "2.5.13.31",
                "directoryStringFirstComponentMatch",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            ("2.5.13.32", "wordMatch", "1.3.6.1.4.1.1466.115.121.1.15"),
            ("2.5.13.33", "keywordMatch", "1.3.6.1.4.1.1466.115.121.1.15"),
            (
                "1.3.6.1.4.1.1466.109.114.2",
                "caseIgnoreIA5Match",
                "1.3.6.1.4.1.1466.115.121.1.26",
            ),
            (
                "1.3.6.1.4.1.1466.109.114.1",
                "caseExactIA5Match",
                "1.3.6.1.4.1.1466.115.121.1.26",
            ),
            (
                "1.3.6.1.4.1.1466.109.114.3",
                "caseIgnoreIA5SubstringsMatch",
                "1.3.6.1.4.1.1466.115.121.1.26",
            ),
            (
                "1.3.6.1.4.1.4203.1.2.1",
                "caseExactIA5SubstringsMatch",
                "1.3.6.1.4.1.1466.115.121.1.26",
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

    fn replace_attribute_type_with_metadata(
        &mut self,
        attr: AttributeType,
        metadata: AttributeTypeMetadata,
    ) {
        let oid = attr.oid.clone();
        let existing_names = self
            .attribute_types
            .iter()
            .filter_map(|(name, existing)| (existing.oid == oid).then_some(name.clone()))
            .collect::<Vec<_>>();
        for name in existing_names {
            self.attribute_types.remove(&name);
        }
        self.add_attribute_type_with_metadata(attr, metadata);
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

    fn replace_object_class_with_metadata(
        &mut self,
        object_class: ObjectClass,
        metadata: SchemaElementMetadata,
    ) {
        let oid = object_class.oid.clone();
        let existing_names = self
            .object_classes
            .iter()
            .filter_map(|(name, existing)| (existing.oid == oid).then_some(name.clone()))
            .collect::<Vec<_>>();
        for name in existing_names {
            self.object_classes.remove(&name);
        }
        self.add_object_class_with_metadata(object_class, metadata);
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
        let type_name = attribute_description_type_name(name);
        self.attribute_types
            .get(&type_name.to_lowercase())
            .or_else(|| self.attribute_types_by_oid.get(type_name))
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

    pub fn attribute_types_match(&self, left: &str, right: &str) -> bool {
        if attribute_description_type_name(left)
            .eq_ignore_ascii_case(attribute_description_type_name(right))
        {
            return true;
        }

        let Some(left_attribute) = self.get_attribute_type(left) else {
            return false;
        };
        self.get_attribute_type(right)
            .is_some_and(|right_attribute| left_attribute.oid == right_attribute.oid)
    }

    pub fn is_collective_attribute(&self, name: &str) -> bool {
        self.get_attribute_metadata(name)
            .is_some_and(|metadata| metadata.collective)
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
        if x509_matching_rule_applies_to_syntax(
            supported_matching_rule_kind(&rule),
            &profile.syntax_oid,
        ) {
            return Ok(rule);
        }
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
        let mut files = Vec::new();
        collect_schema_files(schema_dir, &mut files)?;
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
            return self.merge_compatible_attribute_type(attr, metadata);
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

    fn merge_compatible_attribute_type(
        &mut self,
        attr: AttributeType,
        metadata: AttributeTypeMetadata,
    ) -> Result<(), SchemaError> {
        let Some(existing) = self.attribute_types_by_oid.get(&attr.oid).cloned() else {
            self.add_attribute_type_with_metadata(attr, metadata);
            return Ok(());
        };
        let existing_metadata = self
            .attribute_metadata_by_oid
            .get(&attr.oid)
            .cloned()
            .unwrap_or_default();
        if existing == attr && existing_metadata == metadata {
            return Ok(());
        }
        if !compatible_optional_name(&existing.equality, &attr.equality)
            || !compatible_schema_value(&existing.syntax, &attr.syntax)
            || existing.single_value != attr.single_value
        {
            return Err(SchemaError::DuplicateOid(attr.oid));
        }

        let names = merged_schema_names(&existing.names, &attr.names);
        for name in &names {
            let normalized = name.to_lowercase();
            if let Some(existing_by_name) = self.attribute_types.get(&normalized)
                && existing_by_name.oid != existing.oid
            {
                return Err(SchemaError::DuplicateName(name.clone()));
            }
        }

        let metadata = merge_attribute_metadata(&existing_metadata, &metadata)
            .ok_or_else(|| SchemaError::DuplicateOid(attr.oid.clone()))?;
        let merged = AttributeType {
            oid: existing.oid.clone(),
            names,
            description: existing.description.or(attr.description),
            equality: existing.equality.or(attr.equality),
            syntax: if existing.syntax.is_empty() {
                attr.syntax
            } else {
                existing.syntax
            },
            single_value: existing.single_value,
        };
        self.replace_attribute_type_with_metadata(merged, metadata);
        Ok(())
    }

    fn try_add_object_class_with_metadata(
        &mut self,
        object_class: ObjectClass,
        metadata: SchemaElementMetadata,
    ) -> Result<(), SchemaError> {
        if self.object_classes_by_oid.contains_key(&object_class.oid) {
            return self.merge_compatible_object_class(object_class, metadata);
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

    fn merge_compatible_object_class(
        &mut self,
        object_class: ObjectClass,
        metadata: SchemaElementMetadata,
    ) -> Result<(), SchemaError> {
        let Some(existing) = self.object_classes_by_oid.get(&object_class.oid).cloned() else {
            self.add_object_class_with_metadata(object_class, metadata);
            return Ok(());
        };
        let existing_metadata = self
            .object_class_metadata_by_oid
            .get(&object_class.oid)
            .cloned()
            .unwrap_or_default();
        if existing == object_class && existing_metadata == metadata {
            return Ok(());
        }
        if existing.kind != object_class.kind
            || !schema_name_sets_equal(&existing.sup, &object_class.sup)
            || !schema_name_sets_equal(&existing.must, &object_class.must)
        {
            return Err(SchemaError::DuplicateOid(object_class.oid));
        }

        let names = merged_schema_names(&existing.names, &object_class.names);
        for name in &names {
            let normalized = name.to_lowercase();
            if let Some(existing_by_name) = self.object_classes.get(&normalized)
                && existing_by_name.oid != existing.oid
            {
                return Err(SchemaError::DuplicateName(name.clone()));
            }
        }

        let metadata = merge_schema_element_metadata(&existing_metadata, &metadata)
            .ok_or_else(|| SchemaError::DuplicateOid(object_class.oid.clone()))?;
        let merged = ObjectClass {
            oid: existing.oid.clone(),
            names,
            sup: existing.sup,
            kind: existing.kind,
            must: existing.must,
            may: merged_schema_names(&existing.may, &object_class.may),
        };
        self.replace_object_class_with_metadata(merged, metadata);
        Ok(())
    }

    fn try_add_ldap_syntax(&mut self, syntax: LdapSyntax) -> Result<(), SchemaError> {
        if let Some(existing) = self.ldap_syntaxes.get(&syntax.oid) {
            if existing == &syntax {
                return Ok(());
            }
            if existing.obsolete != syntax.obsolete || existing.extensions != syntax.extensions {
                return Err(SchemaError::DuplicateOid(syntax.oid));
            }
            let mut merged = existing.clone();
            if merged.description.is_none() {
                merged.description = syntax.description;
            }
            self.ldap_syntaxes.insert(merged.oid.clone(), merged);
            return Ok(());
        }
        self.ldap_syntaxes.insert(syntax.oid.clone(), syntax);
        Ok(())
    }

    fn try_add_matching_rule(&mut self, rule: MatchingRule) -> Result<(), SchemaError> {
        if let Some(existing) = self.matching_rules_by_oid.get(&rule.oid) {
            if existing == &rule {
                return Ok(());
            }
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
        if let Some(existing) = self.matching_rule_uses_by_oid.get(&rule_use.oid) {
            if existing == &rule_use {
                return Ok(());
            }
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
        if let Some(existing) = self.dit_content_rules.get(&rule.oid) {
            if existing == &rule {
                return Ok(());
            }
            return Err(SchemaError::DuplicateOid(rule.oid));
        }
        self.dit_content_rules.insert(rule.oid.clone(), rule);
        Ok(())
    }

    fn try_add_name_form(&mut self, name_form: NameForm) -> Result<(), SchemaError> {
        if let Some(existing) = self.name_forms_by_oid.get(&name_form.oid) {
            if existing == &name_form {
                return Ok(());
            }
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
        if let Some(existing) = self.dit_structure_rules.get(&rule.rule_id) {
            if existing == &rule {
                return Ok(());
            }
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
            if let Some(superior) = metadata.superior.as_deref() {
                let Some(superior_attribute) = self.get_attribute_type(superior) else {
                    return Err(SchemaError::MissingDependency(format!(
                        "attribute {} references unknown superior {}",
                        attribute
                            .names
                            .first()
                            .map(String::as_str)
                            .unwrap_or(&attribute.oid),
                        superior
                    )));
                };
                if self
                    .attribute_metadata_by_oid
                    .get(&superior_attribute.oid)
                    .is_some_and(|superior_metadata| superior_metadata.collective)
                    && !metadata.collective
                {
                    return Err(SchemaError::MissingDependency(format!(
                        "non-collective attribute {} must not subtype collective attribute {}",
                        attribute
                            .names
                            .first()
                            .map(String::as_str)
                            .unwrap_or(&attribute.oid),
                        superior
                    )));
                }
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
                let Some(attribute_type) = self.get_attribute_type(attribute) else {
                    return Err(SchemaError::MissingDependency(format!(
                        "object class {} references unknown attribute {}",
                        object_class
                            .names
                            .first()
                            .map(String::as_str)
                            .unwrap_or(&object_class.oid),
                        attribute
                    )));
                };
                if self
                    .attribute_metadata_by_oid
                    .get(&attribute_type.oid)
                    .is_some_and(|metadata| metadata.collective)
                {
                    return Err(SchemaError::MissingDependency(format!(
                        "object class {} must not list collective attribute {} in MUST or MAY",
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

        for rule_use in self.matching_rule_uses_by_oid.values() {
            if self.get_matching_rule(&rule_use.oid).is_none() {
                return Err(SchemaError::MissingDependency(format!(
                    "matching rule use {} references unknown matching rule {}",
                    rule_use
                        .names
                        .first()
                        .map(String::as_str)
                        .unwrap_or(&rule_use.oid),
                    rule_use.oid
                )));
            }
            for attribute in &rule_use.applies {
                if self.get_attribute_type(attribute).is_none() {
                    return Err(SchemaError::MissingDependency(format!(
                        "matching rule use {} applies to unknown attribute {}",
                        rule_use
                            .names
                            .first()
                            .map(String::as_str)
                            .unwrap_or(&rule_use.oid),
                        attribute
                    )));
                }
            }
        }

        for rule in self.dit_content_rules.values() {
            let Some(structural_class) = self.get_object_class(&rule.oid) else {
                return Err(SchemaError::MissingDependency(format!(
                    "DIT content rule {} references unknown structural object class {}",
                    rule.names.first().map(String::as_str).unwrap_or(&rule.oid),
                    rule.oid
                )));
            };
            if structural_class.kind != ObjectClassKind::Structural {
                return Err(SchemaError::MissingDependency(format!(
                    "DIT content rule {} references non-structural object class {}",
                    rule.names.first().map(String::as_str).unwrap_or(&rule.oid),
                    structural_class
                        .names
                        .first()
                        .map(String::as_str)
                        .unwrap_or(&structural_class.oid)
                )));
            }
            for auxiliary in &rule.auxiliary {
                let Some(object_class) = self.get_object_class(auxiliary) else {
                    return Err(SchemaError::MissingDependency(format!(
                        "DIT content rule {} references unknown auxiliary class {}",
                        rule.names.first().map(String::as_str).unwrap_or(&rule.oid),
                        auxiliary
                    )));
                };
                if object_class.kind != ObjectClassKind::Auxiliary {
                    return Err(SchemaError::MissingDependency(format!(
                        "DIT content rule {} references non-auxiliary class {}",
                        rule.names.first().map(String::as_str).unwrap_or(&rule.oid),
                        auxiliary
                    )));
                }
            }
            for attribute in rule
                .must
                .iter()
                .chain(rule.may.iter())
                .chain(rule.not.iter())
            {
                if self.get_attribute_type(attribute).is_none() {
                    return Err(SchemaError::MissingDependency(format!(
                        "DIT content rule {} references unknown attribute {}",
                        rule.names.first().map(String::as_str).unwrap_or(&rule.oid),
                        attribute
                    )));
                }
            }
        }

        for name_form in self.name_forms_by_oid.values() {
            let Some(object_class) = self.get_object_class(&name_form.object_class) else {
                return Err(SchemaError::MissingDependency(format!(
                    "name form {} references unknown object class {}",
                    name_form
                        .names
                        .first()
                        .map(String::as_str)
                        .unwrap_or(&name_form.oid),
                    name_form.object_class
                )));
            };
            if object_class.kind != ObjectClassKind::Structural {
                return Err(SchemaError::MissingDependency(format!(
                    "name form {} references non-structural object class {}",
                    name_form
                        .names
                        .first()
                        .map(String::as_str)
                        .unwrap_or(&name_form.oid),
                    name_form.object_class
                )));
            }
            for attribute in name_form.must.iter().chain(name_form.may.iter()) {
                if self.get_attribute_type(attribute).is_none() {
                    return Err(SchemaError::MissingDependency(format!(
                        "name form {} references unknown attribute {}",
                        name_form
                            .names
                            .first()
                            .map(String::as_str)
                            .unwrap_or(&name_form.oid),
                        attribute
                    )));
                }
            }
        }

        for structure_rule in self.dit_structure_rules.values() {
            if self.get_name_form(&structure_rule.name_form).is_none() {
                return Err(SchemaError::MissingDependency(format!(
                    "DIT structure rule {} references unknown name form {}",
                    structure_rule_label(structure_rule),
                    structure_rule.name_form
                )));
            }
            for superior_rule in &structure_rule.superior_rules {
                if !self.dit_structure_rules.contains_key(superior_rule) {
                    return Err(SchemaError::MissingDependency(format!(
                        "DIT structure rule {} references unknown superior rule {}",
                        structure_rule_label(structure_rule),
                        superior_rule
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
        let (mut must_attrs, mut may_attrs) = self.collect_attributes(&oc_definitions);
        if let Some(rule) = self.applicable_dit_content_rule(&oc_definitions)? {
            must_attrs.extend(rule.must.iter().cloned());
            may_attrs.extend(rule.may.iter().cloned());
        }

        // Validate required attributes are present
        for must_attr in &must_attrs {
            let attr_lower = must_attr.to_lowercase();
            let must_oid = self
                .get_attribute_type(must_attr)
                .map(|attribute| attribute.oid.as_str());
            let found = attributes.keys().any(|k| {
                let entry_attr = attribute_description_type_name(k);
                entry_attr.to_lowercase() == attr_lower
                    || must_oid.is_some_and(|oid| {
                        self.get_attribute_type(entry_attr)
                            .is_some_and(|attribute| attribute.oid == oid)
                    })
            });
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
        let allowed_oids: HashSet<String> = must_attrs
            .iter()
            .chain(may_attrs.iter())
            .filter_map(|name| self.get_attribute_type(name).map(|attr| attr.oid.clone()))
            .collect();

        let is_collective_attribute_subentry =
            entry_declares_object_class(attributes, "collectiveAttributeSubentry");
        for attr_name in attributes.keys() {
            let attr_lower = attribute_description_type_name(attr_name).to_lowercase();
            if !all_allowed.contains(&attr_lower) {
                // Check if attribute exists in schema
                let Some(attr_type) = self.get_attribute_type(attr_name) else {
                    return Err(SchemaError::AttributeNotFound(attr_name.clone()));
                };
                if self
                    .attribute_metadata_by_oid
                    .get(&attr_type.oid)
                    .is_some_and(|metadata| metadata.collective)
                {
                    if is_collective_attribute_subentry {
                        continue;
                    }
                    return Err(SchemaError::AttributeNotAllowed(attr_name.clone()));
                }
                if allowed_oids.contains(&attr_type.oid) {
                    continue;
                }
                if self.attribute_is_globally_allowed_operational(attr_type) {
                    continue;
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

    pub fn has_dit_structure_rules(&self) -> bool {
        !self.dit_structure_rules.is_empty()
    }

    pub fn requires_parent_attributes_for_entry(
        &self,
        attributes: &HashMap<String, Vec<String>>,
    ) -> bool {
        self.has_dit_structure_rules() || entry_declares_object_class(attributes, "subentry")
    }

    pub fn validate_entry_at_dn(
        &self,
        dn: &str,
        attributes: &HashMap<String, Vec<String>>,
        parent_attributes: Option<&HashMap<String, Vec<String>>>,
    ) -> Result<(), SchemaError> {
        self.validate_entry(attributes)?;
        let rdn = parse_dn(dn)
            .map_err(|err| SchemaError::NamingViolation(format!("Invalid DN syntax: {}", err)))?
            .rdns()
            .first()
            .ok_or_else(|| SchemaError::NamingViolation("DN must not be empty".to_string()))?
            .to_canonical_string();
        self.validate_rdn_for_entry(attributes, &rdn)?;
        self.validate_subentry_administrative_parent(attributes, parent_attributes)?;
        self.validate_dit_structure_for_entry(attributes, parent_attributes)
    }

    pub fn validate_renamed_entry(
        &self,
        original_dn: &str,
        attributes: &HashMap<String, Vec<String>>,
        new_rdn: &str,
        delete_old: bool,
        parent_attributes: Option<&HashMap<String, Vec<String>>>,
    ) -> Result<(), SchemaError> {
        let candidate_attributes =
            candidate_attributes_for_rename(original_dn, attributes, new_rdn, delete_old)?;
        self.validate_rdn_for_entry(&candidate_attributes, new_rdn)?;
        self.validate_entry(&candidate_attributes)?;
        self.validate_subentry_administrative_parent(&candidate_attributes, parent_attributes)?;
        self.validate_dit_structure_for_entry(&candidate_attributes, parent_attributes)
    }

    fn attribute_is_globally_allowed_operational(&self, attr_type: &AttributeType) -> bool {
        matches!(
            attr_type.oid.as_str(),
            "2.5.18.5" | "2.5.18.7" | "2.5.18.12"
        ) && self
            .attribute_metadata_by_oid
            .get(&attr_type.oid)
            .and_then(|metadata| metadata.usage.as_deref())
            .is_some_and(|usage| usage.eq_ignore_ascii_case("directoryOperation"))
    }

    fn validate_subentry_administrative_parent(
        &self,
        attributes: &HashMap<String, Vec<String>>,
        parent_attributes: Option<&HashMap<String, Vec<String>>>,
    ) -> Result<(), SchemaError> {
        if entry_declares_object_class(attributes, "collectiveAttributeSubentry")
            && !entry_declares_object_class(attributes, "subentry")
        {
            return Err(SchemaError::StructureRuleViolation(
                "collectiveAttributeSubentry must be used with the subentry structural object class"
                    .to_string(),
            ));
        }
        if !entry_declares_object_class(attributes, "subentry") {
            return Ok(());
        }
        let Some(parent_attributes) = parent_attributes else {
            return Err(SchemaError::StructureRuleViolation(
                "subentry requires a parent administrative entry with administrativeRole"
                    .to_string(),
            ));
        };
        if attribute_values(parent_attributes, "administrativeRole").is_none_or(|roles| {
            roles
                .iter()
                .all(|role| !is_valid_oid_or_descriptor(role.as_str()))
        }) {
            return Err(SchemaError::StructureRuleViolation(
                "subentry parent must define administrativeRole".to_string(),
            ));
        }
        if entry_declares_object_class(attributes, "collectiveAttributeSubentry")
            && attribute_values(parent_attributes, "administrativeRole").is_none_or(|roles| {
                roles.iter().all(|role| {
                    !role.eq_ignore_ascii_case("collectiveAttributeSpecificArea")
                        && !role.eq_ignore_ascii_case("collectiveAttributeInnerArea")
                        && role != "2.5.23.5"
                        && role != "2.5.23.6"
                })
            })
        {
            return Err(SchemaError::StructureRuleViolation(
                "collectiveAttributeSubentry requires a parent administrative entry with collectiveAttributeSpecificArea or collectiveAttributeInnerArea"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_dit_structure_for_entry(
        &self,
        attributes: &HashMap<String, Vec<String>>,
        parent_attributes: Option<&HashMap<String, Vec<String>>>,
    ) -> Result<(), SchemaError> {
        let entry_rules = self.applicable_dit_structure_rules_for_attributes(attributes)?;
        if entry_rules.is_empty() {
            return Ok(());
        }
        for rule in &entry_rules {
            if rule.obsolete {
                return Err(SchemaError::StructureRuleViolation(format!(
                    "DIT structure rule {} is obsolete",
                    structure_rule_label(rule)
                )));
            }
        }
        if entry_rules
            .iter()
            .any(|rule| rule.superior_rules.is_empty())
        {
            return Ok(());
        }

        let Some(parent_attributes) = parent_attributes else {
            let expected = entry_rules
                .iter()
                .flat_map(|rule| rule.superior_rules.iter())
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(SchemaError::StructureRuleViolation(format!(
                "entry requires a parent governed by one of DIT structure rules: {}",
                expected
            )));
        };

        let parent_rule_ids = self
            .applicable_dit_structure_rules_for_attributes(parent_attributes)?
            .into_iter()
            .map(|rule| rule.rule_id)
            .collect::<HashSet<_>>();

        if entry_rules.iter().any(|rule| {
            rule.superior_rules
                .iter()
                .any(|superior| parent_rule_ids.contains(superior))
        }) {
            return Ok(());
        }

        let expected = entry_rules
            .iter()
            .flat_map(|rule| rule.superior_rules.iter())
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let actual = if parent_rule_ids.is_empty() {
            "no applicable DIT structure rule".to_string()
        } else {
            parent_rule_ids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        Err(SchemaError::StructureRuleViolation(format!(
            "parent is governed by {}, but entry requires one of DIT structure rules: {}",
            actual, expected
        )))
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
        let applicable_name_forms = self.applicable_name_forms_for_attributes(attributes)?;
        if applicable_name_forms.is_empty() {
            return Ok(());
        }

        let mut diagnostics = Vec::new();
        for name_form in applicable_name_forms {
            match self.rdn_satisfies_name_form(attributes, &rdn, name_form) {
                Ok(()) => return Ok(()),
                Err(err) => diagnostics.push(err),
            }
        }

        Err(SchemaError::NamingViolation(diagnostics.join("; ")))
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

    fn structural_class_definitions_for_attributes(
        &self,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<&ObjectClass>, SchemaError> {
        let object_classes = attributes
            .get("objectclass")
            .or_else(|| attributes.get("objectClass"))
            .ok_or(SchemaError::MissingRequiredAttribute(
                "objectClass".to_string(),
            ))?;
        Ok(object_classes
            .iter()
            .filter_map(|object_class| self.get_object_class(object_class))
            .filter(|object_class| object_class.kind == ObjectClassKind::Structural)
            .collect())
    }

    fn leaf_structural_class<'a>(
        &self,
        oc_definitions: &'a [&ObjectClass],
    ) -> Result<Option<&'a ObjectClass>, SchemaError> {
        let structural = oc_definitions
            .iter()
            .copied()
            .filter(|object_class| object_class.kind == ObjectClassKind::Structural)
            .collect::<Vec<_>>();
        if structural.is_empty() {
            return Ok(None);
        }

        let leaves = structural
            .iter()
            .copied()
            .filter(|candidate| {
                !structural.iter().any(|other| {
                    candidate.oid != other.oid && self.object_class_is_superior_of(candidate, other)
                })
            })
            .collect::<Vec<_>>();

        match leaves.as_slice() {
            [leaf] => Ok(Some(*leaf)),
            _ => Err(SchemaError::MultipleStructuralClasses),
        }
    }

    fn object_class_is_superior_of(&self, superior: &ObjectClass, child: &ObjectClass) -> bool {
        let mut superiors = HashSet::new();
        self.collect_superior_classes(&child.names[0], &mut superiors);
        superiors.iter().any(|candidate| {
            candidate.eq_ignore_ascii_case(&superior.oid)
                || superior
                    .names
                    .iter()
                    .any(|name| candidate.eq_ignore_ascii_case(name))
        })
    }

    fn applicable_dit_content_rule<'a>(
        &'a self,
        oc_definitions: &[&ObjectClass],
    ) -> Result<Option<&'a DitContentRule>, SchemaError> {
        let Some(structural) = self.leaf_structural_class(oc_definitions)? else {
            return Ok(None);
        };
        Ok(self.dit_content_rules.get(&structural.oid))
    }

    fn get_name_form(&self, name_or_oid: &str) -> Option<&NameForm> {
        self.name_forms
            .get(&name_or_oid.to_lowercase())
            .or_else(|| self.name_forms_by_oid.get(name_or_oid))
    }

    fn applicable_name_forms_for_attributes(
        &self,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<&NameForm>, SchemaError> {
        let structural = self.structural_class_definitions_for_attributes(attributes)?;
        let Some(leaf) = self.leaf_structural_class(&structural)? else {
            return Ok(Vec::new());
        };
        Ok(self
            .name_forms_by_oid
            .values()
            .filter(|name_form| {
                self.get_object_class(&name_form.object_class)
                    .is_some_and(|object_class| object_class.oid == leaf.oid)
            })
            .collect())
    }

    fn applicable_dit_structure_rules_for_attributes(
        &self,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<&DitStructureRule>, SchemaError> {
        let structural = self.structural_class_definitions_for_attributes(attributes)?;
        let Some(leaf) = self.leaf_structural_class(&structural)? else {
            return Ok(Vec::new());
        };
        Ok(self
            .dit_structure_rules
            .values()
            .filter(|rule| {
                self.get_name_form(&rule.name_form)
                    .and_then(|name_form| self.get_object_class(&name_form.object_class))
                    .is_some_and(|object_class| object_class.oid == leaf.oid)
            })
            .collect())
    }

    fn rdn_satisfies_name_form(
        &self,
        attributes: &HashMap<String, Vec<String>>,
        rdn: &crate::dn::Rdn,
        name_form: &NameForm,
    ) -> Result<(), String> {
        let name_form_name = name_form
            .names
            .first()
            .map(String::as_str)
            .unwrap_or(&name_form.oid);
        let rdn_attributes = rdn
            .avas()
            .iter()
            .map(|ava| ava.attribute().to_ascii_lowercase())
            .collect::<HashSet<_>>();

        for required in &name_form.must {
            if !rdn_attributes.contains(&required.to_ascii_lowercase()) {
                return Err(format!(
                    "RDN is missing required attribute {} from name form {}",
                    required, name_form_name
                ));
            }
        }

        for ava in rdn.avas() {
            if !name_form
                .must
                .iter()
                .chain(name_form.may.iter())
                .any(|candidate| candidate.eq_ignore_ascii_case(ava.attribute()))
            {
                return Err(format!(
                    "RDN attribute {} is not allowed by name form {}",
                    ava.attribute(),
                    name_form_name
                ));
            }
            if !self.entry_contains_attribute_value(attributes, ava.attribute(), ava.value())? {
                return Err(format!(
                    "RDN value {}={} is not present in the entry",
                    ava.attribute(),
                    ava.value()
                ));
            }
        }

        Ok(())
    }

    fn entry_contains_attribute_value(
        &self,
        attributes: &HashMap<String, Vec<String>>,
        attribute: &str,
        value: &str,
    ) -> Result<bool, String> {
        let Some((stored_name, values)) = attributes
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(attribute))
        else {
            return Ok(false);
        };

        let equality = self
            .get_attribute_type(stored_name)
            .and_then(|attribute_type| attribute_type.equality.as_deref())
            .and_then(|rule| self.resolve_matching_rule(rule).ok());

        for candidate in values {
            let matches = if let Some(rule) = &equality {
                rule.values_equal(candidate, value)
                    .map_err(|err| err.to_string())?
            } else {
                candidate == value
            };
            if matches {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn validate_dit_content_rules(
        &self,
        oc_definitions: &[&ObjectClass],
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<(), SchemaError> {
        let Some(structural) = self.leaf_structural_class(oc_definitions)? else {
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
        })?;

        if effective.oid == "2.16.840.1.113730.3.1.39" {
            validate_preferred_language(value)
                .map_err(|reason| SchemaError::InvalidSyntax(attr_name.to_string(), reason))?;
        }
        validate_rfc2307_attribute_semantics(&effective.oid, value)
            .map_err(|reason| SchemaError::InvalidSyntax(attr_name.to_string(), reason))?;

        Ok(())
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

fn collect_schema_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), SchemaError> {
    for entry in fs::read_dir(dir)
        .map_err(|err| SchemaError::IoError(format!("{}: {}", dir.display(), err)))?
    {
        let entry =
            entry.map_err(|err| SchemaError::IoError(format!("{}: {}", dir.display(), err)))?;
        let path = entry.path();
        if path.is_dir() {
            collect_schema_files(&path, files)?;
        } else if is_schema_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_schema_file(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("ldif")
                    || extension.eq_ignore_ascii_case("schema")
                    || extension.eq_ignore_ascii_case("conf")
            })
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
        if !self.syntax.is_empty() {
            parts.push(format!("SYNTAX {}", self.syntax));
        }
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

fn structure_rule_label(rule: &DitStructureRule) -> String {
    rule.names
        .first()
        .cloned()
        .unwrap_or_else(|| rule.rule_id.to_string())
}

fn candidate_attributes_for_rename(
    original_dn: &str,
    attributes: &HashMap<String, Vec<String>>,
    new_rdn: &str,
    delete_old: bool,
) -> Result<HashMap<String, Vec<String>>, SchemaError> {
    let mut candidate = attributes.clone();

    if delete_old
        && let Some(old_rdn) = parse_dn(original_dn)
            .map_err(|err| SchemaError::NamingViolation(format!("Invalid DN syntax: {}", err)))?
            .rdns()
            .first()
            .cloned()
    {
        for ava in old_rdn.avas() {
            if let Some(key) = attribute_key_case_insensitive(&candidate, ava.attribute()) {
                let values = candidate
                    .get_mut(&key)
                    .expect("key was selected from the same attributes map");
                values.retain(|candidate| candidate != ava.value());
                if values.is_empty() {
                    candidate.remove(&key);
                }
            }
        }
    }

    for (attribute, value) in rdn_attribute_values(new_rdn)
        .map_err(|err| SchemaError::NamingViolation(format!("Invalid RDN syntax: {}", err)))?
    {
        let key = attribute_key_case_insensitive(&candidate, &attribute).unwrap_or(attribute);
        let values = candidate.entry(key).or_default();
        if !values.contains(&value) {
            values.push(value);
        }
    }

    Ok(candidate)
}

fn attribute_key_case_insensitive(
    attributes: &HashMap<String, Vec<String>>,
    attribute: &str,
) -> Option<String> {
    attributes
        .keys()
        .find(|candidate| candidate.eq_ignore_ascii_case(attribute))
        .cloned()
}

fn attribute_description_type_name(attribute_description: &str) -> &str {
    attribute_description
        .split_once(';')
        .map_or(attribute_description, |(attribute_type, _)| attribute_type)
}

fn attribute_values<'a>(
    attributes: &'a HashMap<String, Vec<String>>,
    attribute_type: &str,
) -> Option<&'a Vec<String>> {
    attributes
        .iter()
        .find(|(name, _)| {
            attribute_description_type_name(name).eq_ignore_ascii_case(attribute_type)
        })
        .map(|(_, values)| values)
}

fn entry_declares_object_class(
    attributes: &HashMap<String, Vec<String>>,
    object_class: &str,
) -> bool {
    attribute_values(attributes, "objectClass").is_some_and(|values| {
        values
            .iter()
            .any(|value| value.eq_ignore_ascii_case(object_class))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubtreeSpecification {
    pub(crate) base: Option<String>,
    pub(crate) specific_exclusions: Vec<SpecificExclusion>,
    pub(crate) minimum: u32,
    pub(crate) maximum: Option<u32>,
    pub(crate) specification_filter: Option<Refinement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpecificExclusion {
    pub(crate) kind: SpecificExclusionKind,
    pub(crate) local_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecificExclusionKind {
    ChopBefore,
    ChopAfter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refinement {
    Item(String),
    And(Vec<Refinement>),
    Or(Vec<Refinement>),
    Not(Box<Refinement>),
}

impl SubtreeSpecification {
    pub(crate) fn contains_entry(
        &self,
        administrative_point_dn: &str,
        entry_dn: &str,
        object_classes: &[String],
    ) -> bool {
        let base_dn = self
            .base
            .as_deref()
            .filter(|base| !base.is_empty())
            .map(|base| format!("{base},{administrative_point_dn}"))
            .unwrap_or_else(|| administrative_point_dn.to_string());
        if !crate::dn::dn_is_in_scope(entry_dn, &base_dn, ldap_parser::ldap::SearchScope(2)) {
            return false;
        }

        let Some(distance) = subtree_base_distance(&base_dn, entry_dn) else {
            return false;
        };
        if distance < self.minimum {
            return false;
        }
        if self.maximum.is_some_and(|maximum| distance > maximum) {
            return false;
        }
        if self
            .specific_exclusions
            .iter()
            .any(|exclusion| exclusion.excludes(&base_dn, entry_dn))
        {
            return false;
        }
        self.specification_filter
            .as_ref()
            .is_none_or(|filter| filter.matches(object_classes))
    }
}

impl SpecificExclusion {
    fn excludes(&self, base_dn: &str, entry_dn: &str) -> bool {
        let excluded_dn = if self.local_name.is_empty() {
            base_dn.to_string()
        } else {
            format!("{},{}", self.local_name, base_dn)
        };
        match self.kind {
            SpecificExclusionKind::ChopBefore => {
                crate::dn::dn_is_in_scope(entry_dn, &excluded_dn, ldap_parser::ldap::SearchScope(2))
            }
            SpecificExclusionKind::ChopAfter => {
                !crate::dn::dn_eq(entry_dn, &excluded_dn)
                    && crate::dn::dn_is_in_scope(
                        entry_dn,
                        &excluded_dn,
                        ldap_parser::ldap::SearchScope(2),
                    )
            }
        }
    }
}

impl Refinement {
    fn matches(&self, object_classes: &[String]) -> bool {
        match self {
            Self::Item(expected) => object_classes
                .iter()
                .any(|object_class| object_class.eq_ignore_ascii_case(expected)),
            Self::And(children) => children.iter().all(|child| child.matches(object_classes)),
            Self::Or(children) => children.iter().any(|child| child.matches(object_classes)),
            Self::Not(child) => !child.matches(object_classes),
        }
    }
}

pub(crate) fn parse_subtree_specification(value: &str) -> Result<SubtreeSpecification, String> {
    let inner = braced_inner(value, "SubtreeSpecification")?;
    let components = split_gser_components(inner)?;
    let mut seen = HashSet::new();
    let mut last_order = 0usize;
    let mut spec = SubtreeSpecification {
        base: None,
        specific_exclusions: Vec::new(),
        minimum: 0,
        maximum: None,
        specification_filter: None,
    };

    for component in components {
        let (keyword, rest) = split_gser_keyword(component)?;
        let (order, normalized_keyword) = match keyword {
            "base" => (1, "base"),
            "specificExclusions" => (2, "specificExclusions"),
            "minimum" => (3, "minimum"),
            "maximum" => (4, "maximum"),
            "specificationFilter" => (5, "specificationFilter"),
            _ => {
                return Err(format!("unknown SubtreeSpecification component {keyword}"));
            }
        };
        if order < last_order {
            return Err("SubtreeSpecification components must follow RFC 3672 order".to_string());
        }
        if !seen.insert(normalized_keyword) {
            return Err(format!(
                "duplicate SubtreeSpecification component {normalized_keyword}"
            ));
        }
        last_order = order;

        match normalized_keyword {
            "base" => spec.base = Some(parse_local_name(rest)?),
            "specificExclusions" => {
                spec.specific_exclusions = parse_specific_exclusions(rest)?;
            }
            "minimum" => spec.minimum = parse_base_distance(rest, "minimum")?,
            "maximum" => spec.maximum = Some(parse_base_distance(rest, "maximum")?),
            "specificationFilter" => {
                spec.specification_filter = Some(parse_refinement(rest, 0)?);
            }
            _ => unreachable!("keyword match above restricts components"),
        }
    }

    if let Some(maximum) = spec.maximum
        && spec.minimum > maximum
    {
        return Err("SubtreeSpecification minimum must not exceed maximum".to_string());
    }

    Ok(spec)
}

fn validate_subtree_specification(value: &str) -> Result<(), String> {
    parse_subtree_specification(value).map(|_| ())
}

fn subtree_base_distance(base_dn: &str, entry_dn: &str) -> Option<u32> {
    let base = parse_dn(base_dn).ok()?;
    let entry = parse_dn(entry_dn).ok()?;
    if !entry.is_descendant_or_equal_of(&base) {
        return None;
    }
    let distance = entry.rdns().len().checked_sub(base.rdns().len())?;
    u32::try_from(distance).ok()
}

fn braced_inner<'a>(value: &'a str, label: &str) -> Result<&'a str, String> {
    let trimmed = value.trim();
    let Some(inner) = trimmed
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return Err(format!("{label} must be enclosed in braces"));
    };
    Ok(inner.trim())
}

fn split_gser_keyword(component: &str) -> Result<(&str, &str), String> {
    let component = component.trim();
    let Some(index) = component.find(char::is_whitespace) else {
        return Err(format!(
            "SubtreeSpecification component {component} has no value"
        ));
    };
    let keyword = &component[..index];
    let rest = component[index..].trim();
    if rest.is_empty() {
        return Err(format!(
            "SubtreeSpecification component {keyword} has no value"
        ));
    }
    Ok((keyword, rest))
}

fn split_gser_components(value: &str) -> Result<Vec<&str>, String> {
    let mut components = Vec::new();
    let mut depth = 0_i32;
    let mut in_quote = false;
    let mut escaped = false;
    let mut start = 0usize;

    for (index, ch) in value.char_indices() {
        if in_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quote = false;
            }
            continue;
        }

        match ch {
            '"' => in_quote = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return Err("unbalanced braces in SubtreeSpecification".to_string());
                }
            }
            ',' if depth == 0 => {
                let component = value[start..index].trim();
                if component.is_empty() {
                    return Err("empty component in SubtreeSpecification".to_string());
                }
                components.push(component);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }

    if in_quote {
        return Err("unterminated quoted value in SubtreeSpecification".to_string());
    }
    if depth != 0 {
        return Err("unbalanced braces in SubtreeSpecification".to_string());
    }

    let trailing = value[start..].trim();
    if !trailing.is_empty() {
        components.push(trailing);
    } else if !value.trim().is_empty() && value.trim_end().ends_with(',') {
        return Err("trailing comma in SubtreeSpecification".to_string());
    }
    Ok(components)
}

fn parse_local_name(value: &str) -> Result<String, String> {
    let value = unquote_gser_string(value.trim())?;
    if value.is_empty() {
        return Ok(value);
    }
    canonicalize_dn(&value).map_err(|err| format!("invalid LocalName {value}: {err}"))?;
    Ok(value)
}

fn unquote_gser_string(value: &str) -> Result<String, String> {
    if value.starts_with('"') || value.ends_with('"') {
        if !(value.starts_with('"') && value.ends_with('"') && value.len() >= 2) {
            return Err("quoted LocalName must have both opening and closing quotes".to_string());
        }
        let inner = &value[1..value.len() - 1];
        let mut decoded = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                let Some(next) = chars.next() else {
                    return Err("quoted LocalName has a dangling escape".to_string());
                };
                decoded.push(next);
            } else {
                decoded.push(ch);
            }
        }
        return Ok(decoded);
    }
    Ok(value.to_string())
}

fn parse_specific_exclusions(value: &str) -> Result<Vec<SpecificExclusion>, String> {
    let inner = braced_inner(value, "specificExclusions")?;
    split_gser_components(inner)?
        .into_iter()
        .map(parse_specific_exclusion)
        .collect()
}

fn parse_specific_exclusion(value: &str) -> Result<SpecificExclusion, String> {
    let Some((kind, local_name)) = value.split_once(':') else {
        return Err("specificExclusions entries must use chopBefore: or chopAfter:".to_string());
    };
    let kind = match kind.trim() {
        "chopBefore" => SpecificExclusionKind::ChopBefore,
        "chopAfter" => SpecificExclusionKind::ChopAfter,
        other => return Err(format!("unknown specificExclusions form {other}")),
    };
    Ok(SpecificExclusion {
        kind,
        local_name: parse_local_name(local_name.trim())?,
    })
}

fn parse_base_distance(value: &str, label: &str) -> Result<u32, String> {
    let parsed = parse_integer_syntax(value.trim())?;
    if parsed < 0 {
        return Err(format!("{label} must be a non-negative integer"));
    }
    u32::try_from(parsed).map_err(|_| format!("{label} is outside the supported u32 range"))
}

fn parse_refinement(value: &str, depth: usize) -> Result<Refinement, String> {
    if depth > 32 {
        return Err("specificationFilter nesting is too deep".to_string());
    }
    let Some((kind, rest)) = value.trim().split_once(':') else {
        return Err("specificationFilter refinement must use item, and, or, or not".to_string());
    };
    let kind = kind.trim();
    let rest = rest.trim();
    match kind {
        "item" => {
            if is_valid_oid_or_descriptor(rest) {
                Ok(Refinement::Item(rest.to_string()))
            } else {
                Err("specificationFilter item must be an object identifier".to_string())
            }
        }
        "and" | "or" => {
            let children = parse_refinement_set(rest, depth + 1)?;
            if children.is_empty() {
                return Err(format!(
                    "specificationFilter {kind} requires at least one child"
                ));
            }
            if kind == "and" {
                Ok(Refinement::And(children))
            } else {
                Ok(Refinement::Or(children))
            }
        }
        "not" => Ok(Refinement::Not(Box::new(parse_refinement(
            rest,
            depth + 1,
        )?))),
        other => Err(format!("unknown specificationFilter refinement {other}")),
    }
}

fn parse_refinement_set(value: &str, depth: usize) -> Result<Vec<Refinement>, String> {
    let inner = braced_inner(value, "Refinements")?;
    split_gser_components(inner)?
        .into_iter()
        .map(|component| parse_refinement(component, depth))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedSyntaxKind {
    AttributeTypeDescription,
    Binary,
    BitString,
    Boolean,
    BootParameter,
    Certificate,
    CertificateList,
    CertificatePair,
    CountryString,
    DeliveryMethod,
    DistinguishedName,
    DirectoryString,
    DitContentRuleDescription,
    DitStructureRuleDescription,
    EnhancedGuide,
    FacsimileTelephoneNumber,
    Fax,
    GeneralizedTime,
    Guide,
    Ia5String,
    Integer,
    Jpeg,
    LdapSyntaxDescription,
    MatchingRuleDescription,
    MatchingRuleUseDescription,
    NameAndOptionalUid,
    NameFormDescription,
    NisNetgroupTriple,
    NumericString,
    ObjectClassDescription,
    ObjectIdentifier,
    OtherMailbox,
    OctetString,
    PostalAddress,
    PrintableString,
    SupportedAlgorithm,
    SubtreeSpecification,
    SubstringAssertion,
    TeletexTerminalIdentifier,
    TelephoneNumber,
    TelexNumber,
    UtcTime,
}

fn supported_syntax_kind(syntax_oid: &str) -> Option<SupportedSyntaxKind> {
    match syntax_oid {
        "1.3.6.1.1.1.0.0" => Some(SupportedSyntaxKind::NisNetgroupTriple),
        "1.3.6.1.1.1.0.1" => Some(SupportedSyntaxKind::BootParameter),
        "1.3.6.1.4.1.1466.115.121.1.3" => Some(SupportedSyntaxKind::AttributeTypeDescription),
        "1.3.6.1.4.1.1466.115.121.1.5" => Some(SupportedSyntaxKind::Binary),
        "1.3.6.1.4.1.1466.115.121.1.6" => Some(SupportedSyntaxKind::BitString),
        "1.3.6.1.4.1.1466.115.121.1.7" => Some(SupportedSyntaxKind::Boolean),
        "1.3.6.1.4.1.1466.115.121.1.8" => Some(SupportedSyntaxKind::Certificate),
        "1.3.6.1.4.1.1466.115.121.1.9" => Some(SupportedSyntaxKind::CertificateList),
        "1.3.6.1.4.1.1466.115.121.1.10" => Some(SupportedSyntaxKind::CertificatePair),
        "1.3.6.1.4.1.1466.115.121.1.11" => Some(SupportedSyntaxKind::CountryString),
        "1.3.6.1.4.1.1466.115.121.1.12" => Some(SupportedSyntaxKind::DistinguishedName),
        "1.3.6.1.4.1.1466.115.121.1.14" => Some(SupportedSyntaxKind::DeliveryMethod),
        "1.3.6.1.4.1.1466.115.121.1.15" => Some(SupportedSyntaxKind::DirectoryString),
        "1.3.6.1.4.1.1466.115.121.1.16" => Some(SupportedSyntaxKind::DitContentRuleDescription),
        "1.3.6.1.4.1.1466.115.121.1.17" => Some(SupportedSyntaxKind::DitStructureRuleDescription),
        "1.3.6.1.4.1.1466.115.121.1.21" => Some(SupportedSyntaxKind::EnhancedGuide),
        "1.3.6.1.4.1.1466.115.121.1.22" => Some(SupportedSyntaxKind::FacsimileTelephoneNumber),
        "1.3.6.1.4.1.1466.115.121.1.23" => Some(SupportedSyntaxKind::Fax),
        "1.3.6.1.4.1.1466.115.121.1.24" => Some(SupportedSyntaxKind::GeneralizedTime),
        "1.3.6.1.4.1.1466.115.121.1.25" => Some(SupportedSyntaxKind::Guide),
        "1.3.6.1.4.1.1466.115.121.1.26" => Some(SupportedSyntaxKind::Ia5String),
        "1.3.6.1.4.1.1466.115.121.1.27" => Some(SupportedSyntaxKind::Integer),
        "1.3.6.1.4.1.1466.115.121.1.28" => Some(SupportedSyntaxKind::Jpeg),
        "1.3.6.1.4.1.1466.115.121.1.30" => Some(SupportedSyntaxKind::MatchingRuleDescription),
        "1.3.6.1.4.1.1466.115.121.1.31" => Some(SupportedSyntaxKind::MatchingRuleUseDescription),
        "1.3.6.1.4.1.1466.115.121.1.34" => Some(SupportedSyntaxKind::NameAndOptionalUid),
        "1.3.6.1.4.1.1466.115.121.1.35" => Some(SupportedSyntaxKind::NameFormDescription),
        "1.3.6.1.4.1.1466.115.121.1.36" => Some(SupportedSyntaxKind::NumericString),
        "1.3.6.1.4.1.1466.115.121.1.37" => Some(SupportedSyntaxKind::ObjectClassDescription),
        "1.3.6.1.4.1.1466.115.121.1.38" => Some(SupportedSyntaxKind::ObjectIdentifier),
        "1.3.6.1.4.1.1466.115.121.1.39" => Some(SupportedSyntaxKind::OtherMailbox),
        "1.3.6.1.4.1.1466.115.121.1.40" => Some(SupportedSyntaxKind::OctetString),
        "1.3.6.1.4.1.1466.115.121.1.41" => Some(SupportedSyntaxKind::PostalAddress),
        "1.3.6.1.4.1.1466.115.121.1.44" => Some(SupportedSyntaxKind::PrintableString),
        "1.3.6.1.4.1.1466.115.121.1.45" => Some(SupportedSyntaxKind::SubtreeSpecification),
        "1.3.6.1.4.1.1466.115.121.1.49" => Some(SupportedSyntaxKind::SupportedAlgorithm),
        "1.3.6.1.4.1.1466.115.121.1.50" => Some(SupportedSyntaxKind::TelephoneNumber),
        "1.3.6.1.4.1.1466.115.121.1.51" => Some(SupportedSyntaxKind::TeletexTerminalIdentifier),
        "1.3.6.1.4.1.1466.115.121.1.52" => Some(SupportedSyntaxKind::TelexNumber),
        "1.3.6.1.4.1.1466.115.121.1.53" => Some(SupportedSyntaxKind::UtcTime),
        "1.3.6.1.4.1.1466.115.121.1.54" => Some(SupportedSyntaxKind::LdapSyntaxDescription),
        "1.3.6.1.4.1.1466.115.121.1.58" => Some(SupportedSyntaxKind::SubstringAssertion),
        _ => None,
    }
}

fn validate_ldap_syntax_value(syntax_oid: &str, value: &str) -> Result<(), String> {
    let Some(kind) = supported_syntax_kind(syntax_oid) else {
        return Err(format!("unsupported LDAP syntax {}", syntax_oid));
    };

    match kind {
        SupportedSyntaxKind::AttributeTypeDescription => parse_attribute_type_description(value)
            .map(|_| ())
            .map_err(|err| err.to_string()),
        SupportedSyntaxKind::Binary => Ok(()),
        SupportedSyntaxKind::BitString => validate_bit_string(value),
        SupportedSyntaxKind::BootParameter => validate_boot_parameter(value),
        SupportedSyntaxKind::Boolean => {
            if matches!(value, "TRUE" | "FALSE") {
                Ok(())
            } else {
                Err("boolean values must be TRUE or FALSE".to_string())
            }
        }
        SupportedSyntaxKind::Certificate => validate_certificate(value),
        SupportedSyntaxKind::CertificateList => validate_certificate_list(value),
        SupportedSyntaxKind::CertificatePair => validate_certificate_pair(value),
        SupportedSyntaxKind::CountryString => validate_country_string(value),
        SupportedSyntaxKind::DeliveryMethod => validate_delivery_method(value),
        SupportedSyntaxKind::DistinguishedName => canonicalize_dn(value)
            .map(|_| ())
            .map_err(|err| err.to_string()),
        SupportedSyntaxKind::DirectoryString => prepare_directory_string(value).map(|_| ()),
        SupportedSyntaxKind::DitContentRuleDescription => parse_dit_content_rule_description(value)
            .map(|_| ())
            .map_err(|err| err.to_string()),
        SupportedSyntaxKind::DitStructureRuleDescription => {
            parse_dit_structure_rule_description(value)
                .map(|_| ())
                .map_err(|err| err.to_string())
        }
        SupportedSyntaxKind::EnhancedGuide => validate_guide(value, true),
        SupportedSyntaxKind::FacsimileTelephoneNumber => validate_facsimile_telephone_number(value),
        SupportedSyntaxKind::Fax => Ok(()),
        SupportedSyntaxKind::GeneralizedTime => parse_generalized_time(value).map(|_| ()),
        SupportedSyntaxKind::Guide => validate_guide(value, false),
        SupportedSyntaxKind::Ia5String => validate_ia5_string(value),
        SupportedSyntaxKind::Integer => parse_integer_syntax(value).map(|_| ()),
        SupportedSyntaxKind::Jpeg => Ok(()),
        SupportedSyntaxKind::LdapSyntaxDescription => parse_ldap_syntax_description(value)
            .map(|_| ())
            .map_err(|err| err.to_string()),
        SupportedSyntaxKind::MatchingRuleDescription => parse_matching_rule_description(value)
            .map(|_| ())
            .map_err(|err| err.to_string()),
        SupportedSyntaxKind::MatchingRuleUseDescription => {
            parse_matching_rule_use_description(value)
                .map(|_| ())
                .map_err(|err| err.to_string())
        }
        SupportedSyntaxKind::NameAndOptionalUid => validate_name_and_optional_uid(value),
        SupportedSyntaxKind::NameFormDescription => parse_name_form_description(value)
            .map(|_| ())
            .map_err(|err| err.to_string()),
        SupportedSyntaxKind::NisNetgroupTriple => validate_nis_netgroup_triple(value),
        SupportedSyntaxKind::NumericString => validate_numeric_string(value),
        SupportedSyntaxKind::ObjectClassDescription => parse_object_class_description(value)
            .map(|_| ())
            .map_err(|err| err.to_string()),
        SupportedSyntaxKind::ObjectIdentifier => {
            if is_valid_oid_or_descriptor(value) {
                Ok(())
            } else {
                Err("value must be a numeric OID or descriptor".to_string())
            }
        }
        SupportedSyntaxKind::OtherMailbox => validate_other_mailbox(value),
        SupportedSyntaxKind::OctetString => Ok(()),
        SupportedSyntaxKind::PostalAddress => validate_postal_address(value),
        SupportedSyntaxKind::PrintableString => {
            validate_printable_string(value, "Printable String")
        }
        SupportedSyntaxKind::SupportedAlgorithm => validate_supported_algorithm(value),
        SupportedSyntaxKind::SubtreeSpecification => validate_subtree_specification(value),
        SupportedSyntaxKind::SubstringAssertion => validate_substring_assertion(value),
        SupportedSyntaxKind::TeletexTerminalIdentifier => {
            validate_teletex_terminal_identifier(value)
        }
        SupportedSyntaxKind::TelephoneNumber => validate_telephone_number(value),
        SupportedSyntaxKind::TelexNumber => validate_telex_number(value),
        SupportedSyntaxKind::UtcTime => parse_utc_time(value).map(|_| ()),
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
    BitString,
    Boolean,
    CaseIgnore,
    CaseIgnoreOrdering,
    CaseExact,
    CaseExactOrdering,
    CaseIgnoreIa5,
    CaseExactIa5,
    NumericString,
    NumericStringOrdering,
    NumericStringSubstring,
    CaseIgnoreList,
    CaseIgnoreListSubstring,
    Integer,
    IntegerOrdering,
    GeneralizedTime,
    GeneralizedTimeOrdering,
    IntegerFirstComponent,
    ObjectIdentifierFirstComponent,
    DirectoryStringFirstComponent,
    DistinguishedName,
    ObjectIdentifier,
    OctetString,
    OctetStringOrdering,
    UniqueMember,
    Word,
    Keyword,
    TelephoneNumber,
    TelephoneNumberSubstring,
    CaseIgnoreSubstring,
    CaseExactSubstring,
    CaseIgnoreIa5Substring,
    CaseExactIa5Substring,
    X509CertificateExact,
    X509Certificate,
    X509CertificateListExact,
    X509CertificateList,
    X509CertificatePairExact,
    X509CertificatePair,
    X509AlgorithmIdentifier,
}

fn supported_matching_rule_kind(rule: &ResolvedMatchingRule) -> Option<SupportedMatchingRuleKind> {
    let name = rule.primary_name.to_ascii_lowercase();
    match (rule.oid.as_str(), name.as_str()) {
        ("2.5.13.2", _) | (_, "caseignorematch") => Some(SupportedMatchingRuleKind::CaseIgnore),
        ("2.5.13.3", _) | (_, "caseignoreorderingmatch") => {
            Some(SupportedMatchingRuleKind::CaseIgnoreOrdering)
        }
        ("2.5.13.5", _) | (_, "caseexactmatch") => Some(SupportedMatchingRuleKind::CaseExact),
        ("2.5.13.6", _) | (_, "caseexactorderingmatch") => {
            Some(SupportedMatchingRuleKind::CaseExactOrdering)
        }
        ("1.3.6.1.4.1.1466.109.114.2", _) | (_, "caseignoreia5match") => {
            Some(SupportedMatchingRuleKind::CaseIgnoreIa5)
        }
        ("1.3.6.1.4.1.1466.109.114.1", _) | (_, "caseexactia5match") => {
            Some(SupportedMatchingRuleKind::CaseExactIa5)
        }
        ("1.3.6.1.4.1.1466.109.114.3", _) | (_, "caseignoreia5substringsmatch") => {
            Some(SupportedMatchingRuleKind::CaseIgnoreIa5Substring)
        }
        ("1.3.6.1.4.1.4203.1.2.1", _) | (_, "caseexactia5substringsmatch") => {
            Some(SupportedMatchingRuleKind::CaseExactIa5Substring)
        }
        ("2.5.13.8", _) | (_, "numericstringmatch") => {
            Some(SupportedMatchingRuleKind::NumericString)
        }
        ("2.5.13.9", _) | (_, "numericstringorderingmatch") => {
            Some(SupportedMatchingRuleKind::NumericStringOrdering)
        }
        ("2.5.13.10", _) | (_, "numericstringsubstringsmatch") => {
            Some(SupportedMatchingRuleKind::NumericStringSubstring)
        }
        ("2.5.13.11", _) | (_, "caseignorelistmatch") => {
            Some(SupportedMatchingRuleKind::CaseIgnoreList)
        }
        ("2.5.13.12", _) | (_, "caseignorelistsubstringsmatch") => {
            Some(SupportedMatchingRuleKind::CaseIgnoreListSubstring)
        }
        ("2.5.13.13", _) | (_, "booleanmatch") => Some(SupportedMatchingRuleKind::Boolean),
        ("2.5.13.14", _) | (_, "integermatch") => Some(SupportedMatchingRuleKind::Integer),
        ("2.5.13.15", _) | (_, "integerorderingmatch") => {
            Some(SupportedMatchingRuleKind::IntegerOrdering)
        }
        ("2.5.13.16", _) | (_, "bitstringmatch") => Some(SupportedMatchingRuleKind::BitString),
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
        ("2.5.13.18", _) | (_, "octetstringorderingmatch") => {
            Some(SupportedMatchingRuleKind::OctetStringOrdering)
        }
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
        ("2.5.13.23", _) | (_, "uniquemembermatch") => {
            Some(SupportedMatchingRuleKind::UniqueMember)
        }
        ("2.5.13.29", _) | (_, "integerfirstcomponentmatch") => {
            Some(SupportedMatchingRuleKind::IntegerFirstComponent)
        }
        ("2.5.13.30", _) | (_, "objectidentifierfirstcomponentmatch") => {
            Some(SupportedMatchingRuleKind::ObjectIdentifierFirstComponent)
        }
        ("2.5.13.31", _) | (_, "directorystringfirstcomponentmatch") => {
            Some(SupportedMatchingRuleKind::DirectoryStringFirstComponent)
        }
        ("2.5.13.32", _) | (_, "wordmatch") => Some(SupportedMatchingRuleKind::Word),
        ("2.5.13.33", _) | (_, "keywordmatch") => Some(SupportedMatchingRuleKind::Keyword),
        ("2.5.13.34", _) | (_, "certificateexactmatch") => {
            Some(SupportedMatchingRuleKind::X509CertificateExact)
        }
        ("2.5.13.35", _) | (_, "certificatematch") => {
            Some(SupportedMatchingRuleKind::X509Certificate)
        }
        ("2.5.13.36", _) | (_, "certificatepairexactmatch") => {
            Some(SupportedMatchingRuleKind::X509CertificatePairExact)
        }
        ("2.5.13.37", _) | (_, "certificatepairmatch") => {
            Some(SupportedMatchingRuleKind::X509CertificatePair)
        }
        ("2.5.13.38", _) | (_, "certificatelistexactmatch") => {
            Some(SupportedMatchingRuleKind::X509CertificateListExact)
        }
        ("2.5.13.39", _) | (_, "certificatelistmatch") => {
            Some(SupportedMatchingRuleKind::X509CertificateList)
        }
        ("2.5.13.40", _) | (_, "algorithmidentifiermatch") | (_, "algorithmidentifier") => {
            Some(SupportedMatchingRuleKind::X509AlgorithmIdentifier)
        }
        _ => None,
    }
}

fn x509_matching_rule_applies_to_syntax(
    kind: Option<SupportedMatchingRuleKind>,
    syntax_oid: &str,
) -> bool {
    let syntax_oid = base_syntax_oid(syntax_oid);
    matches!(
        (kind, syntax_oid),
        (
            Some(SupportedMatchingRuleKind::X509CertificateExact)
                | Some(SupportedMatchingRuleKind::X509Certificate),
            "1.3.6.1.4.1.1466.115.121.1.8"
        ) | (
            Some(SupportedMatchingRuleKind::X509CertificateListExact)
                | Some(SupportedMatchingRuleKind::X509CertificateList),
            "1.3.6.1.4.1.1466.115.121.1.9"
        ) | (
            Some(SupportedMatchingRuleKind::X509CertificatePairExact)
                | Some(SupportedMatchingRuleKind::X509CertificatePair),
            "1.3.6.1.4.1.1466.115.121.1.10"
        ) | (
            Some(SupportedMatchingRuleKind::X509AlgorithmIdentifier),
            "1.3.6.1.4.1.1466.115.121.1.49"
        )
    )
}

fn normalize_matching_rule_value(
    rule: &ResolvedMatchingRule,
    value: &str,
) -> Result<String, MatchingRuleError> {
    let Some(kind) = supported_matching_rule_kind(rule) else {
        return Err(MatchingRuleError::UnsupportedRule(rule.label().to_string()));
    };
    match kind {
        SupportedMatchingRuleKind::BitString => {
            validate_bit_string(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))?;
            Ok(normalize_bit_string(value))
        }
        SupportedMatchingRuleKind::Boolean => {
            validate_ldap_syntax_value("1.3.6.1.4.1.1466.115.121.1.7", value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))?;
            Ok(value.to_string())
        }
        SupportedMatchingRuleKind::CaseIgnore
        | SupportedMatchingRuleKind::CaseIgnoreOrdering
        | SupportedMatchingRuleKind::CaseIgnoreSubstring => {
            normalize_directory_string_case_ignore(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::CaseExact
        | SupportedMatchingRuleKind::CaseExactOrdering
        | SupportedMatchingRuleKind::CaseExactSubstring => normalize_directory_string(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::CaseIgnoreIa5 => normalize_ia5_string_case_ignore(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::CaseExactIa5 => normalize_ia5_string(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::CaseIgnoreIa5Substring => {
            normalize_ia5_string_case_ignore(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::CaseExactIa5Substring => normalize_ia5_string(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::NumericString
        | SupportedMatchingRuleKind::NumericStringOrdering
        | SupportedMatchingRuleKind::NumericStringSubstring => normalize_numeric_string(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::CaseIgnoreList
        | SupportedMatchingRuleKind::CaseIgnoreListSubstring => normalize_case_ignore_list(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::Integer | SupportedMatchingRuleKind::IntegerOrdering => {
            parse_integer_for_rule(rule, value).map(|value| value.to_string())
        }
        SupportedMatchingRuleKind::GeneralizedTime
        | SupportedMatchingRuleKind::GeneralizedTimeOrdering => {
            normalize_generalized_time_for_rule(rule, value)
        }
        SupportedMatchingRuleKind::IntegerFirstComponent => {
            let component = first_component(value);
            parse_integer_for_rule(rule, component).map(|value| value.to_string())
        }
        SupportedMatchingRuleKind::ObjectIdentifierFirstComponent => {
            let component = first_component(value);
            if !is_valid_oid_or_descriptor(component) {
                return Err(invalid_matching_syntax(
                    rule,
                    value,
                    "first component must be a numeric OID or descriptor",
                ));
            }
            Ok(component.to_ascii_lowercase())
        }
        SupportedMatchingRuleKind::DirectoryStringFirstComponent => {
            normalize_directory_string_case_ignore(first_component(value))
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
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
        SupportedMatchingRuleKind::OctetString | SupportedMatchingRuleKind::OctetStringOrdering => {
            Ok(value.to_string())
        }
        SupportedMatchingRuleKind::UniqueMember => normalize_name_and_optional_uid(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::Word | SupportedMatchingRuleKind::Keyword => {
            normalize_directory_string_case_ignore(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::TelephoneNumber
        | SupportedMatchingRuleKind::TelephoneNumberSubstring => {
            normalize_telephone_number_for_matching(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::X509CertificateExact => {
            normalize_x509_certificate_exact_match_value(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::X509Certificate => normalize_x509_certificate_match_value(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::X509CertificateListExact => {
            normalize_x509_certificate_list_exact_match_value(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::X509CertificateList => {
            normalize_x509_certificate_list_match_value(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::X509CertificatePairExact => {
            normalize_x509_certificate_pair_exact_match_value(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::X509CertificatePair => {
            normalize_x509_certificate_pair_match_value(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::X509AlgorithmIdentifier => {
            normalize_x509_algorithm_identifier_match_value(value)
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
        SupportedMatchingRuleKind::CaseIgnoreOrdering => {
            normalize_directory_string_case_ignore(value)
                .map_err(|reason| invalid_matching_syntax(rule, value, &reason))
        }
        SupportedMatchingRuleKind::CaseExactOrdering => normalize_directory_string(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
        SupportedMatchingRuleKind::NumericStringOrdering => normalize_numeric_string(value)
            .map_err(|reason| invalid_matching_syntax(rule, value, &reason)),
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
        SupportedMatchingRuleKind::OctetStringOrdering => Ok(value.to_string()),
        SupportedMatchingRuleKind::X509CertificateExact
        | SupportedMatchingRuleKind::X509Certificate
        | SupportedMatchingRuleKind::X509CertificateListExact
        | SupportedMatchingRuleKind::X509CertificateList
        | SupportedMatchingRuleKind::X509CertificatePairExact
        | SupportedMatchingRuleKind::X509CertificatePair
        | SupportedMatchingRuleKind::X509AlgorithmIdentifier => Err(
            MatchingRuleError::UnsupportedRule(format!("{} is not an ordering rule", rule.label())),
        ),
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
        SupportedMatchingRuleKind::CaseIgnoreOrdering
        | SupportedMatchingRuleKind::CaseExactOrdering
        | SupportedMatchingRuleKind::NumericStringOrdering
        | SupportedMatchingRuleKind::OctetStringOrdering => {
            Ok(matching_rule_ordering_key(rule, left)?
                .cmp(&matching_rule_ordering_key(rule, right)?))
        }
        _ => Ok(normalize_matching_rule_value(rule, left)?
            .cmp(&normalize_matching_rule_value(rule, right)?)),
    }
}

fn value_matches_normalized_assertion(
    rule: &ResolvedMatchingRule,
    candidate: &str,
    normalized_assertion: &str,
) -> Result<bool, MatchingRuleError> {
    let Some(kind) = supported_matching_rule_kind(rule) else {
        return Err(MatchingRuleError::UnsupportedRule(rule.label().to_string()));
    };

    match kind {
        SupportedMatchingRuleKind::Word => Ok(word_tokens(candidate, rule)?
            .iter()
            .any(|token| token == normalized_assertion)),
        SupportedMatchingRuleKind::Keyword => Ok(keyword_tokens(candidate, rule)?
            .iter()
            .any(|token| token == normalized_assertion)),
        SupportedMatchingRuleKind::X509Certificate => {
            x509_certificate_value_matches(candidate, normalized_assertion)
                .map_err(|reason| invalid_matching_syntax(rule, candidate, &reason))
        }
        SupportedMatchingRuleKind::X509CertificateList => {
            x509_certificate_list_value_matches(candidate, normalized_assertion)
                .map_err(|reason| invalid_matching_syntax(rule, candidate, &reason))
        }
        SupportedMatchingRuleKind::X509CertificatePairExact => {
            x509_certificate_pair_exact_value_matches(candidate, normalized_assertion)
                .map_err(|reason| invalid_matching_syntax(rule, candidate, &reason))
        }
        SupportedMatchingRuleKind::X509CertificatePair => {
            x509_certificate_pair_value_matches(candidate, normalized_assertion)
                .map_err(|reason| invalid_matching_syntax(rule, candidate, &reason))
        }
        _ => Ok(normalize_matching_rule_value(rule, candidate)? == normalized_assertion),
    }
}

fn normalize_directory_string(value: &str) -> Result<String, String> {
    prepare_x520_string(value, false)
}

fn normalize_directory_string_case_ignore(value: &str) -> Result<String, String> {
    prepare_x520_string(value, true)
}

fn prepare_directory_string(value: &str) -> Result<String, String> {
    let prepared = normalize_directory_string(value)?;
    if prepared.is_empty() {
        Err("Directory String values must not be empty".to_string())
    } else {
        Ok(prepared)
    }
}

fn prepare_x520_string(value: &str, case_fold: bool) -> Result<String, String> {
    let prepared = if case_fold {
        x520_stringprep_to_case_ignore_string(value)
    } else {
        x520_stringprep_to_case_exact_string(value)
    }
    .map_err(|ch| format!("value contains prohibited code point U+{:04X}", ch as u32))?;
    Ok(prepared.split_whitespace().collect::<Vec<_>>().join(" "))
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

fn normalize_ia5_string(value: &str) -> Result<String, String> {
    validate_ia5_string(value)?;
    Ok(value.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn normalize_ia5_string_case_ignore(value: &str) -> Result<String, String> {
    validate_ia5_string(value)?;
    Ok(value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase())
}

fn validate_bit_string(value: &str) -> Result<(), String> {
    let Some(bits) = bit_string_bits(value) else {
        return Err("Bit String values must use the form '0101'B".to_string());
    };
    if bits.is_empty() {
        return Err("Bit String values must contain at least one bit".to_string());
    }
    if !bits.chars().all(|ch| matches!(ch, '0' | '1')) {
        return Err("Bit String values may contain only 0 and 1 bits".to_string());
    }
    Ok(())
}

fn bit_string_bits(value: &str) -> Option<&str> {
    value.strip_prefix('\'')?.strip_suffix("'B")
}

fn normalize_bit_string(value: &str) -> String {
    format!("'{}'B", bit_string_bits(value).unwrap_or_default())
}

fn validate_country_string(value: &str) -> Result<(), String> {
    if value.chars().count() != 2 {
        return Err("Country String values must contain exactly two characters".to_string());
    }
    validate_printable_string(value, "Country String")
}

fn validate_printable_string(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} values must not be empty"));
    }
    if value.chars().all(is_printable_string_char) {
        Ok(())
    } else {
        Err(format!(
            "{label} values must use PrintableString characters"
        ))
    }
}

fn validate_numeric_string(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("Numeric String values must not be empty".to_string());
    }
    if value.chars().all(|ch| ch.is_ascii_digit() || ch == ' ') {
        Ok(())
    } else {
        Err("Numeric String values may contain only digits and spaces".to_string())
    }
}

fn normalize_numeric_string(value: &str) -> Result<String, String> {
    let prepared = prepare_x520_string(value, true)?;
    if prepared.chars().all(|ch| ch.is_ascii_digit() || ch == ' ') {
        Ok(prepared.chars().filter(|ch| *ch != ' ').collect())
    } else {
        Err("Numeric String values may contain only digits and spaces".to_string())
    }
}

fn validate_delivery_method(value: &str) -> Result<(), String> {
    const ALLOWED: &[&str] = &[
        "any",
        "mhs",
        "physical",
        "telex",
        "teletex",
        "g3fax",
        "g4fax",
        "ia5",
        "videotex",
        "telephone",
    ];
    if value.is_empty() {
        return Err("Delivery Method values must not be empty".to_string());
    }
    for method in value.split('$') {
        let method = method.trim();
        if method.is_empty() || !ALLOWED.contains(&method) {
            return Err(format!("unsupported Delivery Method value: {method}"));
        }
    }
    Ok(())
}

fn validate_facsimile_telephone_number(value: &str) -> Result<(), String> {
    const ALLOWED: &[&str] = &[
        "twoDimensional",
        "fineResolution",
        "unlimitedLength",
        "b4Length",
        "a3Width",
        "b4Width",
        "uncompressed",
    ];
    let mut parts = value.split('$');
    let number = parts
        .next()
        .ok_or_else(|| "Facsimile Telephone Number is empty".to_string())?;
    validate_telephone_number(number)?;
    for parameter in parts {
        if parameter.is_empty() || !ALLOWED.contains(&parameter) {
            return Err(format!(
                "unsupported Facsimile Telephone Number parameter: {parameter}"
            ));
        }
    }
    Ok(())
}

fn validate_other_mailbox(value: &str) -> Result<(), String> {
    let Some((mailbox_type, mailbox)) = value.split_once('$') else {
        return Err("Other Mailbox values must use mailbox-type$mailbox".to_string());
    };
    validate_printable_string(mailbox_type, "Other Mailbox type")?;
    if mailbox.is_empty() {
        return Err("Other Mailbox address must not be empty".to_string());
    }
    validate_ia5_string(mailbox)
}

fn validate_teletex_terminal_identifier(value: &str) -> Result<(), String> {
    const ALLOWED_KEYS: &[&str] = &["graphic", "control", "misc", "page", "private"];
    let mut parts = value.split('$');
    let terminal = parts
        .next()
        .ok_or_else(|| "Teletex Terminal Identifier is empty".to_string())?;
    validate_printable_string(terminal, "Teletex terminal identifier")?;
    for parameter in parts {
        let Some((key, raw_value)) = parameter.split_once(':') else {
            return Err("Teletex parameters must use key:value".to_string());
        };
        if !ALLOWED_KEYS.contains(&key) {
            return Err(format!("unsupported Teletex parameter key: {key}"));
        }
        validate_teletex_parameter_value(raw_value)?;
    }
    Ok(())
}

fn validate_teletex_parameter_value(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            let Some(escape) = value.get(index + 1..index + 3) else {
                return Err("Teletex parameter escape is incomplete".to_string());
            };
            if !matches!(escape, "24" | "5C") {
                return Err("Teletex parameter escapes may only be \\24 or \\5C".to_string());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn validate_telex_number(value: &str) -> Result<(), String> {
    let parts = value.split('$').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err("Telex Number values must use number$country-code$answerback".to_string());
    }
    for part in parts {
        validate_printable_string(part, "Telex Number component")?;
    }
    Ok(())
}

fn validate_name_and_optional_uid(value: &str) -> Result<(), String> {
    normalize_name_and_optional_uid(value).map(|_| ())
}

fn normalize_name_and_optional_uid(value: &str) -> Result<String, String> {
    if let Some((dn, uid)) = value.rsplit_once('#') {
        let dn = canonicalize_dn(dn).map_err(|err| err.to_string())?;
        validate_bit_string(uid)?;
        Ok(format!("{dn}#{}", normalize_bit_string(uid)))
    } else {
        canonicalize_dn(value).map_err(|err| err.to_string())
    }
}

fn validate_substring_assertion(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("Substring Assertion values must not be empty".to_string());
    }
    if !value.contains('*') {
        return prepare_directory_string(value).map(|_| ());
    }
    if value.contains("**") {
        return Err(
            "Substring Assertion values must not contain empty interior fragments".to_string(),
        );
    }
    for fragment in value.split('*').filter(|fragment| !fragment.is_empty()) {
        prepare_directory_string(fragment)?;
    }
    Ok(())
}

fn validate_guide(value: &str, enhanced: bool) -> Result<(), String> {
    let parts = value.split('#').collect::<Vec<_>>();
    let expected_parts = if enhanced { 3 } else { 2 };
    if parts.len() != expected_parts {
        return Err(if enhanced {
            "Enhanced Guide values must use objectClass#criteria#subset".to_string()
        } else {
            "Guide values must use objectClass#criteria".to_string()
        });
    }
    if !is_valid_oid_or_descriptor(parts[0]) {
        return Err("Guide objectClass must be a descriptor or numeric OID".to_string());
    }
    validate_guide_criteria(parts[1])?;
    if enhanced {
        validate_guide_subset(parts[2])?;
    }
    Ok(())
}

fn certificate_der_is_valid(value: &[u8]) -> bool {
    matches!(
        x509_parser::parse_x509_certificate(value),
        Ok((remainder, _certificate)) if remainder.is_empty()
    )
}

#[derive(Debug, Clone, Copy)]
struct DerTlv<'a> {
    tag: u8,
    full: &'a [u8],
    content: &'a [u8],
}

fn read_der_tlv(input: &[u8]) -> Result<(&[u8], DerTlv<'_>), String> {
    if input.len() < 2 {
        return Err("DER value is truncated".to_string());
    }

    let tag = input[0];
    let length_byte = input[1];
    let (length, content_offset) = if length_byte & 0x80 == 0 {
        (usize::from(length_byte), 2)
    } else {
        let length_octets = usize::from(length_byte & 0x7f);
        if length_octets == 0 {
            return Err("DER indefinite lengths are not allowed".to_string());
        }
        if length_octets > std::mem::size_of::<usize>() || input.len() < 2 + length_octets {
            return Err("DER length is truncated".to_string());
        }
        if input[2] == 0 {
            return Err("DER length must use the shortest form".to_string());
        }
        let mut length = 0usize;
        for octet in &input[2..2 + length_octets] {
            length = (length << 8) | usize::from(*octet);
        }
        if length < 128 {
            return Err("DER long-form length used for short value".to_string());
        }
        (length, 2 + length_octets)
    };

    let end = content_offset
        .checked_add(length)
        .ok_or_else(|| "DER length overflows input".to_string())?;
    if input.len() < end {
        return Err("DER content is truncated".to_string());
    }

    Ok((
        &input[end..],
        DerTlv {
            tag,
            full: &input[..end],
            content: &input[content_offset..end],
        },
    ))
}

fn encode_der_length(length: usize, output: &mut Vec<u8>) {
    if length < 128 {
        output.push(length as u8);
        return;
    }

    let bytes = length.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let length_bytes = &bytes[first_non_zero..];
    output.push(0x80 | length_bytes.len() as u8);
    output.extend_from_slice(length_bytes);
}

fn wrap_der_value(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(content.len() + 8);
    output.push(tag);
    encode_der_length(content.len(), &mut output);
    output.extend_from_slice(content);
    output
}

fn der_oid_content_is_valid(content: &[u8]) -> bool {
    if content.is_empty() {
        return false;
    }
    let mut saw_continuation = false;
    for octet in content {
        saw_continuation = octet & 0x80 != 0;
    }
    !saw_continuation
}

fn algorithm_identifier_der_is_valid(value: &[u8]) -> bool {
    parse_algorithm_identifier_der(value).is_ok()
}

fn parse_algorithm_identifier_der(value: &[u8]) -> Result<(), String> {
    let (remainder, algorithm_identifier) = read_der_tlv(value)?;
    if !remainder.is_empty() {
        return Err("AlgorithmIdentifier DER contains trailing data".to_string());
    }
    if algorithm_identifier.tag != 0x30 {
        return Err("AlgorithmIdentifier must be a DER SEQUENCE".to_string());
    }

    let (remaining, oid) = read_der_tlv(algorithm_identifier.content)?;
    if oid.tag != 0x06 || !der_oid_content_is_valid(oid.content) {
        return Err("AlgorithmIdentifier must start with an object identifier".to_string());
    }
    if remaining.is_empty() {
        return Ok(());
    }
    let (remaining, _parameters) = read_der_tlv(remaining)?;
    if remaining.is_empty() {
        Ok(())
    } else {
        Err("AlgorithmIdentifier must contain only algorithm and optional parameters".to_string())
    }
}

fn certificate_list_der_is_valid(value: &[u8]) -> bool {
    matches!(
        x509_parser::parse_x509_crl(value),
        Ok((remainder, _certificate_list)) if remainder.is_empty()
    )
}

fn certificate_pair_der_is_valid(value: &[u8]) -> bool {
    parse_certificate_pair_der(value).is_ok()
}

fn parse_certificate_pair_der(value: &[u8]) -> Result<(), String> {
    let (remainder, pair) = read_der_tlv(value)?;
    if !remainder.is_empty() {
        return Err("certificate pair DER contains trailing data".to_string());
    }
    if pair.tag != 0x30 {
        return Err("certificate pair must be a DER SEQUENCE".to_string());
    }

    let mut remaining = pair.content;
    let mut seen_issued_to_this_ca = false;
    let mut seen_issued_by_this_ca = false;
    while !remaining.is_empty() {
        let (next, component) = read_der_tlv(remaining)?;
        match component.tag {
            0xa0 if !seen_issued_to_this_ca => {
                validate_certificate_pair_component(component.content)?;
                seen_issued_to_this_ca = true;
            }
            0xa1 if !seen_issued_by_this_ca => {
                validate_certificate_pair_component(component.content)?;
                seen_issued_by_this_ca = true;
            }
            0xa0 | 0xa1 => {
                return Err(
                    "certificate pair contains a duplicate certificate component".to_string(),
                );
            }
            _ => return Err("certificate pair contains an unexpected component".to_string()),
        }
        remaining = next;
    }

    if seen_issued_to_this_ca || seen_issued_by_this_ca {
        Ok(())
    } else {
        Err("certificate pair must contain at least one certificate".to_string())
    }
}

fn validate_certificate_pair_component(content: &[u8]) -> Result<(), String> {
    if certificate_der_is_valid(content) {
        return Ok(());
    }
    let wrapped = wrap_der_value(0x30, content);
    if certificate_der_is_valid(&wrapped) {
        Ok(())
    } else {
        Err("certificate pair component is not a valid X.509 certificate".to_string())
    }
}

fn supported_algorithm_der_is_valid(value: &[u8]) -> bool {
    extract_supported_algorithm_identifier_der(value).is_ok()
}

fn extract_supported_algorithm_identifier_der(value: &[u8]) -> Result<&[u8], String> {
    let (remainder, supported_algorithm) = read_der_tlv(value)?;
    if !remainder.is_empty() {
        return Err("SupportedAlgorithm DER contains trailing data".to_string());
    }
    if supported_algorithm.tag != 0x30 {
        return Err("SupportedAlgorithm must be a DER SEQUENCE".to_string());
    }

    let (mut remaining, algorithm_identifier) = read_der_tlv(supported_algorithm.content)?;
    if !algorithm_identifier_der_is_valid(algorithm_identifier.full) {
        return Err("SupportedAlgorithm must start with an AlgorithmIdentifier".to_string());
    }
    while !remaining.is_empty() {
        let (next, _component) = read_der_tlv(remaining)?;
        remaining = next;
    }
    Ok(algorithm_identifier.full)
}

fn decode_der_like_value<F>(
    value: &str,
    value_name: &str,
    pem_labels: &[&str],
    is_valid_der: F,
) -> Result<Vec<u8>, String>
where
    F: Fn(&[u8]) -> bool,
{
    let raw = value.as_bytes();
    if is_valid_der(raw) {
        return Ok(raw.to_vec());
    }

    let trimmed = value.trim();
    if trimmed.starts_with("-----BEGIN ") {
        let (remainder, pem) = x509_parser::pem::parse_x509_pem(trimmed.as_bytes())
            .map_err(|err| format!("{value_name} PEM could not be parsed: {err}"))?;
        if !remainder.iter().all(u8::is_ascii_whitespace) {
            return Err(format!(
                "{value_name} PEM contains trailing non-whitespace data"
            ));
        }
        if !pem_labels.iter().any(|label| *label == pem.label) {
            return Err(format!(
                "{value_name} PEM block must use one of these labels: {}",
                pem_labels.join(", ")
            ));
        }
        if is_valid_der(&pem.contents) {
            return Ok(pem.contents);
        }
        return Err(format!("{value_name} DER could not be parsed"));
    }

    let compact_base64 = trimmed
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    if compact_base64.is_empty() {
        return Err(format!("{value_name} value must not be empty"));
    }
    let decoded = general_purpose::STANDARD
        .decode(compact_base64)
        .map_err(|_| format!("{value_name} value must be DER, PEM, or base64 DER"))?;
    if is_valid_der(&decoded) {
        Ok(decoded)
    } else {
        Err(format!("{value_name} DER could not be parsed"))
    }
}

fn decode_certificate_value(value: &str) -> Result<Vec<u8>, String> {
    decode_der_like_value(
        value,
        "certificate",
        &["CERTIFICATE"],
        certificate_der_is_valid,
    )
}

fn decode_certificate_list_value(value: &str) -> Result<Vec<u8>, String> {
    decode_der_like_value(
        value,
        "certificate list",
        &["X509 CRL", "CRL"],
        certificate_list_der_is_valid,
    )
}

fn decode_certificate_pair_value(value: &str) -> Result<Vec<u8>, String> {
    decode_der_like_value(
        value,
        "certificate pair",
        &["CERTIFICATE PAIR"],
        certificate_pair_der_is_valid,
    )
}

fn decode_supported_algorithm_value(value: &str) -> Result<Vec<u8>, String> {
    decode_der_like_value(
        value,
        "supported algorithm",
        &["SUPPORTED ALGORITHM"],
        supported_algorithm_der_is_valid,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X509CertificateExactKey {
    serial_number: String,
    issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X509CertificateListExactKey {
    issuer: String,
    this_update: String,
    distribution_point: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X509CertificatePairExactKey {
    issued_to_this_ca: Option<X509CertificateExactKey>,
    issued_by_this_ca: Option<X509CertificateExactKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X509AlgorithmIdentifierKey {
    algorithm: String,
    parameters_der_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct X509CertificateAssertion {
    serial_number: Option<String>,
    issuer: Option<String>,
    subject_key_identifier: Option<String>,
    authority_key_identifier: Option<X509AuthorityKeyIdentifierAssertion>,
    subject: Option<String>,
    certificate_valid: Option<String>,
    private_key_valid: Option<String>,
    subject_public_key_alg_id: Option<String>,
    key_usage_flags: Option<u16>,
    subject_alt_name: Option<X509AltNameTypeAssertion>,
    policy_oids: Option<Vec<String>>,
    name_constraints: Option<X509NameConstraintsAssertion>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct X509CertificateListAssertion {
    issuer: Option<String>,
    min_crl_number: Option<String>,
    max_crl_number: Option<String>,
    reason_flags: Option<u16>,
    date_and_time: Option<String>,
    distribution_point: Option<X509DistributionPointNameAssertion>,
    authority_key_identifier: Option<X509AuthorityKeyIdentifierAssertion>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct X509CertificatePairAssertion {
    issued_to_this_ca: Option<X509CertificateAssertion>,
    issued_by_this_ca: Option<X509CertificateAssertion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X509PrivateKeyUsagePeriod {
    not_before: Option<String>,
    not_after: Option<String>,
}

impl X509PrivateKeyUsagePeriod {
    fn contains(&self, assertion: &str) -> Result<bool, String> {
        if let Some(not_before) = self.not_before.as_deref()
            && !normalized_time_in_range(assertion, not_before, None)?
        {
            return Ok(false);
        }
        if let Some(not_after) = self.not_after.as_deref()
            && parse_normalized_time_key(assertion)? > parse_normalized_time_key(not_after)?
        {
            return Ok(false);
        }
        Ok(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct X509AuthorityKeyIdentifierAssertion {
    key_identifier: Option<String>,
    authority_cert_issuer: Option<Vec<X509GeneralNameAssertion>>,
    authority_cert_serial_number: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct X509AltNameTypeAssertion {
    builtin_name_form: Option<String>,
    other_name_form: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct X509DistributionPointNameAssertion {
    full_name: Option<Vec<X509GeneralNameAssertion>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
enum X509GeneralNameAssertion {
    Rfc822Name(String),
    DnsName(String),
    DirectoryName(String),
    UniformResourceIdentifier(String),
    IpAddress(String),
    RegisteredId(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct X509NameConstraintsAssertion {
    permitted_subtrees: Option<Vec<X509GeneralSubtreeAssertion>>,
    excluded_subtrees: Option<Vec<X509GeneralSubtreeAssertion>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct X509GeneralSubtreeAssertion {
    base: X509GeneralNameAssertion,
    minimum: Option<String>,
    maximum: Option<String>,
}

#[derive(Debug, Clone)]
struct X509NameConstraintsCandidate<'a> {
    permitted_subtrees: Option<Vec<X509GeneralSubtreeCandidate<'a>>>,
    excluded_subtrees: Option<Vec<X509GeneralSubtreeCandidate<'a>>>,
}

#[derive(Debug, Clone)]
struct X509GeneralSubtreeCandidate<'a> {
    base: x509_parser::extensions::GeneralName<'a>,
    minimum: Option<String>,
    maximum: Option<String>,
}

fn normalize_x509_certificate_exact_match_value(value: &str) -> Result<String, String> {
    if let Ok(key) = parse_certificate_exact_assertion(value) {
        return Ok(format_certificate_exact_key(&key));
    }
    let der = decode_certificate_value(value)?;
    let key = certificate_exact_key_from_der(&der)?;
    Ok(format_certificate_exact_key(&key))
}

fn normalize_x509_certificate_match_value(value: &str) -> Result<String, String> {
    let assertion = parse_certificate_assertion(value)?;
    serde_json::to_string(&assertion)
        .map_err(|err| format!("CertificateAssertion could not be serialized: {err}"))
}

fn normalize_x509_certificate_list_exact_match_value(value: &str) -> Result<String, String> {
    if let Ok(key) = parse_certificate_list_exact_assertion(value) {
        return Ok(format_certificate_list_exact_key(&key));
    }
    let der = decode_certificate_list_value(value)?;
    let key = certificate_list_exact_key_from_der(&der)?;
    Ok(format_certificate_list_exact_key(&key))
}

fn normalize_x509_certificate_list_match_value(value: &str) -> Result<String, String> {
    let assertion = parse_certificate_list_assertion(value)?;
    serde_json::to_string(&assertion)
        .map_err(|err| format!("CertificateListAssertion could not be serialized: {err}"))
}

fn normalize_x509_certificate_pair_exact_match_value(value: &str) -> Result<String, String> {
    if let Ok(key) = parse_certificate_pair_exact_assertion(value) {
        return Ok(format_certificate_pair_exact_key(&key));
    }
    let der = decode_certificate_pair_value(value)?;
    let key = certificate_pair_exact_key_from_der(&der)?;
    Ok(format_certificate_pair_exact_key(&key))
}

fn normalize_x509_certificate_pair_match_value(value: &str) -> Result<String, String> {
    let assertion = parse_certificate_pair_assertion(value)?;
    serde_json::to_string(&assertion)
        .map_err(|err| format!("CertificatePairAssertion could not be serialized: {err}"))
}

fn normalize_x509_algorithm_identifier_match_value(value: &str) -> Result<String, String> {
    if let Ok(key) = parse_algorithm_identifier_assertion(value) {
        return Ok(format_algorithm_identifier_key(&key));
    }
    let der = decode_supported_algorithm_value(value)?;
    let algorithm_identifier = extract_supported_algorithm_identifier_der(&der)?;
    let key = algorithm_identifier_key_from_der(algorithm_identifier)?;
    Ok(format_algorithm_identifier_key(&key))
}

fn x509_certificate_pair_exact_value_matches(
    candidate: &str,
    normalized_assertion: &str,
) -> Result<bool, String> {
    let assertion = parse_normalized_certificate_pair_exact_key(normalized_assertion)?;
    let der = decode_certificate_pair_value(candidate)?;
    let candidate = certificate_pair_exact_key_from_der(&der)?;

    if let Some(asserted_issued_to) = assertion.issued_to_this_ca.as_ref()
        && candidate.issued_to_this_ca.as_ref() != Some(asserted_issued_to)
    {
        return Ok(false);
    }
    if let Some(asserted_issued_by) = assertion.issued_by_this_ca.as_ref()
        && candidate.issued_by_this_ca.as_ref() != Some(asserted_issued_by)
    {
        return Ok(false);
    }

    Ok(true)
}

fn x509_certificate_value_matches(
    candidate: &str,
    normalized_assertion: &str,
) -> Result<bool, String> {
    let assertion: X509CertificateAssertion = serde_json::from_str(normalized_assertion)
        .map_err(|err| format!("normalized CertificateAssertion is invalid: {err}"))?;
    let der = decode_certificate_value(candidate)?;
    x509_certificate_der_matches_assertion(&der, &assertion)
}

fn x509_certificate_list_value_matches(
    candidate: &str,
    normalized_assertion: &str,
) -> Result<bool, String> {
    let assertion: X509CertificateListAssertion = serde_json::from_str(normalized_assertion)
        .map_err(|err| format!("normalized CertificateListAssertion is invalid: {err}"))?;
    let der = decode_certificate_list_value(candidate)?;
    let (remainder, certificate_list) = x509_parser::parse_x509_crl(&der)
        .map_err(|err| format!("certificate list DER could not be parsed: {err}"))?;
    if !remainder.is_empty() {
        return Err("certificate list DER contains trailing data".to_string());
    }

    if let Some(asserted_issuer) = assertion.issuer.as_ref()
        && normalize_x509_name(certificate_list.issuer())? != *asserted_issuer
    {
        return Ok(false);
    }

    if let Some(asserted_time) = assertion.date_and_time.as_ref() {
        let this_update = format_x509_time_key(certificate_list.last_update());
        let next_update = certificate_list.next_update().map(format_x509_time_key);
        if !normalized_time_in_range(asserted_time, &this_update, next_update.as_deref())? {
            return Ok(false);
        }
    }

    if assertion.min_crl_number.is_some() || assertion.max_crl_number.is_some() {
        let Some(crl_number) = certificate_list.crl_number() else {
            return Ok(false);
        };
        let crl_number = normalize_unsigned_decimal_integer(&crl_number.to_string())?;
        if let Some(min_crl_number) = assertion.min_crl_number.as_ref()
            && compare_unsigned_decimal_strings(&crl_number, min_crl_number)? == CmpOrdering::Less
        {
            return Ok(false);
        }
        if let Some(max_crl_number) = assertion.max_crl_number.as_ref()
            && compare_unsigned_decimal_strings(&crl_number, max_crl_number)?
                == CmpOrdering::Greater
        {
            return Ok(false);
        }
    }

    if let Some(asserted_reason_flags) = assertion.reason_flags {
        let Some(issuing_distribution_point) =
            certificate_list.extensions().iter().find_map(|extension| {
                match extension.parsed_extension() {
                    x509_parser::extensions::ParsedExtension::IssuingDistributionPoint(value) => {
                        Some(value)
                    }
                    _ => None,
                }
            })
        else {
            return Ok(false);
        };
        let Some(reasons) = issuing_distribution_point.only_some_reasons.as_ref() else {
            return Ok(false);
        };
        if reasons.flags & asserted_reason_flags != asserted_reason_flags {
            return Ok(false);
        }
    }

    if let Some(asserted_distribution_point) = assertion.distribution_point.as_ref() {
        let Some(issuing_distribution_point) =
            certificate_list.extensions().iter().find_map(|extension| {
                match extension.parsed_extension() {
                    x509_parser::extensions::ParsedExtension::IssuingDistributionPoint(value) => {
                        Some(value)
                    }
                    _ => None,
                }
            })
        else {
            return Ok(false);
        };
        let Some(distribution_point) = issuing_distribution_point.distribution_point.as_ref()
        else {
            return Ok(false);
        };
        if !distribution_point_name_matches(distribution_point, asserted_distribution_point)? {
            return Ok(false);
        }
    }

    if let Some(asserted_authority_key_identifier) = assertion.authority_key_identifier.as_ref() {
        let Some(authority_key_identifier) =
            certificate_list.extensions().iter().find_map(|extension| {
                match extension.parsed_extension() {
                    x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(value) => {
                        Some(value)
                    }
                    _ => None,
                }
            })
        else {
            return Ok(false);
        };
        if !authority_key_identifier_matches(
            authority_key_identifier,
            asserted_authority_key_identifier,
        )? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn x509_certificate_pair_value_matches(
    candidate: &str,
    normalized_assertion: &str,
) -> Result<bool, String> {
    let assertion: X509CertificatePairAssertion = serde_json::from_str(normalized_assertion)
        .map_err(|err| format!("normalized CertificatePairAssertion is invalid: {err}"))?;
    let der = decode_certificate_pair_value(candidate)?;
    let components = certificate_pair_component_ders_from_der(&der)?;

    if let Some(asserted_issued_to) = assertion.issued_to_this_ca.as_ref() {
        let Some(issued_to_this_ca) = components.issued_to_this_ca.as_deref() else {
            return Ok(false);
        };
        if !x509_certificate_der_matches_assertion(issued_to_this_ca, asserted_issued_to)? {
            return Ok(false);
        }
    }

    if let Some(asserted_issued_by) = assertion.issued_by_this_ca.as_ref() {
        let Some(issued_by_this_ca) = components.issued_by_this_ca.as_deref() else {
            return Ok(false);
        };
        if !x509_certificate_der_matches_assertion(issued_by_this_ca, asserted_issued_by)? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn x509_certificate_der_matches_assertion(
    der: &[u8],
    assertion: &X509CertificateAssertion,
) -> Result<bool, String> {
    let (remainder, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|err| format!("certificate DER could not be parsed: {err}"))?;
    if !remainder.is_empty() {
        return Err("certificate DER contains trailing data".to_string());
    }

    if let Some(asserted_serial_number) = assertion.serial_number.as_ref()
        && normalize_unsigned_decimal_integer(&certificate.tbs_certificate.serial.to_string())?
            != *asserted_serial_number
    {
        return Ok(false);
    }
    if let Some(asserted_issuer) = assertion.issuer.as_ref()
        && normalize_x509_name(certificate.issuer())? != *asserted_issuer
    {
        return Ok(false);
    }
    if let Some(asserted_subject_key_identifier) = assertion.subject_key_identifier.as_ref() {
        let subject_key_identifier = certificate.iter_extensions().find_map(|extension| {
            match extension.parsed_extension() {
                x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(value) => {
                    Some(value)
                }
                _ => None,
            }
        });
        let Some(subject_key_identifier) = subject_key_identifier else {
            return Ok(false);
        };
        if normalize_hex_bytes(subject_key_identifier.0) != *asserted_subject_key_identifier {
            return Ok(false);
        }
    }
    if let Some(asserted_authority_key_identifier) = assertion.authority_key_identifier.as_ref() {
        let authority_key_identifier = certificate.iter_extensions().find_map(|extension| {
            match extension.parsed_extension() {
                x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(value) => {
                    Some(value)
                }
                _ => None,
            }
        });
        let Some(authority_key_identifier) = authority_key_identifier else {
            return Ok(false);
        };
        if !authority_key_identifier_matches(
            authority_key_identifier,
            asserted_authority_key_identifier,
        )? {
            return Ok(false);
        }
    }
    if let Some(asserted_subject) = assertion.subject.as_ref()
        && normalize_x509_name(certificate.subject())? != *asserted_subject
    {
        return Ok(false);
    }
    if let Some(asserted_time) = assertion.certificate_valid.as_ref() {
        let validity = certificate.validity();
        let not_before = format_x509_time_key(validity.not_before);
        let not_after = format_x509_time_key(validity.not_after);
        if !normalized_time_in_range(asserted_time, &not_before, Some(&not_after))? {
            return Ok(false);
        }
    }
    if let Some(asserted_time) = assertion.private_key_valid.as_ref() {
        let Some(private_key_usage_period) = certificate.iter_extensions().find_map(|extension| {
            if extension.oid.to_id_string() == "2.5.29.16" {
                Some(extension.value)
            } else {
                None
            }
        }) else {
            return Ok(false);
        };
        let private_key_usage_period =
            parse_private_key_usage_period_der(private_key_usage_period)?;
        if !private_key_usage_period.contains(asserted_time)? {
            return Ok(false);
        }
    }
    if let Some(asserted_algorithm) = assertion.subject_public_key_alg_id.as_ref()
        && certificate
            .tbs_certificate
            .subject_pki
            .algorithm
            .algorithm
            .to_id_string()
            != *asserted_algorithm
    {
        return Ok(false);
    }
    if let Some(asserted_key_usage_flags) = assertion.key_usage_flags {
        let key_usage = certificate
            .tbs_certificate
            .key_usage()
            .map_err(|err| format!("certificate keyUsage extension could not be read: {err}"))?;
        let Some(key_usage) = key_usage else {
            return Ok(false);
        };
        if key_usage.value.flags & asserted_key_usage_flags != asserted_key_usage_flags {
            return Ok(false);
        }
    }
    if let Some(asserted_subject_alt_name) = assertion.subject_alt_name.as_ref() {
        let subject_alt_name = certificate
            .subject_alternative_name()
            .map_err(|err| {
                format!("certificate subjectAltName extension could not be read: {err}")
            })?
            .map(|extension| extension.value);
        let Some(subject_alt_name) = subject_alt_name else {
            return Ok(false);
        };
        if !subject_alt_name
            .general_names
            .iter()
            .any(|name| subject_alt_name_type_matches(name, asserted_subject_alt_name))
        {
            return Ok(false);
        }
    }
    if let Some(asserted_policy_oids) = assertion.policy_oids.as_ref() {
        let certificate_policies = certificate.iter_extensions().find_map(|extension| {
            match extension.parsed_extension() {
                x509_parser::extensions::ParsedExtension::CertificatePolicies(value) => Some(value),
                _ => None,
            }
        });
        let Some(certificate_policies) = certificate_policies else {
            return Ok(false);
        };
        let candidate_oids = certificate_policies
            .iter()
            .map(|policy| policy.policy_id.to_id_string())
            .collect::<HashSet<_>>();
        if asserted_policy_oids
            .iter()
            .any(|policy_oid| !candidate_oids.contains(policy_oid))
        {
            return Ok(false);
        }
    }
    if let Some(asserted_name_constraints) = assertion.name_constraints.as_ref() {
        let Some(name_constraints) = certificate
            .iter_extensions()
            .find(|extension| extension.oid.to_id_string() == "2.5.29.30")
        else {
            return Ok(false);
        };
        let parsed_name_constraints = parse_name_constraints_candidate_der(name_constraints.value)?;
        if !name_constraints_match(&parsed_name_constraints, asserted_name_constraints) {
            return Ok(false);
        }
    }

    Ok(true)
}

fn authority_key_identifier_matches(
    candidate: &x509_parser::extensions::AuthorityKeyIdentifier<'_>,
    assertion: &X509AuthorityKeyIdentifierAssertion,
) -> Result<bool, String> {
    if let Some(asserted_key_identifier) = assertion.key_identifier.as_ref() {
        let Some(key_identifier) = candidate.key_identifier.as_ref() else {
            return Ok(false);
        };
        if normalize_hex_bytes(key_identifier.0) != *asserted_key_identifier {
            return Ok(false);
        }
    }

    if let Some(asserted_issuer_names) = assertion.authority_cert_issuer.as_ref() {
        let Some(candidate_issuer_names) = candidate.authority_cert_issuer.as_ref() else {
            return Ok(false);
        };
        for asserted_name in asserted_issuer_names {
            if !candidate_issuer_names
                .iter()
                .any(|candidate_name| general_name_matches(candidate_name, asserted_name))
            {
                return Ok(false);
            }
        }
    }

    if let Some(asserted_serial) = assertion.authority_cert_serial_number.as_ref() {
        let Some(candidate_serial) = candidate.authority_cert_serial.as_ref() else {
            return Ok(false);
        };
        if normalize_unsigned_decimal_integer(&der_unsigned_integer_decimal(candidate_serial)?)?
            != *asserted_serial
        {
            return Ok(false);
        }
    }

    Ok(true)
}

fn subject_alt_name_type_matches(
    candidate: &x509_parser::extensions::GeneralName<'_>,
    assertion: &X509AltNameTypeAssertion,
) -> bool {
    if let Some(builtin_name_form) = assertion.builtin_name_form.as_deref() {
        return matches!(
            (builtin_name_form, candidate),
            (
                "rfc822Name",
                x509_parser::extensions::GeneralName::RFC822Name(_)
            ) | ("dNSName", x509_parser::extensions::GeneralName::DNSName(_))
                | (
                    "x400Address",
                    x509_parser::extensions::GeneralName::X400Address(_)
                )
                | (
                    "directoryName",
                    x509_parser::extensions::GeneralName::DirectoryName(_)
                )
                | (
                    "ediPartyName",
                    x509_parser::extensions::GeneralName::EDIPartyName(_)
                )
                | (
                    "uniformResourceIdentifier",
                    x509_parser::extensions::GeneralName::URI(_)
                )
                | (
                    "iPAddress",
                    x509_parser::extensions::GeneralName::IPAddress(_)
                )
                | (
                    "registeredId",
                    x509_parser::extensions::GeneralName::RegisteredID(_)
                )
        );
    }

    if let Some(other_name_form) = assertion.other_name_form.as_deref() {
        return matches!(
            candidate,
            x509_parser::extensions::GeneralName::OtherName(oid, _)
                if oid.to_id_string() == other_name_form
        );
    }

    false
}

fn distribution_point_name_matches(
    candidate: &x509_parser::extensions::DistributionPointName<'_>,
    assertion: &X509DistributionPointNameAssertion,
) -> Result<bool, String> {
    if let Some(asserted_names) = assertion.full_name.as_ref() {
        let x509_parser::extensions::DistributionPointName::FullName(candidate_names) = candidate
        else {
            return Ok(false);
        };
        for asserted_name in asserted_names {
            if !candidate_names
                .iter()
                .any(|candidate_name| general_name_matches(candidate_name, asserted_name))
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn name_constraints_match(
    candidate: &X509NameConstraintsCandidate<'_>,
    assertion: &X509NameConstraintsAssertion,
) -> bool {
    if let Some(asserted_permitted) = assertion.permitted_subtrees.as_ref()
        && !general_subtrees_match(candidate.permitted_subtrees.as_deref(), asserted_permitted)
    {
        return false;
    }
    if let Some(asserted_excluded) = assertion.excluded_subtrees.as_ref()
        && !general_subtrees_match(candidate.excluded_subtrees.as_deref(), asserted_excluded)
    {
        return false;
    }
    true
}

fn general_subtrees_match(
    candidate: Option<&[X509GeneralSubtreeCandidate<'_>]>,
    assertion: &[X509GeneralSubtreeAssertion],
) -> bool {
    let Some(candidate) = candidate else {
        return assertion.is_empty();
    };
    assertion.iter().all(|asserted_subtree| {
        candidate
            .iter()
            .any(|candidate_subtree| general_subtree_matches(candidate_subtree, asserted_subtree))
    })
}

fn general_subtree_matches(
    candidate: &X509GeneralSubtreeCandidate<'_>,
    assertion: &X509GeneralSubtreeAssertion,
) -> bool {
    if !general_name_matches(&candidate.base, &assertion.base) {
        return false;
    }
    if let Some(asserted_minimum) = assertion.minimum.as_deref() {
        let candidate_minimum = candidate.minimum.as_deref().unwrap_or("0");
        if candidate_minimum != asserted_minimum {
            return false;
        }
    }
    if let Some(asserted_maximum) = assertion.maximum.as_deref()
        && candidate.maximum.as_deref() != Some(asserted_maximum)
    {
        return false;
    }
    true
}

fn general_name_matches(
    candidate: &x509_parser::extensions::GeneralName<'_>,
    assertion: &X509GeneralNameAssertion,
) -> bool {
    match (candidate, assertion) {
        (
            x509_parser::extensions::GeneralName::RFC822Name(candidate),
            X509GeneralNameAssertion::Rfc822Name(asserted),
        ) => *candidate == asserted,
        (
            x509_parser::extensions::GeneralName::DNSName(candidate),
            X509GeneralNameAssertion::DnsName(asserted),
        ) => candidate.eq_ignore_ascii_case(asserted),
        (
            x509_parser::extensions::GeneralName::DirectoryName(candidate),
            X509GeneralNameAssertion::DirectoryName(asserted),
        ) => normalize_x509_name(candidate).as_deref() == Ok(asserted.as_str()),
        (
            x509_parser::extensions::GeneralName::URI(candidate),
            X509GeneralNameAssertion::UniformResourceIdentifier(asserted),
        ) => *candidate == asserted,
        (
            x509_parser::extensions::GeneralName::IPAddress(candidate),
            X509GeneralNameAssertion::IpAddress(asserted),
        ) => normalize_hex_bytes(candidate) == *asserted,
        (
            x509_parser::extensions::GeneralName::RegisteredID(candidate),
            X509GeneralNameAssertion::RegisteredId(asserted),
        ) => candidate.to_id_string() == *asserted,
        _ => false,
    }
}

fn certificate_exact_key_from_der(value: &[u8]) -> Result<X509CertificateExactKey, String> {
    let (remainder, certificate) = x509_parser::parse_x509_certificate(value)
        .map_err(|err| format!("certificate DER could not be parsed: {err}"))?;
    if !remainder.is_empty() {
        return Err("certificate DER contains trailing data".to_string());
    }
    Ok(X509CertificateExactKey {
        serial_number: normalize_unsigned_decimal_integer(
            &certificate.tbs_certificate.serial.to_string(),
        )?,
        issuer: normalize_x509_name(certificate.issuer())?,
    })
}

fn certificate_list_exact_key_from_der(
    value: &[u8],
) -> Result<X509CertificateListExactKey, String> {
    let (remainder, certificate_list) = x509_parser::parse_x509_crl(value)
        .map_err(|err| format!("certificate list DER could not be parsed: {err}"))?;
    if !remainder.is_empty() {
        return Err("certificate list DER contains trailing data".to_string());
    }
    let this_update = certificate_list.last_update().to_datetime();
    Ok(X509CertificateListExactKey {
        issuer: normalize_x509_name(certificate_list.issuer())?,
        this_update: format!(
            "{}.{:09}",
            this_update.unix_timestamp(),
            this_update.nanosecond()
        ),
        distribution_point: None,
    })
}

fn certificate_pair_exact_key_from_der(
    value: &[u8],
) -> Result<X509CertificatePairExactKey, String> {
    let (remainder, pair) = read_der_tlv(value)?;
    if !remainder.is_empty() {
        return Err("certificate pair DER contains trailing data".to_string());
    }
    if pair.tag != 0x30 {
        return Err("certificate pair must be a DER SEQUENCE".to_string());
    }

    let mut remaining = pair.content;
    let mut issued_to_this_ca = None;
    let mut issued_by_this_ca = None;
    while !remaining.is_empty() {
        let (next, component) = read_der_tlv(remaining)?;
        match component.tag {
            0xa0 if issued_to_this_ca.is_none() => {
                issued_to_this_ca = Some(certificate_exact_key_from_der(
                    &certificate_pair_component_der(component.content)?,
                )?);
            }
            0xa1 if issued_by_this_ca.is_none() => {
                issued_by_this_ca = Some(certificate_exact_key_from_der(
                    &certificate_pair_component_der(component.content)?,
                )?);
            }
            0xa0 | 0xa1 => {
                return Err(
                    "certificate pair contains a duplicate certificate component".to_string(),
                );
            }
            _ => return Err("certificate pair contains an unexpected component".to_string()),
        }
        remaining = next;
    }

    if issued_to_this_ca.is_none() && issued_by_this_ca.is_none() {
        return Err("certificate pair must contain at least one certificate".to_string());
    }

    Ok(X509CertificatePairExactKey {
        issued_to_this_ca,
        issued_by_this_ca,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X509CertificatePairComponents {
    issued_to_this_ca: Option<Vec<u8>>,
    issued_by_this_ca: Option<Vec<u8>>,
}

fn certificate_pair_component_ders_from_der(
    value: &[u8],
) -> Result<X509CertificatePairComponents, String> {
    let (remainder, pair) = read_der_tlv(value)?;
    if !remainder.is_empty() {
        return Err("certificate pair DER contains trailing data".to_string());
    }
    if pair.tag != 0x30 {
        return Err("certificate pair must be a DER SEQUENCE".to_string());
    }

    let mut remaining = pair.content;
    let mut issued_to_this_ca = None;
    let mut issued_by_this_ca = None;
    while !remaining.is_empty() {
        let (next, component) = read_der_tlv(remaining)?;
        match component.tag {
            0xa0 if issued_to_this_ca.is_none() => {
                issued_to_this_ca = Some(certificate_pair_component_der(component.content)?);
            }
            0xa1 if issued_by_this_ca.is_none() => {
                issued_by_this_ca = Some(certificate_pair_component_der(component.content)?);
            }
            0xa0 | 0xa1 => {
                return Err(
                    "certificate pair contains a duplicate certificate component".to_string(),
                );
            }
            _ => return Err("certificate pair contains an unexpected component".to_string()),
        }
        remaining = next;
    }

    if issued_to_this_ca.is_none() && issued_by_this_ca.is_none() {
        return Err("certificate pair must contain at least one certificate".to_string());
    }

    Ok(X509CertificatePairComponents {
        issued_to_this_ca,
        issued_by_this_ca,
    })
}

fn certificate_pair_component_der(content: &[u8]) -> Result<Vec<u8>, String> {
    if certificate_der_is_valid(content) {
        return Ok(content.to_vec());
    }
    let wrapped = wrap_der_value(0x30, content);
    if certificate_der_is_valid(&wrapped) {
        Ok(wrapped)
    } else {
        Err("certificate pair component is not a valid X.509 certificate".to_string())
    }
}

fn algorithm_identifier_key_from_der(value: &[u8]) -> Result<X509AlgorithmIdentifierKey, String> {
    let (remainder, algorithm_identifier) = read_der_tlv(value)?;
    if !remainder.is_empty() {
        return Err("AlgorithmIdentifier DER contains trailing data".to_string());
    }
    if algorithm_identifier.tag != 0x30 {
        return Err("AlgorithmIdentifier must be a DER SEQUENCE".to_string());
    }

    let (remaining, oid) = read_der_tlv(algorithm_identifier.content)?;
    if oid.tag != 0x06 || !der_oid_content_is_valid(oid.content) {
        return Err("AlgorithmIdentifier must start with an object identifier".to_string());
    }
    let algorithm = decode_der_oid(oid.content)?;
    let parameters_der_hex = if remaining.is_empty() {
        None
    } else {
        let (after_parameters, parameters) = read_der_tlv(remaining)?;
        if !after_parameters.is_empty() {
            return Err(
                "AlgorithmIdentifier must contain only algorithm and optional parameters"
                    .to_string(),
            );
        }
        Some(hex::encode(parameters.full))
    };

    Ok(X509AlgorithmIdentifierKey {
        algorithm,
        parameters_der_hex,
    })
}

fn parse_certificate_exact_assertion(value: &str) -> Result<X509CertificateExactKey, String> {
    let components = parse_gser_sequence_fields(value, "CertificateExactAssertion")?;
    let mut serial_number = None;
    let mut issuer = None;

    for (keyword, rest) in components {
        match keyword {
            "serialNumber" if serial_number.is_none() => {
                serial_number = Some(normalize_unsigned_decimal_integer(rest)?);
            }
            "issuer" if issuer.is_none() => {
                issuer = Some(parse_rfc4523_name(rest)?);
            }
            "serialNumber" | "issuer" => {
                return Err(format!(
                    "duplicate CertificateExactAssertion component {keyword}"
                ));
            }
            other => {
                return Err(format!(
                    "unknown CertificateExactAssertion component {other}"
                ));
            }
        }
    }

    Ok(X509CertificateExactKey {
        serial_number: serial_number
            .ok_or_else(|| "CertificateExactAssertion requires serialNumber".to_string())?,
        issuer: issuer.ok_or_else(|| "CertificateExactAssertion requires issuer".to_string())?,
    })
}

fn parse_certificate_list_exact_assertion(
    value: &str,
) -> Result<X509CertificateListExactKey, String> {
    let components = parse_gser_sequence_fields(value, "CertificateListExactAssertion")?;
    let mut issuer = None;
    let mut this_update = None;
    let mut distribution_point = None;

    for (keyword, rest) in components {
        match keyword {
            "issuer" if issuer.is_none() => issuer = Some(parse_rfc4523_name(rest)?),
            "thisUpdate" if this_update.is_none() => {
                this_update = Some(parse_rfc4523_time(rest)?);
            }
            "distributionPoint" if distribution_point.is_none() => {
                distribution_point = Some(rest.trim().to_string());
            }
            "issuer" | "thisUpdate" | "distributionPoint" => {
                return Err(format!(
                    "duplicate CertificateListExactAssertion component {keyword}"
                ));
            }
            other => {
                return Err(format!(
                    "unknown CertificateListExactAssertion component {other}"
                ));
            }
        }
    }

    Ok(X509CertificateListExactKey {
        issuer: issuer
            .ok_or_else(|| "CertificateListExactAssertion requires issuer".to_string())?,
        this_update: this_update
            .ok_or_else(|| "CertificateListExactAssertion requires thisUpdate".to_string())?,
        distribution_point,
    })
}

fn parse_certificate_assertion(value: &str) -> Result<X509CertificateAssertion, String> {
    let components = parse_gser_sequence_fields(value, "CertificateAssertion")?;
    let mut assertion = X509CertificateAssertion {
        serial_number: None,
        issuer: None,
        subject_key_identifier: None,
        authority_key_identifier: None,
        subject: None,
        certificate_valid: None,
        private_key_valid: None,
        subject_public_key_alg_id: None,
        key_usage_flags: None,
        subject_alt_name: None,
        policy_oids: None,
        name_constraints: None,
    };

    for (keyword, rest) in components {
        match keyword {
            "serialNumber" if assertion.serial_number.is_none() => {
                assertion.serial_number = Some(normalize_unsigned_decimal_integer(rest)?);
            }
            "issuer" if assertion.issuer.is_none() => {
                assertion.issuer = Some(parse_rfc4523_name(rest)?);
            }
            "subjectKeyIdentifier" if assertion.subject_key_identifier.is_none() => {
                assertion.subject_key_identifier = Some(parse_octet_string_hex(rest)?);
            }
            "authorityKeyIdentifier" if assertion.authority_key_identifier.is_none() => {
                assertion.authority_key_identifier =
                    Some(parse_authority_key_identifier_assertion(rest)?);
            }
            "subject" if assertion.subject.is_none() => {
                assertion.subject = Some(parse_rfc4523_name(rest)?);
            }
            "certificateValid" if assertion.certificate_valid.is_none() => {
                assertion.certificate_valid = Some(parse_rfc4523_time(rest)?);
            }
            "privateKeyValid" if assertion.private_key_valid.is_none() => {
                assertion.private_key_valid = Some(parse_rfc4523_generalized_time(rest)?);
            }
            "subjectPublicKeyAlgID" if assertion.subject_public_key_alg_id.is_none() => {
                assertion.subject_public_key_alg_id =
                    Some(parse_object_identifier_component(rest)?);
            }
            "keyUsage" if assertion.key_usage_flags.is_none() => {
                assertion.key_usage_flags = Some(parse_key_usage_flags(rest)?);
            }
            "subjectAltName" if assertion.subject_alt_name.is_none() => {
                assertion.subject_alt_name = Some(parse_alt_name_type_assertion(rest)?);
            }
            "policy" if assertion.policy_oids.is_none() => {
                assertion.policy_oids = Some(parse_cert_policy_set(rest)?);
            }
            "nameConstraints" if assertion.name_constraints.is_none() => {
                assertion.name_constraints = Some(parse_name_constraints_assertion(rest)?);
            }
            "serialNumber"
            | "issuer"
            | "subjectKeyIdentifier"
            | "authorityKeyIdentifier"
            | "subject"
            | "certificateValid"
            | "privateKeyValid"
            | "subjectPublicKeyAlgID"
            | "keyUsage"
            | "subjectAltName"
            | "policy"
            | "nameConstraints" => {
                return Err(format!(
                    "duplicate CertificateAssertion component {keyword}"
                ));
            }
            "pathToName" => {
                return Err(format!(
                    "unsupported CertificateAssertion component {keyword}"
                ));
            }
            other => {
                return Err(format!("unknown CertificateAssertion component {other}"));
            }
        }
    }

    Ok(assertion)
}

fn parse_certificate_list_assertion(value: &str) -> Result<X509CertificateListAssertion, String> {
    let components = parse_gser_sequence_fields(value, "CertificateListAssertion")?;
    let mut assertion = X509CertificateListAssertion {
        issuer: None,
        min_crl_number: None,
        max_crl_number: None,
        reason_flags: None,
        date_and_time: None,
        distribution_point: None,
        authority_key_identifier: None,
    };

    for (keyword, rest) in components {
        match keyword {
            "issuer" if assertion.issuer.is_none() => {
                assertion.issuer = Some(parse_rfc4523_name(rest)?);
            }
            "minCRLNumber" if assertion.min_crl_number.is_none() => {
                assertion.min_crl_number = Some(normalize_unsigned_decimal_integer(rest)?);
            }
            "maxCRLNumber" if assertion.max_crl_number.is_none() => {
                assertion.max_crl_number = Some(normalize_unsigned_decimal_integer(rest)?);
            }
            "reasonFlags" if assertion.reason_flags.is_none() => {
                assertion.reason_flags = Some(parse_reason_flags(rest)?);
            }
            "dateAndTime" if assertion.date_and_time.is_none() => {
                assertion.date_and_time = Some(parse_rfc4523_time(rest)?);
            }
            "distributionPoint" if assertion.distribution_point.is_none() => {
                assertion.distribution_point = Some(parse_distribution_point_name(rest)?);
            }
            "authorityKeyIdentifier" if assertion.authority_key_identifier.is_none() => {
                assertion.authority_key_identifier =
                    Some(parse_authority_key_identifier_assertion(rest)?);
            }
            "issuer"
            | "minCRLNumber"
            | "maxCRLNumber"
            | "reasonFlags"
            | "dateAndTime"
            | "distributionPoint"
            | "authorityKeyIdentifier" => {
                return Err(format!(
                    "duplicate CertificateListAssertion component {keyword}"
                ));
            }
            other => {
                return Err(format!(
                    "unknown CertificateListAssertion component {other}"
                ));
            }
        }
    }

    Ok(assertion)
}

fn parse_certificate_pair_exact_assertion(
    value: &str,
) -> Result<X509CertificatePairExactKey, String> {
    let components = parse_gser_sequence_fields(value, "CertificatePairExactAssertion")?;
    let mut issued_to_this_ca = None;
    let mut issued_by_this_ca = None;

    for (keyword, rest) in components {
        match keyword {
            "issuedToThisCAAssertion" if issued_to_this_ca.is_none() => {
                issued_to_this_ca = Some(parse_certificate_exact_assertion(rest)?);
            }
            "issuedByThisCAAssertion" if issued_by_this_ca.is_none() => {
                issued_by_this_ca = Some(parse_certificate_exact_assertion(rest)?);
            }
            "issuedToThisCAAssertion" | "issuedByThisCAAssertion" => {
                return Err(format!(
                    "duplicate CertificatePairExactAssertion component {keyword}"
                ));
            }
            other => {
                return Err(format!(
                    "unknown CertificatePairExactAssertion component {other}"
                ));
            }
        }
    }

    if issued_to_this_ca.is_none() && issued_by_this_ca.is_none() {
        return Err(
            "CertificatePairExactAssertion requires issuedToThisCAAssertion or issuedByThisCAAssertion"
                .to_string(),
        );
    }

    Ok(X509CertificatePairExactKey {
        issued_to_this_ca,
        issued_by_this_ca,
    })
}

fn parse_certificate_pair_assertion(value: &str) -> Result<X509CertificatePairAssertion, String> {
    let components = parse_gser_sequence_fields(value, "CertificatePairAssertion")?;
    let mut issued_to_this_ca = None;
    let mut issued_by_this_ca = None;

    for (keyword, rest) in components {
        match keyword {
            "issuedToThisCAAssertion" if issued_to_this_ca.is_none() => {
                issued_to_this_ca = Some(parse_certificate_assertion(rest)?);
            }
            "issuedByThisCAAssertion" if issued_by_this_ca.is_none() => {
                issued_by_this_ca = Some(parse_certificate_assertion(rest)?);
            }
            "issuedToThisCAAssertion" | "issuedByThisCAAssertion" => {
                return Err(format!(
                    "duplicate CertificatePairAssertion component {keyword}"
                ));
            }
            other => {
                return Err(format!(
                    "unknown CertificatePairAssertion component {other}"
                ));
            }
        }
    }

    if issued_to_this_ca.is_none() && issued_by_this_ca.is_none() {
        return Err(
            "CertificatePairAssertion requires issuedToThisCAAssertion or issuedByThisCAAssertion"
                .to_string(),
        );
    }

    Ok(X509CertificatePairAssertion {
        issued_to_this_ca,
        issued_by_this_ca,
    })
}

fn parse_algorithm_identifier_assertion(value: &str) -> Result<X509AlgorithmIdentifierKey, String> {
    let components = parse_gser_sequence_fields(value, "AlgorithmIdentifier")?;
    let mut algorithm = None;
    let mut parameters_der_hex = None;

    for (keyword, rest) in components {
        match keyword {
            "algorithm" if algorithm.is_none() => {
                let oid = rest.trim();
                if !is_valid_numeric_oid(oid) {
                    return Err("AlgorithmIdentifier algorithm must be a numeric OID".to_string());
                }
                algorithm = Some(oid.to_string());
            }
            "parameters" if parameters_der_hex.is_none() => {
                parameters_der_hex = Some(parse_algorithm_identifier_parameters(rest)?);
            }
            "algorithm" | "parameters" => {
                return Err(format!("duplicate AlgorithmIdentifier component {keyword}"));
            }
            other => return Err(format!("unknown AlgorithmIdentifier component {other}")),
        }
    }

    Ok(X509AlgorithmIdentifierKey {
        algorithm: algorithm.ok_or_else(|| "AlgorithmIdentifier requires algorithm".to_string())?,
        parameters_der_hex,
    })
}

fn parse_gser_sequence_fields<'a>(
    value: &'a str,
    label: &str,
) -> Result<Vec<(&'a str, &'a str)>, String> {
    let inner = braced_inner(value, label)?;
    split_gser_components(inner)?
        .into_iter()
        .map(split_gser_keyword)
        .collect()
}

fn parse_rfc4523_name(value: &str) -> Result<String, String> {
    let Some(rdn_sequence) = value.trim().strip_prefix("rdnSequence:") else {
        return Err("Name must use rdnSequence:<RDNSequence>".to_string());
    };
    let dn = unquote_gser_dquote_string(rdn_sequence.trim())?;
    canonicalize_dn(&dn).map_err(|err| format!("invalid RDNSequence name {dn}: {err}"))
}

fn parse_rfc4523_time(value: &str) -> Result<String, String> {
    let value = value.trim();
    let time = if let Some(generalized_time) = value.strip_prefix("generalizedTime:") {
        parse_generalized_time(generalized_time.trim())?
    } else if let Some(utc_time) = value.strip_prefix("utcTime:") {
        parse_utc_time(utc_time.trim())?
    } else {
        return Err(
            "Time must use utcTime:<UTCTime> or generalizedTime:<GeneralizedTime>".to_string(),
        );
    };
    Ok(format_datetime_time_key(time))
}

fn parse_rfc4523_generalized_time(value: &str) -> Result<String, String> {
    parse_generalized_time(value.trim()).map(format_datetime_time_key)
}

fn parse_private_key_usage_period_der(value: &[u8]) -> Result<X509PrivateKeyUsagePeriod, String> {
    let (remainder, sequence) = read_der_tlv(value)?;
    if sequence.tag != 0x30 {
        return Err("privateKeyUsagePeriod extension must be a DER SEQUENCE".to_string());
    }
    if !remainder.is_empty() {
        return Err("privateKeyUsagePeriod extension contains trailing data".to_string());
    }

    let mut remaining = sequence.content;
    let mut period = X509PrivateKeyUsagePeriod {
        not_before: None,
        not_after: None,
    };
    while !remaining.is_empty() {
        let (next, field) = read_der_tlv(remaining)?;
        match field.tag {
            0x80 if period.not_before.is_none() => {
                let value = std::str::from_utf8(field.content)
                    .map_err(|_| "privateKeyUsagePeriod notBefore is not UTF-8".to_string())?;
                period.not_before = Some(parse_rfc4523_generalized_time(value)?);
            }
            0x81 if period.not_after.is_none() => {
                let value = std::str::from_utf8(field.content)
                    .map_err(|_| "privateKeyUsagePeriod notAfter is not UTF-8".to_string())?;
                period.not_after = Some(parse_rfc4523_generalized_time(value)?);
            }
            0x80 => {
                return Err("duplicate privateKeyUsagePeriod notBefore".to_string());
            }
            0x81 => {
                return Err("duplicate privateKeyUsagePeriod notAfter".to_string());
            }
            _ => {
                return Err(format!(
                    "unsupported privateKeyUsagePeriod field tag 0x{:02x}",
                    field.tag
                ));
            }
        }
        remaining = next;
    }

    if period.not_before.is_none() && period.not_after.is_none() {
        return Err("privateKeyUsagePeriod requires notBefore or notAfter".to_string());
    }
    Ok(period)
}

fn parse_algorithm_identifier_parameters(value: &str) -> Result<String, String> {
    match value.trim() {
        "NULL" | "null" => Ok("0500".to_string()),
        other => Err(format!(
            "unsupported AlgorithmIdentifier parameters GSER value {other:?}; only NULL is currently supported"
        )),
    }
}

fn parse_authority_key_identifier_assertion(
    value: &str,
) -> Result<X509AuthorityKeyIdentifierAssertion, String> {
    let components = parse_gser_sequence_fields(value, "AuthorityKeyIdentifier")?;
    let mut assertion = X509AuthorityKeyIdentifierAssertion {
        key_identifier: None,
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };

    for (keyword, rest) in components {
        match keyword {
            "keyIdentifier" if assertion.key_identifier.is_none() => {
                assertion.key_identifier = Some(parse_octet_string_hex(rest)?);
            }
            "authorityCertIssuer" if assertion.authority_cert_issuer.is_none() => {
                assertion.authority_cert_issuer = Some(parse_general_names(rest)?);
            }
            "authorityCertSerialNumber" if assertion.authority_cert_serial_number.is_none() => {
                assertion.authority_cert_serial_number =
                    Some(normalize_unsigned_decimal_integer(rest)?);
            }
            "keyIdentifier" | "authorityCertIssuer" | "authorityCertSerialNumber" => {
                return Err(format!(
                    "duplicate AuthorityKeyIdentifier component {keyword}"
                ));
            }
            other => {
                return Err(format!("unknown AuthorityKeyIdentifier component {other}"));
            }
        }
    }

    if assertion.key_identifier.is_none()
        && assertion.authority_cert_issuer.is_none()
        && assertion.authority_cert_serial_number.is_none()
    {
        return Err(
            "AuthorityKeyIdentifier requires keyIdentifier, authorityCertIssuer, or authorityCertSerialNumber"
                .to_string(),
        );
    }

    Ok(assertion)
}

fn parse_alt_name_type_assertion(value: &str) -> Result<X509AltNameTypeAssertion, String> {
    let value = value.trim();
    if let Some(name_form) = value.strip_prefix("builtinNameForm:") {
        let name_form = name_form.trim();
        if is_supported_builtin_name_form(name_form) {
            return Ok(X509AltNameTypeAssertion {
                builtin_name_form: Some(name_form.to_string()),
                other_name_form: None,
            });
        }
        return Err(format!("unknown builtinNameForm {name_form}"));
    }
    if let Some(oid) = value.strip_prefix("otherNameForm:") {
        return Ok(X509AltNameTypeAssertion {
            builtin_name_form: None,
            other_name_form: Some(parse_object_identifier_component(oid)?),
        });
    }
    Err("AltNameType must use builtinNameForm:<name> or otherNameForm:<OID>".to_string())
}

fn is_supported_builtin_name_form(value: &str) -> bool {
    matches!(
        value,
        "rfc822Name"
            | "dNSName"
            | "x400Address"
            | "directoryName"
            | "ediPartyName"
            | "uniformResourceIdentifier"
            | "iPAddress"
            | "registeredId"
    )
}

fn parse_cert_policy_set(value: &str) -> Result<Vec<String>, String> {
    let inner = braced_inner(value, "CertPolicySet")?;
    let policies = split_gser_components(inner)?;
    if policies.is_empty() {
        return Err("CertPolicySet must contain at least one policy OID".to_string());
    }
    let mut normalized = Vec::with_capacity(policies.len());
    for policy in policies {
        let policy = parse_object_identifier_component(policy)?;
        if normalized.contains(&policy) {
            return Err(format!("duplicate CertPolicyId {policy}"));
        }
        normalized.push(policy);
    }
    Ok(normalized)
}

fn parse_name_constraints_assertion(value: &str) -> Result<X509NameConstraintsAssertion, String> {
    let components = parse_gser_sequence_fields(value, "NameConstraints")?;
    let mut assertion = X509NameConstraintsAssertion {
        permitted_subtrees: None,
        excluded_subtrees: None,
    };

    for (keyword, rest) in components {
        match keyword {
            "permittedSubtrees" if assertion.permitted_subtrees.is_none() => {
                assertion.permitted_subtrees = Some(parse_general_subtrees(rest)?);
            }
            "excludedSubtrees" if assertion.excluded_subtrees.is_none() => {
                assertion.excluded_subtrees = Some(parse_general_subtrees(rest)?);
            }
            "permittedSubtrees" | "excludedSubtrees" => {
                return Err(format!("duplicate NameConstraints component {keyword}"));
            }
            other => return Err(format!("unknown NameConstraints component {other}")),
        }
    }

    Ok(assertion)
}

fn parse_general_subtrees(value: &str) -> Result<Vec<X509GeneralSubtreeAssertion>, String> {
    let inner = braced_inner(value, "GeneralSubtrees")?;
    let subtrees = split_gser_components(inner)?;
    if subtrees.is_empty() {
        return Err("GeneralSubtrees must contain at least one GeneralSubtree".to_string());
    }
    subtrees
        .into_iter()
        .map(parse_general_subtree)
        .collect::<Result<Vec<_>, _>>()
}

fn parse_general_subtree(value: &str) -> Result<X509GeneralSubtreeAssertion, String> {
    let components = parse_gser_sequence_fields(value, "GeneralSubtree")?;
    let mut base = None;
    let mut minimum = None;
    let mut maximum = None;

    for (keyword, rest) in components {
        match keyword {
            "base" if base.is_none() => base = Some(parse_general_name(rest)?),
            "minimum" if minimum.is_none() => {
                minimum = Some(normalize_unsigned_decimal_integer(rest)?);
            }
            "maximum" if maximum.is_none() => {
                maximum = Some(normalize_unsigned_decimal_integer(rest)?);
            }
            "base" | "minimum" | "maximum" => {
                return Err(format!("duplicate GeneralSubtree component {keyword}"));
            }
            other => return Err(format!("unknown GeneralSubtree component {other}")),
        }
    }

    Ok(X509GeneralSubtreeAssertion {
        base: base.ok_or_else(|| "GeneralSubtree requires a base component".to_string())?,
        minimum,
        maximum,
    })
}

fn parse_name_constraints_candidate_der(
    value: &[u8],
) -> Result<X509NameConstraintsCandidate<'_>, String> {
    let (remainder, sequence) = read_der_tlv(value)?;
    if sequence.tag != 0x30 {
        return Err("NameConstraints extension must be a DER SEQUENCE".to_string());
    }
    if !remainder.is_empty() {
        return Err("NameConstraints extension has trailing DER data".to_string());
    }

    let mut permitted_subtrees = None;
    let mut excluded_subtrees = None;
    let mut remaining = sequence.content;
    while !remaining.is_empty() {
        let (next, field) = read_der_tlv(remaining)?;
        match field.tag {
            0xa0 if permitted_subtrees.is_none() => {
                permitted_subtrees = Some(parse_general_subtree_candidates(field.content)?);
            }
            0xa1 if excluded_subtrees.is_none() => {
                excluded_subtrees = Some(parse_general_subtree_candidates(field.content)?);
            }
            0xa0 => return Err("duplicate permittedSubtrees in NameConstraints".to_string()),
            0xa1 => return Err("duplicate excludedSubtrees in NameConstraints".to_string()),
            other => {
                return Err(format!(
                    "unexpected NameConstraints DER field tag 0x{other:02x}"
                ));
            }
        }
        remaining = next;
    }

    Ok(X509NameConstraintsCandidate {
        permitted_subtrees,
        excluded_subtrees,
    })
}

fn parse_general_subtree_candidates(
    mut value: &[u8],
) -> Result<Vec<X509GeneralSubtreeCandidate<'_>>, String> {
    let mut subtrees = Vec::new();
    while !value.is_empty() {
        let (next, subtree) = read_der_tlv(value)?;
        if subtree.tag != 0x30 {
            return Err("GeneralSubtree must be encoded as a DER SEQUENCE".to_string());
        }
        subtrees.push(parse_general_subtree_candidate(subtree.content)?);
        value = next;
    }
    if subtrees.is_empty() {
        return Err("GeneralSubtrees must contain at least one GeneralSubtree".to_string());
    }
    Ok(subtrees)
}

fn parse_general_subtree_candidate(
    value: &[u8],
) -> Result<X509GeneralSubtreeCandidate<'_>, String> {
    let (mut remaining, base_tlv) = read_der_tlv(value)?;
    let (_, base) = x509_parser::extensions::GeneralName::from_der(base_tlv.full)
        .map_err(|err| format!("GeneralSubtree base GeneralName could not be parsed: {err}"))?;

    let mut minimum = None;
    let mut maximum = None;
    while !remaining.is_empty() {
        let (next, field) = read_der_tlv(remaining)?;
        match field.tag {
            0x80 if minimum.is_none() => {
                minimum = Some(der_base_distance_decimal(
                    field.content,
                    "GeneralSubtree minimum",
                )?);
            }
            0x81 if maximum.is_none() => {
                maximum = Some(der_base_distance_decimal(
                    field.content,
                    "GeneralSubtree maximum",
                )?);
            }
            0x80 => return Err("duplicate GeneralSubtree minimum".to_string()),
            0x81 => return Err("duplicate GeneralSubtree maximum".to_string()),
            other => return Err(format!("unexpected GeneralSubtree DER tag 0x{other:02x}")),
        }
        remaining = next;
    }

    Ok(X509GeneralSubtreeCandidate {
        base,
        minimum,
        maximum,
    })
}

fn der_base_distance_decimal(value: &[u8], label: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("{label} DER INTEGER content must not be empty"));
    }
    if value[0] & 0x80 != 0 {
        return Err(format!("{label} must not be negative"));
    }
    if value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
        return Err(format!("{label} DER INTEGER is not minimally encoded"));
    }
    der_unsigned_integer_decimal(value)
}

fn parse_distribution_point_name(
    value: &str,
) -> Result<X509DistributionPointNameAssertion, String> {
    let value = value.trim();
    let Some(general_names) = value.strip_prefix("fullName:") else {
        return Err(
            "only distributionPoint fullName:<GeneralNames> is currently supported".to_string(),
        );
    };
    Ok(X509DistributionPointNameAssertion {
        full_name: Some(parse_general_names(general_names.trim())?),
    })
}

fn parse_general_names(value: &str) -> Result<Vec<X509GeneralNameAssertion>, String> {
    let inner = braced_inner(value, "GeneralNames")?;
    let names = split_gser_components(inner)?;
    if names.is_empty() {
        return Err("GeneralNames must contain at least one GeneralName".to_string());
    }
    names
        .into_iter()
        .map(parse_general_name)
        .collect::<Result<Vec<_>, _>>()
}

fn parse_general_name(value: &str) -> Result<X509GeneralNameAssertion, String> {
    let Some((kind, rest)) = value.trim().split_once(':') else {
        return Err("GeneralName must use <nameForm>:<value>".to_string());
    };
    let rest = rest.trim();
    match kind.trim() {
        "rfc822Name" => Ok(X509GeneralNameAssertion::Rfc822Name(
            unquote_gser_dquote_string(rest)?,
        )),
        "dNSName" => Ok(X509GeneralNameAssertion::DnsName(
            unquote_gser_dquote_string(rest)?,
        )),
        "directoryName" => Ok(X509GeneralNameAssertion::DirectoryName(parse_rfc4523_name(
            rest,
        )?)),
        "uniformResourceIdentifier" => Ok(X509GeneralNameAssertion::UniformResourceIdentifier(
            unquote_gser_dquote_string(rest)?,
        )),
        "iPAddress" => Ok(X509GeneralNameAssertion::IpAddress(parse_octet_string_hex(
            rest,
        )?)),
        "registeredID" => Ok(X509GeneralNameAssertion::RegisteredId(
            parse_object_identifier_component(rest)?,
        )),
        "otherName" | "x400Address" | "ediPartyName" => {
            Err(format!("unsupported GeneralName form {kind}"))
        }
        other => Err(format!("unknown GeneralName form {other}")),
    }
}

fn parse_object_identifier_component(value: &str) -> Result<String, String> {
    let oid = value.trim();
    if is_valid_numeric_oid(oid) {
        Ok(oid.to_string())
    } else {
        Err("object identifier component must be a numeric OID".to_string())
    }
}

fn parse_reason_flags(value: &str) -> Result<u16, String> {
    let value = value.trim();
    if value.starts_with('{') {
        let inner = braced_inner(value, "ReasonFlags")?;
        if inner.is_empty() {
            return Ok(0);
        }
        let mut flags = 0_u16;
        for component in split_gser_components(inner)? {
            flags |= reason_named_flag(component.trim())?;
        }
        return Ok(flags);
    }
    parse_gser_bit_string_flags(value, "ReasonFlags")
}

fn reason_named_flag(value: &str) -> Result<u16, String> {
    match value {
        "unused" => Ok(1 << 0),
        "keyCompromise" => Ok(1 << 1),
        "cACompromise" => Ok(1 << 2),
        "affiliationChanged" => Ok(1 << 3),
        "superseded" => Ok(1 << 4),
        "cessationOfOperation" => Ok(1 << 5),
        "certificateHold" => Ok(1 << 6),
        "privilegeWithdrawn" => Ok(1 << 7),
        "aACompromise" => Ok(1 << 8),
        other => Err(format!("unknown ReasonFlags flag {other}")),
    }
}

fn parse_key_usage_flags(value: &str) -> Result<u16, String> {
    let value = value.trim();
    if value.starts_with('{') {
        let inner = braced_inner(value, "KeyUsage")?;
        if inner.is_empty() {
            return Ok(0);
        }
        let mut flags = 0_u16;
        for component in split_gser_components(inner)? {
            flags |= key_usage_named_flag(component.trim())?;
        }
        return Ok(flags);
    }

    parse_gser_bit_string_flags(value, "KeyUsage")
}

fn parse_gser_bit_string_flags(value: &str, label: &str) -> Result<u16, String> {
    if let Some(bits) = bit_string_bits(value) {
        return bit_string_flags_from_bits(bits, label);
    }
    let octets = parse_hstring_bytes(value, label)?;
    let mut flags = 0_u16;
    let mut index = 0_usize;
    for octet in octets {
        for bit_index in (0..8).rev() {
            if index >= u16::BITS as usize {
                return Err(format!("{label} bit string is too long"));
            }
            if (octet >> bit_index) & 1 == 1 {
                flags |= 1_u16 << index;
            }
            index += 1;
        }
    }
    Ok(flags)
}

fn bit_string_flags_from_bits(bits: &str, label: &str) -> Result<u16, String> {
    if bits.is_empty() {
        return Err(format!("{label} bit string must contain at least one bit"));
    }
    if !bits.chars().all(|ch| matches!(ch, '0' | '1')) {
        return Err(format!("{label} bit string may contain only 0 and 1 bits"));
    }
    let mut flags = 0_u16;
    for (index, bit) in bits.chars().enumerate() {
        if index >= u16::BITS as usize {
            return Err(format!("{label} bit string is too long"));
        }
        if bit == '1' {
            flags |= 1_u16 << index;
        }
    }
    Ok(flags)
}

fn key_usage_named_flag(value: &str) -> Result<u16, String> {
    match value {
        "digitalSignature" => Ok(1 << 0),
        "nonRepudiation" => Ok(1 << 1),
        "keyEncipherment" => Ok(1 << 2),
        "dataEncipherment" => Ok(1 << 3),
        "keyAgreement" => Ok(1 << 4),
        "keyCertSign" => Ok(1 << 5),
        "cRLSign" => Ok(1 << 6),
        "encipherOnly" => Ok(1 << 7),
        "decipherOnly" => Ok(1 << 8),
        other => Err(format!("unknown KeyUsage flag {other}")),
    }
}

fn parse_octet_string_hex(value: &str) -> Result<String, String> {
    parse_hstring_bytes(value, "OCTET-STRING").map(|bytes| normalize_hex_bytes(&bytes))
}

fn parse_hstring_bytes(value: &str, label: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    let Some(hex_value) = value.strip_prefix('\'').and_then(|value| {
        value
            .strip_suffix("'H")
            .or_else(|| value.strip_suffix("'h"))
    }) else {
        return Err(format!("{label} must use GSER hstring form '...'H"));
    };
    if hex_value.is_empty() {
        return Ok(Vec::new());
    }
    if !hex_value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} hstring contains non-hexadecimal digits"));
    }
    let mut padded = hex_value.to_string();
    if padded.len() % 2 != 0 {
        padded.push('0');
    }
    hex::decode(padded).map_err(|err| format!("{label} hstring could not be decoded: {err}"))
}

fn normalize_hex_bytes(value: &[u8]) -> String {
    hex::encode(value)
}

fn der_unsigned_integer_decimal(value: &[u8]) -> Result<String, String> {
    if value.is_empty() {
        return Err("DER INTEGER content must not be empty".to_string());
    }
    let mut digits = vec![0_u8];
    for byte in value.iter().skip_while(|byte| **byte == 0) {
        let mut carry = u16::from(*byte);
        for digit in digits.iter_mut().rev() {
            let updated = u16::from(*digit) * 256 + carry;
            *digit = (updated % 10) as u8;
            carry = updated / 10;
        }
        while carry > 0 {
            digits.insert(0, (carry % 10) as u8);
            carry /= 10;
        }
    }
    while digits.len() > 1 && digits.first() == Some(&0) {
        digits.remove(0);
    }
    Ok(digits
        .into_iter()
        .map(|digit| char::from(b'0' + digit))
        .collect())
}

fn format_x509_time_key(time: x509_parser::time::ASN1Time) -> String {
    let time = time.to_datetime();
    format!("{}.{:09}", time.unix_timestamp(), time.nanosecond())
}

fn format_datetime_time_key(time: DateTime<Utc>) -> String {
    format!("{}.{:09}", time.timestamp(), time.timestamp_subsec_nanos())
}

fn normalized_time_in_range(
    assertion: &str,
    start: &str,
    end: Option<&str>,
) -> Result<bool, String> {
    let assertion = parse_normalized_time_key(assertion)?;
    let start = parse_normalized_time_key(start)?;
    if assertion < start {
        return Ok(false);
    }
    if let Some(end) = end
        && assertion > parse_normalized_time_key(end)?
    {
        return Ok(false);
    }
    Ok(true)
}

fn parse_normalized_time_key(value: &str) -> Result<(i64, u32), String> {
    let Some((seconds, nanos)) = value.split_once('.') else {
        return Err("normalized time key is missing fractional seconds".to_string());
    };
    if nanos.len() != 9 || !nanos.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("normalized time key must use exactly 9 fractional digits".to_string());
    }
    let seconds = seconds
        .parse::<i64>()
        .map_err(|_| "normalized time key seconds are invalid".to_string())?;
    let nanos = nanos
        .parse::<u32>()
        .map_err(|_| "normalized time key nanoseconds are invalid".to_string())?;
    Ok((seconds, nanos))
}

fn compare_unsigned_decimal_strings(left: &str, right: &str) -> Result<CmpOrdering, String> {
    let left = normalize_unsigned_decimal_integer(left)?;
    let right = normalize_unsigned_decimal_integer(right)?;
    Ok(left.len().cmp(&right.len()).then_with(|| left.cmp(&right)))
}

fn normalize_unsigned_decimal_integer(value: &str) -> Result<String, String> {
    let value = value.trim();
    let value = value.strip_prefix('+').unwrap_or(value);
    if value.is_empty() {
        return Err("integer value must not be empty".to_string());
    }
    if value.starts_with('-') {
        return Err("integer value must not be negative".to_string());
    }
    if !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err("integer value must contain only decimal digits".to_string());
    }
    let trimmed = value.trim_start_matches('0');
    Ok(if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    })
}

fn normalize_x509_name(name: &x509_parser::x509::X509Name<'_>) -> Result<String, String> {
    let rendered = name.to_string();
    canonicalize_dn(&rendered).map_err(|err| format!("invalid X.509 name {rendered}: {err}"))
}

fn unquote_gser_dquote_string(value: &str) -> Result<String, String> {
    let value = value.trim();
    if !(value.starts_with('"') && value.ends_with('"') && value.len() >= 2) {
        return Err("GSER string must be enclosed in double quotes".to_string());
    }
    let inner = &value[1..value.len() - 1];
    let mut decoded = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            if chars.peek() == Some(&'"') {
                chars.next();
                decoded.push('"');
            } else {
                return Err("embedded GSER double quotes must be doubled".to_string());
            }
        } else {
            decoded.push(ch);
        }
    }
    Ok(decoded)
}

fn decode_der_oid(content: &[u8]) -> Result<String, String> {
    let mut subidentifiers = Vec::new();
    let mut current = 0_u128;
    let mut in_component = false;
    for byte in content {
        current = current
            .checked_mul(128)
            .and_then(|value| value.checked_add(u128::from(byte & 0x7f)))
            .ok_or_else(|| "object identifier component is too large".to_string())?;
        in_component = true;
        if byte & 0x80 == 0 {
            subidentifiers.push(current);
            current = 0;
            in_component = false;
        }
    }
    if in_component || subidentifiers.is_empty() {
        return Err("object identifier DER is truncated".to_string());
    }

    let first_subidentifier = subidentifiers[0];
    let (first, second) = if first_subidentifier < 40 {
        (0, first_subidentifier)
    } else if first_subidentifier < 80 {
        (1, first_subidentifier - 40)
    } else {
        (2, first_subidentifier - 80)
    };
    let mut arcs = vec![first.to_string(), second.to_string()];
    arcs.extend(
        subidentifiers
            .into_iter()
            .skip(1)
            .map(|arc| arc.to_string()),
    );
    Ok(arcs.join("."))
}

fn format_certificate_exact_key(key: &X509CertificateExactKey) -> String {
    format!("serialNumber={};issuer={}", key.serial_number, key.issuer)
}

fn format_certificate_list_exact_key(key: &X509CertificateListExactKey) -> String {
    format!(
        "issuer={};thisUpdate={};distributionPoint={}",
        key.issuer,
        key.this_update,
        key.distribution_point.as_deref().unwrap_or("")
    )
}

fn format_certificate_pair_exact_key(key: &X509CertificatePairExactKey) -> String {
    format!(
        "issuedToThisCAAssertion={};issuedByThisCAAssertion={}",
        key.issued_to_this_ca
            .as_ref()
            .map(format_certificate_exact_key)
            .unwrap_or_default(),
        key.issued_by_this_ca
            .as_ref()
            .map(format_certificate_exact_key)
            .unwrap_or_default()
    )
}

fn parse_normalized_certificate_pair_exact_key(
    value: &str,
) -> Result<X509CertificatePairExactKey, String> {
    let Some(rest) = value.strip_prefix("issuedToThisCAAssertion=") else {
        return Err("invalid normalized CertificatePairExactAssertion".to_string());
    };
    let Some((issued_to, issued_by)) = rest.split_once(";issuedByThisCAAssertion=") else {
        return Err("invalid normalized CertificatePairExactAssertion".to_string());
    };
    let issued_to_this_ca = if issued_to.is_empty() {
        None
    } else {
        Some(parse_normalized_certificate_exact_key(issued_to)?)
    };
    let issued_by_this_ca = if issued_by.is_empty() {
        None
    } else {
        Some(parse_normalized_certificate_exact_key(issued_by)?)
    };
    if issued_to_this_ca.is_none() && issued_by_this_ca.is_none() {
        return Err("normalized CertificatePairExactAssertion is empty".to_string());
    }
    Ok(X509CertificatePairExactKey {
        issued_to_this_ca,
        issued_by_this_ca,
    })
}

fn parse_normalized_certificate_exact_key(value: &str) -> Result<X509CertificateExactKey, String> {
    let Some((serial, issuer)) = value.split_once(";issuer=") else {
        return Err("invalid normalized CertificateExactAssertion".to_string());
    };
    let Some(serial_number) = serial.strip_prefix("serialNumber=") else {
        return Err("invalid normalized CertificateExactAssertion".to_string());
    };
    Ok(X509CertificateExactKey {
        serial_number: serial_number.to_string(),
        issuer: issuer.to_string(),
    })
}

fn format_algorithm_identifier_key(key: &X509AlgorithmIdentifierKey) -> String {
    format!(
        "algorithm={};parameters={}",
        key.algorithm,
        key.parameters_der_hex.as_deref().unwrap_or("")
    )
}

fn validate_certificate(value: &str) -> Result<(), String> {
    decode_certificate_value(value).map(|_| ())
}

fn validate_certificate_list(value: &str) -> Result<(), String> {
    decode_certificate_list_value(value).map(|_| ())
}

fn validate_certificate_pair(value: &str) -> Result<(), String> {
    decode_certificate_pair_value(value).map(|_| ())
}

fn validate_supported_algorithm(value: &str) -> Result<(), String> {
    decode_supported_algorithm_value(value).map(|_| ())
}

fn validate_rfc2307_attribute_semantics(oid: &str, value: &str) -> Result<(), String> {
    match oid {
        "1.3.6.1.1.1.1.15" => validate_integer_range(value, "ipServicePort", 0, 65_535),
        "1.3.6.1.1.1.1.17" => validate_integer_range(value, "ipProtocolNumber", 0, 255),
        "1.3.6.1.1.1.1.18" => {
            validate_integer_range(value, "oncRpcNumber", 0, i128::from(u32::MAX))
        }
        "1.3.6.1.1.1.1.19" => validate_ip_host_number(value),
        "1.3.6.1.1.1.1.20" => validate_ip_network_number(value),
        "1.3.6.1.1.1.1.21" => validate_ipv4_octets(value, 4)
            .map(|_| ())
            .map_err(|reason| format!("ipNetmaskNumber {reason}")),
        "1.3.6.1.1.1.1.22" => validate_mac_address(value),
        _ => Ok(()),
    }
}

fn validate_integer_range(value: &str, label: &str, min: i128, max: i128) -> Result<(), String> {
    let number = parse_integer_syntax(value)?;
    if (min..=max).contains(&number) {
        Ok(())
    } else {
        Err(format!("{label} must be between {min} and {max}"))
    }
}

fn validate_ip_host_number(value: &str) -> Result<(), String> {
    validate_ia5_string(value)?;
    if validate_ipv4_octets(value, 4).is_ok() || validate_preferred_ipv6_address(value).is_ok() {
        Ok(())
    } else {
        Err("ipHostNumber must be an IPv4 dotted decimal address without leading zeros or an RFC 2307 preferred IPv6 address".to_string())
    }
}

fn validate_ip_network_number(value: &str) -> Result<(), String> {
    validate_ia5_string(value)?;
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));

    if address.contains(':') {
        validate_preferred_ipv6_address(address)?;
        if let Some(prefix) = prefix {
            validate_prefix_length(prefix, 128)?;
        }
        return Ok(());
    }

    let octets = validate_ipv4_octet_count(address, 1, 4)?;
    if octets.len() > 1 && octets.last() == Some(&0) {
        return Err("ipNetworkNumber must omit trailing zero octets".to_string());
    }
    if let Some(prefix) = prefix {
        validate_prefix_length(prefix, 32)?;
    }
    Ok(())
}

fn validate_ipv4_octets(value: &str, expected_count: usize) -> Result<Vec<u8>, String> {
    validate_ipv4_octet_count(value, expected_count, expected_count)
}

fn validate_ipv4_octet_count(
    value: &str,
    min_count: usize,
    max_count: usize,
) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Err("IPv4 address must not be empty".to_string());
    }
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() < min_count || parts.len() > max_count {
        return Err(format!(
            "IPv4 address must contain {min_count} to {max_count} octets"
        ));
    }

    let mut octets = Vec::with_capacity(parts.len());
    for part in parts {
        if part.is_empty() {
            return Err("IPv4 octets must not be empty".to_string());
        }
        if part.len() > 1 && part.starts_with('0') {
            return Err("IPv4 octets must omit leading zeros".to_string());
        }
        if !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("IPv4 octets must contain only decimal digits".to_string());
        }
        let octet = part
            .parse::<u16>()
            .map_err(|_| "IPv4 octet is outside the supported range".to_string())?;
        if octet > 255 {
            return Err("IPv4 octets must be between 0 and 255".to_string());
        }
        octets.push(octet as u8);
    }
    Ok(octets)
}

fn validate_preferred_ipv6_address(value: &str) -> Result<(), String> {
    let address = value
        .parse::<std::net::Ipv6Addr>()
        .map_err(|_| "IPv6 address could not be parsed".to_string())?;
    let preferred = address
        .segments()
        .iter()
        .map(|segment| format!("{segment:x}"))
        .collect::<Vec<_>>()
        .join(":");
    if value.eq_ignore_ascii_case(&preferred) {
        Ok(())
    } else {
        Err("IPv6 addresses must use RFC 2307 preferred form with all components and no leading zeros".to_string())
    }
}

fn validate_prefix_length(value: &str, max: u8) -> Result<(), String> {
    let prefix = parse_integer_syntax(value)?;
    if (0..=i128::from(max)).contains(&prefix) {
        Ok(())
    } else {
        Err(format!("CIDR prefix length must be between 0 and {max}"))
    }
}

fn validate_mac_address(value: &str) -> Result<(), String> {
    validate_ia5_string(value)?;
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err("macAddress must contain six colon-separated octets".to_string());
    }
    for part in parts {
        if part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("macAddress octets must use two hexadecimal characters each".to_string());
        }
    }
    Ok(())
}

fn validate_nis_netgroup_triple(value: &str) -> Result<(), String> {
    let Some(inner) = value
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
    else {
        return Err("nisNetgroupTriple values must use (hostname,username,domainname)".to_string());
    };
    let components = inner.split(',').collect::<Vec<_>>();
    if components.len() != 3 {
        return Err(
            "nisNetgroupTriple values must contain three comma-separated fields".to_string(),
        );
    }
    for component in components {
        validate_nis_key_field(component, &[',', '(', ')'], "nisNetgroupTriple")?;
    }
    Ok(())
}

fn validate_boot_parameter(value: &str) -> Result<(), String> {
    let Some((key, server_and_path)) = value.split_once('=') else {
        return Err("bootParameter values must use key=server:path".to_string());
    };
    let Some((server, path)) = server_and_path.split_once(':') else {
        return Err("bootParameter values must use key=server:path".to_string());
    };
    validate_required_nis_key_field(key, &['=', ':'], "bootParameter key")?;
    validate_required_nis_key_field(server, &['=', ':'], "bootParameter server")?;
    validate_required_nis_key_field(path, &['=', ':'], "bootParameter path")
}

fn validate_required_nis_key_field(
    value: &str,
    forbidden: &[char],
    label: &str,
) -> Result<(), String> {
    if value.is_empty() || value == "-" {
        return Err(format!("{label} must not be empty or '-'"));
    }
    validate_nis_key_field(value, forbidden, label)
}

fn validate_nis_key_field(value: &str, forbidden: &[char], label: &str) -> Result<(), String> {
    if value.is_empty() || value == "-" {
        return Ok(());
    }
    validate_ia5_string(value)?;
    if value
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || forbidden.contains(&ch))
    {
        Err(format!(
            "{label} fields must not contain whitespace or separators"
        ))
    } else {
        Ok(())
    }
}

fn validate_preferred_language(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("preferredLanguage must not be empty".to_string());
    }
    if trimmed.to_ascii_lowercase().starts_with("accept-language:") {
        return Err("preferredLanguage omits the Accept-Language header name".to_string());
    }
    for language_item in trimmed.split(',') {
        let language_item = language_item.trim();
        if language_item.is_empty() {
            return Err("preferredLanguage contains an empty language range".to_string());
        }
        let mut parts = language_item.split(';');
        let language_range = parts.next().unwrap_or_default().trim();
        validate_language_range(language_range)?;
        for parameter in parts {
            let Some((name, value)) = parameter.trim().split_once('=') else {
                return Err("preferredLanguage parameters must use name=value".to_string());
            };
            if !name.trim().eq_ignore_ascii_case("q") {
                return Err("preferredLanguage only supports q quality parameters".to_string());
            }
            validate_quality_value(value.trim())?;
        }
    }
    Ok(())
}

fn validate_language_range(value: &str) -> Result<(), String> {
    if value == "*" {
        return Ok(());
    }
    let mut subtags = value.split('-');
    let first = subtags.next().unwrap_or_default();
    validate_language_subtag(first)?;
    for subtag in subtags {
        validate_language_subtag(subtag)?;
    }
    Ok(())
}

fn validate_language_subtag(value: &str) -> Result<(), String> {
    if (1..=8).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        Ok(())
    } else {
        Err(
            "preferredLanguage language tags must use 1-8 alphabetic characters per subtag"
                .to_string(),
        )
    }
}

fn validate_quality_value(value: &str) -> Result<(), String> {
    let Some((whole, fraction)) = value.split_once('.') else {
        return match value {
            "0" | "1" => Ok(()),
            _ => Err("preferredLanguage q values must be between 0 and 1".to_string()),
        };
    };
    if fraction.is_empty() || fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err("preferredLanguage q values may use up to three decimal digits".to_string());
    }
    match whole {
        "0" => Ok(()),
        "1" if fraction.bytes().all(|byte| byte == b'0') => Ok(()),
        _ => Err("preferredLanguage q values must be between 0 and 1".to_string()),
    }
}

fn validate_guide_subset(value: &str) -> Result<(), String> {
    match value {
        "baseObject" | "oneLevel" | "wholeSubtree" => Ok(()),
        _ => Err("Enhanced Guide subset must be baseObject, oneLevel, or wholeSubtree".to_string()),
    }
}

fn validate_guide_criteria(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("Guide criteria must not be empty".to_string());
    }
    if matches!(value, "?true" | "?false") {
        return Ok(());
    }
    if let Some(rest) = value.strip_prefix('!') {
        return validate_guide_criteria(rest);
    }
    if let Some(inner) = parenthesized_inner(value) {
        if let Some(parts) = split_guide_criteria(inner, '&') {
            for part in parts {
                validate_guide_criteria(part)?;
            }
            return Ok(());
        }
        if let Some(parts) = split_guide_criteria(inner, '|') {
            for part in parts {
                validate_guide_criteria(part)?;
            }
            return Ok(());
        }
        return validate_guide_criteria(inner);
    }
    let Some((attribute, match_type)) = value.split_once('$') else {
        return Err("Guide item criteria must use attribute$match-type".to_string());
    };
    if !is_valid_oid_or_descriptor(attribute) {
        return Err("Guide item attribute must be a descriptor or numeric OID".to_string());
    }
    if ["eq", "substr", "ge", "le", "approx"]
        .iter()
        .any(|allowed| match_type.eq_ignore_ascii_case(allowed))
    {
        Ok(())
    } else {
        Err("Guide match type must be eq, substr, ge, le, or approx".to_string())
    }
}

fn parenthesized_inner(value: &str) -> Option<&str> {
    value.strip_prefix('(')?.strip_suffix(')')
}

fn split_guide_criteria(value: &str, separator: char) -> Option<Vec<&str>> {
    let mut depth = 0_i32;
    let mut start = 0;
    let mut parts = Vec::new();
    for (index, ch) in value.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ if ch == separator && depth == 0 => {
                parts.push(value[start..index].trim());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
        if depth < 0 {
            return None;
        }
    }
    if depth != 0 || parts.is_empty() {
        return None;
    }
    parts.push(value[start..].trim());
    if parts.iter().any(|part| part.is_empty()) {
        None
    } else {
        Some(parts)
    }
}

fn normalize_case_ignore_list(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("caseIgnoreList values must not be empty".to_string());
    }
    value
        .split('$')
        .map(normalize_directory_string_case_ignore)
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join("$"))
}

fn first_component(value: &str) -> &str {
    let value = value.trim();
    if let Some(schema_body) = value
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return schema_body
            .split_whitespace()
            .next()
            .unwrap_or(schema_body)
            .trim_matches('\'');
    }
    value
        .split(['$', '#'])
        .next()
        .unwrap_or(value)
        .trim()
        .trim_matches('\'')
}

fn word_tokens(value: &str, rule: &ResolvedMatchingRule) -> Result<Vec<String>, MatchingRuleError> {
    let normalized = normalize_directory_string_case_ignore(value)
        .map_err(|reason| invalid_matching_syntax(rule, value, &reason))?;
    Ok(normalized
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect())
}

fn keyword_tokens(
    value: &str,
    rule: &ResolvedMatchingRule,
) -> Result<Vec<String>, MatchingRuleError> {
    let normalized = normalize_directory_string_case_ignore(value)
        .map_err(|reason| invalid_matching_syntax(rule, value, &reason))?;
    Ok(normalized
        .split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | ';'))
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect())
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

fn parse_utc_time(value: &str) -> Result<DateTime<Utc>, String> {
    if value.is_empty() {
        return Err("UTC Time value is empty".to_string());
    }
    if value.chars().any(char::is_whitespace) {
        return Err("UTC Time values must not contain whitespace".to_string());
    }

    let upper = value.to_ascii_uppercase();
    let (time_part, offset_seconds) = if let Some(time_part) = upper.strip_suffix('Z') {
        (time_part, 0)
    } else if let Some((offset_start, sign)) = upper
        .char_indices()
        .rev()
        .find(|(_, ch)| matches!(ch, '+' | '-'))
    {
        let offset = &upper[offset_start + 1..];
        if offset.len() != 4 || !offset.chars().all(|ch| ch.is_ascii_digit()) {
            return Err("UTC Time timezone offset must use +/-HHMM".to_string());
        }
        let hours = parse_utc_decimal_u32(&offset[..2], "timezone hour")?;
        let minutes = parse_utc_decimal_u32(&offset[2..], "timezone minute")?;
        if hours > 23 || minutes > 59 {
            return Err("UTC Time timezone offset is out of range".to_string());
        }
        let seconds = (hours as i32 * 3600) + (minutes as i32 * 60);
        let signed_seconds = if sign == '-' { -seconds } else { seconds };
        (&upper[..offset_start], signed_seconds)
    } else {
        (upper.as_str(), 0)
    };

    if !matches!(time_part.len(), 10 | 12) || !time_part.chars().all(|ch| ch.is_ascii_digit()) {
        return Err("expected YYMMDDHHMM[SS] UTC Time".to_string());
    }

    let year = parse_utc_decimal_u32(&time_part[0..2], "year")?;
    let full_year = if year >= 50 {
        1900 + year as i32
    } else {
        2000 + year as i32
    };
    let month = parse_utc_decimal_u32(&time_part[2..4], "month")?;
    let day = parse_utc_decimal_u32(&time_part[4..6], "day")?;
    let hour = parse_utc_decimal_u32(&time_part[6..8], "hour")?;
    let minute = parse_utc_decimal_u32(&time_part[8..10], "minute")?;
    let second = if time_part.len() == 12 {
        parse_utc_decimal_u32(&time_part[10..12], "second")?
    } else {
        0
    };

    let date = NaiveDate::from_ymd_opt(full_year, month, day)
        .ok_or_else(|| "UTC Time date is out of range".to_string())?;
    let time = NaiveTime::from_hms_opt(hour, minute, second)
        .ok_or_else(|| "UTC Time clock value is out of range".to_string())?;
    let offset = FixedOffset::east_opt(offset_seconds)
        .ok_or_else(|| "UTC Time timezone offset is out of range".to_string())?;
    let local = offset
        .from_local_datetime(&NaiveDateTime::new(date, time))
        .single()
        .ok_or_else(|| "UTC Time value is ambiguous for timezone".to_string())?;
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

fn parse_utc_decimal_u32(value: &str, label: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("invalid UTC Time {}", label))
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
    let prepared = prepare_x520_string(value, true)?;
    let mut normalized = String::with_capacity(value.len());
    for ch in prepared.chars() {
        if is_insignificant_telephone_char(ch) {
            continue;
        }
        if !is_printable_string_char(ch) {
            return Err("Telephone Number values must use PrintableString characters".to_string());
        }
        normalized.push(ch);
    }
    Ok(normalized)
}

fn is_insignificant_telephone_char(ch: char) -> bool {
    matches!(
        ch,
        ' ' | '-' | '\u{058A}' | '\u{2010}' | '\u{2011}' | '\u{2212}' | '\u{FE63}' | '\u{FF0D}'
    )
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

fn merged_schema_names(left: &[String], right: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut merged = Vec::new();
    for name in left.iter().chain(right.iter()) {
        if seen.insert(name.to_lowercase()) {
            merged.push(name.clone());
        }
    }
    merged
}

fn schema_name_sets_equal(left: &[String], right: &[String]) -> bool {
    let left = left
        .iter()
        .map(|name| name.to_lowercase())
        .collect::<HashSet<_>>();
    let right = right
        .iter()
        .map(|name| name.to_lowercase())
        .collect::<HashSet<_>>();
    left == right
}

fn compatible_optional_name(left: &Option<String>, right: &Option<String>) -> bool {
    match (left.as_deref(), right.as_deref()) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => true,
    }
}

fn compatible_schema_value(left: &str, right: &str) -> bool {
    left.is_empty() || right.is_empty() || left.eq_ignore_ascii_case(right)
}

fn merge_optional_schema_name(
    left: &Option<String>,
    right: &Option<String>,
) -> Option<Option<String>> {
    match (left.as_ref(), right.as_ref()) {
        (Some(left), Some(right)) if left.eq_ignore_ascii_case(right) => Some(Some(left.clone())),
        (Some(_), Some(_)) => None,
        (Some(left), None) => Some(Some(left.clone())),
        (None, Some(right)) => Some(Some(right.clone())),
        (None, None) => Some(None),
    }
}

fn merge_optional_schema_value<T: Clone + Eq>(
    left: &Option<T>,
    right: &Option<T>,
) -> Option<Option<T>> {
    match (left, right) {
        (Some(left), Some(right)) if left == right => Some(Some(left.clone())),
        (Some(_), Some(_)) => None,
        (Some(left), None) => Some(Some(left.clone())),
        (None, Some(right)) => Some(Some(right.clone())),
        (None, None) => Some(None),
    }
}

fn merge_schema_extensions(
    left: &BTreeMap<String, Vec<String>>,
    right: &BTreeMap<String, Vec<String>>,
) -> Option<BTreeMap<String, Vec<String>>> {
    let mut merged = left.clone();
    for (name, values) in right {
        if let Some(existing_values) = merged.get(name) {
            if existing_values != values {
                return None;
            }
        } else {
            merged.insert(name.clone(), values.clone());
        }
    }
    Some(merged)
}

fn merge_attribute_metadata(
    left: &AttributeTypeMetadata,
    right: &AttributeTypeMetadata,
) -> Option<AttributeTypeMetadata> {
    Some(AttributeTypeMetadata {
        obsolete: left.obsolete || right.obsolete,
        superior: merge_optional_schema_name(&left.superior, &right.superior)?,
        ordering: merge_optional_schema_name(&left.ordering, &right.ordering)?,
        substring: merge_optional_schema_name(&left.substring, &right.substring)?,
        collective: left.collective || right.collective,
        no_user_modification: left.no_user_modification || right.no_user_modification,
        usage: merge_optional_schema_name(&left.usage, &right.usage)?,
        syntax_length: merge_optional_schema_value(&left.syntax_length, &right.syntax_length)?,
        extensions: merge_schema_extensions(&left.extensions, &right.extensions)?,
    })
}

fn merge_schema_element_metadata(
    left: &SchemaElementMetadata,
    right: &SchemaElementMetadata,
) -> Option<SchemaElementMetadata> {
    Some(SchemaElementMetadata {
        description: merge_optional_schema_value(&left.description, &right.description)?,
        obsolete: left.obsolete || right.obsolete,
        extensions: merge_schema_extensions(&left.extensions, &right.extensions)?,
    })
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
    if metadata.collective && single_value {
        return Err(SchemaError::ParseError(format!(
            "collective attribute type {} must not be SINGLE-VALUE",
            names.first().map(String::as_str).unwrap_or(&oid)
        )));
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
    if !is_valid_numeric_oid(&oid) {
        return Err(SchemaError::ParseError(format!(
            "invalid LDAP syntax OID: {}",
            oid
        )));
    }
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
    if !is_valid_numeric_oid(&oid) {
        return Err(SchemaError::ParseError(format!(
            "invalid matching rule OID: {}",
            oid
        )));
    }
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
    if !is_valid_numeric_oid(&oid) {
        return Err(SchemaError::ParseError(format!(
            "invalid matching rule use OID: {}",
            oid
        )));
    }
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
    if !is_valid_numeric_oid(&oid) {
        return Err(SchemaError::ParseError(format!(
            "invalid DIT content rule OID: {}",
            oid
        )));
    }
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
    if !is_valid_numeric_oid(&oid) {
        return Err(SchemaError::ParseError(format!(
            "invalid name form OID: {}",
            oid
        )));
    }
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
    fn core_schema_loads_file_backed_rfc3671_and_rfc3672_definitions() {
        let mut schema = LdapSchema::with_core_schema();

        assert!(schema.get_attribute_type("administrativeRole").is_some());
        assert!(schema.get_attribute_type("subtreeSpecification").is_some());
        assert!(schema.get_object_class("subentry").is_some());
        assert!(
            schema
                .get_attribute_type("collectiveAttributeSubentries")
                .is_some()
        );
        assert!(schema.get_attribute_type("collectiveExclusions").is_some());
        assert!(schema.get_attribute_type("c-l").is_some());
        assert!(
            schema
                .get_object_class("collectiveAttributeSubentry")
                .is_some()
        );
        assert!(schema.is_collective_attribute("c-l"));
        assert!(
            schema
                .ldap_syntax_descriptions_unique_sorted()
                .iter()
                .any(|description| description.contains("1.3.6.1.4.1.1466.115.121.1.45"))
        );

        schema.load_builtin_schema("core").unwrap();
        assert!(schema.get_object_class("subentry").is_some());
        assert!(
            schema
                .get_object_class("collectiveAttributeSubentry")
                .is_some()
        );
    }

    #[test]
    fn cosine_schema_loads_file_backed_rfc4524_definitions() {
        let mut schema = LdapSchema::with_core_schema();

        schema.load_builtin_schema("cosine").unwrap();

        assert!(schema.get_attribute_type("associatedDomain").is_some());
        assert!(schema.get_attribute_type("friendlyCountryName").is_some());
        assert!(schema.get_object_class("document").is_some());
        assert!(schema.get_object_class("simpleSecurityObject").is_some());
    }

    #[test]
    fn x509_schema_loads_file_backed_rfc4523_definitions() {
        let mut schema = LdapSchema::with_core_schema();

        schema.load_builtin_schema("x509").unwrap();

        assert!(schema.get_attribute_type("cACertificate").is_some());
        assert!(
            schema
                .get_attribute_type("certificateRevocationList")
                .is_some()
        );
        assert!(schema.get_attribute_type("supportedAlgorithms").is_some());
        assert!(schema.get_object_class("pkiUser").is_some());
        assert!(schema.get_object_class("cRLDistributionPoint").is_some());
        assert!(schema.get_matching_rule("certificateExactMatch").is_some());
        assert!(
            schema
                .get_matching_rule("algorithmIdentifierMatch")
                .is_some()
        );
    }

    #[test]
    fn rfc4523_bit_list_parsers_accept_empty_and_hstring_forms() {
        assert_eq!(parse_key_usage_flags("{ }").unwrap(), 0);
        assert_eq!(
            parse_key_usage_flags("{ digitalSignature, keyEncipherment }").unwrap(),
            (1 << 0) | (1 << 2)
        );
        assert_eq!(parse_key_usage_flags("'A0'H").unwrap(), (1 << 0) | (1 << 2));

        assert_eq!(parse_reason_flags("{ }").unwrap(), 0);
        assert_eq!(
            parse_reason_flags("{ keyCompromise, cACompromise }").unwrap(),
            (1 << 1) | (1 << 2)
        );
        assert_eq!(parse_reason_flags("'60'H").unwrap(), (1 << 1) | (1 << 2));
    }

    #[test]
    fn subtree_specification_parser_accepts_rfc3672_components() {
        let spec = parse_subtree_specification(
            r#"{ base "ou=People", specificExclusions { chopBefore:"ou=Skip" }, minimum 1, maximum 2, specificationFilter item:person }"#,
        )
        .unwrap();

        assert_eq!(spec.base.as_deref(), Some("ou=People"));
        assert_eq!(spec.minimum, 1);
        assert_eq!(spec.maximum, Some(2));
        assert!(spec.contains_entry(
            "dc=example,dc=org",
            "cn=Alice,ou=People,dc=example,dc=org",
            &["person".to_string()]
        ));
        assert!(!spec.contains_entry(
            "dc=example,dc=org",
            "cn=Bob,ou=Skip,ou=People,dc=example,dc=org",
            &["person".to_string()]
        ));
        assert!(!spec.contains_entry(
            "dc=example,dc=org",
            "cn=Carol,ou=People,dc=example,dc=org",
            &["organizationalUnit".to_string()]
        ));
    }

    #[test]
    fn subtree_specification_parser_rejects_malformed_values() {
        for value in [
            "base \"ou=People\"",
            "{ maximum 1, minimum 2 }",
            "{ minimum -1 }",
            "{ specificationFilter item:2.05 }",
            "{ specificExclusions { chopSideways:\"ou=Skip\" } }",
        ] {
            assert!(
                parse_subtree_specification(value).is_err(),
                "{value} should be rejected"
            );
        }
    }

    #[test]
    fn rfc3672_subentry_requires_administrative_parent() {
        let schema = LdapSchema::with_core_schema();
        let parent = HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec!["People".to_string()]),
            (
                "administrativeRole".to_string(),
                vec!["collectiveAttributeSpecificArea".to_string()],
            ),
        ]);
        let parent_without_role = HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec!["People".to_string()]),
        ]);
        let subentry = HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "subentry".to_string()],
            ),
            ("cn".to_string(), vec!["Collective People".to_string()]),
            ("subtreeSpecification".to_string(), vec!["{}".to_string()]),
        ]);

        assert!(schema.validate_entry(&parent).is_ok());
        assert!(
            schema
                .validate_entry_at_dn(
                    "cn=Collective People,ou=People,dc=example,dc=org",
                    &subentry,
                    Some(&parent)
                )
                .is_ok()
        );
        assert!(matches!(
            schema.validate_entry_at_dn(
                "cn=Collective People,ou=People,dc=example,dc=org",
                &subentry,
                None
            ),
            Err(SchemaError::StructureRuleViolation(_))
        ));
        assert!(matches!(
            schema.validate_entry_at_dn(
                "cn=Collective People,ou=People,dc=example,dc=org",
                &subentry,
                Some(&parent_without_role)
            ),
            Err(SchemaError::StructureRuleViolation(_))
        ));
    }

    #[test]
    fn rfc3671_collective_attributes_are_only_stored_on_collective_subentries() {
        let schema = LdapSchema::with_core_schema();
        let parent = HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec!["People".to_string()]),
            (
                "administrativeRole".to_string(),
                vec!["collectiveAttributeSpecificArea".to_string()],
            ),
        ]);
        let collective_subentry = HashMap::from([
            (
                "objectClass".to_string(),
                vec![
                    "top".to_string(),
                    "subentry".to_string(),
                    "collectiveAttributeSubentry".to_string(),
                ],
            ),
            ("cn".to_string(), vec!["Collective People".to_string()]),
            ("subtreeSpecification".to_string(), vec!["{}".to_string()]),
            ("c-l".to_string(), vec!["Colombo".to_string()]),
        ]);
        let ordinary_entry = HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            ("cn".to_string(), vec!["Alice".to_string()]),
            ("sn".to_string(), vec!["Example".to_string()]),
            ("c-l".to_string(), vec!["Colombo".to_string()]),
        ]);
        let excluded_entry = HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            ("cn".to_string(), vec!["Alice".to_string()]),
            ("sn".to_string(), vec!["Example".to_string()]),
            ("collectiveExclusions".to_string(), vec!["c-l".to_string()]),
        ]);

        assert!(
            schema
                .validate_entry_at_dn(
                    "cn=Collective People,ou=People,dc=example,dc=org",
                    &collective_subentry,
                    Some(&parent)
                )
                .is_ok()
        );
        assert!(matches!(
            schema.validate_entry(&ordinary_entry),
            Err(SchemaError::AttributeNotAllowed(attribute)) if attribute == "c-l"
        ));
        assert!(schema.validate_entry(&excluded_entry).is_ok());
    }

    #[test]
    fn rfc3671_collective_subentry_requires_collective_administrative_area() {
        let schema = LdapSchema::with_core_schema();
        let parent_without_collective_role = HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec!["People".to_string()]),
            (
                "administrativeRole".to_string(),
                vec!["accessControlSpecificArea".to_string()],
            ),
        ]);
        let collective_subentry = HashMap::from([
            (
                "objectClass".to_string(),
                vec![
                    "top".to_string(),
                    "subentry".to_string(),
                    "collectiveAttributeSubentry".to_string(),
                ],
            ),
            ("cn".to_string(), vec!["Collective People".to_string()]),
            ("subtreeSpecification".to_string(), vec!["{}".to_string()]),
            ("c-l".to_string(), vec!["Colombo".to_string()]),
        ]);

        assert!(matches!(
            schema.validate_entry_at_dn(
                "cn=Collective People,ou=People,dc=example,dc=org",
                &collective_subentry,
                Some(&parent_without_collective_role)
            ),
            Err(SchemaError::StructureRuleViolation(_))
        ));
    }

    #[test]
    fn rfc3671_rejects_invalid_collective_schema_definitions() {
        let mut schema = LdapSchema::with_core_schema();

        let single_value_collective = schema
            .load_ldif_str(
                "attributeTypes: ( 1.3.6.1.4.1.55555.3671.1 NAME 'badCollectiveSingle' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE COLLECTIVE )",
            )
            .unwrap_err();
        assert!(
            single_value_collective
                .to_string()
                .contains("must not be SINGLE-VALUE")
        );

        let mut schema = LdapSchema::with_core_schema();
        let non_collective_subtype = schema
            .load_ldif_str(
                "attributeTypes: ( 1.3.6.1.4.1.55555.3671.2 NAME 'badNonCollectiveSubtype' SUP c-l )",
            )
            .unwrap_err();
        assert!(
            non_collective_subtype
                .to_string()
                .contains("must not subtype collective attribute")
        );

        let mut schema = LdapSchema::with_core_schema();
        let object_class_collective_may = schema
            .load_ldif_str(
                "objectClasses: ( 1.3.6.1.4.1.55555.3671.3 NAME 'badCollectiveObject' SUP top AUXILIARY MAY c-l )",
            )
            .unwrap_err();
        assert!(
            object_class_collective_may
                .to_string()
                .contains("must not list collective attribute")
        );
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

        assert_eq!(
            attribute_oids.len(),
            attribute_oids.iter().collect::<HashSet<_>>().len()
        );
        assert_eq!(
            object_class_oids.len(),
            object_class_oids.iter().collect::<HashSet<_>>().len()
        );
        assert!(attribute_oids.contains(&"2.16.840.1.113730.3.1.3".to_string()));
        assert!(object_class_oids.contains(&"2.16.840.1.113730.3.2.2".to_string()));
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

        assert!(description.starts_with(
            "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL"
        ));
        for attribute in [
            "audio",
            "photo",
            "userCertificate",
            "x500UniqueIdentifier",
            "userSMIMECertificate",
            "userPKCS12",
        ] {
            assert!(
                description.contains(attribute),
                "schema description should include RFC 2798 attribute {attribute}"
            );
        }
    }

    #[test]
    fn load_ldif_schema_definitions_with_rfc_descriptions() {
        let mut schema = LdapSchema::with_core_schema();

        schema
            .load_ldif_str(
                "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.9999.1.1 NAME 'exampleEmployeeNumber' DESC 'Employee number' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
objectClasses: ( 1.3.6.1.4.1.9999.1.2 NAME 'exampleEmployee' DESC 'Example employee' SUP top AUXILIARY MAY exampleEmployeeNumber )
nameForms: ( 1.3.6.1.4.1.9999.1.3 NAME 'exampleEmployeeNameForm' OC person MUST cn )
dITStructureRules: ( 999 NAME 'exampleEmployeeStructureRule' FORM exampleEmployeeNameForm )
",
            )
            .unwrap();

        let attribute_description = schema.explain("exampleEmployeeNumber").unwrap();
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
