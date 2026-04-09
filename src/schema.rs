// LDAP Schema Validation (RFC 4512)
// Implements schema enforcement for entries and attributes

use std::collections::{HashMap, HashSet};

/// LDAP Schema containing attribute types and object classes
#[derive(Debug, Clone)]
pub struct LdapSchema {
    attribute_types: HashMap<String, AttributeType>,
    object_classes: HashMap<String, ObjectClass>,
}

/// Attribute type definition
#[derive(Debug, Clone)]
pub struct AttributeType {
    pub oid: String,
    pub names: Vec<String>,
    pub description: Option<String>,
    pub equality: Option<String>,
    pub syntax: String,
    pub single_value: bool,
}

/// Object class definition
#[derive(Debug, Clone)]
pub struct ObjectClass {
    pub oid: String,
    pub names: Vec<String>,
    pub sup: Vec<String>, // Superior object classes
    pub kind: ObjectClassKind,
    pub must: Vec<String>, // Required attributes
    pub may: Vec<String>,  // Optional attributes
}

/// Object class type
#[derive(Debug, Clone, PartialEq)]
pub enum ObjectClassKind {
    Abstract,
    Structural,
    Auxiliary,
}

/// Schema validation error
#[derive(Debug, Clone, PartialEq)]
pub enum SchemaError {
    ObjectClassNotFound(String),
    AttributeNotFound(String),
    MissingRequiredAttribute(String),
    InvalidStructuralChain,
    MultipleStructuralClasses,
    SingleValueViolation(String),
    InvalidSyntax(String, String),
    NoStructuralClass,
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::ObjectClassNotFound(name) => write!(f, "Object class not found: {}", name),
            SchemaError::AttributeNotFound(name) => write!(f, "Attribute type not found: {}", name),
            SchemaError::MissingRequiredAttribute(name) => {
                write!(f, "Missing required attribute: {}", name)
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
        }
    }
}

impl std::error::Error for SchemaError {}

impl LdapSchema {
    /// Create an empty schema
    pub fn new() -> Self {
        Self {
            attribute_types: HashMap::new(),
            object_classes: HashMap::new(),
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
        ];

        for attr in core_attributes {
            for name in &attr.names {
                self.attribute_types
                    .insert(name.to_lowercase(), attr.clone());
            }
        }

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
                may: vec!["userPassword".to_string(), "description".to_string()],
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
        ];

        for oc in core_classes {
            for name in &oc.names {
                self.object_classes.insert(name.to_lowercase(), oc.clone());
            }
        }
    }

    /// Add an attribute type to the schema
    pub fn add_attribute_type(&mut self, attr: AttributeType) {
        for name in &attr.names {
            self.attribute_types
                .insert(name.to_lowercase(), attr.clone());
        }
    }

    /// Add an object class to the schema
    pub fn add_object_class(&mut self, oc: ObjectClass) {
        for name in &oc.names {
            self.object_classes.insert(name.to_lowercase(), oc.clone());
        }
    }

    /// Get an attribute type by name
    pub fn get_attribute_type(&self, name: &str) -> Option<&AttributeType> {
        self.attribute_types.get(&name.to_lowercase())
    }

    /// Get an object class by name
    pub fn get_object_class(&self, name: &str) -> Option<&ObjectClass> {
        self.object_classes.get(&name.to_lowercase())
    }

    /// Return unique attribute types keyed by OID, sorted for stable publication.
    pub fn attribute_types_unique_sorted(&self) -> Vec<AttributeType> {
        let mut by_oid = HashMap::new();
        for attribute in self.attribute_types.values() {
            by_oid
                .entry(attribute.oid.clone())
                .or_insert_with(|| attribute.clone());
        }

        let mut attributes = by_oid.into_values().collect::<Vec<_>>();
        attributes.sort_by(|left, right| left.oid.cmp(&right.oid));
        attributes
    }

    /// Return unique object classes keyed by OID, sorted for stable publication.
    pub fn object_classes_unique_sorted(&self) -> Vec<ObjectClass> {
        let mut by_oid = HashMap::new();
        for object_class in self.object_classes.values() {
            by_oid
                .entry(object_class.oid.clone())
                .or_insert_with(|| object_class.clone());
        }

        let mut object_classes = by_oid.into_values().collect::<Vec<_>>();
        object_classes.sort_by(|left, right| left.oid.cmp(&right.oid));
        object_classes
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
            }
        }

        // Validate single-value constraints
        for (attr_name, values) in attributes {
            if let Some(attr_type) = self.get_attribute_type(attr_name) {
                if attr_type.single_value && values.len() > 1 {
                    return Err(SchemaError::SingleValueViolation(attr_name.clone()));
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
        let mut parts = vec![format!("( {}", self.oid)];

        if !self.names.is_empty() {
            parts.push(format!("NAME {}", format_name_list(&self.names)));
        }
        if let Some(description) = &self.description {
            parts.push(format!("DESC '{}'", escape_schema_value(description)));
        }
        if let Some(equality) = &self.equality {
            parts.push(format!("EQUALITY {}", equality));
        }
        parts.push(format!("SYNTAX {}", self.syntax));
        if self.single_value {
            parts.push("SINGLE-VALUE".to_string());
        }

        parts.push(")".to_string());
        parts.join(" ")
    }
}

impl ObjectClass {
    pub fn to_schema_description(&self) -> String {
        let mut parts = vec![format!("( {}", self.oid)];

        if !self.names.is_empty() {
            parts.push(format!("NAME {}", format_name_list(&self.names)));
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

fn escape_schema_value(value: &str) -> String {
    value.replace('\'', "\\27")
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

        assert_eq!(attribute_oids.len(), 10);
        assert_eq!(object_class_oids.len(), 6);
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
            "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( uid $ givenName $ mail ) )"
        );
    }
}
