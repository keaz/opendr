//! LDAP Schema Adapter
//!
//! This module provides an adapter between the write FSM's SchemaValidator trait
//! and the LdapSchema implementation. It handles LDIF parsing and validation.

use crate::schema::LdapSchema;
use crate::write_fsm::{Modification, SchemaValidator, WriteEntry};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// LDAP Schema Validator that implements the SchemaValidator trait
pub struct LdapSchemaValidator {
    schema: Arc<LdapSchema>,
}

impl LdapSchemaValidator {
    /// Create a new LdapSchemaValidator with the default core schema
    pub fn new() -> Self {
        Self {
            schema: Arc::new(LdapSchema::with_core_schema()),
        }
    }

    /// Create a new LdapSchemaValidator with a custom schema
    pub fn with_schema(schema: LdapSchema) -> Self {
        Self {
            schema: Arc::new(schema),
        }
    }

    /// Parse LDIF bytes into attributes map
    ///
    /// LDIF format:
    /// ```text
    /// dn: cn=John Doe,ou=users,dc=example,dc=com
    /// objectClass: top
    /// objectClass: person
    /// cn: John Doe
    /// sn: Doe
    /// ```
    #[cfg(test)]
    fn parse_ldif_to_attributes(ldif_bytes: &[u8]) -> Result<HashMap<String, Vec<String>>, String> {
        let ldif_str =
            std::str::from_utf8(ldif_bytes).map_err(|e| format!("Invalid UTF-8 in LDIF: {}", e))?;

        let mut attributes: HashMap<String, Vec<String>> = HashMap::new();

        for line in ldif_str.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Skip DN line (it's already in WriteEntry.dn)
            if line.starts_with("dn:") || line.starts_with("DN:") {
                continue;
            }

            // Parse attribute: value pairs
            if let Some(colon_pos) = line.find(':') {
                let attr_name = line[..colon_pos].trim().to_string();
                let attr_value = line[colon_pos + 1..].trim().to_string();

                attributes.entry(attr_name).or_default().push(attr_value);
            }
        }

        Ok(attributes)
    }

    /// Convert WriteEntry to attributes map for validation
    fn entry_to_attributes(entry: &WriteEntry) -> HashMap<String, Vec<String>> {
        let mut attributes = entry.attributes.clone();

        // Add objectClass attributes
        attributes.insert("objectClass".to_string(), entry.object_classes.clone());

        attributes
    }
}

impl Default for LdapSchemaValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SchemaValidator for LdapSchemaValidator {
    async fn validate_entry(&self, entry: &WriteEntry) -> Result<(), String> {
        let attributes = Self::entry_to_attributes(entry);

        self.schema
            .validate_entry(&attributes)
            .map_err(|e| e.to_string())
    }

    async fn validate_modifications(
        &self,
        _dn: &str,
        modifications: &[Modification],
    ) -> Result<(), String> {
        // Basic validation: ensure all modified attributes exist in schema
        for modification in modifications {
            let attr_name = match modification {
                Modification::Add { name, .. } => name,
                Modification::Delete { name, .. } => name,
                Modification::Replace { name, .. } => name,
            };

            // Check if attribute type exists in schema
            if self.schema.get_attribute_type(attr_name).is_none() {
                return Err(format!("Unknown attribute type: {}", attr_name));
            }

            // Check single-value constraints for Add and Replace
            match modification {
                Modification::Add { name, values } | Modification::Replace { name, values } => {
                    if let Some(attr_type) = self.schema.get_attribute_type(name)
                        && attr_type.single_value
                        && values.len() > 1
                    {
                        return Err(format!("Single-value violation for attribute: {}", name));
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn validate_dn_modification(
        &self,
        _dn: &str,
        new_rdn: &str,
        _new_superior: Option<&str>,
    ) -> Result<(), String> {
        // Validate RDN format: attribute=value
        if !new_rdn.contains('=') {
            return Err("Invalid RDN format: must be attribute=value".to_string());
        }

        let parts: Vec<&str> = new_rdn.split('=').collect();
        if parts.len() != 2 {
            return Err("Invalid RDN format: must be attribute=value".to_string());
        }

        let attr_name = parts[0].trim();

        // Check if the attribute exists in schema
        if self.schema.get_attribute_type(attr_name).is_none() {
            return Err(format!("Unknown attribute type in RDN: {}", attr_name));
        }

        Ok(())
    }

    fn is_object_class_defined(&self, object_class: &str) -> bool {
        self.schema.get_object_class(object_class).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ldif_to_attributes() {
        let ldif = b"dn: cn=John Doe,ou=users,dc=example,dc=com
objectClass: top
objectClass: person
cn: John Doe
sn: Doe
mail: john@example.com
";

        let attributes = LdapSchemaValidator::parse_ldif_to_attributes(ldif).unwrap();

        assert_eq!(attributes.get("objectClass").unwrap().len(), 2);
        assert!(
            attributes
                .get("objectClass")
                .unwrap()
                .contains(&"top".to_string())
        );
        assert!(
            attributes
                .get("objectClass")
                .unwrap()
                .contains(&"person".to_string())
        );
        assert_eq!(attributes.get("cn").unwrap()[0], "John Doe");
        assert_eq!(attributes.get("sn").unwrap()[0], "Doe");
        assert_eq!(attributes.get("mail").unwrap()[0], "john@example.com");
    }

    #[tokio::test]
    async fn test_validate_valid_entry() {
        let validator = LdapSchemaValidator::new();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
        attributes.insert("sn".to_string(), vec!["Doe".to_string()]);

        let entry = WriteEntry {
            dn: "cn=John Doe,ou=users,dc=example,dc=com".to_string(),
            attributes,
            object_classes: vec!["top".to_string(), "person".to_string()],
            binary_attributes: HashMap::new(),
        };

        assert!(validator.validate_entry(&entry).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_missing_required_attribute() {
        let validator = LdapSchemaValidator::new();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
        // Missing 'sn' which is required by person

        let entry = WriteEntry {
            dn: "cn=John Doe,ou=users,dc=example,dc=com".to_string(),
            attributes,
            object_classes: vec!["top".to_string(), "person".to_string()],
            binary_attributes: HashMap::new(),
        };

        let result = validator.validate_entry(&entry).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing required attribute"));
    }

    #[tokio::test]
    async fn test_validate_unknown_object_class() {
        let validator = LdapSchemaValidator::new();

        let entry = WriteEntry {
            dn: "cn=John Doe,ou=users,dc=example,dc=com".to_string(),
            attributes: HashMap::new(),
            object_classes: vec!["unknownClass".to_string()],
            binary_attributes: HashMap::new(),
        };

        let result = validator.validate_entry(&entry).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Object class not found"));
    }

    #[tokio::test]
    async fn test_validate_modifications() {
        let validator = LdapSchemaValidator::new();

        let modifications = vec![
            Modification::Add {
                name: "mail".to_string(),
                values: vec!["john@example.com".to_string()],
            },
            Modification::Replace {
                name: "description".to_string(),
                values: vec!["Updated description".to_string()],
            },
        ];

        assert!(
            validator
                .validate_modifications("cn=John Doe,dc=example,dc=com", &modifications)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_validate_unknown_attribute_modification() {
        let validator = LdapSchemaValidator::new();

        let modifications = vec![Modification::Add {
            name: "unknownAttr".to_string(),
            values: vec!["value".to_string()],
        }];

        let result = validator
            .validate_modifications("cn=John Doe,dc=example,dc=com", &modifications)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown attribute type"));
    }

    #[tokio::test]
    async fn test_validate_dn_modification() {
        let validator = LdapSchemaValidator::new();

        assert!(
            validator
                .validate_dn_modification("cn=John Doe,dc=example,dc=com", "cn=Jane Doe", None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_validate_invalid_rdn() {
        let validator = LdapSchemaValidator::new();

        let result = validator
            .validate_dn_modification("cn=John Doe,dc=example,dc=com", "invalid_rdn", None)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid RDN format"));
    }

    #[test]
    fn test_is_object_class_defined() {
        let validator = LdapSchemaValidator::new();

        assert!(validator.is_object_class_defined("person"));
        assert!(validator.is_object_class_defined("inetOrgPerson"));
        assert!(!validator.is_object_class_defined("unknownClass"));
    }
}
