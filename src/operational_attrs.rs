//! Operational Attributes Search Support
//!
//! This module provides utilities for handling operational attribute requests
//! in LDAP search operations per RFC 4512 section 3.4.
//!
//! ## LDAP Operational Attributes Behavior
//!
//! - By default, operational attributes are NOT returned in search results
//! - Client must explicitly request operational attributes using:
//!   - "+" in attribute list → returns ALL operational attributes
//!   - Specific attribute names (e.g., "entryCSN", "modifyTimestamp")
//! - Client can request both user and operational attributes:
//!   - "*" → all user attributes (default behavior)
//!   - "+" → all operational attributes
//!   - ["*", "+"] → all user and operational attributes
//!   - ["cn", "mail", "entryCSN"] → specific user attrs + specific operational attr

use crate::backend::OperationalAttributes;
use std::collections::HashMap;

/// Check if the requested attributes include operational attributes
///
/// # Arguments
/// * `requested_attrs` - Attributes requested by the client
///
/// # Returns
/// * `(include_user, include_operational, specific_operational)` tuple where:
///   - `include_user` - Whether to include user attributes
///   - `include_operational` - Whether to include ALL operational attributes
///   - `specific_operational` - List of specific operational attributes requested
pub fn parse_attribute_request(requested_attrs: &[String]) -> (bool, bool, Vec<String>) {
    // Empty list means return all user attributes (not operational)
    if requested_attrs.is_empty() {
        return (true, false, Vec::new());
    }

    let mut include_user = false;
    let mut include_all_operational = false;
    let mut specific_operational = Vec::new();

    let mut has_user_attrs = false;

    for attr in requested_attrs {
        let attr_lower = attr.to_ascii_lowercase();

        match attr_lower.as_str() {
            "*" => include_user = true,
            "+" => include_all_operational = true,
            _ => {
                if OperationalAttributes::is_operational(&attr_lower) {
                    specific_operational.push(attr_lower);
                } else {
                    has_user_attrs = true;
                }
            }
        }
    }

    // Include user attributes if:
    // 1. "*" was explicitly requested, OR
    // 2. Specific user attributes were requested
    include_user = include_user || has_user_attrs;

    (include_user, include_all_operational, specific_operational)
}

/// Filter operational attributes based on request
///
/// # Arguments
/// * `operational_attrs` - The operational attributes from the entry
/// * `requested_attrs` - Attributes requested by the client
///
/// # Returns
/// * HashMap of operational attributes that should be included in the response
pub fn filter_operational_attributes(
    operational_attrs: &OperationalAttributes,
    requested_attrs: &[String],
) -> HashMap<String, Vec<String>> {
    let (_, include_all_operational, specific_operational) =
        parse_attribute_request(requested_attrs);

    // If neither "+" nor specific operational attrs requested, return empty
    if !include_all_operational && specific_operational.is_empty() {
        return HashMap::new();
    }

    let all_operational = operational_attrs.to_attributes();

    if include_all_operational {
        // Return all operational attributes
        all_operational
    } else {
        // Return only specifically requested operational attributes
        all_operational
            .into_iter()
            .filter(|(key, _)| specific_operational.contains(&key.to_ascii_lowercase()))
            .collect()
    }
}

/// Filter user attributes based on request
///
/// # Arguments
/// * `user_attrs` - The user attributes from the entry
/// * `requested_attrs` - Attributes requested by the client
///
/// # Returns
/// * HashMap of user attributes that should be included in the response
pub fn filter_user_attributes(
    user_attrs: &HashMap<String, Vec<String>>,
    requested_attrs: &[String],
) -> HashMap<String, Vec<String>> {
    let (include_user, _, _) = parse_attribute_request(requested_attrs);

    // If user attributes not requested, return empty
    if !include_user {
        return HashMap::new();
    }

    // If empty list or "*" present, return all user attributes
    if requested_attrs.is_empty() || requested_attrs.iter().any(|a| a == "*") {
        return user_attrs.clone();
    }

    // Return only specifically requested user attributes
    let requested_lower: Vec<String> = requested_attrs
        .iter()
        .map(|a| a.to_ascii_lowercase())
        .collect();

    user_attrs
        .iter()
        .filter(|(key, _)| {
            let key_lower = key.to_ascii_lowercase();
            // Include if requested and not operational
            requested_lower.contains(&key_lower)
                && !OperationalAttributes::is_operational(&key_lower)
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Merge user and operational attributes for search results
///
/// # Arguments
/// * `user_attrs` - User attributes from the entry
/// * `operational_attrs` - Operational attributes to include
///
/// # Returns
/// * Combined HashMap of all attributes to return
pub fn merge_attributes(
    user_attrs: HashMap<String, Vec<String>>,
    operational_attrs: HashMap<String, Vec<String>>,
) -> HashMap<String, Vec<String>> {
    let mut result = user_attrs;
    result.extend(operational_attrs);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csn::Csn;

    #[test]
    fn test_parse_empty_request() {
        let (user, operational, specific) = parse_attribute_request(&[]);
        assert!(user, "Empty request should include user attributes");
        assert!(
            !operational,
            "Empty request should not include operational attributes"
        );
        assert!(
            specific.is_empty(),
            "Empty request should have no specific operational attributes"
        );
    }

    #[test]
    fn test_parse_user_only() {
        let attrs = vec!["cn".to_string(), "mail".to_string()];
        let (user, operational, specific) = parse_attribute_request(&attrs);
        assert!(user);
        assert!(!operational);
        assert!(specific.is_empty());
    }

    #[test]
    fn test_parse_all_operational() {
        let attrs = vec!["+".to_string()];
        let (user, operational, specific) = parse_attribute_request(&attrs);
        assert!(!user, "Only '+' should not include user attributes");
        assert!(operational);
        assert!(specific.is_empty());
    }

    #[test]
    fn test_parse_all_user_and_operational() {
        let attrs = vec!["*".to_string(), "+".to_string()];
        let (user, operational, specific) = parse_attribute_request(&attrs);
        assert!(user);
        assert!(operational);
        assert!(specific.is_empty());
    }

    #[test]
    fn test_parse_specific_operational() {
        let attrs = vec!["entrycsn".to_string(), "modifytimestamp".to_string()];
        let (user, operational, specific) = parse_attribute_request(&attrs);
        assert!(
            !user,
            "Only operational attrs should not include user attributes"
        );
        assert!(
            !operational,
            "Specific operational should not set include_all flag"
        );
        assert_eq!(specific.len(), 2);
        assert!(specific.contains(&"entrycsn".to_string()));
        assert!(specific.contains(&"modifytimestamp".to_string()));
    }

    #[test]
    fn test_parse_mixed_user_and_operational() {
        let attrs = vec!["cn".to_string(), "entrycsn".to_string(), "mail".to_string()];
        let (user, operational, specific) = parse_attribute_request(&attrs);
        assert!(user);
        assert!(!operational);
        assert_eq!(specific.len(), 1);
        assert!(specific.contains(&"entrycsn".to_string()));
    }

    #[test]
    fn test_filter_operational_none_requested() {
        let csn = Csn::new(1);
        let op_attrs = OperationalAttributes::for_new_entry(csn, Some("cn=admin".to_string()));
        let requested = vec!["cn".to_string(), "mail".to_string()];

        let result = filter_operational_attributes(&op_attrs, &requested);
        assert!(
            result.is_empty(),
            "Should not return operational attrs when not requested"
        );
    }

    #[test]
    fn test_filter_operational_all_requested() {
        let csn = Csn::new(1);
        let op_attrs = OperationalAttributes::for_new_entry(csn, Some("cn=admin".to_string()));
        let requested = vec!["+".to_string()];

        let result = filter_operational_attributes(&op_attrs, &requested);
        assert!(
            !result.is_empty(),
            "Should return operational attrs when '+' requested"
        );
        assert!(result.contains_key("entrycsn"), "Should include entryCSN");
        assert!(
            result.contains_key("createtimestamp"),
            "Should include createTimestamp"
        );
    }

    #[test]
    fn test_filter_operational_specific_requested() {
        let csn = Csn::new(1);
        let op_attrs = OperationalAttributes::for_new_entry(csn, Some("cn=admin".to_string()));
        let requested = vec!["entrycsn".to_string()];

        let result = filter_operational_attributes(&op_attrs, &requested);
        assert_eq!(
            result.len(),
            1,
            "Should return only requested operational attr"
        );
        assert!(result.contains_key("entrycsn"), "Should include entryCSN");
        assert!(
            !result.contains_key("createtimestamp"),
            "Should not include non-requested attr"
        );
    }

    #[test]
    fn test_merge_attributes() {
        let mut user_attrs = HashMap::new();
        user_attrs.insert("cn".to_string(), vec!["John Doe".to_string()]);
        user_attrs.insert("mail".to_string(), vec!["john@example.com".to_string()]);

        let mut op_attrs = HashMap::new();
        op_attrs.insert(
            "entrycsn".to_string(),
            vec!["20250107120000.000000Z#000001#000#000000".to_string()],
        );

        let result = merge_attributes(user_attrs.clone(), op_attrs.clone());

        assert_eq!(result.len(), 3);
        assert_eq!(result.get("cn"), user_attrs.get("cn"));
        assert_eq!(result.get("mail"), user_attrs.get("mail"));
        assert_eq!(result.get("entrycsn"), op_attrs.get("entrycsn"));
    }
}
