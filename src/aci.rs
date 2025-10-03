//! Access Control Information (ACI) System
//!
//! This module provides a comprehensive ACI system for fine-grained access control
//! in LDAP operations, following LDAP ACI specifications.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// ACI permission types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Read permission
    Read,
    /// Write permission (add/modify/delete)
    Write,
    /// Search permission
    Search,
    /// Compare permission
    Compare,
    /// Add permission (create entries)
    Add,
    /// Delete permission
    Delete,
    /// Modify permission
    Modify,
    /// Proxy (act as another user)
    Proxy,
}

impl Permission {
    /// Parse permission from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "read" => Some(Permission::Read),
            "write" => Some(Permission::Write),
            "search" => Some(Permission::Search),
            "compare" => Some(Permission::Compare),
            "add" => Some(Permission::Add),
            "delete" => Some(Permission::Delete),
            "modify" => Some(Permission::Modify),
            "proxy" => Some(Permission::Proxy),
            _ => None,
        }
    }

    /// Convert permission to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Write => "write",
            Permission::Search => "search",
            Permission::Compare => "compare",
            Permission::Add => "add",
            Permission::Delete => "delete",
            Permission::Modify => "modify",
            Permission::Proxy => "proxy",
        }
    }
}

/// ACI target specification
#[derive(Debug, Clone, PartialEq)]
pub enum AciTarget {
    /// Target specific DN
    Dn(String),
    /// Target DN and all descendants
    Subtree(String),
    /// Target specific attributes
    Attributes(Vec<String>),
    /// Combination of targets
    Combined(Box<AciTarget>, Box<AciTarget>),
}

impl AciTarget {
    /// Check if a DN matches this target
    pub fn matches_dn(&self, dn: &str) -> bool {
        match self {
            AciTarget::Dn(target_dn) => dn.eq_ignore_ascii_case(target_dn),
            AciTarget::Subtree(base_dn) => {
                dn.eq_ignore_ascii_case(base_dn) ||
                dn.to_lowercase().ends_with(&format!(",{}", base_dn.to_lowercase()))
            }
            AciTarget::Attributes(_) => true, // DN matching for attributes is always true
            AciTarget::Combined(left, right) => {
                left.matches_dn(dn) && right.matches_dn(dn)
            }
        }
    }

    /// Check if an attribute matches this target
    pub fn matches_attribute(&self, attr: &str) -> bool {
        match self {
            AciTarget::Dn(_) | AciTarget::Subtree(_) => true,
            AciTarget::Attributes(attrs) => {
                attrs.iter().any(|a| a.eq_ignore_ascii_case(attr))
            }
            AciTarget::Combined(left, right) => {
                left.matches_attribute(attr) && right.matches_attribute(attr)
            }
        }
    }
}

/// ACI subject (who the rule applies to)
#[derive(Debug, Clone, PartialEq)]
pub enum AciSubject {
    /// Specific user DN
    User(String),
    /// Group membership
    Group(String),
    /// All authenticated users
    AllAuthenticated,
    /// All users (including anonymous)
    All,
    /// Self (the user's own entry)
    SelfEntry,
}

impl AciSubject {
    /// Check if a user DN matches this subject
    pub fn matches_user(&self, user_dn: Option<&str>, target_dn: &str) -> bool {
        match self {
            AciSubject::User(dn) => {
                user_dn.map(|u| u.eq_ignore_ascii_case(dn)).unwrap_or(false)
            }
            AciSubject::Group(_group_dn) => {
                // TODO: Implement group membership checking
                // This would require a backend lookup
                false
            }
            AciSubject::AllAuthenticated => user_dn.is_some(),
            AciSubject::All => true,
            AciSubject::SelfEntry => {
                user_dn.map(|u| u.eq_ignore_ascii_case(target_dn)).unwrap_or(false)
            }
        }
    }
}

/// ACI rule defining access control
#[derive(Debug, Clone)]
pub struct AciRule {
    /// Rule name/identifier
    pub name: String,
    /// Target of the rule
    pub target: AciTarget,
    /// Permissions granted/denied
    pub permissions: Vec<Permission>,
    /// Subject the rule applies to
    pub subject: AciSubject,
    /// Whether this is a grant or deny rule
    pub is_grant: bool,
    /// Priority (higher priority rules are evaluated first)
    pub priority: i32,
}

impl AciRule {
    /// Create a new grant rule
    pub fn grant(
        name: impl Into<String>,
        target: AciTarget,
        permissions: Vec<Permission>,
        subject: AciSubject,
    ) -> Self {
        Self {
            name: name.into(),
            target,
            permissions,
            subject,
            is_grant: true,
            priority: 0,
        }
    }

    /// Create a new deny rule
    pub fn deny(
        name: impl Into<String>,
        target: AciTarget,
        permissions: Vec<Permission>,
        subject: AciSubject,
    ) -> Self {
        Self {
            name: name.into(),
            target,
            permissions,
            subject,
            is_grant: false,
            priority: 0,
        }
    }

    /// Set rule priority
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Check if this rule matches the given parameters
    pub fn matches(
        &self,
        user_dn: Option<&str>,
        target_dn: &str,
        attribute: Option<&str>,
        permission: Permission,
    ) -> Option<bool> {
        // Check if permission matches
        if !self.permissions.contains(&permission) {
            return None;
        }

        // Check if target matches
        if !self.target.matches_dn(target_dn) {
            return None;
        }

        // Check if attribute matches (if specified)
        if let Some(attr) = attribute {
            if !self.target.matches_attribute(attr) {
                return None;
            }
        }

        // Check if subject matches
        if !self.subject.matches_user(user_dn, target_dn) {
            return None;
        }

        // Return grant/deny decision
        Some(self.is_grant)
    }
}

/// ACI engine for evaluating access control rules
pub struct AciEngine {
    /// Active ACI rules
    rules: Arc<RwLock<Vec<AciRule>>>,
    /// Default policy when no rules match (default: deny)
    default_allow: bool,
}

impl AciEngine {
    /// Create a new ACI engine
    ///
    /// # Arguments
    /// * `default_allow` - Whether to allow access when no rules match
    ///
    /// # Returns
    /// * New ACI engine instance
    pub fn new(default_allow: bool) -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            default_allow,
        }
    }

    /// Create a permissive ACI engine (allows by default)
    pub fn permissive() -> Self {
        Self::new(true)
    }

    /// Create a restrictive ACI engine (denies by default)
    pub fn restrictive() -> Self {
        Self::new(false)
    }

    /// Add an ACI rule
    pub async fn add_rule(&self, rule: AciRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
        // Sort by priority (highest first)
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Remove an ACI rule by name
    pub async fn remove_rule(&self, name: &str) -> bool {
        let mut rules = self.rules.write().await;
        let initial_len = rules.len();
        rules.retain(|r| r.name != name);
        rules.len() < initial_len
    }

    /// Clear all rules
    pub async fn clear_rules(&self) {
        let mut rules = self.rules.write().await;
        rules.clear();
    }

    /// Get all rules
    pub async fn get_rules(&self) -> Vec<AciRule> {
        let rules = self.rules.read().await;
        rules.clone()
    }

    /// Check if an operation is allowed
    ///
    /// # Arguments
    /// * `user_dn` - DN of user performing the operation (None for anonymous)
    /// * `target_dn` - DN of target entry
    /// * `attribute` - Optional attribute name
    /// * `permission` - Permission being requested
    ///
    /// # Returns
    /// * `Ok(())` if operation is allowed
    /// * `Err(String)` if operation is denied
    pub async fn check_permission(
        &self,
        user_dn: Option<&str>,
        target_dn: &str,
        attribute: Option<&str>,
        permission: Permission,
    ) -> Result<(), String> {
        let rules = self.rules.read().await;

        // Evaluate rules in priority order
        for rule in rules.iter() {
            if let Some(decision) = rule.matches(user_dn, target_dn, attribute, permission) {
                if decision {
                    return Ok(()); // Explicitly granted
                } else {
                    return Err(format!(
                        "Access denied by rule '{}' for {} on {}",
                        rule.name,
                        permission.as_str(),
                        target_dn
                    ));
                }
            }
        }

        // No matching rules - apply default policy
        if self.default_allow {
            Ok(())
        } else {
            Err(format!(
                "Access denied (no matching rules) for {} on {}",
                permission.as_str(),
                target_dn
            ))
        }
    }

    /// Check multiple permissions at once
    pub async fn check_permissions(
        &self,
        user_dn: Option<&str>,
        target_dn: &str,
        attribute: Option<&str>,
        permissions: &[Permission],
    ) -> Result<(), String> {
        for permission in permissions {
            self.check_permission(user_dn, target_dn, attribute, *permission).await?;
        }
        Ok(())
    }
}

impl Default for AciEngine {
    fn default() -> Self {
        Self::restrictive()
    }
}

/// ACI rule builder for easier rule construction
pub struct AciRuleBuilder {
    name: String,
    target: Option<AciTarget>,
    permissions: Vec<Permission>,
    subject: Option<AciSubject>,
    is_grant: bool,
    priority: i32,
}

impl AciRuleBuilder {
    /// Create a new grant rule builder
    pub fn grant(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            target: None,
            permissions: Vec::new(),
            subject: None,
            is_grant: true,
            priority: 0,
        }
    }

    /// Create a new deny rule builder
    pub fn deny(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            target: None,
            permissions: Vec::new(),
            subject: None,
            is_grant: false,
            priority: 0,
        }
    }

    /// Set target DN
    pub fn target_dn(mut self, dn: impl Into<String>) -> Self {
        self.target = Some(AciTarget::Dn(dn.into()));
        self
    }

    /// Set target subtree
    pub fn target_subtree(mut self, base_dn: impl Into<String>) -> Self {
        self.target = Some(AciTarget::Subtree(base_dn.into()));
        self
    }

    /// Set target attributes
    pub fn target_attributes(mut self, attrs: Vec<String>) -> Self {
        self.target = Some(AciTarget::Attributes(attrs));
        self
    }

    /// Add a permission
    pub fn permission(mut self, perm: Permission) -> Self {
        self.permissions.push(perm);
        self
    }

    /// Add multiple permissions
    pub fn permissions(mut self, perms: Vec<Permission>) -> Self {
        self.permissions.extend(perms);
        self
    }

    /// Set subject to specific user
    pub fn subject_user(mut self, dn: impl Into<String>) -> Self {
        self.subject = Some(AciSubject::User(dn.into()));
        self
    }

    /// Set subject to all authenticated users
    pub fn subject_all_authenticated(mut self) -> Self {
        self.subject = Some(AciSubject::AllAuthenticated);
        self
    }

    /// Set subject to all users
    pub fn subject_all(mut self) -> Self {
        self.subject = Some(AciSubject::All);
        self
    }

    /// Set subject to self
    pub fn subject_self(mut self) -> Self {
        self.subject = Some(AciSubject::SelfEntry);
        self
    }

    /// Set priority
    pub fn priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Build the ACI rule
    pub fn build(self) -> Result<AciRule, String> {
        let target = self.target.ok_or("Target not specified")?;
        let subject = self.subject.ok_or("Subject not specified")?;

        if self.permissions.is_empty() {
            return Err("No permissions specified".to_string());
        }

        Ok(AciRule {
            name: self.name,
            target,
            permissions: self.permissions,
            subject,
            is_grant: self.is_grant,
            priority: self.priority,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_from_str() {
        assert_eq!(Permission::from_str("read"), Some(Permission::Read));
        assert_eq!(Permission::from_str("WRITE"), Some(Permission::Write));
        assert_eq!(Permission::from_str("invalid"), None);
    }

    #[test]
    fn test_aci_target_dn_matching() {
        let target = AciTarget::Dn("cn=user,dc=example,dc=org".to_string());
        assert!(target.matches_dn("cn=user,dc=example,dc=org"));
        assert!(target.matches_dn("CN=USER,DC=EXAMPLE,DC=ORG"));
        assert!(!target.matches_dn("cn=other,dc=example,dc=org"));
    }

    #[test]
    fn test_aci_target_subtree_matching() {
        let target = AciTarget::Subtree("dc=example,dc=org".to_string());
        assert!(target.matches_dn("dc=example,dc=org"));
        assert!(target.matches_dn("cn=user,dc=example,dc=org"));
        assert!(target.matches_dn("ou=dept,cn=user,dc=example,dc=org"));
        assert!(!target.matches_dn("dc=other,dc=org"));
    }

    #[test]
    fn test_aci_target_attribute_matching() {
        let target = AciTarget::Attributes(vec!["cn".to_string(), "sn".to_string()]);
        assert!(target.matches_attribute("cn"));
        assert!(target.matches_attribute("SN"));
        assert!(!target.matches_attribute("mail"));
    }

    #[test]
    fn test_aci_subject_user_matching() {
        let subject = AciSubject::User("cn=admin,dc=example,dc=org".to_string());
        assert!(subject.matches_user(
            Some("cn=admin,dc=example,dc=org"),
            "cn=user,dc=example,dc=org"
        ));
        assert!(!subject.matches_user(
            Some("cn=other,dc=example,dc=org"),
            "cn=user,dc=example,dc=org"
        ));
        assert!(!subject.matches_user(None, "cn=user,dc=example,dc=org"));
    }

    #[test]
    fn test_aci_subject_all_authenticated() {
        let subject = AciSubject::AllAuthenticated;
        assert!(subject.matches_user(
            Some("cn=anyone,dc=example,dc=org"),
            "cn=user,dc=example,dc=org"
        ));
        assert!(!subject.matches_user(None, "cn=user,dc=example,dc=org"));
    }

    #[test]
    fn test_aci_subject_self() {
        let subject = AciSubject::SelfEntry;
        assert!(subject.matches_user(
            Some("cn=user,dc=example,dc=org"),
            "cn=user,dc=example,dc=org"
        ));
        assert!(!subject.matches_user(
            Some("cn=other,dc=example,dc=org"),
            "cn=user,dc=example,dc=org"
        ));
    }

    #[tokio::test]
    async fn test_aci_engine_grant_rule() {
        let engine = AciEngine::restrictive();

        let rule = AciRule::grant(
            "allow-admin-read",
            AciTarget::Subtree("dc=example,dc=org".to_string()),
            vec![Permission::Read, Permission::Search],
            AciSubject::User("cn=admin,dc=example,dc=org".to_string()),
        );

        engine.add_rule(rule).await;

        // Should allow admin to read
        let result = engine.check_permission(
            Some("cn=admin,dc=example,dc=org"),
            "cn=user,dc=example,dc=org",
            None,
            Permission::Read,
        ).await;
        assert!(result.is_ok());

        // Should deny other users
        let result = engine.check_permission(
            Some("cn=other,dc=example,dc=org"),
            "cn=user,dc=example,dc=org",
            None,
            Permission::Read,
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_aci_engine_deny_rule() {
        let engine = AciEngine::permissive();

        let rule = AciRule::deny(
            "deny-user-write",
            AciTarget::Subtree("dc=example,dc=org".to_string()),
            vec![Permission::Write],
            AciSubject::User("cn=user,dc=example,dc=org".to_string()),
        );

        engine.add_rule(rule).await;

        // Should deny user write
        let result = engine.check_permission(
            Some("cn=user,dc=example,dc=org"),
            "cn=other,dc=example,dc=org",
            None,
            Permission::Write,
        ).await;
        assert!(result.is_err());

        // Should allow other permissions
        let result = engine.check_permission(
            Some("cn=user,dc=example,dc=org"),
            "cn=other,dc=example,dc=org",
            None,
            Permission::Read,
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_aci_rule_builder() {
        let rule = AciRuleBuilder::grant("test-rule")
            .target_subtree("dc=example,dc=org")
            .permissions(vec![Permission::Read, Permission::Search])
            .subject_all_authenticated()
            .priority(10)
            .build()
            .unwrap();

        assert_eq!(rule.name, "test-rule");
        assert_eq!(rule.permissions.len(), 2);
        assert_eq!(rule.priority, 10);
        assert!(rule.is_grant);
    }

    #[tokio::test]
    async fn test_aci_engine_priority() {
        let engine = AciEngine::restrictive();

        // High priority deny rule
        let deny_rule = AciRule::deny(
            "deny-high",
            AciTarget::Subtree("dc=example,dc=org".to_string()),
            vec![Permission::Write],
            AciSubject::AllAuthenticated,
        ).with_priority(100);

        // Low priority grant rule
        let grant_rule = AciRule::grant(
            "grant-low",
            AciTarget::Subtree("dc=example,dc=org".to_string()),
            vec![Permission::Write],
            AciSubject::AllAuthenticated,
        ).with_priority(10);

        engine.add_rule(grant_rule).await;
        engine.add_rule(deny_rule).await;

        // Deny should win due to higher priority
        let result = engine.check_permission(
            Some("cn=user,dc=example,dc=org"),
            "cn=target,dc=example,dc=org",
            None,
            Permission::Write,
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_aci_engine_remove_rule() {
        let engine = AciEngine::restrictive();

        let rule = AciRule::grant(
            "test-rule",
            AciTarget::Subtree("dc=example,dc=org".to_string()),
            vec![Permission::Read],
            AciSubject::AllAuthenticated,
        );

        engine.add_rule(rule).await;
        assert_eq!(engine.get_rules().await.len(), 1);

        let removed = engine.remove_rule("test-rule").await;
        assert!(removed);
        assert_eq!(engine.get_rules().await.len(), 0);
    }

    #[tokio::test]
    async fn test_aci_engine_multiple_permissions() {
        let engine = AciEngine::restrictive();

        let rule = AciRule::grant(
            "multi-perm",
            AciTarget::Subtree("dc=example,dc=org".to_string()),
            vec![Permission::Read, Permission::Search, Permission::Compare],
            AciSubject::AllAuthenticated,
        );

        engine.add_rule(rule).await;

        let result = engine.check_permissions(
            Some("cn=user,dc=example,dc=org"),
            "cn=target,dc=example,dc=org",
            None,
            &[Permission::Read, Permission::Search],
        ).await;
        assert!(result.is_ok());

        let result = engine.check_permissions(
            Some("cn=user,dc=example,dc=org"),
            "cn=target,dc=example,dc=org",
            None,
            &[Permission::Read, Permission::Write],
        ).await;
        assert!(result.is_err());
    }
}
