//! Access Control Information (ACI) System
//!
//! This module provides a comprehensive ACI system for fine-grained access control
//! in LDAP operations, following LDAP ACI specifications.

use crate::backend::{DirectoryBackend, DirectoryEntry, OperationalAttributes};
use crate::dn::{dn_eq, dn_is_descendant_or_equal};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
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
    pub fn parse_name(s: &str) -> Option<Self> {
        s.parse().ok()
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

impl FromStr for Permission {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "read" => Ok(Permission::Read),
            "write" => Ok(Permission::Write),
            "search" => Ok(Permission::Search),
            "compare" => Ok(Permission::Compare),
            "add" => Ok(Permission::Add),
            "delete" => Ok(Permission::Delete),
            "modify" => Ok(Permission::Modify),
            "proxy" => Ok(Permission::Proxy),
            _ => Err(()),
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
            AciTarget::Dn(target_dn) => dn_eq(dn, target_dn),
            AciTarget::Subtree(base_dn) => dn_is_descendant_or_equal(dn, base_dn),
            AciTarget::Attributes(_) => true, // DN matching for attributes is always true
            AciTarget::Combined(left, right) => left.matches_dn(dn) && right.matches_dn(dn),
        }
    }

    /// Check if an attribute matches this target
    pub fn matches_attribute(&self, attr: &str) -> bool {
        match self {
            AciTarget::Dn(_) | AciTarget::Subtree(_) => true,
            AciTarget::Attributes(attrs) => attrs.iter().any(|a| a.eq_ignore_ascii_case(attr)),
            AciTarget::Combined(left, right) => {
                left.matches_attribute(attr) && right.matches_attribute(attr)
            }
        }
    }

    fn requires_attribute(&self) -> bool {
        match self {
            AciTarget::Attributes(_) => true,
            AciTarget::Combined(left, right) => {
                left.requires_attribute() || right.requires_attribute()
            }
            AciTarget::Dn(_) | AciTarget::Subtree(_) => false,
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
            AciSubject::User(dn) => user_dn.map(|u| dn_eq(u, dn)).unwrap_or(false),
            AciSubject::Group(_group_dn) => {
                // TODO: Implement group membership checking
                // This would require a backend lookup
                false
            }
            AciSubject::AllAuthenticated => user_dn.is_some(),
            AciSubject::All => true,
            AciSubject::SelfEntry => user_dn.map(|u| dn_eq(u, target_dn)).unwrap_or(false),
        }
    }

    async fn matches_user_with_backend(
        &self,
        user_dn: Option<&str>,
        target_dn: &str,
        backend: &dyn DirectoryBackend,
    ) -> Result<bool, String> {
        match self {
            AciSubject::Group(group_dn) => {
                let Some(user_dn) = user_dn else {
                    return Ok(false);
                };
                let group_entry = backend.get_entry(group_dn).await.map_err(|err| {
                    format!("unable to resolve group '{}' membership: {}", group_dn, err)
                })?;
                let Some(group_entry) = group_entry else {
                    return Err(format!(
                        "unable to resolve group '{}' membership: group not found",
                        group_dn
                    ));
                };

                Ok(group_entry
                    .attributes
                    .get("member")
                    .into_iter()
                    .chain(group_entry.attributes.get("uniquemember"))
                    .flat_map(|values| values.iter())
                    .any(|member_dn| dn_eq(member_dn, user_dn)))
            }
            _ => Ok(self.matches_user(user_dn, target_dn)),
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

    fn target_matches(
        &self,
        target_dn: &str,
        attribute: Option<&str>,
        permission: Permission,
    ) -> bool {
        if !self.permission_matches(permission) {
            return false;
        }

        if !self.target.matches_dn(target_dn) {
            return false;
        }

        match attribute {
            Some(attr) if !self.target.matches_attribute(attr) => return false,
            None if self.target.requires_attribute() => return false,
            _ => {}
        }

        true
    }

    fn permission_matches(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
            || matches!(
                permission,
                Permission::Add | Permission::Delete | Permission::Modify
            ) && self.permissions.contains(&Permission::Write)
    }

    /// Check if this rule matches the given parameters
    pub fn matches(
        &self,
        user_dn: Option<&str>,
        target_dn: &str,
        attribute: Option<&str>,
        permission: Permission,
    ) -> Option<bool> {
        if !self.target_matches(target_dn, attribute, permission) {
            return None;
        }

        // Check if subject matches
        if !self.subject.matches_user(user_dn, target_dn) {
            return None;
        }

        // Return grant/deny decision
        Some(self.is_grant)
    }

    async fn matches_with_backend(
        &self,
        user_dn: Option<&str>,
        target_dn: &str,
        attribute: Option<&str>,
        permission: Permission,
        backend: &dyn DirectoryBackend,
    ) -> Result<Option<bool>, String> {
        if !self.target_matches(target_dn, attribute, permission) {
            return Ok(None);
        }

        if !self
            .subject
            .matches_user_with_backend(user_dn, target_dn, backend)
            .await?
        {
            return Ok(None);
        }

        Ok(Some(self.is_grant))
    }
}

/// Errors emitted when loading ACI rules from configuration.
#[derive(Debug, Error)]
pub enum AciRuleLoadError {
    #[error("failed to read ACI rules file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse ACI rules: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid ACI rule {name}: {reason}")]
    InvalidRule { name: String, reason: String },
}

#[derive(Debug, Deserialize)]
struct AciRulesFile {
    rules: Vec<AciRuleConfig>,
}

#[derive(Debug, Deserialize)]
struct AciRuleConfig {
    name: String,
    effect: String,
    target: AciTargetConfig,
    subject: AciSubjectConfig,
    permissions: Vec<String>,
    #[serde(default)]
    priority: i32,
}

#[derive(Debug, Deserialize)]
struct AciTargetConfig {
    dn: Option<String>,
    subtree: Option<String>,
    attributes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct AciSubjectConfig {
    user: Option<String>,
    group: Option<String>,
    all_authenticated: Option<bool>,
    all: Option<bool>,
    #[serde(alias = "self")]
    self_entry: Option<bool>,
}

impl AciRuleConfig {
    fn into_rule(self) -> Result<AciRule, AciRuleLoadError> {
        let name = self.name;
        let permissions = parse_rule_permissions(&name, self.permissions)?;
        let target = parse_rule_target(&name, self.target)?;
        let subject = parse_rule_subject(&name, self.subject)?;
        let is_grant = parse_rule_effect(&name, &self.effect)?;

        Ok(AciRule {
            name,
            target,
            permissions,
            subject,
            is_grant,
            priority: self.priority,
        })
    }
}

fn parse_rule_effect(name: &str, effect: &str) -> Result<bool, AciRuleLoadError> {
    match effect.to_ascii_lowercase().as_str() {
        "grant" | "allow" => Ok(true),
        "deny" => Ok(false),
        _ => Err(invalid_rule(name, "effect must be grant, allow, or deny")),
    }
}

fn parse_rule_permissions(
    name: &str,
    permissions: Vec<String>,
) -> Result<Vec<Permission>, AciRuleLoadError> {
    if permissions.is_empty() {
        return Err(invalid_rule(name, "permissions must not be empty"));
    }

    permissions
        .into_iter()
        .map(|permission| {
            Permission::parse_name(&permission)
                .ok_or_else(|| invalid_rule(name, format!("unsupported permission {permission}")))
        })
        .collect()
}

fn parse_rule_target(name: &str, target: AciTargetConfig) -> Result<AciTarget, AciRuleLoadError> {
    let base = match (target.dn, target.subtree) {
        (Some(_), Some(_)) => {
            return Err(invalid_rule(name, "target cannot set both dn and subtree"));
        }
        (Some(dn), None) => Some(AciTarget::Dn(dn)),
        (None, Some(subtree)) => Some(AciTarget::Subtree(subtree)),
        (None, None) => None,
    };

    let attribute_target = target.attributes.map(AciTarget::Attributes);
    match (base, attribute_target) {
        (Some(base), Some(attributes)) => {
            Ok(AciTarget::Combined(Box::new(base), Box::new(attributes)))
        }
        (Some(base), None) => Ok(base),
        (None, Some(attributes)) => Ok(attributes),
        (None, None) => Err(invalid_rule(
            name,
            "target must set dn, subtree, attributes, or a dn/subtree plus attributes",
        )),
    }
}

fn parse_rule_subject(
    name: &str,
    subject: AciSubjectConfig,
) -> Result<AciSubject, AciRuleLoadError> {
    let mut subjects = Vec::new();
    if let Some(user) = subject.user {
        subjects.push(AciSubject::User(user));
    }
    if let Some(group) = subject.group {
        subjects.push(AciSubject::Group(group));
    }
    if subject.all_authenticated.unwrap_or(false) {
        subjects.push(AciSubject::AllAuthenticated);
    }
    if subject.all.unwrap_or(false) {
        subjects.push(AciSubject::All);
    }
    if subject.self_entry.unwrap_or(false) {
        subjects.push(AciSubject::SelfEntry);
    }

    if subjects.len() != 1 {
        return Err(invalid_rule(
            name,
            "subject must set exactly one of user, group, all_authenticated, all, or self_entry",
        ));
    }

    Ok(subjects.remove(0))
}

fn invalid_rule(name: impl Into<String>, reason: impl Into<String>) -> AciRuleLoadError {
    AciRuleLoadError::InvalidRule {
        name: name.into(),
        reason: reason.into(),
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
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.priority));
    }

    /// Load ACI rules from a TOML file and append them to the active rule set.
    pub async fn load_rules_from_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<usize, AciRuleLoadError> {
        let path = path.as_ref();
        let rules =
            tokio::fs::read_to_string(path)
                .await
                .map_err(|source| AciRuleLoadError::Read {
                    path: path.to_path_buf(),
                    source,
                })?;
        self.load_rules_from_str(&rules).await
    }

    /// Load ACI rules from TOML text and append them to the active rule set.
    pub async fn load_rules_from_str(&self, rules: &str) -> Result<usize, AciRuleLoadError> {
        let rules_file: AciRulesFile = toml::from_str(rules)?;
        let mut parsed_rules = Vec::with_capacity(rules_file.rules.len());
        for rule_config in rules_file.rules {
            parsed_rules.push(rule_config.into_rule()?);
        }

        let count = parsed_rules.len();
        let mut rules = self.rules.write().await;
        rules.extend(parsed_rules);
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.priority));
        Ok(count)
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

    /// Check whether an attribute-targeted rule can affect this target.
    pub async fn has_attribute_rule(&self, target_dn: &str, permission: Permission) -> bool {
        let rules = self.rules.read().await;
        rules.iter().any(|rule| {
            rule.permission_matches(permission)
                && rule.target.requires_attribute()
                && rule.target.matches_dn(target_dn)
        })
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
            if !rule.target_matches(target_dn, attribute, permission) {
                continue;
            }

            if matches!(rule.subject, AciSubject::Group(_)) {
                return Err(format!(
                    "Access denied by rule '{}' because group membership requires backend context",
                    rule.name
                ));
            }

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

    pub async fn check_permission_with_backend(
        &self,
        user_dn: Option<&str>,
        target_dn: &str,
        attribute: Option<&str>,
        permission: Permission,
        backend: &dyn DirectoryBackend,
    ) -> Result<(), String> {
        let rules = self.rules.read().await;

        for rule in rules.iter() {
            match rule
                .matches_with_backend(user_dn, target_dn, attribute, permission, backend)
                .await
            {
                Ok(Some(true)) => return Ok(()),
                Ok(Some(false)) => {
                    return Err(format!(
                        "Access denied by rule '{}' for {} on {}",
                        rule.name,
                        permission.as_str(),
                        target_dn
                    ));
                }
                Ok(None) => {}
                Err(err) => {
                    return Err(format!(
                        "Access denied by rule '{}' for {} on {}: {}",
                        rule.name,
                        permission.as_str(),
                        target_dn,
                        err
                    ));
                }
            }
        }

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
            self.check_permission(user_dn, target_dn, attribute, *permission)
                .await?;
        }
        Ok(())
    }

    pub async fn check_permissions_with_backend(
        &self,
        user_dn: Option<&str>,
        target_dn: &str,
        attribute: Option<&str>,
        permissions: &[Permission],
        backend: &dyn DirectoryBackend,
    ) -> Result<(), String> {
        for permission in permissions {
            self.check_permission_with_backend(user_dn, target_dn, attribute, *permission, backend)
                .await?;
        }
        Ok(())
    }

    pub async fn filter_readable_entry_with_backend(
        &self,
        user_dn: Option<&str>,
        entry: &DirectoryEntry,
        backend: &dyn DirectoryBackend,
    ) -> Result<Option<DirectoryEntry>, String> {
        let entry_read_allowed = self
            .check_permission_with_backend(user_dn, &entry.dn, None, Permission::Read, backend)
            .await
            .is_ok();

        let mut attributes = std::collections::HashMap::new();
        for (name, values) in &entry.attributes {
            if self
                .check_permission_with_backend(
                    user_dn,
                    &entry.dn,
                    Some(name),
                    Permission::Read,
                    backend,
                )
                .await
                .is_ok()
            {
                attributes.insert(name.clone(), values.clone());
            }
        }

        let operational_attributes = filter_readable_operational_attributes(
            self,
            user_dn,
            &entry.dn,
            &entry.operational_attributes,
            backend,
        )
        .await;

        if attributes.is_empty()
            && operational_attributes == OperationalAttributes::new()
            && !entry_read_allowed
        {
            return Ok(None);
        }

        Ok(Some(DirectoryEntry::with_operational_attrs(
            entry.dn.clone(),
            attributes,
            operational_attributes,
        )))
    }
}

async fn can_read_operational_attribute(
    engine: &AciEngine,
    user_dn: Option<&str>,
    target_dn: &str,
    attribute: &str,
    backend: &dyn DirectoryBackend,
) -> bool {
    engine
        .check_permission_with_backend(
            user_dn,
            target_dn,
            Some(attribute),
            Permission::Read,
            backend,
        )
        .await
        .is_ok()
}

async fn filter_readable_operational_attributes(
    engine: &AciEngine,
    user_dn: Option<&str>,
    target_dn: &str,
    attrs: &OperationalAttributes,
    backend: &dyn DirectoryBackend,
) -> OperationalAttributes {
    OperationalAttributes {
        entry_csn: if attrs.entry_csn.is_some()
            && can_read_operational_attribute(engine, user_dn, target_dn, "entryCSN", backend).await
        {
            attrs.entry_csn.clone()
        } else {
            None
        },
        entry_uuid: if attrs.entry_uuid.is_some()
            && can_read_operational_attribute(engine, user_dn, target_dn, "entryUUID", backend)
                .await
        {
            attrs.entry_uuid.clone()
        } else {
            None
        },
        create_timestamp: if attrs.create_timestamp.is_some()
            && can_read_operational_attribute(
                engine,
                user_dn,
                target_dn,
                "createTimestamp",
                backend,
            )
            .await
        {
            attrs.create_timestamp.clone()
        } else {
            None
        },
        modify_timestamp: if attrs.modify_timestamp.is_some()
            && can_read_operational_attribute(
                engine,
                user_dn,
                target_dn,
                "modifyTimestamp",
                backend,
            )
            .await
        {
            attrs.modify_timestamp.clone()
        } else {
            None
        },
        creators_name: if attrs.creators_name.is_some()
            && can_read_operational_attribute(engine, user_dn, target_dn, "creatorsName", backend)
                .await
        {
            attrs.creators_name.clone()
        } else {
            None
        },
        modifiers_name: if attrs.modifiers_name.is_some()
            && can_read_operational_attribute(engine, user_dn, target_dn, "modifiersName", backend)
                .await
        {
            attrs.modifiers_name.clone()
        } else {
            None
        },
        last_successful_login: if attrs.last_successful_login.is_some()
            && can_read_operational_attribute(
                engine,
                user_dn,
                target_dn,
                "lastSuccessfulLogin",
                backend,
            )
            .await
        {
            attrs.last_successful_login.clone()
        } else {
            None
        },
        last_failed_login: if attrs.last_failed_login.is_some()
            && can_read_operational_attribute(
                engine,
                user_dn,
                target_dn,
                "lastFailedLogin",
                backend,
            )
            .await
        {
            attrs.last_failed_login.clone()
        } else {
            None
        },
        failed_login_count: if attrs.failed_login_count.is_some()
            && can_read_operational_attribute(
                engine,
                user_dn,
                target_dn,
                "failedLoginCount",
                backend,
            )
            .await
        {
            attrs.failed_login_count
        } else {
            None
        },
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
        self.set_target(AciTarget::Dn(dn.into()));
        self
    }

    /// Set target subtree
    pub fn target_subtree(mut self, base_dn: impl Into<String>) -> Self {
        self.set_target(AciTarget::Subtree(base_dn.into()));
        self
    }

    /// Set target attributes
    pub fn target_attributes(mut self, attrs: Vec<String>) -> Self {
        self.set_target(AciTarget::Attributes(attrs));
        self
    }

    fn set_target(&mut self, target: AciTarget) {
        self.target = Some(match self.target.take() {
            Some(existing) => AciTarget::Combined(Box::new(existing), Box::new(target)),
            None => target,
        });
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

    /// Set subject to group membership
    pub fn subject_group(mut self, dn: impl Into<String>) -> Self {
        self.subject = Some(AciSubject::Group(dn.into()));
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
    use crate::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
    use std::collections::HashMap;

    #[test]
    fn test_permission_from_str() {
        assert_eq!(Permission::parse_name("read"), Some(Permission::Read));
        assert_eq!(Permission::parse_name("WRITE"), Some(Permission::Write));
        assert_eq!(Permission::parse_name("invalid"), None);
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
    fn test_aci_dn_matching_uses_rfc4514_canonicalization() {
        let target = AciTarget::Dn(r"cn=Doe\, John+uid=user\+1,dc=example,dc=org".to_string());
        assert!(target.matches_dn(r"UID=user\2B1+CN=doe\2C john,DC=example,DC=org"));

        let subtree = AciTarget::Subtree(r"ou=People,dc=example,dc=org".to_string());
        assert!(subtree.matches_dn(r"cn=Doe\, John+uid=user\+1,ou=people,dc=example,dc=org"));

        let subject = AciSubject::SelfEntry;
        assert!(subject.matches_user(
            Some(r"CN=doe\2C john,DC=example,DC=org"),
            r"cn=Doe\, John,dc=example,dc=org"
        ));
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

    #[test]
    fn test_aci_rule_builder_group_subject() {
        let rule = AciRuleBuilder::grant("group-rule")
            .target_subtree("dc=example,dc=org")
            .permission(Permission::Read)
            .subject_group("cn=admins,dc=example,dc=org")
            .build()
            .unwrap();

        assert_eq!(
            rule.subject,
            AciSubject::Group("cn=admins,dc=example,dc=org".to_string())
        );
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
        let result = engine
            .check_permission(
                Some("cn=admin,dc=example,dc=org"),
                "cn=user,dc=example,dc=org",
                None,
                Permission::Read,
            )
            .await;
        assert!(result.is_ok());

        // Should deny other users
        let result = engine
            .check_permission(
                Some("cn=other,dc=example,dc=org"),
                "cn=user,dc=example,dc=org",
                None,
                Permission::Read,
            )
            .await;
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
        let result = engine
            .check_permission(
                Some("cn=user,dc=example,dc=org"),
                "cn=other,dc=example,dc=org",
                None,
                Permission::Write,
            )
            .await;
        assert!(result.is_err());

        // Should allow other permissions
        let result = engine
            .check_permission(
                Some("cn=user,dc=example,dc=org"),
                "cn=other,dc=example,dc=org",
                None,
                Permission::Read,
            )
            .await;
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
        )
        .with_priority(100);

        // Low priority grant rule
        let grant_rule = AciRule::grant(
            "grant-low",
            AciTarget::Subtree("dc=example,dc=org".to_string()),
            vec![Permission::Write],
            AciSubject::AllAuthenticated,
        )
        .with_priority(10);

        engine.add_rule(grant_rule).await;
        engine.add_rule(deny_rule).await;

        // Deny should win due to higher priority
        let result = engine
            .check_permission(
                Some("cn=user,dc=example,dc=org"),
                "cn=target,dc=example,dc=org",
                None,
                Permission::Write,
            )
            .await;
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

        let result = engine
            .check_permissions(
                Some("cn=user,dc=example,dc=org"),
                "cn=target,dc=example,dc=org",
                None,
                &[Permission::Read, Permission::Search],
            )
            .await;
        assert!(result.is_ok());

        let result = engine
            .check_permissions(
                Some("cn=user,dc=example,dc=org"),
                "cn=target,dc=example,dc=org",
                None,
                &[Permission::Read, Permission::Write],
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_group_rules_require_backend_context() {
        let engine = AciEngine::restrictive();
        let rule = AciRuleBuilder::grant("group-read")
            .target_subtree("dc=example,dc=org")
            .permission(Permission::Read)
            .subject_group("cn=admins,dc=example,dc=org")
            .build()
            .unwrap();
        engine.add_rule(rule).await;

        let result = engine
            .check_permission(
                Some("cn=alice,dc=example,dc=org"),
                "cn=target,dc=example,dc=org",
                None,
                Permission::Read,
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("backend context"));
    }

    #[tokio::test]
    async fn test_group_rules_allow_member_with_backend() {
        let engine = AciEngine::restrictive();
        let backend = MockBackend::new();
        let group_dn = "cn=admins,dc=example,dc=org";
        backend
            .add_entry(
                DirectoryEntry::new(
                    group_dn,
                    HashMap::from([
                        (
                            "member".to_string(),
                            vec!["cn=alice,dc=example,dc=org".to_string()],
                        ),
                        ("objectclass".to_string(), vec!["groupOfNames".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let rule = AciRuleBuilder::grant("group-read")
            .target_subtree("dc=example,dc=org")
            .permission(Permission::Read)
            .subject_group(group_dn)
            .build()
            .unwrap();
        engine.add_rule(rule).await;

        let result = engine
            .check_permission_with_backend(
                Some("cn=alice,dc=example,dc=org"),
                "cn=target,dc=example,dc=org",
                None,
                Permission::Read,
                &backend,
            )
            .await;
        assert!(result.is_ok());

        let denied = engine
            .check_permission_with_backend(
                Some("cn=bob,dc=example,dc=org"),
                "cn=target,dc=example,dc=org",
                None,
                Permission::Read,
                &backend,
            )
            .await;
        assert!(denied.is_err());
    }

    #[tokio::test]
    async fn test_group_rules_fail_closed_when_group_cannot_be_resolved() {
        let engine = AciEngine::restrictive();
        let backend = MockBackend::new();

        let rule = AciRuleBuilder::grant("group-read")
            .target_subtree("dc=example,dc=org")
            .permission(Permission::Read)
            .subject_group("cn=missing,dc=example,dc=org")
            .build()
            .unwrap();
        engine.add_rule(rule).await;

        let result = engine
            .check_permission_with_backend(
                Some("cn=alice,dc=example,dc=org"),
                "cn=target,dc=example,dc=org",
                None,
                Permission::Read,
                &backend,
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("group not found"));
    }

    #[tokio::test]
    async fn test_attribute_target_does_not_match_entry_level_request() {
        let engine = AciEngine::restrictive();
        let rule = AciRuleBuilder::grant("cn-read")
            .target_attributes(vec!["cn".to_string()])
            .permission(Permission::Read)
            .subject_all_authenticated()
            .build()
            .unwrap();
        engine.add_rule(rule).await;

        let entry_level = engine
            .check_permission(
                Some("cn=alice,dc=example,dc=org"),
                "cn=target,dc=example,dc=org",
                None,
                Permission::Read,
            )
            .await;
        assert!(entry_level.is_err());

        let attribute_level = engine
            .check_permission(
                Some("cn=alice,dc=example,dc=org"),
                "cn=target,dc=example,dc=org",
                Some("cn"),
                Permission::Read,
            )
            .await;
        assert!(attribute_level.is_ok());
    }

    #[tokio::test]
    async fn test_write_permission_matches_specific_write_operations() {
        let engine = AciEngine::restrictive();
        let rule = AciRuleBuilder::grant("write-subtree")
            .target_subtree("dc=example,dc=org")
            .permission(Permission::Write)
            .subject_all_authenticated()
            .build()
            .unwrap();
        engine.add_rule(rule).await;

        for permission in [Permission::Add, Permission::Modify, Permission::Delete] {
            let result = engine
                .check_permission(
                    Some("cn=alice,dc=example,dc=org"),
                    "cn=target,dc=example,dc=org",
                    None,
                    permission,
                )
                .await;
            assert!(result.is_ok(), "{permission:?} should match write");
        }
    }

    #[tokio::test]
    async fn test_load_rules_from_toml() {
        let engine = AciEngine::restrictive();
        let rules = r#"
[[rules]]
name = "operators-search"
effect = "grant"
priority = 20
permissions = ["search", "read"]
target = { subtree = "dc=example,dc=org", attributes = ["cn", "mail"] }
subject = { group = "cn=operators,dc=example,dc=org" }

[[rules]]
name = "deny-password"
effect = "deny"
priority = 100
permissions = ["read"]
target = { subtree = "dc=example,dc=org", attributes = ["userPassword"] }
subject = { all_authenticated = true }
"#;

        let count = engine.load_rules_from_str(rules).await.unwrap();
        assert_eq!(count, 2);

        let loaded = engine.get_rules().await;
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "deny-password");
        assert_eq!(loaded[1].name, "operators-search");
    }

    #[tokio::test]
    async fn test_filter_readable_entry_with_backend() {
        let engine = AciEngine::restrictive();
        let backend = MockBackend::new();

        engine
            .add_rule(
                AciRuleBuilder::grant("read-cn")
                    .target_subtree("dc=example,dc=org")
                    .permission(Permission::Read)
                    .subject_all_authenticated()
                    .build()
                    .unwrap(),
            )
            .await;
        engine
            .add_rule(
                AciRuleBuilder::deny("deny-secret")
                    .target_subtree("dc=example,dc=org")
                    .target_attributes(vec!["userPassword".to_string()])
                    .permission(Permission::Read)
                    .subject_all_authenticated()
                    .priority(100)
                    .build()
                    .unwrap(),
            )
            .await;

        let entry = DirectoryEntry::new(
            "cn=alice,dc=example,dc=org",
            HashMap::from([
                ("cn".to_string(), vec!["alice".to_string()]),
                ("userPassword".to_string(), vec!["secret".to_string()]),
            ]),
        );

        let filtered = engine
            .filter_readable_entry_with_backend(
                Some("cn=reader,dc=example,dc=org"),
                &entry,
                &backend,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(filtered.attributes.contains_key("cn"));
        assert!(!filtered.attributes.contains_key("userpassword"));
    }
}
