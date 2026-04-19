use std::collections::{HashMap, HashSet};

use ldap_parser::ldap::SearchScope;

use crate::backend::{BackendError, DirectoryBackend, DirectoryEntry};
use crate::dn::{canonicalize_dn, parent_dn};
use crate::schema::{LdapSchema, parse_subtree_specification};

const COLLECTIVE_ATTRIBUTE_SUBENTRIES: &str = "collectiveAttributeSubentries";
const COLLECTIVE_EXCLUSIONS: &str = "collectiveExclusions";
const EXCLUDE_ALL_COLLECTIVE_ATTRIBUTES: &str = "excludeAllCollectiveAttributes";
const EXCLUDE_ALL_COLLECTIVE_ATTRIBUTES_OID: &str = "2.5.18.0";

pub(crate) async fn project_collective_attributes_for_entries(
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    entries: Vec<DirectoryEntry>,
) -> Result<Vec<DirectoryEntry>, BackendError> {
    let mut projected = Vec::with_capacity(entries.len());
    for entry in entries {
        projected.push(project_collective_attributes_for_entry(backend, schema, entry).await?);
    }
    Ok(projected)
}

pub(crate) async fn project_collective_attributes_for_entry(
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    mut entry: DirectoryEntry,
) -> Result<DirectoryEntry, BackendError> {
    if entry_has_object_class(&entry, "subentry") {
        return Ok(entry);
    }

    let object_classes = attribute_values(&entry.attributes, "objectClass")
        .cloned()
        .unwrap_or_default();
    let exclusions = CollectiveExclusions::from_entry(&entry.attributes);
    let mut affecting_subentries = Vec::new();

    for (administrative_point_dn, role_already_verified) in administrative_point_candidates(&entry)?
    {
        if !role_already_verified {
            let Some(allows_collective_subentries) =
                administrative_point_collective_status(backend, &administrative_point_dn).await?
            else {
                break;
            };
            if !allows_collective_subentries {
                continue;
            }
        }

        let subentries = backend
            .search_entries(&administrative_point_dn, SearchScope(1))
            .await?;
        for subentry in subentries {
            if !entry_has_object_class(&subentry, "subentry")
                || !entry_has_object_class(&subentry, "collectiveAttributeSubentry")
            {
                continue;
            }
            if !collective_subentry_applies(
                &subentry,
                &administrative_point_dn,
                &entry.dn,
                &object_classes,
            )? {
                continue;
            }

            let mut has_collective_attribute = false;
            for (name, values) in &subentry.attributes {
                if !schema.is_collective_attribute(name) {
                    continue;
                }
                has_collective_attribute = true;
                if exclusions.excludes(schema, name) {
                    continue;
                }
                append_unique_values(
                    entry.attributes.entry(name.clone()).or_default(),
                    values.iter().cloned(),
                );
            }
            if has_collective_attribute {
                affecting_subentries.push(subentry.dn);
            }
        }
    }

    affecting_subentries.sort_by_key(|dn| dn.to_ascii_lowercase());
    affecting_subentries.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    if !affecting_subentries.is_empty() {
        entry.virtual_operational_attributes.insert(
            COLLECTIVE_ATTRIBUTE_SUBENTRIES.to_string(),
            affecting_subentries,
        );
    }

    Ok(entry)
}

fn append_unique_values(target: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn collective_subentry_applies(
    subentry: &DirectoryEntry,
    administrative_point_dn: &str,
    entry_dn: &str,
    object_classes: &[String],
) -> Result<bool, BackendError> {
    let Some(values) = attribute_values(&subentry.attributes, "subtreeSpecification") else {
        return Ok(false);
    };
    let Some(value) = values.first() else {
        return Ok(false);
    };
    let spec = parse_subtree_specification(value).map_err(|err| {
        BackendError::Storage(format!(
            "invalid subtreeSpecification on collective subentry {}: {}",
            subentry.dn, err
        ))
    })?;
    Ok(spec.contains_entry(administrative_point_dn, entry_dn, object_classes))
}

async fn administrative_point_collective_status(
    backend: &dyn DirectoryBackend,
    dn: &str,
) -> Result<Option<bool>, BackendError> {
    let Some(entry) = backend.get_entry(dn).await? else {
        return Ok(None);
    };
    Ok(Some(entry_allows_collective_subentries(&entry)))
}

fn administrative_point_candidates(
    entry: &DirectoryEntry,
) -> Result<Vec<(String, bool)>, BackendError> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    let entry_dn = canonicalize_dn(&entry.dn).map_err(|err| {
        BackendError::InvalidDn(format!("invalid entry DN for collective projection: {err}"))
    })?;

    if entry_allows_collective_subentries(entry) {
        seen.insert(entry_dn.to_ascii_lowercase());
        candidates.push((entry_dn.clone(), true));
    }

    let mut current = parent_dn(&entry_dn).map_err(|err| {
        BackendError::InvalidDn(format!(
            "invalid parent DN for collective projection: {err}"
        ))
    })?;
    while let Some(dn) = current {
        if seen.insert(dn.to_ascii_lowercase()) {
            candidates.push((dn.clone(), false));
        }
        current = parent_dn(&dn).map_err(|err| {
            BackendError::InvalidDn(format!(
                "invalid parent DN for collective projection: {err}"
            ))
        })?;
    }

    Ok(candidates)
}

fn entry_allows_collective_subentries(entry: &DirectoryEntry) -> bool {
    attribute_values(&entry.attributes, "administrativeRole").is_some_and(|roles| {
        roles.iter().any(|role| {
            role.eq_ignore_ascii_case("collectiveAttributeSpecificArea")
                || role.eq_ignore_ascii_case("collectiveAttributeInnerArea")
                || role == "2.5.23.5"
                || role == "2.5.23.6"
        })
    })
}

fn entry_has_object_class(entry: &DirectoryEntry, object_class: &str) -> bool {
    attribute_values(&entry.attributes, "objectClass").is_some_and(|values| {
        values
            .iter()
            .any(|value| value.eq_ignore_ascii_case(object_class))
    })
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

fn attribute_description_type_name(attribute_description: &str) -> &str {
    attribute_description
        .split_once(';')
        .map_or(attribute_description, |(attribute_type, _)| attribute_type)
}

struct CollectiveExclusions {
    values: Vec<String>,
}

impl CollectiveExclusions {
    fn from_entry(attributes: &HashMap<String, Vec<String>>) -> Self {
        Self {
            values: attribute_values(attributes, COLLECTIVE_EXCLUSIONS)
                .cloned()
                .unwrap_or_default(),
        }
    }

    fn excludes(&self, schema: &LdapSchema, attribute_name: &str) -> bool {
        self.values.iter().any(|value| {
            value.eq_ignore_ascii_case(EXCLUDE_ALL_COLLECTIVE_ATTRIBUTES)
                || value == EXCLUDE_ALL_COLLECTIVE_ATTRIBUTES_OID
                || schema.attribute_types_match(value, attribute_name)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;

    #[tokio::test]
    async fn projects_collective_attributes_from_applicable_subentry() {
        let backend = MockBackend::new();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "ou=People,dc=example,dc=org",
                    HashMap::from([
                        (
                            "objectClass".to_string(),
                            vec!["top".to_string(), "organizationalUnit".to_string()],
                        ),
                        ("ou".to_string(), vec!["People".to_string()]),
                        (
                            "administrativeRole".to_string(),
                            vec!["collectiveAttributeSpecificArea".to_string()],
                        ),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=People Collective,ou=People,dc=example,dc=org",
                    HashMap::from([
                        (
                            "objectClass".to_string(),
                            vec![
                                "top".to_string(),
                                "subentry".to_string(),
                                "collectiveAttributeSubentry".to_string(),
                            ],
                        ),
                        ("cn".to_string(), vec!["People Collective".to_string()]),
                        ("subtreeSpecification".to_string(), vec!["{}".to_string()]),
                        ("c-l".to_string(), vec!["Colombo".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let schema = LdapSchema::with_core_schema();
        let entry = DirectoryEntry::new(
            "uid=alice,ou=People,dc=example,dc=org",
            HashMap::from([
                (
                    "objectClass".to_string(),
                    vec!["top".to_string(), "person".to_string()],
                ),
                ("cn".to_string(), vec!["Alice".to_string()]),
                ("sn".to_string(), vec!["Example".to_string()]),
            ]),
        );

        let projected = project_collective_attributes_for_entry(&backend, &schema, entry)
            .await
            .unwrap();

        assert_eq!(
            projected.attributes.get("c-l"),
            Some(&vec!["Colombo".to_string()])
        );
        assert_eq!(
            projected
                .virtual_operational_attributes
                .get(COLLECTIVE_ATTRIBUTE_SUBENTRIES),
            Some(&vec![
                "cn=People Collective,ou=People,dc=example,dc=org".to_string()
            ])
        );
    }

    #[tokio::test]
    async fn honors_collective_exclusions() {
        let backend = MockBackend::new();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "ou=People,dc=example,dc=org",
                    HashMap::from([
                        (
                            "objectClass".to_string(),
                            vec!["top".to_string(), "organizationalUnit".to_string()],
                        ),
                        ("ou".to_string(), vec!["People".to_string()]),
                        (
                            "administrativeRole".to_string(),
                            vec!["collectiveAttributeSpecificArea".to_string()],
                        ),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=People Collective,ou=People,dc=example,dc=org",
                    HashMap::from([
                        (
                            "objectClass".to_string(),
                            vec![
                                "top".to_string(),
                                "subentry".to_string(),
                                "collectiveAttributeSubentry".to_string(),
                            ],
                        ),
                        ("cn".to_string(), vec!["People Collective".to_string()]),
                        ("subtreeSpecification".to_string(), vec!["{}".to_string()]),
                        ("c-l".to_string(), vec!["Colombo".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let schema = LdapSchema::with_core_schema();
        let entry = DirectoryEntry::new(
            "uid=alice,ou=People,dc=example,dc=org",
            HashMap::from([
                (
                    "objectClass".to_string(),
                    vec!["top".to_string(), "person".to_string()],
                ),
                ("cn".to_string(), vec!["Alice".to_string()]),
                ("sn".to_string(), vec!["Example".to_string()]),
                ("collectiveExclusions".to_string(), vec!["c-l".to_string()]),
            ]),
        );

        let projected = project_collective_attributes_for_entry(&backend, &schema, entry)
            .await
            .unwrap();

        assert!(!projected.attributes.contains_key("c-l"));
        assert!(
            projected
                .virtual_operational_attributes
                .contains_key(COLLECTIVE_ATTRIBUTE_SUBENTRIES)
        );
    }
}
