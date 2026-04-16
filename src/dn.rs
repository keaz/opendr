use ldap_parser::ldap::SearchScope;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapDn {
    rdns: Vec<Rdn>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdn {
    avas: Vec<Ava>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ava {
    attribute: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnError {
    message: String,
}

impl DnError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DnError {}

impl LdapDn {
    pub fn parse(input: &str) -> Result<Self, DnError> {
        let input = input.trim();
        if input.is_empty() {
            return Ok(Self { rdns: Vec::new() });
        }

        let rdns = split_unescaped(input, &[',', ';'])
            .into_iter()
            .map(|part| Rdn::parse(part.trim()))
            .collect::<Result<Vec<_>, _>>()?;

        if rdns.is_empty() {
            return Err(DnError::new("DN must contain at least one RDN"));
        }

        Ok(Self { rdns })
    }

    pub fn from_rdns(rdns: Vec<Rdn>) -> Self {
        Self { rdns }
    }

    pub fn rdns(&self) -> &[Rdn] {
        &self.rdns
    }

    pub fn parent(&self) -> Option<Self> {
        (self.rdns.len() > 1).then(|| Self {
            rdns: self.rdns[1..].to_vec(),
        })
    }

    pub fn to_canonical_string(&self) -> String {
        self.rdns
            .iter()
            .map(Rdn::to_canonical_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn is_same_as(&self, other: &Self) -> bool {
        self.to_canonical_string() == other.to_canonical_string()
    }

    pub fn is_descendant_or_equal_of(&self, base: &Self) -> bool {
        if base.rdns.is_empty() {
            return true;
        }
        if self.rdns.len() < base.rdns.len() {
            return false;
        }

        let offset = self.rdns.len() - base.rdns.len();
        self.rdns[offset..]
            .iter()
            .map(Rdn::canonical_key)
            .eq(base.rdns.iter().map(Rdn::canonical_key))
    }

    pub fn is_one_level_child_of(&self, base: &Self) -> bool {
        self.rdns.len() == base.rdns.len() + 1 && self.is_descendant_or_equal_of(base)
    }

    pub fn dn_attribute_values(&self, attribute: Option<&str>) -> Vec<String> {
        self.rdns
            .iter()
            .flat_map(|rdn| rdn.avas.iter())
            .filter_map(|ava| match attribute {
                Some(attribute) if !ava.attribute.eq_ignore_ascii_case(attribute) => None,
                _ => Some(ava.value.clone()),
            })
            .collect()
    }
}

impl Rdn {
    pub fn parse(input: &str) -> Result<Self, DnError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(DnError::new("RDN must not be empty"));
        }

        let avas = split_unescaped(input, &['+'])
            .into_iter()
            .map(parse_ava)
            .collect::<Result<Vec<_>, _>>()?;

        if avas.is_empty() {
            return Err(DnError::new(
                "RDN must contain at least one attribute value assertion",
            ));
        }

        Ok(Self { avas })
    }

    pub fn avas(&self) -> &[Ava] {
        &self.avas
    }

    pub fn to_canonical_string(&self) -> String {
        self.canonical_key()
            .into_iter()
            .map(|(attribute, value)| format!("{attribute}={}", escape_dn_value(&value)))
            .collect::<Vec<_>>()
            .join("+")
    }

    fn canonical_key(&self) -> Vec<(String, String)> {
        let mut key = self
            .avas
            .iter()
            .map(|ava| {
                (
                    ava.attribute.to_ascii_lowercase(),
                    normalize_dn_value(&ava.value),
                )
            })
            .collect::<Vec<_>>();
        key.sort();
        key
    }
}

impl Ava {
    pub fn attribute(&self) -> &str {
        &self.attribute
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

pub fn parse_dn(input: &str) -> Result<LdapDn, DnError> {
    LdapDn::parse(input)
}

pub fn parse_rdn(input: &str) -> Result<Rdn, DnError> {
    Rdn::parse(input)
}

pub fn canonicalize_dn(input: &str) -> Result<String, DnError> {
    parse_dn(input).map(|dn| dn.to_canonical_string())
}

pub fn canonical_root_dn(root_user_dn: &str, base_dn: &str) -> Result<String, DnError> {
    let root_user_dn = root_user_dn.trim();
    if root_user_dn.is_empty() {
        return Err(DnError::new("root user DN must not be empty"));
    }

    let root_dn = parse_dn(root_user_dn)?;
    if root_dn.rdns().len() == 1 && !base_dn.trim().is_empty() {
        let base_dn = parse_dn(base_dn)?;
        let mut rdns = root_dn.rdns().to_vec();
        rdns.extend_from_slice(base_dn.rdns());
        return Ok(LdapDn::from_rdns(rdns).to_canonical_string());
    }

    Ok(root_dn.to_canonical_string())
}

pub fn dn_eq(left: &str, right: &str) -> bool {
    match (parse_dn(left), parse_dn(right)) {
        (Ok(left), Ok(right)) => left.is_same_as(&right),
        _ => false,
    }
}

pub fn dn_is_descendant_or_equal(dn: &str, base_dn: &str) -> bool {
    match (parse_dn(dn), parse_dn(base_dn)) {
        (Ok(dn), Ok(base_dn)) => dn.is_descendant_or_equal_of(&base_dn),
        _ => false,
    }
}

pub fn dn_is_in_scope(dn: &str, base_dn: &str, scope: SearchScope) -> bool {
    match (parse_dn(dn), parse_dn(base_dn)) {
        (Ok(dn), Ok(base_dn)) => match scope {
            SearchScope(0) => dn.is_same_as(&base_dn),
            SearchScope(1) => dn.is_one_level_child_of(&base_dn),
            SearchScope(2) => dn.is_descendant_or_equal_of(&base_dn),
            _ => false,
        },
        _ => false,
    }
}

pub fn replace_dn_rdn(
    dn: &str,
    new_rdn: &str,
    new_superior: Option<&str>,
) -> Result<String, DnError> {
    let current = parse_dn(dn)?;
    let new_rdn = parse_rdn(new_rdn)?;
    let mut rdns = vec![new_rdn];

    if let Some(new_superior) = new_superior {
        rdns.extend(parse_dn(new_superior)?.rdns);
    } else if let Some(parent) = current.parent() {
        rdns.extend(parent.rdns);
    }

    Ok(LdapDn::from_rdns(rdns).to_canonical_string())
}

pub fn rdn_attribute_values(rdn: &str) -> Result<Vec<(String, String)>, DnError> {
    Ok(parse_rdn(rdn)?
        .avas
        .into_iter()
        .map(|ava| (ava.attribute, ava.value))
        .collect())
}

pub fn dn_attribute_values(dn: &str, attribute: Option<&str>) -> Result<Vec<String>, DnError> {
    Ok(parse_dn(dn)?.dn_attribute_values(attribute))
}

fn parse_ava(input: &str) -> Result<Ava, DnError> {
    let Some(index) = first_unescaped(input, '=') else {
        return Err(DnError::new(format!(
            "RDN component '{input}' must contain '='"
        )));
    };
    let attribute = input[..index].trim();
    let value = input[index + 1..].trim();

    if !is_valid_attribute_type(attribute) {
        return Err(DnError::new(format!(
            "invalid DN attribute type '{attribute}'"
        )));
    }

    Ok(Ava {
        attribute: normalize_attribute_type(attribute),
        value: parse_value(value)?,
    })
}

fn parse_value(input: &str) -> Result<String, DnError> {
    if let Some(hex) = input.strip_prefix('#') {
        if hex.is_empty() || hex.len() % 2 != 0 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(DnError::new("invalid DN hexstring value"));
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().chunks_exact(2) {
            bytes.push(hex_pair_to_byte(pair[0], pair[1])?);
        }
        return String::from_utf8(bytes).map_err(|_| DnError::new("DN hexstring is not UTF-8"));
    }

    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();

    while let Some((_, ch)) = chars.next() {
        if ch != '\\' {
            push_char(&mut bytes, ch);
            continue;
        }

        let Some((_, escaped)) = chars.next() else {
            return Err(DnError::new("DN value has a trailing escape"));
        };

        if escaped.is_ascii_hexdigit()
            && let Some((_, second)) = chars.peek().copied()
            && second.is_ascii_hexdigit()
        {
            chars.next();
            bytes.push(hex_chars_to_byte(escaped, second)?);
            continue;
        }

        push_char(&mut bytes, escaped);
    }

    String::from_utf8(bytes).map_err(|_| DnError::new("DN value is not valid UTF-8"))
}

fn split_unescaped<'a>(input: &'a str, separators: &[char]) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut chars = input.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        if ch == '\\' {
            if let Some((_, first)) = chars.next()
                && first.is_ascii_hexdigit()
                && chars
                    .peek()
                    .is_some_and(|(_, second)| second.is_ascii_hexdigit())
            {
                chars.next();
            }
            continue;
        }

        if separators.contains(&ch) {
            parts.push(&input[start..index]);
            start = index + ch.len_utf8();
        }
    }

    parts.push(&input[start..]);
    parts
}

fn first_unescaped(input: &str, target: char) -> Option<usize> {
    let mut chars = input.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if ch == '\\' {
            if let Some((_, first)) = chars.next()
                && first.is_ascii_hexdigit()
                && chars
                    .peek()
                    .is_some_and(|(_, second)| second.is_ascii_hexdigit())
            {
                chars.next();
            }
            continue;
        }
        if ch == target {
            return Some(index);
        }
    }
    None
}

fn is_valid_attribute_type(attribute: &str) -> bool {
    let attribute = attribute.strip_prefix("OID.").unwrap_or(attribute);
    let attribute = attribute.strip_prefix("oid.").unwrap_or(attribute);
    if attribute.is_empty() {
        return false;
    }

    if attribute
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        return is_valid_numeric_oid(attribute);
    }

    let mut chars = attribute.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic() && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn normalize_attribute_type(attribute: &str) -> String {
    attribute
        .strip_prefix("OID.")
        .or_else(|| attribute.strip_prefix("oid."))
        .unwrap_or(attribute)
        .to_ascii_lowercase()
}

fn is_valid_numeric_oid(value: &str) -> bool {
    let mut saw_component = false;
    for component in value.split('.') {
        if component.is_empty() || !component.chars().all(|ch| ch.is_ascii_digit()) {
            return false;
        }
        saw_component = true;
    }
    saw_component
}

fn normalize_dn_value(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn escape_dn_value(value: &str) -> String {
    let mut escaped = String::new();
    let chars = value.chars().collect::<Vec<_>>();
    for (index, ch) in chars.iter().copied().enumerate() {
        let must_escape = matches!(ch, '"' | '+' | ',' | ';' | '<' | '>' | '\\' | '=')
            || (index == 0 && matches!(ch, ' ' | '#'))
            || (index + 1 == chars.len() && ch == ' ');
        if must_escape {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn push_char(bytes: &mut Vec<u8>, ch: char) {
    let mut buf = [0; 4];
    bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
}

fn hex_chars_to_byte(first: char, second: char) -> Result<u8, DnError> {
    let first = first
        .to_digit(16)
        .ok_or_else(|| DnError::new("invalid DN hex escape"))?;
    let second = second
        .to_digit(16)
        .ok_or_else(|| DnError::new("invalid DN hex escape"))?;
    Ok(((first << 4) | second) as u8)
}

fn hex_pair_to_byte(first: u8, second: u8) -> Result<u8, DnError> {
    hex_chars_to_byte(first as char, second as char)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_case_and_spacing() {
        assert_eq!(
            canonicalize_dn(" CN = Alice   Smith , DC = Example , DC = ORG ").unwrap(),
            "cn=alice smith,dc=example,dc=org"
        );
    }

    #[test]
    fn parses_escaped_separators() {
        let dn = parse_dn(r"cn=Doe\, John+uid=user\+1,dc=example,dc=org").unwrap();
        assert_eq!(
            dn.to_canonical_string(),
            r"cn=doe\, john+uid=user\+1,dc=example,dc=org"
        );
        assert_eq!(
            dn.dn_attribute_values(Some("cn")),
            vec!["Doe, John".to_string()]
        );
        assert_eq!(
            dn.dn_attribute_values(Some("uid")),
            vec!["user+1".to_string()]
        );
    }

    #[test]
    fn hex_escapes_decode_before_canonicalization() {
        assert_eq!(
            canonicalize_dn(r"cn=Doe\2C John,dc=example,dc=org").unwrap(),
            r"cn=doe\, john,dc=example,dc=org"
        );
    }

    #[test]
    fn multi_valued_rdns_are_order_insensitive() {
        assert!(dn_eq(
            "uid=User+cn=Alice,dc=example,dc=org",
            "CN=alice+UID=user,DC=example,DC=org"
        ));
        assert_eq!(
            canonicalize_dn("uid=User+cn=Alice,dc=example,dc=org").unwrap(),
            "cn=alice+uid=user,dc=example,dc=org"
        );
    }

    #[test]
    fn scope_matching_uses_parsed_rdns() {
        assert!(dn_is_in_scope(
            r"cn=Doe\, John,ou=People,dc=example,dc=org",
            "dc=example,dc=org",
            SearchScope(2)
        ));
        assert!(dn_is_in_scope(
            r"cn=Doe\, John,ou=People,dc=example,dc=org",
            "ou=people,dc=example,dc=org",
            SearchScope(1)
        ));
        assert!(!dn_is_in_scope(
            r"cn=Doe\, John,ou=People,dc=example,dc=org",
            "dc=other,dc=org",
            SearchScope(2)
        ));
    }

    #[test]
    fn replace_first_rdn_preserves_escaped_parent_boundaries() {
        assert_eq!(
            replace_dn_rdn(
                r"cn=Doe\, John,ou=People,dc=example,dc=org",
                r"cn=Jane\+Doe",
                None
            )
            .unwrap(),
            r"cn=jane\+doe,ou=people,dc=example,dc=org"
        );
    }

    #[test]
    fn invalid_dns_return_errors() {
        assert!(parse_dn(r"cn=alice\").is_err());
        assert!(parse_dn("cn=alice,,dc=example").is_err());
        assert!(parse_dn("=alice,dc=example").is_err());
        assert!(parse_dn("cn=#0,dc=example").is_err());
    }

    #[test]
    fn canonical_root_dn_expands_rdn_with_base_dn() {
        assert_eq!(
            canonical_root_dn(" CN = Admin ", " DC = Example , DC = COM ").unwrap(),
            "cn=admin,dc=example,dc=com"
        );
    }

    #[test]
    fn canonical_root_dn_preserves_full_dn_without_resuffixing() {
        assert_eq!(
            canonical_root_dn("CN=Admin,DC=Example,DC=COM", "dc=ignored").unwrap(),
            "cn=admin,dc=example,dc=com"
        );
    }

    #[test]
    fn canonical_root_dn_rejects_empty_root_user_dn() {
        assert!(canonical_root_dn(" ", "dc=example,dc=org").is_err());
    }
}
