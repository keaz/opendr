use std::fmt;
use std::str::FromStr;

use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapUrlScheme {
    Ldap,
    Ldaps,
}

impl LdapUrlScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ldap => "ldap",
            Self::Ldaps => "ldaps",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Ldap => 389,
            Self::Ldaps => 636,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapUrlScope {
    Base,
    One,
    Sub,
}

impl LdapUrlScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::One => "one",
            Self::Sub => "sub",
        }
    }
}

impl FromStr for LdapUrlScope {
    type Err = LdapUrlError;

    fn from_str(scope: &str) -> Result<Self, Self::Err> {
        match scope {
            "base" => Ok(Self::Base),
            "one" => Ok(Self::One),
            "sub" => Ok(Self::Sub),
            other => Err(LdapUrlError::InvalidScope {
                scope: other.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapUrlExtension {
    pub critical: bool,
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapUrl {
    pub scheme: LdapUrlScheme,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub dn: String,
    pub attributes: Vec<String>,
    pub scope: Option<LdapUrlScope>,
    pub filter: Option<String>,
    pub extensions: Vec<LdapUrlExtension>,
}

impl LdapUrl {
    pub fn parse(input: &str) -> Result<Self, LdapUrlError> {
        let parsed = Url::parse(input).map_err(|source| LdapUrlError::InvalidUrl {
            source: source.to_string(),
        })?;

        let scheme = match parsed.scheme() {
            "ldap" => LdapUrlScheme::Ldap,
            "ldaps" => LdapUrlScheme::Ldaps,
            other => {
                return Err(LdapUrlError::UnsupportedScheme {
                    scheme: other.to_string(),
                });
            }
        };

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(LdapUrlError::UnsupportedUserInfo);
        }

        let raw_dn = parsed
            .path()
            .strip_prefix('/')
            .unwrap_or_else(|| parsed.path());
        let dn = percent_decode(raw_dn, "dn")?;

        let mut attributes = Vec::new();
        let mut scope = None;
        let mut filter = None;
        let mut extensions = Vec::new();

        if let Some(query) = parsed.query() {
            let parts = query.split('?').collect::<Vec<_>>();
            if parts.len() > 4 {
                return Err(LdapUrlError::TooManyComponents { count: parts.len() });
            }

            if let Some(raw_attributes) = parts.first() {
                attributes = parse_attributes(raw_attributes)?;
            }
            if let Some(raw_scope) = parts.get(1)
                && !raw_scope.is_empty()
            {
                let decoded_scope = percent_decode(raw_scope, "scope")?;
                scope = Some(LdapUrlScope::from_str(decoded_scope.as_str())?);
            }
            if let Some(raw_filter) = parts.get(2)
                && !raw_filter.is_empty()
            {
                let decoded_filter = percent_decode(raw_filter, "filter")?;
                if !decoded_filter.starts_with('(') || !decoded_filter.ends_with(')') {
                    return Err(LdapUrlError::InvalidFilter {
                        filter: decoded_filter,
                    });
                }
                filter = Some(decoded_filter);
            }
            if let Some(raw_extensions) = parts.get(3) {
                extensions = parse_extensions(raw_extensions)?;
            }
        }

        Ok(Self {
            scheme,
            host: parsed.host_str().map(str::to_string),
            port: parsed.port(),
            dn,
            attributes,
            scope,
            filter,
            extensions,
        })
    }

    pub fn to_url_string(&self) -> String {
        let mut url = format!("{}://", self.scheme.as_str());

        if let Some(host) = self.host.as_deref() {
            if host.contains(':') && !host.starts_with('[') {
                url.push('[');
                url.push_str(host);
                url.push(']');
            } else {
                url.push_str(host);
            }
        }

        if let Some(port) = self.port {
            url.push(':');
            url.push_str(&port.to_string());
        }

        url.push('/');
        url.push_str(&percent_encode_path_component(&self.dn));

        let last_component = if !self.extensions.is_empty() {
            4
        } else if self.filter.is_some() {
            3
        } else if self.scope.is_some() {
            2
        } else if !self.attributes.is_empty() {
            1
        } else {
            0
        };

        if last_component >= 1 {
            url.push('?');
            url.push_str(
                &self
                    .attributes
                    .iter()
                    .map(|attribute| percent_encode_query_component(attribute))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if last_component >= 2 {
            url.push('?');
            if let Some(scope) = self.scope {
                url.push_str(scope.as_str());
            }
        }
        if last_component >= 3 {
            url.push('?');
            if let Some(filter) = self.filter.as_deref() {
                url.push_str(&percent_encode_query_component(filter));
            }
        }
        if last_component >= 4 {
            url.push('?');
            url.push_str(
                &self
                    .extensions
                    .iter()
                    .map(render_extension)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        url
    }
}

impl fmt::Display for LdapUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_url_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapUrlError {
    InvalidUrl { source: String },
    UnsupportedScheme { scheme: String },
    UnsupportedUserInfo,
    InvalidPercentEncoding { component: &'static str },
    InvalidUtf8 { component: &'static str },
    EmptyAttribute,
    InvalidScope { scope: String },
    InvalidFilter { filter: String },
    EmptyExtension,
    TooManyComponents { count: usize },
}

impl fmt::Display for LdapUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl { source } => write!(f, "invalid LDAP URL: {source}"),
            Self::UnsupportedScheme { scheme } => {
                write!(f, "unsupported LDAP URL scheme {scheme}")
            }
            Self::UnsupportedUserInfo => {
                write!(f, "LDAP URLs must not contain userinfo")
            }
            Self::InvalidPercentEncoding { component } => {
                write!(f, "invalid percent encoding in LDAP URL {component}")
            }
            Self::InvalidUtf8 { component } => {
                write!(f, "LDAP URL {component} is not valid UTF-8")
            }
            Self::EmptyAttribute => write!(f, "LDAP URL attributes must not be empty"),
            Self::InvalidScope { scope } => write!(f, "invalid LDAP URL scope {scope}"),
            Self::InvalidFilter { filter } => {
                write!(f, "invalid LDAP URL filter {filter}")
            }
            Self::EmptyExtension => write!(f, "LDAP URL extensions must not be empty"),
            Self::TooManyComponents { count } => {
                write!(
                    f,
                    "LDAP URL has {count} selector components, expected at most 4"
                )
            }
        }
    }
}

impl std::error::Error for LdapUrlError {}

fn parse_attributes(raw: &str) -> Result<Vec<String>, LdapUrlError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    raw.split(',')
        .map(|attribute| {
            if attribute.is_empty() {
                Err(LdapUrlError::EmptyAttribute)
            } else {
                percent_decode(attribute, "attribute")
            }
        })
        .collect()
}

fn parse_extensions(raw: &str) -> Result<Vec<LdapUrlExtension>, LdapUrlError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    raw.split(',')
        .map(|extension| {
            if extension.is_empty() {
                return Err(LdapUrlError::EmptyExtension);
            }

            let (critical, rest) = match extension.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, extension),
            };
            if rest.is_empty() {
                return Err(LdapUrlError::EmptyExtension);
            }

            let (raw_name, raw_value) = rest
                .split_once('=')
                .map_or((rest, None), |(name, value)| (name, Some(value)));
            let name = percent_decode(raw_name, "extension name")?;
            if name.is_empty() {
                return Err(LdapUrlError::EmptyExtension);
            }
            let value = raw_value
                .map(|value| percent_decode(value, "extension value"))
                .transpose()?;

            Ok(LdapUrlExtension {
                critical,
                name,
                value,
            })
        })
        .collect()
}

fn render_extension(extension: &LdapUrlExtension) -> String {
    let mut rendered = String::new();
    if extension.critical {
        rendered.push('!');
    }
    rendered.push_str(&percent_encode_query_component(&extension.name));
    if let Some(value) = extension.value.as_deref() {
        rendered.push('=');
        rendered.push_str(&percent_encode_query_component(value));
    }
    rendered
}

fn percent_decode(input: &str, component: &'static str) -> Result<String, LdapUrlError> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(high) = bytes.get(index + 1).and_then(|byte| hex_value(*byte)) else {
                return Err(LdapUrlError::InvalidPercentEncoding { component });
            };
            let Some(low) = bytes.get(index + 2).and_then(|byte| hex_value(*byte)) else {
                return Err(LdapUrlError::InvalidPercentEncoding { component });
            };
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(output).map_err(|_| LdapUrlError::InvalidUtf8 { component })
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_encode_path_component(input: &str) -> String {
    percent_encode_with(input, is_safe_path_byte)
}

fn percent_encode_query_component(input: &str) -> String {
    percent_encode_with(input, is_unreserved)
}

fn percent_encode_with(input: &str, is_safe: fn(u8) -> bool) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        if is_safe(*byte) {
            encoded.push(*byte as char);
        } else {
            encoded.push('%');
            encoded.push(hex_char(byte >> 4));
            encoded.push(hex_char(byte & 0x0f));
        }
    }
    encoded
}

fn is_safe_path_byte(byte: u8) -> bool {
    is_unreserved(byte) || matches!(byte, b',' | b'=' | b'+' | b';' | b'@')
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + (value - 10)) as char,
        _ => unreachable!("hex nibble must be less than 16"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_rfc4516_url_and_render_canonical_form() {
        let url = LdapUrl::parse(
            "ldap://directory.example.com:1389/ou=People,dc=example,dc=org?cn,sn,mail?sub?(objectClass=person)?!bindname=cn%3Dproxy%2Cdc%3Dexample%2Cdc%3Dorg,x-chain",
        )
        .unwrap();

        assert_eq!(url.scheme, LdapUrlScheme::Ldap);
        assert_eq!(url.host.as_deref(), Some("directory.example.com"));
        assert_eq!(url.port, Some(1389));
        assert_eq!(url.dn, "ou=People,dc=example,dc=org");
        assert_eq!(url.attributes, vec!["cn", "sn", "mail"]);
        assert_eq!(url.scope, Some(LdapUrlScope::Sub));
        assert_eq!(url.filter.as_deref(), Some("(objectClass=person)"));
        assert_eq!(
            url.extensions,
            vec![
                LdapUrlExtension {
                    critical: true,
                    name: "bindname".to_string(),
                    value: Some("cn=proxy,dc=example,dc=org".to_string()),
                },
                LdapUrlExtension {
                    critical: false,
                    name: "x-chain".to_string(),
                    value: None,
                },
            ]
        );

        let rendered = url.to_url_string();
        assert_eq!(
            rendered,
            "ldap://directory.example.com:1389/ou=People,dc=example,dc=org?cn,sn,mail?sub?%28objectClass%3Dperson%29?!bindname=cn%3Dproxy%2Cdc%3Dexample%2Cdc%3Dorg,x-chain"
        );
        assert_eq!(LdapUrl::parse(&rendered).unwrap(), url);
    }

    #[test]
    fn parse_hostless_url_with_empty_attributes_and_scope_filter() {
        let url = LdapUrl::parse("ldaps:///dc=example,dc=org??one?%28uid%3Dalice%29").unwrap();

        assert_eq!(url.scheme, LdapUrlScheme::Ldaps);
        assert_eq!(url.host, None);
        assert_eq!(url.port, None);
        assert_eq!(url.dn, "dc=example,dc=org");
        assert!(url.attributes.is_empty());
        assert_eq!(url.scope, Some(LdapUrlScope::One));
        assert_eq!(url.filter.as_deref(), Some("(uid=alice)"));
        assert_eq!(
            url.to_url_string(),
            "ldaps:///dc=example,dc=org??one?%28uid%3Dalice%29"
        );
    }

    #[test]
    fn parse_url_without_dn_defaults_to_empty_dn() {
        let url = LdapUrl::parse("ldap://directory.example.com").unwrap();

        assert_eq!(url.host.as_deref(), Some("directory.example.com"));
        assert_eq!(url.dn, "");
        assert_eq!(url.to_url_string(), "ldap://directory.example.com/");
    }

    #[test]
    fn rejects_invalid_selector_components() {
        assert!(matches!(
            LdapUrl::parse("ldap://directory.example.com/dc=example,dc=org??children"),
            Err(LdapUrlError::InvalidScope { .. })
        ));
        assert!(matches!(
            LdapUrl::parse("ldap://directory.example.com/dc=example,dc=org?cn,,sn"),
            Err(LdapUrlError::EmptyAttribute)
        ));
        assert!(matches!(
            LdapUrl::parse("ldap://directory.example.com/dc=example,dc=org???objectClass=*"),
            Err(LdapUrlError::InvalidFilter { .. })
        ));
        assert!(matches!(
            LdapUrl::parse(
                "ldap://directory.example.com/dc=example,dc=org?cn?sub?(objectClass=*)?x?extra"
            ),
            Err(LdapUrlError::TooManyComponents { .. })
        ));
    }

    #[test]
    fn rejects_bad_syntax() {
        assert!(matches!(
            LdapUrl::parse("http://directory.example.com/dc=example,dc=org"),
            Err(LdapUrlError::UnsupportedScheme { .. })
        ));
        assert!(matches!(
            LdapUrl::parse("ldap://user@directory.example.com/dc=example,dc=org"),
            Err(LdapUrlError::UnsupportedUserInfo)
        ));
        assert!(matches!(
            LdapUrl::parse("ldap://directory.example.com/dc=example%ZZ,dc=org"),
            Err(LdapUrlError::InvalidPercentEncoding { .. })
        ));
    }
}
