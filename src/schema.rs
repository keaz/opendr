use std::collections::HashMap;

#[derive(Debug)]
struct LdapSchema {
    attribute_types: HashMap<String, AttributeType>,
    object_classes: HashMap<String, ObjectClass>,
}

#[derive(Debug, Clone)]
struct AttributeType {
    oid: String,
    names: Vec<String>,
    description: Option<String>,
    equality: Option<String>,
    syntax: String,
    single_value: bool,
}

#[derive(Debug, Clone)]
struct ObjectClass {
    oid: String,
    names: Vec<String>,
    sup: Vec<String>,
    kind: ObjectClassKind,
    must: Vec<String>,
    may: Vec<String>,
}

#[derive(Debug, Clone)]
enum ObjectClassKind {
    Abstract,
    Structural,
    Auxiliary,
}

fn parse_attribute_type(def: &str) -> AttributeType {
    let parts: Vec<&str> = def.split_whitespace().collect();
    let oid = parts[1].to_string();
    let names: Vec<String> = parts
        .iter()
        .skip_while(|&&p| p != "NAME")
        .skip(1)
        .take_while(|&&p| p != "DESC")
        .map(|&p| p.trim_matches('\'').to_string())
        .collect();
    let description = parts
        .iter()
        .skip_while(|&&p| p != "DESC")
        .skip(1)
        .next()
        .map(|&p| p.trim_matches('\'').to_string());
    let equality = parts
        .iter()
        .skip_while(|&&p| p != "EQUALITY")
        .skip(1)
        .next()
        .map(|&p| p.to_string());
    let syntax = parts
        .iter()
        .skip_while(|&&p| p != "SYNTAX")
        .skip(1)
        .next()
        .map(|&p| p.to_string())
        .unwrap_or_default();
    let single_value = parts.contains(&"SINGLE-VALUE");

    AttributeType {
        oid,
        names,
        description,
        equality,
        syntax,
        single_value,
    }
}

fn parse_object_class(def: &str) -> ObjectClass {
    let parts: Vec<&str> = def.split_whitespace().collect();
    let oid = parts[1].to_string();
    let names: Vec<String> = parts
        .iter()
        .skip_while(|&&p| p != "NAME")
        .skip(1)
        .take_while(|&&p| p != "SUP" && p != "STRUCTURAL" && p != "ABSTRACT" && p != "AUXILIARY")
        .map(|&p| p.trim_matches('\'').to_string())
        .collect();
    let sup: Vec<String> = parts
        .iter()
        .skip_while(|&&p| p != "SUP")
        .skip(1)
        .take_while(|&&p| {
            p != "STRUCTURAL" && p != "ABSTRACT" && p != "AUXILIARY" && p != "MUST" && p != "MAY"
        })
        .map(|&p| p.to_string())
        .collect();
    let kind = parts
        .iter()
        .find_map(|&p| match p {
            "STRUCTURAL" => Some(ObjectClassKind::Structural),
            "ABSTRACT" => Some(ObjectClassKind::Abstract),
            "AUXILIARY" => Some(ObjectClassKind::Auxiliary),
            _ => None,
        })
        .unwrap_or(ObjectClassKind::Structural); // Default to Structural if not specified
    let must: Vec<String> = parts
        .iter()
        .skip_while(|&&p| p != "MUST")
        .skip(1)
        .take_while(|&&p| p != "MAY")
        .flat_map(|&p| {
            p.trim_matches(&['(', ')'][..])
                .split('$')
                .map(|s| s.to_string())
        })
        .collect();
    let may: Vec<String> = parts
        .iter()
        .skip_while(|&&p| p != "MAY")
        .skip(1)
        .flat_map(|&p| {
            p.trim_matches(&['(', ')'][..])
                .split('$')
                .map(|s| s.to_string())
        })
        .collect();

    ObjectClass {
        oid,
        names,
        sup,
        kind,
        must,
        may,
    }
}

fn parse_schema(schema: &str) -> LdapSchema {
    let mut attribute_types = HashMap::new();
    let mut object_classes = HashMap::new();

    for line in schema.lines() {
        if line.starts_with("attributeType") {
            let attribute = parse_attribute_type(line);
            for name in &attribute.names {
                attribute_types.insert(name.clone(), attribute.clone());
            }
        } else if line.starts_with("objectClass") {
            let object_class = parse_object_class(line);
            for name in &object_class.names {
                object_classes.insert(name.clone(), object_class.clone());
            }
        }
    }

    LdapSchema {
        attribute_types,
        object_classes,
    }
}

#[cfg(test)]
mod test {

    use super::*;
    #[test]
    fn test_parse_attribute_type() {
        let attr_def = "( 1.2.840.113556.1.4.7000 NAME 'employeeNumber' DESC 'Employee number' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )";
        let attribute_type = parse_attribute_type(attr_def);

        assert_eq!(attribute_type.oid, "1.2.840.113556.1.4.7000");
        assert_eq!(attribute_type.names, vec!["employeeNumber".to_string()]);
        assert_eq!(
            attribute_type.description,
            Some("Employee number".to_string())
        );
        assert_eq!(attribute_type.equality, Some("caseIgnoreMatch".to_string()));
    }
}
