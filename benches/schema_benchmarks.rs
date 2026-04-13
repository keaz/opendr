//! Schema Validation Performance Benchmarks
//!
//! This benchmark suite measures the performance of LDAP schema validation,
//! including object class validation, attribute collection, and constraint checking.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use opendr::schema::{AttributeType, LdapSchema, ObjectClass, ObjectClassKind};
use std::collections::HashMap;

/// Setup function for creating test entries
fn create_simple_person_entry() -> HashMap<String, Vec<String>> {
    HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        ),
        ("cn".to_string(), vec!["John Doe".to_string()]),
        ("sn".to_string(), vec!["Doe".to_string()]),
    ])
}

fn create_complex_inetorgperson_entry() -> HashMap<String, Vec<String>> {
    HashMap::from([
        (
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "inetOrgPerson".to_string(),
            ],
        ),
        ("cn".to_string(), vec!["Alice Johnson".to_string()]),
        ("sn".to_string(), vec!["Johnson".to_string()]),
        ("uid".to_string(), vec!["ajohnson".to_string()]),
        ("mail".to_string(), vec!["ajohnson@example.com".to_string()]),
        ("givenName".to_string(), vec!["Alice".to_string()]),
        (
            "ou".to_string(),
            vec!["Engineering".to_string(), "R&D".to_string()],
        ),
        (
            "description".to_string(),
            vec!["Senior Software Engineer".to_string()],
        ),
    ])
}

fn create_organization_entry() -> HashMap<String, Vec<String>> {
    HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "organization".to_string()],
        ),
        ("o".to_string(), vec!["Example Corporation".to_string()]),
        (
            "description".to_string(),
            vec!["A sample organization".to_string()],
        ),
    ])
}

/// Benchmark: Schema creation and initialization
fn bench_schema_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema_creation");

    group.bench_function("create_core_schema", |b| {
        b.iter(|| black_box(LdapSchema::with_core_schema()));
    });

    group.bench_function("create_empty_schema", |b| {
        b.iter(|| black_box(LdapSchema::new()));
    });

    group.finish();
}

/// Benchmark: Entry validation performance
fn bench_entry_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("entry_validation");
    let schema = LdapSchema::with_core_schema();

    // Benchmark: Simple person entry (2 object classes, 2 attributes)
    let simple_entry = create_simple_person_entry();
    group.bench_function("validate_simple_person", |b| {
        b.iter(|| schema.validate_entry(black_box(&simple_entry)));
    });

    // Benchmark: Complex inetOrgPerson entry (4 object classes, 7 attributes)
    let complex_entry = create_complex_inetorgperson_entry();
    group.bench_function("validate_complex_inetorgperson", |b| {
        b.iter(|| schema.validate_entry(black_box(&complex_entry)));
    });

    // Benchmark: Organization entry
    let org_entry = create_organization_entry();
    group.bench_function("validate_organization", |b| {
        b.iter(|| schema.validate_entry(black_box(&org_entry)));
    });

    // Benchmark: Entry with validation error (missing required attribute)
    let invalid_entry = HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        ),
        ("cn".to_string(), vec!["John Doe".to_string()]),
        // Missing required 'sn' attribute
    ]);
    group.bench_function("validate_invalid_entry", |b| {
        b.iter(|| {
            let _ = schema.validate_entry(black_box(&invalid_entry));
        });
    });

    group.finish();
}

/// Benchmark: Object class operations
fn bench_object_class_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("object_class");
    let schema = LdapSchema::with_core_schema();

    // Benchmark: Object class lookup
    group.bench_function("lookup_object_class", |b| {
        b.iter(|| schema.get_object_class(black_box("person")));
    });

    // Benchmark: Case-insensitive lookup
    group.bench_function("lookup_case_insensitive", |b| {
        b.iter(|| schema.get_object_class(black_box("INETORGPERSON")));
    });

    // Benchmark: Non-existent object class lookup
    group.bench_function("lookup_nonexistent", |b| {
        b.iter(|| schema.get_object_class(black_box("unknownClass")));
    });

    group.finish();
}

/// Benchmark: Attribute type operations
fn bench_attribute_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("attribute_type");
    let schema = LdapSchema::with_core_schema();

    // Benchmark: Attribute type lookup
    group.bench_function("lookup_attribute_type", |b| {
        b.iter(|| schema.get_attribute_type(black_box("cn")));
    });

    // Benchmark: Case-insensitive attribute lookup
    group.bench_function("lookup_attribute_case_insensitive", |b| {
        b.iter(|| schema.get_attribute_type(black_box("MAIL")));
    });

    // Benchmark: Non-existent attribute lookup
    group.bench_function("lookup_attribute_nonexistent", |b| {
        b.iter(|| schema.get_attribute_type(black_box("unknownAttr")));
    });

    group.finish();
}

/// Benchmark: Schema extension operations
fn bench_schema_extension(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema_extension");

    // Benchmark: Adding custom attribute type
    group.bench_function("add_custom_attribute", |b| {
        b.iter(|| {
            let mut schema = LdapSchema::new();
            let custom_attr = AttributeType {
                oid: "1.2.3.4.5.6.7.8".to_string(),
                names: vec!["customAttribute".to_string()],
                description: None,
                equality: None,
                syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
                single_value: false,
            };
            schema.add_attribute_type(black_box(custom_attr));
        });
    });

    // Benchmark: Adding custom object class
    group.bench_function("add_custom_object_class", |b| {
        b.iter(|| {
            let mut schema = LdapSchema::new();
            let custom_oc = ObjectClass {
                oid: "1.2.3.4.5.6.7.9".to_string(),
                names: vec!["customClass".to_string()],
                sup: vec!["top".to_string()],
                kind: ObjectClassKind::Structural,
                must: vec!["cn".to_string()],
                may: vec!["description".to_string()],
            };
            schema.add_object_class(black_box(custom_oc));
        });
    });

    group.finish();
}

/// Benchmark: Structural class validation
fn bench_structural_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("structural_validation");
    let schema = LdapSchema::with_core_schema();

    // Benchmark: Entry with single structural class
    let single_structural = HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        ),
        ("cn".to_string(), vec!["Test".to_string()]),
        ("sn".to_string(), vec!["User".to_string()]),
    ]);
    group.bench_function("single_structural_class", |b| {
        b.iter(|| schema.validate_entry(black_box(&single_structural)));
    });

    // Benchmark: Entry with object class hierarchy (4 levels)
    let hierarchy_entry = HashMap::from([
        (
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "inetOrgPerson".to_string(),
            ],
        ),
        ("cn".to_string(), vec!["Test".to_string()]),
        ("sn".to_string(), vec!["User".to_string()]),
    ]);
    group.bench_function("hierarchical_classes", |b| {
        b.iter(|| schema.validate_entry(black_box(&hierarchy_entry)));
    });

    group.finish();
}

/// Benchmark: Attribute collection and validation
fn bench_attribute_collection(c: &mut Criterion) {
    let mut group = c.benchmark_group("attribute_collection");
    let schema = LdapSchema::with_core_schema();

    // Create entries with varying numbers of attributes
    for num_attrs in [2, 5, 10, 20].iter() {
        let mut entry = HashMap::new();
        entry.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "inetOrgPerson".to_string()],
        );
        entry.insert("cn".to_string(), vec!["Test User".to_string()]);
        entry.insert("sn".to_string(), vec!["User".to_string()]);

        for i in 0..*num_attrs {
            entry.insert(format!("description{}", i), vec![format!("Value {}", i)]);
        }

        group.bench_with_input(BenchmarkId::from_parameter(num_attrs), num_attrs, |b, _| {
            b.iter(|| {
                // This will fail but we're measuring the attribute collection overhead
                let _ = schema.validate_entry(black_box(&entry));
            });
        });
    }

    group.finish();
}

/// Benchmark: Multi-valued attribute validation
fn bench_multivalued_attributes(c: &mut Criterion) {
    let mut group = c.benchmark_group("multivalued_attributes");
    let schema = LdapSchema::with_core_schema();

    // Benchmark: Entry with single-valued attributes
    let single_valued = create_simple_person_entry();
    group.bench_function("single_valued_attributes", |b| {
        b.iter(|| schema.validate_entry(black_box(&single_valued)));
    });

    // Benchmark: Entry with multi-valued attribute
    let multi_valued = HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "inetOrgPerson".to_string()],
        ),
        ("cn".to_string(), vec!["Test User".to_string()]),
        ("sn".to_string(), vec!["User".to_string()]),
        (
            "mail".to_string(),
            vec![
                "test1@example.com".to_string(),
                "test2@example.com".to_string(),
                "test3@example.com".to_string(),
            ],
        ),
    ]);
    group.bench_function("multi_valued_attributes", |b| {
        b.iter(|| schema.validate_entry(black_box(&multi_valued)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_schema_creation,
    bench_entry_validation,
    bench_object_class_operations,
    bench_attribute_operations,
    bench_schema_extension,
    bench_structural_validation,
    bench_attribute_collection,
    bench_multivalued_attributes
);
criterion_main!(benches);
