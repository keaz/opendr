use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;

use clap::Parser;
use opendr::backend::DirectoryEntry;
use opendr::backend_lmdb::{AttributeIndexConfig, IndexConfig, IndexType, LmdbBackend};
use opendr::schema::LdapSchema;

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const BENCHMARK_INDEX_AUXILIARY_CLASS: &str = "benchmarkIndexedObject";
const BENCHMARK_ORDER_ATTRIBUTE: &str = "benchmarkOrder";
const BENCHMARK_SCHEMA_LDIF: &str = "dn: cn=schema\nattributeTypes: ( 1.3.6.1.4.1.55555.200.1 NAME 'benchmarkOrder' DESC 'Benchmark integer ordering key' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )\nobjectClasses: ( 1.3.6.1.4.1.55555.200.2 NAME 'benchmarkIndexedObject' DESC 'Benchmark auxiliary object class for index probes' SUP top AUXILIARY MAY benchmarkOrder )\n";
const SERVER_DEFAULT_INDEXED_ATTRIBUTES: &[&str] = &["cn", "uid", "mail", "objectClass"];

#[derive(Debug, Parser)]
#[command(name = "opendr-perf-fixture-loader")]
#[command(about = "Offline bulk loader for OpenDR LDAP performance fixtures")]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,

    #[arg(long)]
    base_dn: String,

    #[arg(long)]
    root_dn: String,

    #[arg(long)]
    root_password: String,

    #[arg(long)]
    name_prefix: String,

    #[arg(long)]
    preloaded_users: usize,

    #[arg(long, default_value = "InitialUserSecret123!")]
    user_password: String,

    #[arg(long, default_value_t = 1073741824)]
    lmdb_max_size_bytes: usize,

    #[arg(long, default_value_t = 256)]
    lmdb_max_readers: u32,

    #[arg(long, default_value_t = 1000)]
    cache_size: usize,

    #[arg(long, default_value_t = 10000)]
    batch_size: usize,

    #[arg(long, default_value_t = false)]
    index_benchmark: bool,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run(Args::parse()).await {
        eprintln!("opendr_perf_fixture_loader failed: {err}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> AppResult<()> {
    ensure(
        args.preloaded_users > 0,
        "--preloaded-users must be greater than zero",
    )?;
    ensure(
        args.batch_size > 0,
        "--batch-size must be greater than zero",
    )?;

    let max_size_mb = args.lmdb_max_size_bytes.div_ceil(1024 * 1024);
    let mut schema = LdapSchema::with_core_schema();
    let mut index_config = IndexConfig {
        indexed_attributes: SERVER_DEFAULT_INDEXED_ATTRIBUTES
            .iter()
            .map(|attribute| (*attribute).to_string())
            .collect(),
        attribute_indexes: Vec::new(),
    };
    if args.index_benchmark {
        schema.load_ldif_str(BENCHMARK_SCHEMA_LDIF)?;
        index_config.attribute_indexes.push(AttributeIndexConfig {
            attribute: "description".to_string(),
            index_types: vec![IndexType::Substring],
        });
        index_config.attribute_indexes.push(AttributeIndexConfig {
            attribute: BENCHMARK_ORDER_ATTRIBUTE.to_string(),
            index_types: vec![IndexType::Ordering],
        });
    }

    let backend = LmdbBackend::new_with_runtime_and_cache_config_with_schema(
        &args.data_dir,
        max_size_mb,
        1,
        index_config,
        args.lmdb_max_readers,
        args.cache_size,
        &schema,
    )?;

    let root_password_hash =
        LmdbBackend::create_ssha512_password_hash(args.root_password.as_bytes()).into_bytes();
    let user_password_hash =
        LmdbBackend::create_ssha512_password_hash(args.user_password.as_bytes()).into_bytes();
    let benchmark_root_dn = format!("ou={},{}", args.name_prefix, args.base_dn);
    let users_ou_dn = format!("ou=users,ou={},{}", args.name_prefix, args.base_dn);
    let moved_ou_dn = format!("ou=moved,ou={},{}", args.name_prefix, args.base_dn);
    let writes_ou_dn = format!("ou=writes,ou={},{}", args.name_prefix, args.base_dn);

    let setup_entries = vec![
        (
            DirectoryEntry::new(
                args.base_dn.clone(),
                HashMap::from([
                    (
                        "objectClass".to_string(),
                        vec!["top".to_string(), "organization".to_string()],
                    ),
                    ("o".to_string(), vec!["OpenDR Docker".to_string()]),
                    ("description".to_string(), vec!["OpenDR Docker".to_string()]),
                ]),
            ),
            Vec::new(),
        ),
        (
            DirectoryEntry::new(
                args.root_dn.clone(),
                HashMap::from([
                    (
                        "objectClass".to_string(),
                        vec!["top".to_string(), "person".to_string()],
                    ),
                    (
                        "cn".to_string(),
                        vec![
                            args.root_dn
                                .split_once('=')
                                .and_then(|(_, rest)| rest.split_once(','))
                                .map(|(cn, _)| cn.to_string())
                                .unwrap_or_else(|| "admin".to_string()),
                        ],
                    ),
                    ("sn".to_string(), vec!["Manager".to_string()]),
                ]),
            ),
            root_password_hash,
        ),
        (organizational_unit_entry(&benchmark_root_dn), Vec::new()),
        (organizational_unit_entry(&users_ou_dn), Vec::new()),
        (organizational_unit_entry(&moved_ou_dn), Vec::new()),
        (organizational_unit_entry(&writes_ou_dn), Vec::new()),
    ];

    let preloaded_users = args.preloaded_users;
    let name_prefix = args.name_prefix.clone();
    let user_password = args.user_password.clone();
    let include_index_attributes = args.index_benchmark;
    let user_entries = (0..preloaded_users).map(move |index| {
        (
            fixture_user_entry(
                &users_ou_dn,
                &name_prefix,
                index,
                &user_password,
                include_index_attributes,
            ),
            user_password_hash.clone(),
        )
    });

    progress("fixture.bulk_load.start");
    let expected_entries = setup_entries.len() + preloaded_users;
    let added = backend
        .bulk_add_entries(
            setup_entries.into_iter().chain(user_entries),
            args.batch_size,
            Some(&args.root_dn),
            |loaded| {
                if expected_entries >= 100_000
                    && (loaded % 100_000 == 0 || loaded == expected_entries)
                {
                    progress(&format!("fixture.bulk_load.{loaded}of{expected_entries}"));
                }
            },
        )
        .await?;

    ensure(
        added == expected_entries,
        format!("expected to bulk-load {expected_entries} entries, added {added}"),
    )?;
    progress("fixture.bulk_load.complete");
    println!("Bulk-loaded {added} OpenDR perf fixture entries");
    Ok(())
}

fn organizational_unit_entry(dn: &str) -> DirectoryEntry {
    let ou = dn
        .split_once('=')
        .and_then(|(_, rest)| rest.split_once(','))
        .map(|(ou, _)| ou.to_string())
        .unwrap_or_else(|| dn.to_string());
    DirectoryEntry::new(
        dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec![ou]),
        ]),
    )
}

fn fixture_user_entry(
    users_ou_dn: &str,
    name_prefix: &str,
    index: usize,
    user_password: &str,
    include_index_attributes: bool,
) -> DirectoryEntry {
    let uid = format!("{name_prefix}-user-{index:06}");
    let mut attributes = HashMap::from([
        (
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "inetOrgPerson".to_string(),
            ],
        ),
        ("uid".to_string(), vec![uid.clone()]),
        ("cn".to_string(), vec![format!("Benchmark User {index}")]),
        ("sn".to_string(), vec![format!("BenchmarkUser{index:06}")]),
        (
            "description".to_string(),
            vec![format!("Benchmark fixture user {index:06}")],
        ),
        ("mail".to_string(), vec![format!("{uid}@example.com")]),
        ("userPassword".to_string(), vec![user_password.to_string()]),
    ]);
    if include_index_attributes {
        attributes
            .get_mut("objectClass")
            .expect("objectClass attribute")
            .push(BENCHMARK_INDEX_AUXILIARY_CLASS.to_string());
        attributes.insert(
            BENCHMARK_ORDER_ATTRIBUTE.to_string(),
            vec![index.to_string()],
        );
    }

    DirectoryEntry::new(format!("uid={uid},{users_ou_dn}"), attributes)
}

fn progress(message: &str) {
    if std::env::var_os("LDAP_PERF_PROGRESS").is_some() {
        eprintln!("progress: {message}");
    }
}

fn ensure(condition: bool, message: impl Into<String>) -> AppResult<()> {
    if condition {
        Ok(())
    } else {
        Err(std::io::Error::other(message.into()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_user_entry_matches_perf_client_naming() {
        let entry = fixture_user_entry(
            "ou=users,ou=opendr-ten-million,dc=example,dc=com",
            "opendr-ten-million",
            42,
            "secret",
            true,
        );

        assert_eq!(
            entry.dn,
            "uid=opendr-ten-million-user-000042,ou=users,ou=opendr-ten-million,dc=example,dc=com"
        );
        assert_eq!(
            entry.attributes.get("uid").unwrap(),
            &vec!["opendr-ten-million-user-000042".to_string()]
        );
        assert_eq!(
            entry.attributes.get("benchmarkorder").unwrap(),
            &vec!["42".to_string()]
        );
        assert!(
            entry
                .attributes
                .get("objectclass")
                .unwrap()
                .contains(&BENCHMARK_INDEX_AUXILIARY_CLASS.to_string())
        );
    }

    #[test]
    fn organizational_unit_entry_uses_rdn_value() {
        let entry = organizational_unit_entry("ou=users,ou=opendr-ten-million,dc=example,dc=com");

        assert_eq!(entry.dn, "ou=users,ou=opendr-ten-million,dc=example,dc=com");
        assert_eq!(
            entry.attributes.get("ou").unwrap(),
            &vec!["users".to_string()]
        );
    }
}
