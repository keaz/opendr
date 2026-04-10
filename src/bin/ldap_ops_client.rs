use std::collections::HashSet;
use std::error::Error;
use std::io;

use clap::Parser;
use ldap3::exop::{PasswordModify, WhoAmI, WhoAmIResp};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";
const PASSWORD_MODIFY_OID: &str = "1.3.6.1.4.1.4203.1.11.1";
const WHOAMI_OID: &str = "1.3.6.1.4.1.4203.1.11.3";

#[derive(Debug, Parser)]
#[command(name = "ldap-ops-client")]
#[command(about = "Exercise the OpenDR LDAP server through ldap3")]
struct Args {
    #[arg(long)]
    url: String,

    #[arg(long)]
    bind_dn: String,

    #[arg(long)]
    password: String,

    #[arg(long)]
    base_dn: String,

    #[arg(long, default_value_t = false)]
    starttls: bool,

    #[arg(long, default_value_t = false)]
    insecure: bool,

    #[arg(long, default_value = "InitialUserSecret123!")]
    user_password: String,

    #[arg(long, default_value = "UpdatedUserSecret456!")]
    updated_user_password: String,

    #[arg(long, default_value = "ldap-client-app")]
    name_prefix: String,
}

#[derive(Debug, Clone)]
struct ScenarioDns {
    source_ou_dn: String,
    target_ou_dn: String,
    user_dn: String,
    renamed_user_dn: String,
    renamed_cn: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(err) = run(args).await {
        eprintln!("ldap-ops-client failed: {err}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> AppResult<()> {
    let dns = ScenarioDns {
        source_ou_dn: format!("ou={}-source,{}", args.name_prefix, args.base_dn),
        target_ou_dn: format!("ou={}-target,{}", args.name_prefix, args.base_dn),
        user_dn: format!(
            "cn={}-user,ou={}-source,{}",
            args.name_prefix, args.name_prefix, args.base_dn
        ),
        renamed_user_dn: format!(
            "cn={}-user-renamed,ou={}-target,{}",
            args.name_prefix, args.name_prefix, args.base_dn
        ),
        renamed_cn: format!("{}-user-renamed", args.name_prefix),
    };

    let mut admin = connect(&args).await?;
    verify_root_dse(
        &mut admin,
        &args.base_dn,
        args.starttls || args.url.starts_with("ldaps://"),
    )
    .await?;
    simple_bind(&mut admin, &args.bind_dn, &args.password).await?;
    verify_whoami(&mut admin, &args.bind_dn).await?;
    create_test_tree(&mut admin, &dns, &args.user_password).await?;
    verify_search_and_modify(&mut admin, &dns).await?;
    verify_compare(&mut admin, &dns.user_dn).await?;
    verify_modifydn_move(&mut admin, &dns).await?;
    admin.unbind().await?;

    let mut user = connect(&args).await?;
    simple_bind(&mut user, &dns.renamed_user_dn, &args.user_password).await?;
    verify_whoami(&mut user, &dns.renamed_user_dn).await?;
    verify_password_modify(
        &mut user,
        &dns.renamed_user_dn,
        &args.user_password,
        &args.updated_user_password,
    )
    .await?;
    user.unbind().await?;

    let mut old_password_client = connect(&args).await?;
    expect_invalid_bind(
        &mut old_password_client,
        &dns.renamed_user_dn,
        &args.user_password,
    )
    .await?;
    old_password_client.unbind().await?;

    let mut new_password_client = connect(&args).await?;
    simple_bind(
        &mut new_password_client,
        &dns.renamed_user_dn,
        &args.updated_user_password,
    )
    .await?;
    verify_whoami(&mut new_password_client, &dns.renamed_user_dn).await?;
    new_password_client.unbind().await?;

    let mut cleanup = connect(&args).await?;
    simple_bind(&mut cleanup, &args.bind_dn, &args.password).await?;
    cleanup_test_tree(&mut cleanup, &dns).await?;
    cleanup.unbind().await?;

    println!("All LDAP operations completed successfully.");
    Ok(())
}

async fn connect(args: &Args) -> AppResult<Ldap> {
    let mut settings = LdapConnSettings::new();
    if args.starttls {
        settings = settings.set_starttls(true);
    }
    if args.insecure {
        settings = settings.set_no_tls_verify(true);
    }

    let (conn, ldap) = LdapConnAsync::with_settings(settings, &args.url).await?;
    ldap3::drive!(conn);
    Ok(ldap)
}

async fn simple_bind(ldap: &mut Ldap, bind_dn: &str, password: &str) -> AppResult<()> {
    ldap.simple_bind(bind_dn, password).await?.success()?;
    println!("Bound as {bind_dn}");
    Ok(())
}

async fn expect_invalid_bind(ldap: &mut Ldap, bind_dn: &str, password: &str) -> AppResult<()> {
    match ldap.simple_bind(bind_dn, password).await?.success() {
        Ok(_) => Err(other_error(format!(
            "bind for {bind_dn} unexpectedly succeeded with an obsolete password"
        ))),
        Err(err) => {
            let diagnostic = err.to_string();
            ensure(
                diagnostic.contains("InvalidCredentials")
                    || diagnostic.contains("invalid credentials"),
                format!("expected invalid credentials, got: {diagnostic}"),
            )?;
            println!("Old password rejected for {bind_dn}");
            Ok(())
        }
    }
}

async fn verify_root_dse(ldap: &mut Ldap, base_dn: &str, secure_connection: bool) -> AppResult<()> {
    let (entries, _result) = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["namingContexts", "supportedExtension", "supportedControl"],
        )
        .await?
        .success()?;
    ensure(entries.len() == 1, "expected exactly one Root DSE entry")?;
    let entry = SearchEntry::construct(entries.into_iter().next().expect("root dse"));
    let naming_contexts = attr_values(&entry, "namingContexts")?;
    ensure(
        naming_contexts
            .iter()
            .any(|value| value.eq_ignore_ascii_case(base_dn)),
        format!("Root DSE missing namingContexts value {base_dn:?}: {naming_contexts:?}"),
    )?;
    let extensions = attr_values(&entry, "supportedExtension")?;
    if !secure_connection {
        ensure(
            extensions.iter().any(|value| value == STARTTLS_OID),
            "Root DSE does not advertise StartTLS",
        )?;
    }
    ensure(
        extensions.iter().any(|value| value == PASSWORD_MODIFY_OID),
        "Root DSE does not advertise Password Modify",
    )?;
    ensure(
        extensions.iter().any(|value| value == WHOAMI_OID),
        "Root DSE does not advertise WhoAmI",
    )?;
    println!("Verified Root DSE namingContexts and supported extensions");
    Ok(())
}

async fn verify_whoami(ldap: &mut Ldap, expected_dn: &str) -> AppResult<()> {
    let (exop, _result) = ldap.extended(WhoAmI).await?.success()?;
    let whoami: WhoAmIResp = exop.parse();
    ensure(
        whoami
            .authzid
            .eq_ignore_ascii_case(&format!("dn:{expected_dn}")),
        format!(
            "WhoAmI mismatch: expected dn:{expected_dn}, got {}",
            whoami.authzid
        ),
    )?;
    println!("Verified WhoAmI for {expected_dn}");
    Ok(())
}

async fn create_test_tree(
    ldap: &mut Ldap,
    dns: &ScenarioDns,
    user_password: &str,
) -> AppResult<()> {
    add_organizational_unit(ldap, &dns.source_ou_dn).await?;
    add_organizational_unit(ldap, &dns.target_ou_dn).await?;

    ldap.add(
        &dns.user_dn,
        vec![
            (
                "objectClass".to_string(),
                string_set(["top", "person", "inetOrgPerson"]),
            ),
            ("cn".to_string(), string_set([format_dn_cn(&dns.user_dn)?])),
            ("sn".to_string(), string_set(["InitialSurname"])),
            ("givenName".to_string(), string_set(["Integration"])),
            (
                "description".to_string(),
                string_set(["ldap ops client fixture"]),
            ),
            ("userPassword".to_string(), string_set([user_password])),
        ],
    )
    .await?
    .success()?;

    println!("Created test OUs and user {}", dns.user_dn);
    Ok(())
}

async fn add_organizational_unit(ldap: &mut Ldap, dn: &str) -> AppResult<()> {
    let ou_value = dn
        .split_once('=')
        .and_then(|(_, rest)| rest.split_once(','))
        .map(|(ou, _)| ou.to_string())
        .ok_or_else(|| other_error(format!("failed to derive ou value from {dn}")))?;
    ldap.add(
        dn,
        vec![
            (
                "objectClass".to_string(),
                string_set(["top", "organizationalUnit"]),
            ),
            ("ou".to_string(), string_set([ou_value])),
        ],
    )
    .await?
    .success()?;
    Ok(())
}

async fn verify_search_and_modify(ldap: &mut Ldap, dns: &ScenarioDns) -> AppResult<()> {
    let source_entries = search_entries(
        ldap,
        &dns.source_ou_dn,
        Scope::OneLevel,
        "(objectClass=inetOrgPerson)",
        vec!["cn", "sn", "givenName", "description"],
    )
    .await?;
    ensure(
        source_entries.len() == 1,
        "expected exactly one test user in source OU",
    )?;

    ldap.modify(
        &dns.user_dn,
        vec![
            Mod::Add(
                "displayName".to_string(),
                string_set(["LDAP Client Display Name"]),
            ),
            Mod::Replace("sn".to_string(), string_set(["UpdatedSurname"])),
            Mod::Delete("givenName".to_string(), string_set(["Integration"])),
        ],
    )
    .await?
    .success()?;

    let updated_entry = search_single_entry(
        ldap,
        &dns.user_dn,
        Scope::Base,
        "(objectClass=inetOrgPerson)",
        vec!["cn", "sn", "givenName", "displayName"],
    )
    .await?;
    ensure(
        attr_values(&updated_entry, "sn")?
            .iter()
            .any(|value| value == "UpdatedSurname"),
        "Modify replace did not update sn",
    )?;
    ensure(
        attr_values(&updated_entry, "displayName")?
            .iter()
            .any(|value| value == "LDAP Client Display Name"),
        "Modify add did not add displayName",
    )?;
    ensure(
        attr_values_opt(&updated_entry, "givenName").is_none(),
        "Modify delete did not remove givenName",
    )?;
    println!("Verified search and modify operations for {}", dns.user_dn);
    Ok(())
}

async fn verify_compare(ldap: &mut Ldap, user_dn: &str) -> AppResult<()> {
    let match_result = ldap
        .compare(user_dn, "sn", "UpdatedSurname")
        .await?
        .equal()?;
    ensure(match_result, "Compare true assertion failed")?;

    let mismatch_result = ldap.compare(user_dn, "sn", "WrongSurname").await?.equal()?;
    ensure(!mismatch_result, "Compare false assertion failed")?;
    println!("Verified compare true/false on {user_dn}");
    Ok(())
}

async fn verify_modifydn_move(ldap: &mut Ldap, dns: &ScenarioDns) -> AppResult<()> {
    ldap.modifydn(
        &dns.user_dn,
        &format!("cn={}", dns.renamed_cn),
        true,
        Some(&dns.target_ou_dn),
    )
    .await?
    .success()?;

    let source_entries = search_entries(
        ldap,
        &dns.source_ou_dn,
        Scope::Subtree,
        &format!("(cn={})", dns.renamed_cn),
        vec!["cn"],
    )
    .await?;
    ensure(
        source_entries.is_empty(),
        "ModifyDN move left entry in source OU",
    )?;

    let target_entry = search_single_entry(
        ldap,
        &dns.target_ou_dn,
        Scope::Subtree,
        &format!("(cn={})", dns.renamed_cn),
        vec!["cn", "sn", "displayName"],
    )
    .await?;
    ensure(
        target_entry.dn.eq_ignore_ascii_case(&dns.renamed_user_dn),
        format!(
            "ModifyDN returned unexpected DN: expected {}, got {}",
            dns.renamed_user_dn, target_entry.dn
        ),
    )?;
    println!("Verified ModifyDN rename+move to {}", dns.renamed_user_dn);
    Ok(())
}

async fn verify_password_modify(
    ldap: &mut Ldap,
    user_dn: &str,
    old_password: &str,
    new_password: &str,
) -> AppResult<()> {
    let (_exop, _result) = ldap
        .extended(PasswordModify {
            user_id: Some(user_dn),
            old_pass: Some(old_password),
            new_pass: Some(new_password),
        })
        .await?
        .success()?;
    println!("Verified Password Modify for {user_dn}");
    Ok(())
}

async fn cleanup_test_tree(ldap: &mut Ldap, dns: &ScenarioDns) -> AppResult<()> {
    ldap.delete(&dns.renamed_user_dn).await?.success()?;
    let remaining_entries = search_entries(
        ldap,
        &dns.target_ou_dn,
        Scope::Subtree,
        &format!("(cn={})", dns.renamed_cn),
        vec!["cn"],
    )
    .await?;
    ensure(
        remaining_entries.is_empty(),
        "Delete did not remove renamed user entry",
    )?;

    ldap.delete(&dns.target_ou_dn).await?.success()?;
    ldap.delete(&dns.source_ou_dn).await?.success()?;
    println!("Verified delete operations for test tree");
    Ok(())
}

async fn search_entries(
    ldap: &mut Ldap,
    base: &str,
    scope: Scope,
    filter: &str,
    attrs: Vec<&str>,
) -> AppResult<Vec<SearchEntry>> {
    let (entries, _result) = ldap.search(base, scope, filter, attrs).await?.success()?;
    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

async fn search_single_entry(
    ldap: &mut Ldap,
    base: &str,
    scope: Scope,
    filter: &str,
    attrs: Vec<&str>,
) -> AppResult<SearchEntry> {
    let entries = search_entries(ldap, base, scope, filter, attrs).await?;
    ensure(
        entries.len() == 1,
        format!(
            "expected exactly one search result for {base}, got {}",
            entries.len()
        ),
    )?;
    Ok(entries.into_iter().next().expect("one entry"))
}

fn string_set<I, S>(values: I) -> HashSet<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    values.into_iter().map(Into::into).collect()
}

fn attr_values<'a>(entry: &'a SearchEntry, name: &str) -> AppResult<&'a Vec<String>> {
    attr_values_opt(entry, name)
        .ok_or_else(|| other_error(format!("missing attribute {name} in entry {}", entry.dn)))
}

fn attr_values_opt<'a>(entry: &'a SearchEntry, name: &str) -> Option<&'a Vec<String>> {
    entry
        .attrs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, values)| values)
}

fn format_dn_cn(dn: &str) -> AppResult<String> {
    dn.split_once('=')
        .and_then(|(_, rest)| rest.split_once(','))
        .map(|(cn, _)| cn.to_string())
        .ok_or_else(|| other_error(format!("failed to derive cn from {dn}")))
}

fn ensure(condition: bool, message: impl Into<String>) -> AppResult<()> {
    if condition {
        Ok(())
    } else {
        Err(other_error(message))
    }
}

fn other_error(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(io::Error::other(message.into()))
}
