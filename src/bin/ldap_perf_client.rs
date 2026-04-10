use std::collections::HashSet;
use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use ldap3::exop::{PasswordModify, WhoAmI, WhoAmIResp};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};
use serde::Serialize;

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";
const PASSWORD_MODIFY_OID: &str = "1.3.6.1.4.1.4203.1.11.1";
const WHOAMI_OID: &str = "1.3.6.1.4.1.4203.1.11.3";

#[derive(Debug, Parser)]
#[command(name = "ldap-perf-client")]
#[command(about = "Benchmark OpenDR LDAP operations on a single instance")]
struct Args {
    #[arg(long)]
    url: String,

    #[arg(long)]
    bind_dn: String,

    #[arg(long)]
    admin_whoami_expected: Option<String>,

    #[arg(long)]
    password: String,

    #[arg(long)]
    base_dn: String,

    #[arg(long, default_value_t = false)]
    starttls: bool,

    #[arg(long, default_value_t = false)]
    insecure: bool,

    #[arg(long, default_value_t = 1000)]
    preloaded_users: usize,

    #[arg(long, default_value_t = 200)]
    read_iterations: usize,

    #[arg(long, default_value_t = 100)]
    write_iterations: usize,

    #[arg(long, default_value_t = 10)]
    warmup_iterations: usize,

    #[arg(long, default_value = "perfbench")]
    name_prefix: String,

    #[arg(long, default_value = "InitialUserSecret123!")]
    user_password: String,

    #[arg(long, default_value = "UpdatedUserSecret456!")]
    updated_user_password: String,

    #[arg(long)]
    json_out: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct ScenarioDns {
    benchmark_root_dn: String,
    users_ou_dn: String,
    moved_ou_dn: String,
    writes_ou_dn: String,
    control_user_dn: String,
    control_user_uid: String,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    server_url: String,
    base_dn: String,
    total_elapsed_ms: f64,
    fixture: FixtureSummary,
    benchmarks: Vec<BenchmarkStats>,
}

#[derive(Debug, Serialize)]
struct FixtureSummary {
    benchmark_root_dn: String,
    users_ou_dn: String,
    moved_ou_dn: String,
    writes_ou_dn: String,
    preloaded_users: usize,
    records_before_setup: usize,
    records_after_setup: usize,
    records_after_benchmark: usize,
}

#[derive(Debug, Serialize)]
struct BenchmarkStats {
    operation: String,
    iterations: usize,
    elapsed_ms: f64,
    throughput_ops_per_sec: f64,
    min_ms: f64,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(err) = run(args).await {
        eprintln!("ldap_perf_client failed: {err}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> AppResult<()> {
    ensure(
        args.preloaded_users > 0,
        "--preloaded-users must be greater than zero",
    )?;
    ensure(
        args.read_iterations > 0,
        "--read-iterations must be greater than zero",
    )?;
    ensure(
        args.write_iterations > 0,
        "--write-iterations must be greater than zero",
    )?;

    let total_start = Instant::now();
    progress("connect.setup");
    let admin_whoami_expected = args
        .admin_whoami_expected
        .clone()
        .unwrap_or_else(|| format!("dn:{}", args.bind_dn));
    let dns = ScenarioDns {
        benchmark_root_dn: format!("ou={},{}", args.name_prefix, args.base_dn),
        users_ou_dn: format!("ou=users,ou={},{}", args.name_prefix, args.base_dn),
        moved_ou_dn: format!("ou=moved,ou={},{}", args.name_prefix, args.base_dn),
        writes_ou_dn: format!("ou=writes,ou={},{}", args.name_prefix, args.base_dn),
        control_user_dn: format!(
            "uid={}-user-000000,ou=users,ou={},{}",
            args.name_prefix, args.name_prefix, args.base_dn
        ),
        control_user_uid: format!("{}-user-000000", args.name_prefix),
    };

    let mut admin_setup = connect(&args.url, args.starttls, args.insecure).await?;
    simple_bind(&mut admin_setup, &args.bind_dn, &args.password).await?;
    progress("fixture.count.before_setup");
    let records_before_setup = count_entries(&mut admin_setup, &args.base_dn).await?;
    progress("fixture.tree");
    create_benchmark_tree(&mut admin_setup, &dns).await?;
    progress("fixture.preload");
    preload_users(
        &mut admin_setup,
        &dns,
        args.preloaded_users,
        &args.user_password,
        &args.name_prefix,
    )
    .await?;
    progress("fixture.count.after_setup");
    let records_after_setup = count_entries(&mut admin_setup, &args.base_dn).await?;
    admin_setup.unbind().await?;

    progress("connect.benchmark_clients");
    let mut anonymous_client = connect(&args.url, args.starttls, args.insecure).await?;
    let mut admin_ops = connect(&args.url, args.starttls, args.insecure).await?;
    simple_bind(&mut admin_ops, &args.bind_dn, &args.password).await?;
    let mut admin_bind_client = connect(&args.url, args.starttls, args.insecure).await?;
    let mut user_bind_client = connect(&args.url, args.starttls, args.insecure).await?;
    let mut password_client = connect(&args.url, args.starttls, args.insecure).await?;
    simple_bind(
        &mut password_client,
        &dns.control_user_dn,
        &args.user_password,
    )
    .await?;

    let mut benchmarks = Vec::new();

    progress("benchmark.root_dse");
    for _ in 0..args.warmup_iterations {
        verify_root_dse(&mut anonymous_client, &args.base_dn, false).await?;
    }
    let mut root_dse_latencies = Vec::with_capacity(args.read_iterations);
    let root_dse_started = Instant::now();
    for _ in 0..args.read_iterations {
        let started = Instant::now();
        verify_root_dse(&mut anonymous_client, &args.base_dn, false).await?;
        root_dse_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "root_dse_search",
        root_dse_latencies,
        root_dse_started,
    ));

    progress("benchmark.bind_admin");
    for _ in 0..args.warmup_iterations {
        simple_bind(&mut admin_bind_client, &args.bind_dn, &args.password).await?;
    }
    let mut admin_bind_latencies = Vec::with_capacity(args.read_iterations);
    let admin_bind_started = Instant::now();
    for _ in 0..args.read_iterations {
        let started = Instant::now();
        simple_bind(&mut admin_bind_client, &args.bind_dn, &args.password).await?;
        admin_bind_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "bind_admin",
        admin_bind_latencies,
        admin_bind_started,
    ));

    progress("benchmark.bind_fixture_user");
    for _ in 0..args.warmup_iterations {
        simple_bind(
            &mut user_bind_client,
            &dns.control_user_dn,
            &args.user_password,
        )
        .await?;
    }
    let mut user_bind_latencies = Vec::with_capacity(args.read_iterations);
    let user_bind_started = Instant::now();
    for _ in 0..args.read_iterations {
        let started = Instant::now();
        simple_bind(
            &mut user_bind_client,
            &dns.control_user_dn,
            &args.user_password,
        )
        .await?;
        user_bind_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "bind_fixture_user",
        user_bind_latencies,
        user_bind_started,
    ));

    progress("benchmark.whoami_admin");
    for _ in 0..args.warmup_iterations {
        verify_whoami(&mut admin_ops, &admin_whoami_expected).await?;
    }
    let mut whoami_latencies = Vec::with_capacity(args.read_iterations);
    let whoami_started = Instant::now();
    for _ in 0..args.read_iterations {
        let started = Instant::now();
        verify_whoami(&mut admin_ops, &admin_whoami_expected).await?;
        whoami_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "whoami_admin",
        whoami_latencies,
        whoami_started,
    ));

    progress("benchmark.search_base_fixture_user");
    for _ in 0..args.warmup_iterations {
        let entry = search_single_entry(
            &mut admin_ops,
            &dns.control_user_dn,
            Scope::Base,
            "(objectClass=inetOrgPerson)",
            vec!["uid", "cn", "sn", "mail", "description"],
        )
        .await?;
        ensure(
            entry.dn.eq_ignore_ascii_case(&dns.control_user_dn),
            "base search returned unexpected DN",
        )?;
    }
    let mut base_search_latencies = Vec::with_capacity(args.read_iterations);
    let base_search_started = Instant::now();
    for _ in 0..args.read_iterations {
        let started = Instant::now();
        let entry = search_single_entry(
            &mut admin_ops,
            &dns.control_user_dn,
            Scope::Base,
            "(objectClass=inetOrgPerson)",
            vec!["uid", "cn", "sn", "mail", "description"],
        )
        .await?;
        ensure(
            entry.dn.eq_ignore_ascii_case(&dns.control_user_dn),
            "base search returned unexpected DN",
        )?;
        base_search_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "search_base_fixture_user",
        base_search_latencies,
        base_search_started,
    ));

    progress("benchmark.search_subtree_fixture_users");
    for _ in 0..args.warmup_iterations {
        let entries = search_entries(
            &mut admin_ops,
            &dns.users_ou_dn,
            Scope::Subtree,
            "(objectClass=inetOrgPerson)",
            vec!["uid", "cn", "mail"],
        )
        .await?;
        ensure(
            entries.len() == args.preloaded_users,
            format!(
                "expected {} fixture users, got {}",
                args.preloaded_users,
                entries.len()
            ),
        )?;
    }
    let mut subtree_search_latencies = Vec::with_capacity(args.read_iterations);
    let subtree_search_started = Instant::now();
    for _ in 0..args.read_iterations {
        let started = Instant::now();
        let entries = search_entries(
            &mut admin_ops,
            &dns.users_ou_dn,
            Scope::Subtree,
            "(objectClass=inetOrgPerson)",
            vec!["uid", "cn", "mail"],
        )
        .await?;
        ensure(
            entries.len() == args.preloaded_users,
            format!(
                "expected {} fixture users, got {}",
                args.preloaded_users,
                entries.len()
            ),
        )?;
        subtree_search_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "search_subtree_fixture_users",
        subtree_search_latencies,
        subtree_search_started,
    ));

    progress("benchmark.compare_fixture_user_sn");
    for _ in 0..args.warmup_iterations {
        let equal = admin_ops
            .compare(&dns.control_user_dn, "sn", "BenchmarkUser0")
            .await?
            .equal()?;
        ensure(equal, "compare did not match expected surname")?;
    }
    let mut compare_latencies = Vec::with_capacity(args.read_iterations);
    let compare_started = Instant::now();
    for _ in 0..args.read_iterations {
        let started = Instant::now();
        let equal = admin_ops
            .compare(&dns.control_user_dn, "sn", "BenchmarkUser0")
            .await?
            .equal()?;
        ensure(equal, "compare did not match expected surname")?;
        compare_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "compare_fixture_user_sn",
        compare_latencies,
        compare_started,
    ));

    progress("benchmark.modify_fixture_user_description");
    let mut modify_fixture_latencies = Vec::with_capacity(args.write_iterations);
    let modify_fixture_started = Instant::now();
    for index in 0..args.write_iterations {
        let started = Instant::now();
        admin_ops
            .modify(
                &dns.control_user_dn,
                vec![Mod::Replace(
                    "description".to_string(),
                    string_set([format!("{} description {}", args.name_prefix, index)]),
                )],
            )
            .await?
            .success()?;
        modify_fixture_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "modify_fixture_user_description",
        modify_fixture_latencies,
        modify_fixture_started,
    ));

    progress("benchmark.password_modify_fixture_user");
    let mut current_password = args.user_password.clone();
    let mut next_password = args.updated_user_password.clone();
    let mut password_modify_latencies = Vec::with_capacity(args.write_iterations);
    let password_modify_started = Instant::now();
    for _ in 0..args.write_iterations {
        let started = Instant::now();
        password_client
            .extended(PasswordModify {
                user_id: Some(&dns.control_user_dn),
                old_pass: Some(&current_password),
                new_pass: Some(&next_password),
            })
            .await?
            .success()?;
        std::mem::swap(&mut current_password, &mut next_password);
        password_modify_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "password_modify_fixture_user",
        password_modify_latencies,
        password_modify_started,
    ));

    if current_password != args.user_password {
        password_client
            .extended(PasswordModify {
                user_id: Some(&dns.control_user_dn),
                old_pass: Some(&current_password),
                new_pass: Some(&args.user_password),
            })
            .await?
            .success()?;
    }
    password_client.unbind().await?;

    progress("benchmark.add_entries");
    let mut write_dns = Vec::with_capacity(args.write_iterations);

    let mut add_latencies = Vec::with_capacity(args.write_iterations);
    let add_started = Instant::now();
    for index in 0..args.write_iterations {
        let uid = format!("{}-write-{index:06}", args.name_prefix);
        let dn = format!("uid={uid},{}", dns.writes_ou_dn);
        let started = Instant::now();
        admin_ops
            .add(
                &dn,
                vec![
                    (
                        "objectClass".to_string(),
                        string_set(["top", "person", "organizationalPerson", "inetOrgPerson"]),
                    ),
                    ("uid".to_string(), string_set([uid.clone()])),
                    (
                        "cn".to_string(),
                        string_set([format!("Write User {index}")]),
                    ),
                    ("sn".to_string(), string_set([format!("WriteUser{index}")])),
                    (
                        "mail".to_string(),
                        string_set([format!("{uid}@example.com")]),
                    ),
                ],
            )
            .await?
            .success()?;
        write_dns.push(dn);
        add_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "add_entries",
        add_latencies,
        add_started,
    ));

    progress("benchmark.modify_entries");
    let mut modify_entries_latencies = Vec::with_capacity(args.write_iterations);
    let modify_entries_started = Instant::now();
    for index in 0..args.write_iterations {
        let dn = write_dns
            .get(index)
            .ok_or_else(|| other_error("missing write DN for modify benchmark"))?
            .clone();
        let started = Instant::now();
        admin_ops
            .modify(
                &dn,
                vec![Mod::Replace(
                    "description".to_string(),
                    string_set([format!("Modified in iteration {index}")]),
                )],
            )
            .await?
            .success()?;
        modify_entries_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "modify_entries",
        modify_entries_latencies,
        modify_entries_started,
    ));

    progress("benchmark.modifydn_entries");
    let mut modifydn_latencies = Vec::with_capacity(args.write_iterations);
    let modifydn_started = Instant::now();
    for index in 0..args.write_iterations {
        let current_dn = write_dns
            .get(index)
            .ok_or_else(|| other_error("missing write DN for modifydn benchmark"))?
            .clone();
        let new_uid = format!("{}-moved-{index:06}", args.name_prefix);
        let new_dn = format!("uid={new_uid},{}", dns.moved_ou_dn);
        let started = Instant::now();
        admin_ops
            .modifydn(
                &current_dn,
                &format!("uid={new_uid}"),
                true,
                Some(&dns.moved_ou_dn),
            )
            .await?
            .success()?;
        write_dns[index] = new_dn;
        modifydn_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "modifydn_entries",
        modifydn_latencies,
        modifydn_started,
    ));

    progress("benchmark.delete_entries");
    let mut delete_latencies = Vec::with_capacity(args.write_iterations);
    let delete_started = Instant::now();
    for index in 0..args.write_iterations {
        let dn = write_dns
            .get(index)
            .ok_or_else(|| other_error("missing write DN for delete benchmark"))?
            .clone();
        let started = Instant::now();
        admin_ops.delete(&dn).await?.success()?;
        delete_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
    }
    benchmarks.push(build_benchmark_stats(
        "delete_entries",
        delete_latencies,
        delete_started,
    ));

    progress("fixture.count.after_benchmark");
    let records_after_benchmark = count_entries(&mut admin_ops, &args.base_dn).await?;

    anonymous_client.unbind().await?;
    admin_bind_client.unbind().await?;
    user_bind_client.unbind().await?;
    admin_ops.unbind().await?;

    let report = BenchmarkReport {
        server_url: args.url.clone(),
        base_dn: args.base_dn.clone(),
        total_elapsed_ms: elapsed_ms(total_start.elapsed().as_secs_f64()),
        fixture: FixtureSummary {
            benchmark_root_dn: dns.benchmark_root_dn.clone(),
            users_ou_dn: dns.users_ou_dn.clone(),
            moved_ou_dn: dns.moved_ou_dn.clone(),
            writes_ou_dn: dns.writes_ou_dn.clone(),
            preloaded_users: args.preloaded_users,
            records_before_setup,
            records_after_setup,
            records_after_benchmark,
        },
        benchmarks,
    };

    print_human_summary(&report);

    if let Some(path) = args.json_out {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, json)?;
    }

    Ok(())
}

async fn connect(url: &str, starttls: bool, insecure: bool) -> AppResult<Ldap> {
    let mut settings = LdapConnSettings::new();
    if starttls {
        settings = settings.set_starttls(true);
    }
    if insecure {
        settings = settings.set_no_tls_verify(true);
    }
    let (conn, ldap) = LdapConnAsync::with_settings(settings, url).await?;
    ldap3::drive!(conn);
    Ok(ldap)
}

async fn simple_bind(ldap: &mut Ldap, bind_dn: &str, password: &str) -> AppResult<()> {
    ldap.simple_bind(bind_dn, password).await?.success()?;
    Ok(())
}

async fn create_benchmark_tree(ldap: &mut Ldap, dns: &ScenarioDns) -> AppResult<()> {
    add_organizational_unit(ldap, &dns.benchmark_root_dn).await?;
    add_organizational_unit(ldap, &dns.users_ou_dn).await?;
    add_organizational_unit(ldap, &dns.moved_ou_dn).await?;
    add_organizational_unit(ldap, &dns.writes_ou_dn).await?;
    Ok(())
}

async fn preload_users(
    ldap: &mut Ldap,
    dns: &ScenarioDns,
    count: usize,
    password: &str,
    name_prefix: &str,
) -> AppResult<()> {
    for index in 0..count {
        let uid = format!("{name_prefix}-user-{index:06}");
        let dn = format!("uid={uid},{}", dns.users_ou_dn);
        ldap.add(
            &dn,
            vec![
                (
                    "objectClass".to_string(),
                    string_set(["top", "person", "organizationalPerson", "inetOrgPerson"]),
                ),
                ("uid".to_string(), string_set([uid.clone()])),
                (
                    "cn".to_string(),
                    string_set([format!("Benchmark User {index}")]),
                ),
                (
                    "sn".to_string(),
                    string_set([format!("BenchmarkUser{index}")]),
                ),
                (
                    "description".to_string(),
                    string_set([format!("Benchmark fixture user {index}")]),
                ),
                (
                    "mail".to_string(),
                    string_set([format!("{uid}@example.com")]),
                ),
                ("userPassword".to_string(), string_set([password])),
            ],
        )
        .await?
        .success()?;
    }

    ensure(
        dns.control_user_uid == format!("{name_prefix}-user-000000"),
        "control user UID does not match preload naming pattern",
    )?;
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

async fn verify_root_dse(ldap: &mut Ldap, base_dn: &str, expect_starttls: bool) -> AppResult<()> {
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
    if expect_starttls {
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
    Ok(())
}

async fn verify_whoami(ldap: &mut Ldap, expected_authzid: &str) -> AppResult<()> {
    let (exop, _result) = ldap.extended(WhoAmI).await?.success()?;
    let whoami: WhoAmIResp = exop.parse();
    ensure(
        whoami.authzid.eq_ignore_ascii_case(expected_authzid),
        format!(
            "WhoAmI mismatch: expected {expected_authzid}, got {}",
            whoami.authzid
        ),
    )?;
    Ok(())
}

async fn count_entries(ldap: &mut Ldap, base_dn: &str) -> AppResult<usize> {
    Ok(search_entries(
        ldap,
        base_dn,
        Scope::Subtree,
        "(objectClass=*)",
        vec!["objectClass"],
    )
    .await?
    .len())
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

fn build_benchmark_stats(
    operation: &str,
    latencies_ms: Vec<f64>,
    total_start: Instant,
) -> BenchmarkStats {
    let iterations = latencies_ms.len();
    let elapsed_ms_total = elapsed_ms(total_start.elapsed().as_secs_f64());
    let throughput_ops_per_sec = if elapsed_ms_total > 0.0 {
        iterations as f64 / (elapsed_ms_total / 1000.0)
    } else {
        0.0
    };

    BenchmarkStats {
        operation: operation.to_string(),
        iterations,
        elapsed_ms: elapsed_ms_total,
        throughput_ops_per_sec,
        min_ms: percentile(&latencies_ms, 0.0),
        mean_ms: latencies_ms.iter().sum::<f64>() / iterations as f64,
        p50_ms: percentile(&latencies_ms, 0.50),
        p95_ms: percentile(&latencies_ms, 0.95),
        p99_ms: percentile(&latencies_ms, 0.99),
        max_ms: percentile(&latencies_ms, 1.0),
    }
}

fn print_human_summary(report: &BenchmarkReport) {
    println!("# LDAP Single-Instance Perf Summary");
    println!();
    println!("## Fixture");
    println!("- Server URL: `{}`", report.server_url);
    println!("- Base DN: `{}`", report.base_dn);
    println!("- Benchmark root: `{}`", report.fixture.benchmark_root_dn);
    println!("- Users OU: `{}`", report.fixture.users_ou_dn);
    println!("- Moved OU: `{}`", report.fixture.moved_ou_dn);
    println!("- Writes OU: `{}`", report.fixture.writes_ou_dn);
    println!("- Preloaded users: {}", report.fixture.preloaded_users);
    println!(
        "- Records before setup: {}",
        report.fixture.records_before_setup
    );
    println!(
        "- Records after setup: {}",
        report.fixture.records_after_setup
    );
    println!(
        "- Records after benchmark: {}",
        report.fixture.records_after_benchmark
    );
    println!("- Total runtime: {:.3} ms", report.total_elapsed_ms);
    println!();
    println!("## Benchmarks");
    println!();
    println!("| Operation | Iterations | Mean ms | P50 ms | P95 ms | P99 ms | Max ms | Throughput ops/s |");
    println!("|---|---:|---:|---:|---:|---:|---:|---:|");
    for benchmark in &report.benchmarks {
        println!(
            "| {} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.2} |",
            benchmark.operation,
            benchmark.iterations,
            benchmark.mean_ms,
            benchmark.p50_ms,
            benchmark.p95_ms,
            benchmark.p99_ms,
            benchmark.max_ms,
            benchmark.throughput_ops_per_sec,
        );
    }
}

fn percentile(samples: &[f64], quantile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("no NaN latencies"));

    let index = if quantile <= 0.0 {
        0
    } else if quantile >= 1.0 {
        sorted.len() - 1
    } else {
        ((sorted.len() as f64 * quantile).ceil() as usize).saturating_sub(1)
    };
    sorted[index]
}

fn elapsed_ms(seconds: f64) -> f64 {
    seconds * 1000.0
}

fn progress(step: &str) {
    if std::env::var_os("LDAP_PERF_PROGRESS").is_some() {
        eprintln!("progress: {step}");
    }
}

fn string_set<I, S>(values: I) -> HashSet<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    values.into_iter().map(Into::into).collect()
}

fn attr_values<'a>(entry: &'a SearchEntry, name: &str) -> AppResult<&'a Vec<String>> {
    entry
        .attrs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, values)| values)
        .ok_or_else(|| other_error(format!("missing attribute {name} in entry {}", entry.dn)))
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
