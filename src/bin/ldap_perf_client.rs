use std::collections::HashSet;
use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use clap::Parser;
use ldap_parser::ldap::{ProtocolOp as ParserProtocolOp, ResultCode as ParserResultCode};
use ldap_parser::parse_ldap_messages;
use ldap3::exop::{PasswordModify, WhoAmI, WhoAmIResp};
use ldap3::result::LdapError;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};
use rasn::der;
use rasn_ldap::{
    AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest,
    ExtendedRequest as RasnExtendedRequest, LdapMessage as RasnLdapMessage,
    ProtocolOp as RasnProtocolOp, SaslCredentials as RasnSaslCredentials,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use url::Url;

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";
const PASSWORD_MODIFY_OID: &str = "1.3.6.1.4.1.4203.1.11.1";
const WHOAMI_OID: &str = "1.3.6.1.4.1.4203.1.11.3";
const BENCHMARK_INDEX_AUXILIARY_CLASS: &str = "benchmarkIndexedObject";
const BENCHMARK_ORDER_ATTRIBUTE: &str = "benchmarkOrder";

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

    #[arg(long, default_value_t = 1)]
    preload_workers: usize,

    #[arg(long, default_value_t = false)]
    reuse_fixture: bool,

    #[arg(long, default_value_t = false)]
    skip_full_counts: bool,

    #[arg(long, default_value_t = false)]
    skip_subtree_search_benchmark: bool,

    #[arg(long, default_value_t = false)]
    skip_serial_index_benchmarks: bool,

    #[arg(long, default_value_t = 200)]
    read_iterations: usize,

    #[arg(long, default_value_t = 100)]
    write_iterations: usize,

    #[arg(long, default_value_t = 10)]
    warmup_iterations: usize,

    #[arg(long, default_value_t = false)]
    index_benchmark: bool,

    #[arg(long, default_value_t = false)]
    sasl_plain_benchmark: bool,

    #[arg(long, default_value = "dn")]
    sasl_plain_authcid_format: String,

    #[arg(long, default_value_t = false)]
    skip_sasl_plain_admin_benchmark: bool,

    #[arg(long, default_value = "")]
    concurrent_index_search_clients: String,

    #[arg(long, default_value_t = 20)]
    concurrent_index_search_iterations: usize,

    #[arg(long, default_value_t = 1)]
    concurrent_index_search_warmup_iterations: usize,

    #[arg(long, default_value_t = 5000)]
    concurrent_index_search_operation_timeout_ms: u64,

    #[arg(long, default_value = "")]
    concurrent_bind_clients: String,

    #[arg(long, default_value_t = 20)]
    concurrent_bind_iterations: usize,

    #[arg(long, default_value_t = 1)]
    concurrent_bind_warmup_iterations: usize,

    #[arg(long, default_value_t = 5000)]
    concurrent_bind_operation_timeout_ms: u64,

    #[arg(long, default_value_t = 100)]
    concurrent_bind_valid_percent: u8,

    #[arg(long, default_value_t = 0)]
    concurrent_bind_wrong_password_percent: u8,

    #[arg(long, default_value_t = 80)]
    concurrent_bind_hot_user_percent: u8,

    #[arg(long, default_value_t = 1)]
    concurrent_bind_hot_user_count: usize,

    #[arg(long, default_value_t = false)]
    ldapcon_style_benchmark: bool,

    #[arg(long, default_value = "")]
    ldapcon_clients: String,

    #[arg(long, default_value_t = 100)]
    ldapcon_iterations: usize,

    #[arg(long, default_value_t = 5)]
    ldapcon_warmup_iterations: usize,

    #[arg(long, default_value_t = 10000)]
    ldapcon_operation_timeout_ms: u64,

    #[arg(long, default_value_t = 20)]
    ldapcon_mixed_write_percent: u8,

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
    concurrency: usize,
    successes: usize,
    failures: usize,
    failure_rate_percent: f64,
    elapsed_ms: f64,
    throughput_ops_per_sec: f64,
    success_throughput_ops_per_sec: f64,
    min_ms: f64,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
}

#[derive(Debug, Clone)]
struct IndexSearchSpec {
    operation: &'static str,
    base_dn: String,
    filter: String,
    expected_count: usize,
    expected_dn: Option<String>,
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
        args.preload_workers > 0,
        "--preload-workers must be greater than zero",
    )?;
    ensure(
        args.read_iterations > 0,
        "--read-iterations must be greater than zero",
    )?;
    ensure(
        args.write_iterations > 0,
        "--write-iterations must be greater than zero",
    )?;
    let concurrent_bind_clients = parse_concurrent_bind_clients(&args.concurrent_bind_clients)?;
    let concurrent_index_search_clients =
        parse_concurrent_index_search_clients(&args.concurrent_index_search_clients)?;
    let ldapcon_clients = parse_ldapcon_clients(&args.ldapcon_clients)?;
    let run_index_benchmarks = args.index_benchmark || !concurrent_index_search_clients.is_empty();
    let sasl_plain_authcid_format =
        parse_sasl_plain_authcid_format(&args.sasl_plain_authcid_format)?;
    if args.sasl_plain_benchmark {
        ensure(
            args.starttls || args.url.starts_with("ldaps://"),
            "--sasl-plain-benchmark requires --starttls or an ldaps:// URL",
        )?;
    }
    if !concurrent_bind_clients.is_empty() {
        ensure(
            args.concurrent_bind_iterations > 0,
            "--concurrent-bind-iterations must be greater than zero when --concurrent-bind-clients is set",
        )?;
        ensure(
            args.concurrent_bind_operation_timeout_ms > 0,
            "--concurrent-bind-operation-timeout-ms must be greater than zero when --concurrent-bind-clients is set",
        )?;
        ensure(
            args.concurrent_bind_hot_user_count > 0,
            "--concurrent-bind-hot-user-count must be greater than zero when --concurrent-bind-clients is set",
        )?;
        ensure(
            u16::from(args.concurrent_bind_valid_percent)
                + u16::from(args.concurrent_bind_wrong_password_percent)
                <= 100,
            "--concurrent-bind-valid-percent plus --concurrent-bind-wrong-password-percent must be <= 100",
        )?;
        ensure(
            args.concurrent_bind_hot_user_percent <= 100,
            "--concurrent-bind-hot-user-percent must be <= 100",
        )?;
    }
    if !concurrent_index_search_clients.is_empty() {
        ensure(
            args.concurrent_index_search_iterations > 0,
            "--concurrent-index-search-iterations must be greater than zero when --concurrent-index-search-clients is set",
        )?;
        ensure(
            args.concurrent_index_search_warmup_iterations > 0,
            "--concurrent-index-search-warmup-iterations must be greater than zero when --concurrent-index-search-clients is set",
        )?;
        ensure(
            args.concurrent_index_search_operation_timeout_ms > 0,
            "--concurrent-index-search-operation-timeout-ms must be greater than zero when --concurrent-index-search-clients is set",
        )?;
    }
    if args.ldapcon_style_benchmark {
        ensure(
            !ldapcon_clients.is_empty(),
            "--ldapcon-clients must be set when --ldapcon-style-benchmark is enabled",
        )?;
        ensure(
            args.ldapcon_iterations > 0,
            "--ldapcon-iterations must be greater than zero",
        )?;
        ensure(
            args.ldapcon_operation_timeout_ms > 0,
            "--ldapcon-operation-timeout-ms must be greater than zero",
        )?;
        ensure(
            args.ldapcon_mixed_write_percent <= 100,
            "--ldapcon-mixed-write-percent must be <= 100",
        )?;
    }

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
    let skip_full_counts = args.skip_full_counts || args.reuse_fixture;
    let records_before_setup = if skip_full_counts {
        progress("fixture.count.before_setup.skipped");
        expected_fixture_record_count(args.preloaded_users)
    } else {
        progress("fixture.count.before_setup");
        count_entries(&mut admin_setup, &args.base_dn).await?
    };
    let records_after_setup = if args.reuse_fixture {
        progress("fixture.reuse");
        ensure_existing_fixture(&mut admin_setup, &dns, args.preloaded_users).await?;
        if skip_full_counts {
            progress("fixture.count.after_setup.skipped");
            expected_fixture_record_count(args.preloaded_users)
        } else {
            progress("fixture.count.after_setup");
            count_entries(&mut admin_setup, &args.base_dn).await?
        }
    } else {
        progress("fixture.tree");
        create_benchmark_tree(&mut admin_setup, &dns).await?;
        progress("fixture.preload");
        preload_users(&mut admin_setup, &dns, &args, run_index_benchmarks).await?;
        if skip_full_counts {
            progress("fixture.count.after_setup.skipped");
            expected_fixture_record_count(args.preloaded_users)
        } else {
            progress("fixture.count.after_setup");
            count_entries(&mut admin_setup, &args.base_dn).await?
        }
    };
    admin_setup.unbind().await?;

    let mut benchmarks = Vec::new();

    if args.ldapcon_style_benchmark {
        progress("benchmark.ldapcon_style");
        for concurrency in &ldapcon_clients {
            progress(&format!("benchmark.ldapcon_search.c{concurrency}"));
            benchmarks.push(run_ldapcon_search_benchmark(&args, &dns, *concurrency).await?);

            progress(&format!("benchmark.ldapcon_auth.c{concurrency}"));
            benchmarks.push(run_ldapcon_auth_benchmark(&args, &dns, *concurrency).await?);

            progress(&format!("benchmark.ldapcon_modify.c{concurrency}"));
            benchmarks.push(run_ldapcon_modify_benchmark(&args, &dns, *concurrency).await?);

            progress(&format!("benchmark.ldapcon_mixed.c{concurrency}"));
            benchmarks.extend(run_ldapcon_mixed_benchmark(&args, &dns, *concurrency).await?);
        }
    }

    if !concurrent_bind_clients.is_empty() {
        progress("benchmark.concurrent_bind_fixture_users");
        for concurrency in &concurrent_bind_clients {
            progress(&format!(
                "benchmark.concurrent_bind_fixture_users.c{concurrency}"
            ));
            benchmarks.push(run_concurrent_bind_benchmark(&args, &dns, *concurrency).await?);
        }
        if args.sasl_plain_benchmark {
            progress("benchmark.concurrent_sasl_plain_bind_fixture_users");
            for concurrency in &concurrent_bind_clients {
                progress(&format!(
                    "benchmark.concurrent_sasl_plain_bind_fixture_users.c{concurrency}"
                ));
                benchmarks.push(
                    run_concurrent_sasl_plain_bind_benchmark(
                        &args,
                        &dns,
                        *concurrency,
                        sasl_plain_authcid_format,
                    )
                    .await?,
                );
            }
        }
    }

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

    if args.sasl_plain_benchmark {
        if !args.skip_sasl_plain_admin_benchmark {
            progress("benchmark.sasl_plain_bind_admin");
            let admin_authcid = sasl_plain_authcid(&args.bind_dn, sasl_plain_authcid_format)?;
            let mut admin_sasl_bind_client =
                RawLdapClient::connect(&args.url, args.starttls, args.insecure).await?;
            for _ in 0..args.warmup_iterations {
                admin_sasl_bind_client
                    .sasl_plain_bind(&args.bind_dn, &admin_authcid, &args.password)
                    .await?;
            }
            let mut admin_sasl_bind_latencies = Vec::with_capacity(args.read_iterations);
            let admin_sasl_bind_started = Instant::now();
            for _ in 0..args.read_iterations {
                let started = Instant::now();
                admin_sasl_bind_client
                    .sasl_plain_bind(&args.bind_dn, &admin_authcid, &args.password)
                    .await?;
                admin_sasl_bind_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
            }
            benchmarks.push(build_benchmark_stats(
                "sasl_plain_bind_admin",
                admin_sasl_bind_latencies,
                admin_sasl_bind_started,
            ));
        }

        progress("benchmark.sasl_plain_bind_fixture_user");
        let user_authcid = sasl_plain_authcid(&dns.control_user_dn, sasl_plain_authcid_format)?;
        let mut user_sasl_bind_client =
            RawLdapClient::connect(&args.url, args.starttls, args.insecure).await?;
        for _ in 0..args.warmup_iterations {
            user_sasl_bind_client
                .sasl_plain_bind(&dns.control_user_dn, &user_authcid, &args.user_password)
                .await?;
        }
        let mut user_sasl_bind_latencies = Vec::with_capacity(args.read_iterations);
        let user_sasl_bind_started = Instant::now();
        for _ in 0..args.read_iterations {
            let started = Instant::now();
            user_sasl_bind_client
                .sasl_plain_bind(&dns.control_user_dn, &user_authcid, &args.user_password)
                .await?;
            user_sasl_bind_latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
        }
        benchmarks.push(build_benchmark_stats(
            "sasl_plain_bind_fixture_user",
            user_sasl_bind_latencies,
            user_sasl_bind_started,
        ));
    }

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
            &format!("(uid={})", dns.control_user_uid),
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
            &format!("(uid={})", dns.control_user_uid),
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

    if args.skip_subtree_search_benchmark {
        progress("benchmark.search_subtree_fixture_users.skipped");
    } else {
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
    }

    if run_index_benchmarks {
        if args.skip_serial_index_benchmarks {
            progress("benchmark.index_searches.serial.skipped");
        } else {
            progress("benchmark.index_searches");
            benchmarks.extend(run_index_search_benchmarks(&mut admin_ops, &args, &dns).await?);
        }

        for concurrency in &concurrent_index_search_clients {
            progress(&format!("benchmark.concurrent_index_search.c{concurrency}"));
            benchmarks
                .push(run_concurrent_index_search_benchmark(&args, &dns, *concurrency).await?);
        }
    }

    progress("benchmark.compare_fixture_user_sn");
    for _ in 0..args.warmup_iterations {
        let equal = admin_ops
            .compare(&dns.control_user_dn, "sn", "BenchmarkUser000000")
            .await?
            .equal()?;
        ensure(equal, "compare did not match expected surname")?;
    }
    let mut compare_latencies = Vec::with_capacity(args.read_iterations);
    let compare_started = Instant::now();
    for _ in 0..args.read_iterations {
        let started = Instant::now();
        let equal = admin_ops
            .compare(&dns.control_user_dn, "sn", "BenchmarkUser000000")
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

    let records_after_benchmark = if skip_full_counts {
        progress("fixture.count.after_benchmark.skipped");
        expected_fixture_record_count(args.preloaded_users)
    } else {
        progress("fixture.count.after_benchmark");
        count_entries(&mut admin_ops, &args.base_dn).await?
    };

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

    if let Some(path) = args.json_out {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, json)?;
    }
    print_human_summary(&report);

    best_effort_unbind("anonymous_client", anonymous_client).await;
    best_effort_unbind("admin_bind_client", admin_bind_client).await;
    best_effort_unbind("user_bind_client", user_bind_client).await;
    best_effort_unbind("password_client", password_client).await;
    best_effort_unbind("admin_ops", admin_ops).await;

    Ok(())
}

async fn best_effort_unbind(label: &str, mut ldap: Ldap) {
    match tokio::time::timeout(Duration::from_secs(2), ldap.unbind()).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => eprintln!("warning: failed to unbind {label}: {err}"),
        Err(_) => eprintln!("warning: timed out unbinding {label}"),
    }
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

#[derive(Debug)]
struct RawLdapClient {
    stream: RawLdapStream,
    next_message_id: u32,
}

impl RawLdapClient {
    async fn connect(url: &str, starttls: bool, insecure: bool) -> AppResult<Self> {
        let target = LdapTarget::parse(url)?;
        let tcp_stream = TcpStream::connect((target.host.as_str(), target.port)).await?;
        let mut stream = RawLdapStream::Plain(tcp_stream);
        let mut next_message_id = 1_u32;

        if target.ldaps {
            let tls_stream = tls_connect(
                stream
                    .into_plain()
                    .ok_or_else(|| other_error("ldaps connection started in TLS state"))?,
                &target.host,
                insecure,
            )
            .await?;
            stream = RawLdapStream::Tls(Box::new(tls_stream));
        } else if starttls {
            let message = encode_starttls_request(next_message_id)?;
            next_message_id += 1;
            let response = send_ldap_message(&mut stream, &message).await?;
            ensure(
                extended_response_code(&response)? == ParserResultCode::Success,
                "StartTLS request failed",
            )?;
            let tls_stream = tls_connect(
                stream
                    .into_plain()
                    .ok_or_else(|| other_error("StartTLS upgrade requires a plain stream"))?,
                &target.host,
                insecure,
            )
            .await?;
            stream = RawLdapStream::Tls(Box::new(tls_stream));
        }

        Ok(Self {
            stream,
            next_message_id,
        })
    }

    async fn sasl_plain_bind(
        &mut self,
        bind_dn: &str,
        authcid: &str,
        password: &str,
    ) -> AppResult<()> {
        let message_id = self.next_message_id();
        let message = encode_sasl_plain_bind_request(message_id, bind_dn, authcid, password)?;
        let response = send_ldap_message(&mut self.stream, &message).await?;
        let result_code = bind_response_code(&response)?;
        ensure(
            result_code == ParserResultCode::Success,
            format!("SASL PLAIN bind failed for {bind_dn}: {result_code:?}"),
        )?;
        Ok(())
    }

    async fn sasl_plain_bind_matches_expectation(
        &mut self,
        bind_dn: &str,
        authcid: &str,
        password: &str,
        expectation: BindExpectation,
    ) -> bool {
        let message_id = self.next_message_id();
        let Ok(message) = encode_sasl_plain_bind_request(message_id, bind_dn, authcid, password)
        else {
            return false;
        };
        let Ok(response) = send_ldap_message(&mut self.stream, &message).await else {
            return false;
        };
        let Ok(result_code) = bind_response_code(&response) else {
            return false;
        };

        match result_code {
            ParserResultCode::Success => expectation == BindExpectation::Valid,
            ParserResultCode::InvalidCredentials => expectation != BindExpectation::Valid,
            _ => false,
        }
    }

    fn next_message_id(&mut self) -> u32 {
        let message_id = self.next_message_id;
        self.next_message_id = if self.next_message_id == i32::MAX as u32 {
            1
        } else {
            self.next_message_id + 1
        };
        message_id
    }
}

#[derive(Debug)]
struct LdapTarget {
    host: String,
    port: u16,
    ldaps: bool,
}

impl LdapTarget {
    fn parse(raw_url: &str) -> AppResult<Self> {
        let url = Url::parse(raw_url)?;
        let ldaps = match url.scheme() {
            "ldap" => false,
            "ldaps" => true,
            scheme => {
                return Err(other_error(format!(
                    "unsupported LDAP URL scheme for SASL benchmark: {scheme}"
                )));
            }
        };
        let host = url
            .host_str()
            .ok_or_else(|| other_error(format!("LDAP URL missing host: {raw_url}")))?
            .to_string();
        let port = url.port().unwrap_or(if ldaps { 636 } else { 389 });
        Ok(Self { host, port, ldaps })
    }
}

#[derive(Debug)]
enum RawLdapStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl RawLdapStream {
    fn into_plain(self) -> Option<TcpStream> {
        match self {
            RawLdapStream::Plain(stream) => Some(stream),
            RawLdapStream::Tls(_) => None,
        }
    }
}

impl AsyncRead for RawLdapStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RawLdapStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            RawLdapStream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RawLdapStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            RawLdapStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            RawLdapStream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RawLdapStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            RawLdapStream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RawLdapStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            RawLdapStream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

async fn tls_connect(
    stream: TcpStream,
    host: &str,
    insecure: bool,
) -> AppResult<TlsStream<TcpStream>> {
    let config = if insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth()
    };
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = raw_tls_server_name(host, insecure)?;
    Ok(connector.connect(server_name, stream).await?)
}

fn raw_tls_server_name(host: &str, insecure: bool) -> AppResult<ServerName<'static>> {
    let name = if insecure && host.parse::<std::net::IpAddr>().is_ok() {
        "localhost"
    } else {
        host
    };
    ServerName::try_from(name.to_string())
        .map_err(|err| other_error(format!("invalid TLS server name {name:?}: {err}")))
}

fn encode_starttls_request(message_id: u32) -> AppResult<Vec<u8>> {
    let request = RasnExtendedRequest {
        request_name: STARTTLS_OID.as_bytes().to_vec().into(),
        request_value: None,
    };
    let message = RasnLdapMessage::new(message_id, RasnProtocolOp::ExtendedReq(request));
    der::encode(&message)
        .map_err(|err| other_error(format!("failed to encode StartTLS request: {err:?}")))
}

fn encode_sasl_plain_bind_request(
    message_id: u32,
    bind_dn: &str,
    authcid: &str,
    password: &str,
) -> AppResult<Vec<u8>> {
    let mut credentials = Vec::with_capacity(authcid.len() + password.len() + 2);
    credentials.push(0);
    credentials.extend_from_slice(authcid.as_bytes());
    credentials.push(0);
    credentials.extend_from_slice(password.as_bytes());

    let bind_request = RasnBindRequest::new(
        3,
        bind_dn.as_bytes().to_vec().into(),
        RasnAuthChoice::Sasl(RasnSaslCredentials::new(
            b"PLAIN".to_vec().into(),
            Some(credentials.into()),
        )),
    );
    let message = RasnLdapMessage::new(message_id, RasnProtocolOp::BindRequest(bind_request));
    der::encode(&message)
        .map_err(|err| other_error(format!("failed to encode SASL PLAIN bind request: {err:?}")))
}

async fn send_ldap_message<S>(stream: &mut S, message: &[u8]) -> AppResult<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(message).await?;
    stream.flush().await?;
    read_ldap_response(stream).await
}

async fn read_ldap_response<S>(stream: &mut S) -> AppResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut buf = vec![0_u8; 4096];

    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(bytes_read)) => {
                response.extend_from_slice(&buf[..bytes_read]);
                if parse_ldap_messages(&response).is_ok() {
                    break;
                }
            }
            Ok(Err(err)) => return Err(Box::new(err)),
            Err(_) if parse_ldap_messages(&response).is_ok() => break,
            Err(_) => return Err(other_error("timed out waiting for LDAP response")),
        }
    }

    ensure(
        !response.is_empty(),
        "LDAP server closed connection without a response",
    )?;
    Ok(response)
}

fn bind_response_code(response: &[u8]) -> AppResult<ParserResultCode> {
    let (_, messages) = parse_ldap_messages(response)
        .map_err(|err| other_error(format!("failed to parse bind response: {err:?}")))?;
    ensure(messages.len() == 1, "expected exactly one bind response")?;
    match &messages[0].protocol_op {
        ParserProtocolOp::BindResponse(bind_response) => Ok(bind_response.result.result_code),
        other => Err(other_error(format!(
            "unexpected SASL bind response: {other:?}"
        ))),
    }
}

fn extended_response_code(response: &[u8]) -> AppResult<ParserResultCode> {
    let (_, messages) = parse_ldap_messages(response)
        .map_err(|err| other_error(format!("failed to parse extended response: {err:?}")))?;
    ensure(
        messages.len() == 1,
        "expected exactly one extended response",
    )?;
    match &messages[0].protocol_op {
        ParserProtocolOp::ExtendedResponse(response) => Ok(response.result.result_code),
        other => Err(other_error(format!(
            "unexpected extended response: {other:?}"
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindExpectation {
    Valid,
    WrongPassword,
    UnknownDn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaslPlainAuthcidFormat {
    Dn,
    RdnValue,
}

#[derive(Debug)]
struct ConcurrentBindWorkerResult {
    latencies_ms: Vec<f64>,
    successes: usize,
    failures: usize,
}

async fn run_concurrent_bind_benchmark(
    args: &Args,
    dns: &ScenarioDns,
    concurrency: usize,
) -> AppResult<BenchmarkStats> {
    ensure(
        concurrency > 0,
        "--concurrent-bind-clients values must be greater than zero",
    )?;

    let expected_attempts = concurrency * args.concurrent_bind_iterations;
    let operation_timeout = Duration::from_millis(args.concurrent_bind_operation_timeout_ms);
    let per_concurrency_timeout = operation_timeout.saturating_mul(
        (args.concurrent_bind_warmup_iterations + args.concurrent_bind_iterations + 3) as u32,
    );
    let (ready_tx, mut ready_rx) = mpsc::channel(concurrency);
    let (start_tx, start_rx) = watch::channel(false);
    let mut handles = Vec::with_capacity(concurrency);

    for client_index in 0..concurrency {
        let ready_tx = ready_tx.clone();
        let mut start_rx = start_rx.clone();
        let url = args.url.clone();
        let starttls = args.starttls;
        let insecure = args.insecure;
        let users_ou_dn = dns.users_ou_dn.clone();
        let name_prefix = args.name_prefix.clone();
        let password = args.user_password.clone();
        let wrong_password = format!("{}-wrong", args.user_password);
        let preloaded_users = args.preloaded_users;
        let iterations = args.concurrent_bind_iterations;
        let warmup_iterations = args.concurrent_bind_warmup_iterations;
        let valid_percent = args.concurrent_bind_valid_percent;
        let wrong_password_percent = args.concurrent_bind_wrong_password_percent;
        let hot_user_percent = args.concurrent_bind_hot_user_percent;
        let hot_user_count = args.concurrent_bind_hot_user_count;

        handles.push(tokio::spawn(async move {
            let mut ldap =
                match connect_with_timeout(&url, starttls, insecure, operation_timeout).await {
                    Ok(ldap) => ldap,
                    Err(_) => {
                        let _ = ready_tx.send(()).await;
                        return ConcurrentBindWorkerResult {
                            latencies_ms: Vec::new(),
                            successes: 0,
                            failures: iterations,
                        };
                    }
                };

            for warmup in 0..warmup_iterations {
                let global_attempt = client_index * iterations + warmup;
                let dn = fixture_bind_dn(
                    global_attempt,
                    preloaded_users,
                    hot_user_count,
                    hot_user_percent,
                    &name_prefix,
                    &users_ou_dn,
                );
                if simple_bind_with_timeout(&mut ldap, &dn, &password, operation_timeout)
                    .await
                    .is_err()
                {
                    let _ = ready_tx.send(()).await;
                    let _ = ldap.unbind().await;
                    return ConcurrentBindWorkerResult {
                        latencies_ms: Vec::new(),
                        successes: 0,
                        failures: iterations,
                    };
                }
            }

            let _ = ready_tx.send(()).await;
            while !*start_rx.borrow() {
                if start_rx.changed().await.is_err() {
                    let _ = ldap.unbind().await;
                    return ConcurrentBindWorkerResult {
                        latencies_ms: Vec::new(),
                        successes: 0,
                        failures: iterations,
                    };
                }
            }

            let mut latencies_ms = Vec::with_capacity(iterations);
            let mut successes = 0;
            let mut failures = 0;
            for iteration in 0..iterations {
                let global_attempt = client_index * iterations + iteration;
                let expectation =
                    bind_expectation(global_attempt, valid_percent, wrong_password_percent);
                let dn = match expectation {
                    BindExpectation::UnknownDn => {
                        format!("uid={name_prefix}-missing-{global_attempt:06},{users_ou_dn}")
                    }
                    BindExpectation::Valid | BindExpectation::WrongPassword => fixture_bind_dn(
                        global_attempt,
                        preloaded_users,
                        hot_user_count,
                        hot_user_percent,
                        &name_prefix,
                        &users_ou_dn,
                    ),
                };
                let bind_password = match expectation {
                    BindExpectation::Valid => password.as_str(),
                    BindExpectation::WrongPassword | BindExpectation::UnknownDn => {
                        wrong_password.as_str()
                    }
                };

                let started = Instant::now();
                if bind_matches_expectation_with_timeout(
                    &mut ldap,
                    &dn,
                    bind_password,
                    expectation,
                    operation_timeout,
                )
                .await
                {
                    successes += 1;
                } else {
                    failures += 1;
                }
                latencies_ms.push(elapsed_ms(started.elapsed().as_secs_f64()));
            }

            let _ = ldap.unbind().await;
            ConcurrentBindWorkerResult {
                latencies_ms,
                successes,
                failures,
            }
        }));
    }

    drop(ready_tx);
    let timeout_started = Instant::now();
    let ready_deadline = tokio::time::Instant::now() + per_concurrency_timeout;
    for _ in 0..concurrency {
        match tokio::time::timeout_at(ready_deadline, ready_rx.recv()).await {
            Ok(Some(())) => {}
            Ok(None) => break,
            Err(_) => {
                for handle in &handles {
                    handle.abort();
                }
                return Ok(build_benchmark_stats_with_counts(
                    &format!("concurrent_bind_fixture_users_c{concurrency}"),
                    Vec::new(),
                    timeout_started,
                    expected_attempts,
                    0,
                    expected_attempts,
                    concurrency,
                ));
            }
        }
    }

    let total_started = Instant::now();
    let _ = start_tx.send(true);

    let mut latencies_ms = Vec::with_capacity(expected_attempts);
    let mut successes = 0;
    let mut failures = 0;
    let collect_deadline = tokio::time::Instant::now() + per_concurrency_timeout;
    for handle_index in 0..handles.len() {
        match tokio::time::timeout_at(collect_deadline, &mut handles[handle_index]).await {
            Ok(Ok(result)) => {
                latencies_ms.extend(result.latencies_ms);
                successes += result.successes;
                failures += result.failures;
            }
            Ok(Err(_)) => {
                failures += args.concurrent_bind_iterations;
            }
            Err(_) => {
                for handle in handles.iter().skip(handle_index) {
                    handle.abort();
                    failures += args.concurrent_bind_iterations;
                }
                break;
            }
        }
    }

    Ok(build_benchmark_stats_with_counts(
        &format!("concurrent_bind_fixture_users_c{concurrency}"),
        latencies_ms,
        total_started,
        expected_attempts,
        successes,
        failures,
        concurrency,
    ))
}

async fn run_concurrent_sasl_plain_bind_benchmark(
    args: &Args,
    dns: &ScenarioDns,
    concurrency: usize,
    authcid_format: SaslPlainAuthcidFormat,
) -> AppResult<BenchmarkStats> {
    ensure(
        concurrency > 0,
        "--concurrent-bind-clients values must be greater than zero",
    )?;

    let expected_attempts = concurrency * args.concurrent_bind_iterations;
    let operation_timeout = Duration::from_millis(args.concurrent_bind_operation_timeout_ms);
    let per_concurrency_timeout = operation_timeout.saturating_mul(
        (args.concurrent_bind_warmup_iterations + args.concurrent_bind_iterations + 3) as u32,
    );
    let (ready_tx, mut ready_rx) = mpsc::channel(concurrency);
    let (start_tx, start_rx) = watch::channel(false);
    let mut handles = Vec::with_capacity(concurrency);

    for client_index in 0..concurrency {
        let ready_tx = ready_tx.clone();
        let mut start_rx = start_rx.clone();
        let url = args.url.clone();
        let starttls = args.starttls;
        let insecure = args.insecure;
        let users_ou_dn = dns.users_ou_dn.clone();
        let name_prefix = args.name_prefix.clone();
        let password = args.user_password.clone();
        let wrong_password = format!("{}-wrong", args.user_password);
        let preloaded_users = args.preloaded_users;
        let iterations = args.concurrent_bind_iterations;
        let warmup_iterations = args.concurrent_bind_warmup_iterations;
        let valid_percent = args.concurrent_bind_valid_percent;
        let wrong_password_percent = args.concurrent_bind_wrong_password_percent;
        let hot_user_percent = args.concurrent_bind_hot_user_percent;
        let hot_user_count = args.concurrent_bind_hot_user_count;

        handles.push(tokio::spawn(async move {
            let mut ldap =
                match connect_raw_ldap_with_timeout(&url, starttls, insecure, operation_timeout)
                    .await
                {
                    Ok(ldap) => ldap,
                    Err(_) => {
                        let _ = ready_tx.send(()).await;
                        return ConcurrentBindWorkerResult {
                            latencies_ms: Vec::new(),
                            successes: 0,
                            failures: iterations,
                        };
                    }
                };

            for warmup in 0..warmup_iterations {
                let global_attempt = client_index * iterations + warmup;
                let dn = fixture_bind_dn(
                    global_attempt,
                    preloaded_users,
                    hot_user_count,
                    hot_user_percent,
                    &name_prefix,
                    &users_ou_dn,
                );
                let authcid = match sasl_plain_authcid(&dn, authcid_format) {
                    Ok(authcid) => authcid,
                    Err(_) => {
                        let _ = ready_tx.send(()).await;
                        return ConcurrentBindWorkerResult {
                            latencies_ms: Vec::new(),
                            successes: 0,
                            failures: iterations,
                        };
                    }
                };
                if sasl_plain_bind_with_timeout(
                    &mut ldap,
                    &dn,
                    &authcid,
                    &password,
                    operation_timeout,
                )
                .await
                .is_err()
                {
                    let _ = ready_tx.send(()).await;
                    return ConcurrentBindWorkerResult {
                        latencies_ms: Vec::new(),
                        successes: 0,
                        failures: iterations,
                    };
                }
            }

            let _ = ready_tx.send(()).await;
            while !*start_rx.borrow() {
                if start_rx.changed().await.is_err() {
                    return ConcurrentBindWorkerResult {
                        latencies_ms: Vec::new(),
                        successes: 0,
                        failures: iterations,
                    };
                }
            }

            let mut latencies_ms = Vec::with_capacity(iterations);
            let mut successes = 0;
            let mut failures = 0;
            for iteration in 0..iterations {
                let global_attempt = client_index * iterations + iteration;
                let expectation =
                    bind_expectation(global_attempt, valid_percent, wrong_password_percent);
                let dn = match expectation {
                    BindExpectation::UnknownDn => {
                        format!("uid={name_prefix}-missing-{global_attempt:06},{users_ou_dn}")
                    }
                    BindExpectation::Valid | BindExpectation::WrongPassword => fixture_bind_dn(
                        global_attempt,
                        preloaded_users,
                        hot_user_count,
                        hot_user_percent,
                        &name_prefix,
                        &users_ou_dn,
                    ),
                };
                let bind_password = match expectation {
                    BindExpectation::Valid => password.as_str(),
                    BindExpectation::WrongPassword | BindExpectation::UnknownDn => {
                        wrong_password.as_str()
                    }
                };
                let authcid = match sasl_plain_authcid(&dn, authcid_format) {
                    Ok(authcid) => authcid,
                    Err(_) => {
                        failures += 1;
                        latencies_ms.push(0.0);
                        continue;
                    }
                };

                let started = Instant::now();
                if sasl_plain_bind_matches_expectation_with_timeout(
                    &mut ldap,
                    &dn,
                    &authcid,
                    bind_password,
                    expectation,
                    operation_timeout,
                )
                .await
                {
                    successes += 1;
                } else {
                    failures += 1;
                }
                latencies_ms.push(elapsed_ms(started.elapsed().as_secs_f64()));
            }

            ConcurrentBindWorkerResult {
                latencies_ms,
                successes,
                failures,
            }
        }));
    }

    drop(ready_tx);
    let timeout_started = Instant::now();
    let ready_deadline = tokio::time::Instant::now() + per_concurrency_timeout;
    for _ in 0..concurrency {
        match tokio::time::timeout_at(ready_deadline, ready_rx.recv()).await {
            Ok(Some(())) => {}
            Ok(None) => break,
            Err(_) => {
                for handle in &handles {
                    handle.abort();
                }
                return Ok(build_benchmark_stats_with_counts(
                    &format!("concurrent_sasl_plain_bind_fixture_users_c{concurrency}"),
                    Vec::new(),
                    timeout_started,
                    expected_attempts,
                    0,
                    expected_attempts,
                    concurrency,
                ));
            }
        }
    }

    let total_started = Instant::now();
    let _ = start_tx.send(true);

    let mut latencies_ms = Vec::with_capacity(expected_attempts);
    let mut successes = 0;
    let mut failures = 0;
    let collect_deadline = tokio::time::Instant::now() + per_concurrency_timeout;
    for handle_index in 0..handles.len() {
        match tokio::time::timeout_at(collect_deadline, &mut handles[handle_index]).await {
            Ok(Ok(result)) => {
                latencies_ms.extend(result.latencies_ms);
                successes += result.successes;
                failures += result.failures;
            }
            Ok(Err(_)) => {
                failures += args.concurrent_bind_iterations;
            }
            Err(_) => {
                for handle in handles.iter().skip(handle_index) {
                    handle.abort();
                    failures += args.concurrent_bind_iterations;
                }
                break;
            }
        }
    }

    Ok(build_benchmark_stats_with_counts(
        &format!("concurrent_sasl_plain_bind_fixture_users_c{concurrency}"),
        latencies_ms,
        total_started,
        expected_attempts,
        successes,
        failures,
        concurrency,
    ))
}

#[derive(Debug, Clone, Copy)]
enum LdapConOperation {
    Search,
    Auth,
    Modify,
}

impl LdapConOperation {
    fn label(self) -> &'static str {
        match self {
            Self::Search => "ldapcon_search",
            Self::Auth => "ldapcon_auth",
            Self::Modify => "ldapcon_modify",
        }
    }
}

#[derive(Debug)]
struct LdapConWorkerResult {
    latencies_ms: Vec<f64>,
    successes: usize,
    failures: usize,
}

async fn run_ldapcon_search_benchmark(
    args: &Args,
    dns: &ScenarioDns,
    concurrency: usize,
) -> AppResult<BenchmarkStats> {
    run_ldapcon_single_operation_benchmark(args, dns, concurrency, LdapConOperation::Search).await
}

async fn run_ldapcon_auth_benchmark(
    args: &Args,
    dns: &ScenarioDns,
    concurrency: usize,
) -> AppResult<BenchmarkStats> {
    run_ldapcon_single_operation_benchmark(args, dns, concurrency, LdapConOperation::Auth).await
}

async fn run_ldapcon_modify_benchmark(
    args: &Args,
    dns: &ScenarioDns,
    concurrency: usize,
) -> AppResult<BenchmarkStats> {
    run_ldapcon_single_operation_benchmark(args, dns, concurrency, LdapConOperation::Modify).await
}

async fn run_ldapcon_single_operation_benchmark(
    args: &Args,
    dns: &ScenarioDns,
    concurrency: usize,
    operation: LdapConOperation,
) -> AppResult<BenchmarkStats> {
    ensure(
        concurrency > 0,
        "--ldapcon-clients values must be greater than zero",
    )?;

    let expected_attempts = concurrency * args.ldapcon_iterations;
    let operation_timeout = Duration::from_millis(args.ldapcon_operation_timeout_ms);
    let per_concurrency_timeout = operation_timeout
        .saturating_mul((args.ldapcon_warmup_iterations + args.ldapcon_iterations + 3) as u32);
    let (ready_tx, mut ready_rx) = mpsc::channel(concurrency);
    let (start_tx, start_rx) = watch::channel(false);
    let mut handles = Vec::with_capacity(concurrency);

    for client_index in 0..concurrency {
        let ready_tx = ready_tx.clone();
        let mut start_rx = start_rx.clone();
        let url = args.url.clone();
        let starttls = args.starttls;
        let insecure = args.insecure;
        let bind_dn = args.bind_dn.clone();
        let admin_password = args.password.clone();
        let user_password = args.user_password.clone();
        let name_prefix = args.name_prefix.clone();
        let users_ou_dn = dns.users_ou_dn.clone();
        let preloaded_users = args.preloaded_users;
        let iterations = args.ldapcon_iterations;
        let warmup_iterations = args.ldapcon_warmup_iterations;

        handles.push(tokio::spawn(async move {
            let mut ldap =
                match connect_with_timeout(&url, starttls, insecure, operation_timeout).await {
                    Ok(ldap) => ldap,
                    Err(_) => {
                        let _ = ready_tx.send(()).await;
                        return LdapConWorkerResult {
                            latencies_ms: Vec::new(),
                            successes: 0,
                            failures: iterations,
                        };
                    }
                };

            if !matches!(operation, LdapConOperation::Auth)
                && simple_bind_with_timeout(&mut ldap, &bind_dn, &admin_password, operation_timeout)
                    .await
                    .is_err()
            {
                let _ = ready_tx.send(()).await;
                let _ = ldap.unbind().await;
                return LdapConWorkerResult {
                    latencies_ms: Vec::new(),
                    successes: 0,
                    failures: iterations,
                };
            }

            for warmup in 0..warmup_iterations {
                let global_attempt = client_index * (iterations + warmup_iterations) + warmup;
                if !run_ldapcon_operation_once(
                    &mut ldap,
                    operation,
                    global_attempt,
                    preloaded_users,
                    &name_prefix,
                    &users_ou_dn,
                    &user_password,
                    operation_timeout,
                )
                .await
                {
                    let _ = ready_tx.send(()).await;
                    let _ = ldap.unbind().await;
                    return LdapConWorkerResult {
                        latencies_ms: Vec::new(),
                        successes: 0,
                        failures: iterations,
                    };
                }
            }

            let _ = ready_tx.send(()).await;
            while !*start_rx.borrow() {
                if start_rx.changed().await.is_err() {
                    let _ = ldap.unbind().await;
                    return LdapConWorkerResult {
                        latencies_ms: Vec::new(),
                        successes: 0,
                        failures: iterations,
                    };
                }
            }

            let mut latencies_ms = Vec::with_capacity(iterations);
            let mut successes = 0;
            let mut failures = 0;
            for iteration in 0..iterations {
                let global_attempt = client_index * iterations + iteration;
                let started = Instant::now();
                if run_ldapcon_operation_once(
                    &mut ldap,
                    operation,
                    global_attempt,
                    preloaded_users,
                    &name_prefix,
                    &users_ou_dn,
                    &user_password,
                    operation_timeout,
                )
                .await
                {
                    successes += 1;
                } else {
                    failures += 1;
                }
                latencies_ms.push(elapsed_ms(started.elapsed().as_secs_f64()));
            }

            let _ = ldap.unbind().await;
            LdapConWorkerResult {
                latencies_ms,
                successes,
                failures,
            }
        }));
    }

    drop(ready_tx);
    let timeout_started = Instant::now();
    let ready_deadline = tokio::time::Instant::now() + per_concurrency_timeout;
    for _ in 0..concurrency {
        match tokio::time::timeout_at(ready_deadline, ready_rx.recv()).await {
            Ok(Some(())) => {}
            Ok(None) => break,
            Err(_) => {
                for handle in &handles {
                    handle.abort();
                }
                return Ok(build_benchmark_stats_with_counts(
                    &format!("{}_c{concurrency}", operation.label()),
                    Vec::new(),
                    timeout_started,
                    expected_attempts,
                    0,
                    expected_attempts,
                    concurrency,
                ));
            }
        }
    }

    let total_started = Instant::now();
    let _ = start_tx.send(true);

    let mut latencies_ms = Vec::with_capacity(expected_attempts);
    let mut successes = 0;
    let mut failures = 0;
    let collect_deadline = tokio::time::Instant::now() + per_concurrency_timeout;
    for handle_index in 0..handles.len() {
        match tokio::time::timeout_at(collect_deadline, &mut handles[handle_index]).await {
            Ok(Ok(result)) => {
                latencies_ms.extend(result.latencies_ms);
                successes += result.successes;
                failures += result.failures;
            }
            Ok(Err(_)) => {
                failures += args.ldapcon_iterations;
            }
            Err(_) => {
                for handle in handles.iter().skip(handle_index) {
                    handle.abort();
                    failures += args.ldapcon_iterations;
                }
                break;
            }
        }
    }

    Ok(build_benchmark_stats_with_counts(
        &format!("{}_c{concurrency}", operation.label()),
        latencies_ms,
        total_started,
        expected_attempts,
        successes,
        failures,
        concurrency,
    ))
}

#[derive(Debug)]
struct LdapConMixedWorkerResult {
    search_latencies_ms: Vec<f64>,
    modify_latencies_ms: Vec<f64>,
    search_successes: usize,
    search_failures: usize,
    modify_successes: usize,
    modify_failures: usize,
}

async fn run_ldapcon_mixed_benchmark(
    args: &Args,
    dns: &ScenarioDns,
    concurrency: usize,
) -> AppResult<Vec<BenchmarkStats>> {
    ensure(
        concurrency > 0,
        "--ldapcon-clients values must be greater than zero",
    )?;

    let operation_timeout = Duration::from_millis(args.ldapcon_operation_timeout_ms);
    let per_concurrency_timeout = operation_timeout
        .saturating_mul((args.ldapcon_warmup_iterations + args.ldapcon_iterations + 3) as u32);
    let expected_attempts = concurrency * args.ldapcon_iterations;
    let (expected_search_attempts, expected_modify_attempts) =
        ldapcon_mixed_expected_counts(expected_attempts, args.ldapcon_mixed_write_percent);
    let (ready_tx, mut ready_rx) = mpsc::channel(concurrency);
    let (start_tx, start_rx) = watch::channel(false);
    let mut handles = Vec::with_capacity(concurrency);

    for client_index in 0..concurrency {
        let ready_tx = ready_tx.clone();
        let mut start_rx = start_rx.clone();
        let url = args.url.clone();
        let starttls = args.starttls;
        let insecure = args.insecure;
        let bind_dn = args.bind_dn.clone();
        let admin_password = args.password.clone();
        let name_prefix = args.name_prefix.clone();
        let users_ou_dn = dns.users_ou_dn.clone();
        let preloaded_users = args.preloaded_users;
        let iterations = args.ldapcon_iterations;
        let warmup_iterations = args.ldapcon_warmup_iterations;
        let write_percent = args.ldapcon_mixed_write_percent;

        handles.push(tokio::spawn(async move {
            let mut ldap =
                match connect_with_timeout(&url, starttls, insecure, operation_timeout).await {
                    Ok(ldap) => ldap,
                    Err(_) => {
                        let _ = ready_tx.send(()).await;
                        let (search_failures, modify_failures) =
                            ldapcon_mixed_expected_counts(iterations, write_percent);
                        return LdapConMixedWorkerResult {
                            search_latencies_ms: Vec::new(),
                            modify_latencies_ms: Vec::new(),
                            search_successes: 0,
                            search_failures,
                            modify_successes: 0,
                            modify_failures,
                        };
                    }
                };

            if simple_bind_with_timeout(&mut ldap, &bind_dn, &admin_password, operation_timeout)
                .await
                .is_err()
            {
                let _ = ready_tx.send(()).await;
                let _ = ldap.unbind().await;
                let (search_failures, modify_failures) =
                    ldapcon_mixed_expected_counts(iterations, write_percent);
                return LdapConMixedWorkerResult {
                    search_latencies_ms: Vec::new(),
                    modify_latencies_ms: Vec::new(),
                    search_successes: 0,
                    search_failures,
                    modify_successes: 0,
                    modify_failures,
                };
            }

            for warmup in 0..warmup_iterations {
                let global_attempt = client_index * (iterations + warmup_iterations) + warmup;
                let operation = ldapcon_mixed_operation(global_attempt, write_percent);
                if !run_ldapcon_operation_once(
                    &mut ldap,
                    operation,
                    global_attempt,
                    preloaded_users,
                    &name_prefix,
                    &users_ou_dn,
                    "",
                    operation_timeout,
                )
                .await
                {
                    let _ = ready_tx.send(()).await;
                    let _ = ldap.unbind().await;
                    let (search_failures, modify_failures) =
                        ldapcon_mixed_expected_counts(iterations, write_percent);
                    return LdapConMixedWorkerResult {
                        search_latencies_ms: Vec::new(),
                        modify_latencies_ms: Vec::new(),
                        search_successes: 0,
                        search_failures,
                        modify_successes: 0,
                        modify_failures,
                    };
                }
            }

            let _ = ready_tx.send(()).await;
            while !*start_rx.borrow() {
                if start_rx.changed().await.is_err() {
                    let _ = ldap.unbind().await;
                    let (search_failures, modify_failures) =
                        ldapcon_mixed_expected_counts(iterations, write_percent);
                    return LdapConMixedWorkerResult {
                        search_latencies_ms: Vec::new(),
                        modify_latencies_ms: Vec::new(),
                        search_successes: 0,
                        search_failures,
                        modify_successes: 0,
                        modify_failures,
                    };
                }
            }

            let mut search_latencies_ms = Vec::new();
            let mut modify_latencies_ms = Vec::new();
            let mut search_successes = 0;
            let mut search_failures = 0;
            let mut modify_successes = 0;
            let mut modify_failures = 0;
            for iteration in 0..iterations {
                let global_attempt = client_index * iterations + iteration;
                let operation = ldapcon_mixed_operation(global_attempt, write_percent);
                let started = Instant::now();
                let succeeded = run_ldapcon_operation_once(
                    &mut ldap,
                    operation,
                    global_attempt,
                    preloaded_users,
                    &name_prefix,
                    &users_ou_dn,
                    "",
                    operation_timeout,
                )
                .await;
                let latency = elapsed_ms(started.elapsed().as_secs_f64());
                match operation {
                    LdapConOperation::Search => {
                        search_latencies_ms.push(latency);
                        if succeeded {
                            search_successes += 1;
                        } else {
                            search_failures += 1;
                        }
                    }
                    LdapConOperation::Modify => {
                        modify_latencies_ms.push(latency);
                        if succeeded {
                            modify_successes += 1;
                        } else {
                            modify_failures += 1;
                        }
                    }
                    LdapConOperation::Auth => {}
                }
            }

            let _ = ldap.unbind().await;
            LdapConMixedWorkerResult {
                search_latencies_ms,
                modify_latencies_ms,
                search_successes,
                search_failures,
                modify_successes,
                modify_failures,
            }
        }));
    }

    drop(ready_tx);
    let timeout_started = Instant::now();
    let ready_deadline = tokio::time::Instant::now() + per_concurrency_timeout;
    for _ in 0..concurrency {
        match tokio::time::timeout_at(ready_deadline, ready_rx.recv()).await {
            Ok(Some(())) => {}
            Ok(None) => break,
            Err(_) => {
                for handle in &handles {
                    handle.abort();
                }
                let elapsed = elapsed_ms(timeout_started.elapsed().as_secs_f64());
                return Ok(vec![
                    build_benchmark_stats_with_elapsed(
                        &format!("ldapcon_mixed_search_c{concurrency}"),
                        Vec::new(),
                        elapsed,
                        expected_search_attempts,
                        0,
                        expected_search_attempts,
                        concurrency,
                    ),
                    build_benchmark_stats_with_elapsed(
                        &format!("ldapcon_mixed_modify_c{concurrency}"),
                        Vec::new(),
                        elapsed,
                        expected_modify_attempts,
                        0,
                        expected_modify_attempts,
                        concurrency,
                    ),
                ]);
            }
        }
    }

    let total_started = Instant::now();
    let _ = start_tx.send(true);

    let mut search_latencies_ms = Vec::with_capacity(expected_search_attempts);
    let mut modify_latencies_ms = Vec::with_capacity(expected_modify_attempts);
    let mut search_successes = 0;
    let mut search_failures = 0;
    let mut modify_successes = 0;
    let mut modify_failures = 0;
    let collect_deadline = tokio::time::Instant::now() + per_concurrency_timeout;
    for handle_index in 0..handles.len() {
        match tokio::time::timeout_at(collect_deadline, &mut handles[handle_index]).await {
            Ok(Ok(result)) => {
                search_latencies_ms.extend(result.search_latencies_ms);
                modify_latencies_ms.extend(result.modify_latencies_ms);
                search_successes += result.search_successes;
                search_failures += result.search_failures;
                modify_successes += result.modify_successes;
                modify_failures += result.modify_failures;
            }
            Ok(Err(_)) | Err(_) => {
                if handle_index < handles.len() {
                    for handle in handles.iter().skip(handle_index) {
                        handle.abort();
                    }
                }
                let remaining_workers = handles.len() - handle_index;
                let remaining_attempts = remaining_workers * args.ldapcon_iterations;
                let (remaining_search_failures, remaining_modify_failures) =
                    ldapcon_mixed_expected_counts(
                        remaining_attempts,
                        args.ldapcon_mixed_write_percent,
                    );
                search_failures += remaining_search_failures;
                modify_failures += remaining_modify_failures;
                break;
            }
        }
    }

    let elapsed_ms_total = elapsed_ms(total_started.elapsed().as_secs_f64());
    Ok(vec![
        build_benchmark_stats_with_elapsed(
            &format!("ldapcon_mixed_search_c{concurrency}"),
            search_latencies_ms,
            elapsed_ms_total,
            search_successes + search_failures,
            search_successes,
            search_failures,
            concurrency,
        ),
        build_benchmark_stats_with_elapsed(
            &format!("ldapcon_mixed_modify_c{concurrency}"),
            modify_latencies_ms,
            elapsed_ms_total,
            modify_successes + modify_failures,
            modify_successes,
            modify_failures,
            concurrency,
        ),
    ])
}

async fn run_ldapcon_operation_once(
    ldap: &mut Ldap,
    operation: LdapConOperation,
    global_attempt: usize,
    preloaded_users: usize,
    name_prefix: &str,
    users_ou_dn: &str,
    user_password: &str,
    operation_timeout: Duration,
) -> bool {
    let user_index = global_attempt % preloaded_users;
    let uid = ldapcon_user_uid(name_prefix, user_index);
    let dn = ldapcon_user_dn(&uid, users_ou_dn);

    match operation {
        LdapConOperation::Search => {
            ldapcon_search_matches_with_timeout(ldap, users_ou_dn, &uid, &dn, operation_timeout)
                .await
        }
        LdapConOperation::Auth => {
            simple_bind_with_timeout(ldap, &dn, user_password, operation_timeout)
                .await
                .is_ok()
        }
        LdapConOperation::Modify => {
            ldapcon_modify_description_with_timeout(
                ldap,
                &dn,
                &format!("LDAPCon modify attempt {global_attempt}"),
                operation_timeout,
            )
            .await
        }
    }
}

async fn ldapcon_search_matches_with_timeout(
    ldap: &mut Ldap,
    users_ou_dn: &str,
    uid: &str,
    expected_dn: &str,
    operation_timeout: Duration,
) -> bool {
    match tokio::time::timeout(
        operation_timeout,
        search_single_entry(
            ldap,
            users_ou_dn,
            Scope::Subtree,
            &format!("(uid={uid})"),
            vec!["uid", "cn", "sn", "mail"],
        ),
    )
    .await
    {
        Ok(Ok(entry)) => entry.dn.eq_ignore_ascii_case(expected_dn),
        _ => false,
    }
}

async fn ldapcon_modify_description_with_timeout(
    ldap: &mut Ldap,
    dn: &str,
    description: &str,
    operation_timeout: Duration,
) -> bool {
    match tokio::time::timeout(
        operation_timeout,
        ldap.modify(
            dn,
            vec![Mod::Replace(
                "description".to_string(),
                string_set([description.to_string()]),
            )],
        ),
    )
    .await
    {
        Ok(Ok(result)) => result.success().is_ok(),
        _ => false,
    }
}

fn ldapcon_mixed_operation(global_attempt: usize, write_percent: u8) -> LdapConOperation {
    let bucket = ((global_attempt % 100) * 37 + 17) % 100;
    if bucket < usize::from(write_percent) {
        LdapConOperation::Modify
    } else {
        LdapConOperation::Search
    }
}

fn ldapcon_mixed_expected_counts(attempts: usize, write_percent: u8) -> (usize, usize) {
    let mut search_attempts = 0;
    let mut modify_attempts = 0;
    for attempt in 0..attempts {
        match ldapcon_mixed_operation(attempt, write_percent) {
            LdapConOperation::Search => search_attempts += 1,
            LdapConOperation::Modify => modify_attempts += 1,
            LdapConOperation::Auth => {}
        }
    }
    (search_attempts, modify_attempts)
}

fn ldapcon_user_uid(name_prefix: &str, user_index: usize) -> String {
    format!("{name_prefix}-user-{user_index:06}")
}

fn ldapcon_user_dn(uid: &str, users_ou_dn: &str) -> String {
    format!("uid={uid},{users_ou_dn}")
}

async fn run_index_search_benchmarks(
    ldap: &mut Ldap,
    args: &Args,
    dns: &ScenarioDns,
) -> AppResult<Vec<BenchmarkStats>> {
    let mut benchmarks = Vec::new();
    for spec in index_search_specs(args, dns) {
        progress(&format!("benchmark.{}", spec.operation));
        for _ in 0..args.warmup_iterations {
            verify_index_search(ldap, &spec).await?;
        }

        let mut latencies = Vec::with_capacity(args.read_iterations);
        let started_all = Instant::now();
        for _ in 0..args.read_iterations {
            let started = Instant::now();
            verify_index_search(ldap, &spec).await?;
            latencies.push(elapsed_ms(started.elapsed().as_secs_f64()));
        }
        benchmarks.push(build_benchmark_stats(
            spec.operation,
            latencies,
            started_all,
        ));
    }

    Ok(benchmarks)
}

#[derive(Debug)]
struct ConcurrentIndexSearchWorkerResult {
    latencies_ms: Vec<f64>,
    successes: usize,
    failures: usize,
}

async fn run_concurrent_index_search_benchmark(
    args: &Args,
    dns: &ScenarioDns,
    concurrency: usize,
) -> AppResult<BenchmarkStats> {
    ensure(
        concurrency > 0,
        "--concurrent-index-search-clients values must be greater than zero",
    )?;

    let specs = concurrent_index_search_specs(args, dns);
    let expected_attempts = concurrency * args.concurrent_index_search_iterations;
    let operation_timeout =
        Duration::from_millis(args.concurrent_index_search_operation_timeout_ms);
    let per_concurrency_timeout = operation_timeout.saturating_mul(
        (args.concurrent_index_search_warmup_iterations
            + args.concurrent_index_search_iterations
            + 3) as u32,
    );
    let (ready_tx, mut ready_rx) = mpsc::channel(concurrency);
    let (start_tx, start_rx) = watch::channel(false);
    let mut handles = Vec::with_capacity(concurrency);

    for client_index in 0..concurrency {
        let ready_tx = ready_tx.clone();
        let mut start_rx = start_rx.clone();
        let url = args.url.clone();
        let starttls = args.starttls;
        let insecure = args.insecure;
        let bind_dn = args.bind_dn.clone();
        let password = args.password.clone();
        let specs = specs.clone();
        let iterations = args.concurrent_index_search_iterations;
        let warmup_iterations = args.concurrent_index_search_warmup_iterations;

        handles.push(tokio::spawn(async move {
            let mut ldap =
                match connect_with_timeout(&url, starttls, insecure, operation_timeout).await {
                    Ok(ldap) => ldap,
                    Err(_) => {
                        let _ = ready_tx.send(()).await;
                        return ConcurrentIndexSearchWorkerResult {
                            latencies_ms: Vec::new(),
                            successes: 0,
                            failures: iterations,
                        };
                    }
                };

            if simple_bind_with_timeout(&mut ldap, &bind_dn, &password, operation_timeout)
                .await
                .is_err()
            {
                let _ = ready_tx.send(()).await;
                let _ = ldap.unbind().await;
                return ConcurrentIndexSearchWorkerResult {
                    latencies_ms: Vec::new(),
                    successes: 0,
                    failures: iterations,
                };
            }

            for warmup in 0..warmup_iterations {
                let spec = &specs[(client_index + warmup) % specs.len()];
                if !index_search_matches_with_timeout(&mut ldap, spec, operation_timeout).await {
                    let _ = ready_tx.send(()).await;
                    let _ = ldap.unbind().await;
                    return ConcurrentIndexSearchWorkerResult {
                        latencies_ms: Vec::new(),
                        successes: 0,
                        failures: iterations,
                    };
                }
            }

            let _ = ready_tx.send(()).await;
            while !*start_rx.borrow() {
                if start_rx.changed().await.is_err() {
                    let _ = ldap.unbind().await;
                    return ConcurrentIndexSearchWorkerResult {
                        latencies_ms: Vec::new(),
                        successes: 0,
                        failures: iterations,
                    };
                }
            }

            let mut latencies_ms = Vec::with_capacity(iterations);
            let mut successes = 0;
            let mut failures = 0;
            for iteration in 0..iterations {
                let spec = &specs[(client_index * iterations + iteration) % specs.len()];
                let started = Instant::now();
                if index_search_matches_with_timeout(&mut ldap, spec, operation_timeout).await {
                    successes += 1;
                } else {
                    failures += 1;
                }
                latencies_ms.push(elapsed_ms(started.elapsed().as_secs_f64()));
            }

            let _ = ldap.unbind().await;
            ConcurrentIndexSearchWorkerResult {
                latencies_ms,
                successes,
                failures,
            }
        }));
    }

    drop(ready_tx);
    let timeout_started = Instant::now();
    let ready_deadline = tokio::time::Instant::now() + per_concurrency_timeout;
    for _ in 0..concurrency {
        match tokio::time::timeout_at(ready_deadline, ready_rx.recv()).await {
            Ok(Some(())) => {}
            Ok(None) => break,
            Err(_) => {
                for handle in &handles {
                    handle.abort();
                }
                return Ok(build_benchmark_stats_with_counts(
                    &format!("concurrent_index_search_c{concurrency}"),
                    Vec::new(),
                    timeout_started,
                    expected_attempts,
                    0,
                    expected_attempts,
                    concurrency,
                ));
            }
        }
    }

    let total_started = Instant::now();
    let _ = start_tx.send(true);

    let mut latencies_ms = Vec::with_capacity(expected_attempts);
    let mut successes = 0;
    let mut failures = 0;
    let collect_deadline = tokio::time::Instant::now() + per_concurrency_timeout;
    for handle_index in 0..handles.len() {
        match tokio::time::timeout_at(collect_deadline, &mut handles[handle_index]).await {
            Ok(Ok(result)) => {
                latencies_ms.extend(result.latencies_ms);
                successes += result.successes;
                failures += result.failures;
            }
            Ok(Err(_)) => {
                failures += args.concurrent_index_search_iterations;
            }
            Err(_) => {
                for handle in handles.iter().skip(handle_index) {
                    handle.abort();
                    failures += args.concurrent_index_search_iterations;
                }
                break;
            }
        }
    }

    Ok(build_benchmark_stats_with_counts(
        &format!("concurrent_index_search_c{concurrency}"),
        latencies_ms,
        total_started,
        expected_attempts,
        successes,
        failures,
        concurrency,
    ))
}

fn index_search_specs(args: &Args, dns: &ScenarioDns) -> Vec<IndexSearchSpec> {
    let midpoint = args.preloaded_users / 2;
    let midpoint_order = midpoint.to_string();

    vec![
        IndexSearchSpec {
            operation: "index_equality_uid",
            base_dn: dns.users_ou_dn.clone(),
            filter: format!("(uid={})", dns.control_user_uid),
            expected_count: 1,
            expected_dn: Some(dns.control_user_dn.clone()),
        },
        IndexSearchSpec {
            operation: "index_presence_mail",
            base_dn: dns.users_ou_dn.clone(),
            filter: "(mail=*)".to_string(),
            expected_count: args.preloaded_users,
            expected_dn: Some(dns.control_user_dn.clone()),
        },
        IndexSearchSpec {
            operation: "index_substring_description",
            base_dn: dns.users_ou_dn.clone(),
            filter: "(description=*fixture user 000000*)".to_string(),
            expected_count: 1,
            expected_dn: Some(dns.control_user_dn.clone()),
        },
        IndexSearchSpec {
            operation: "index_ordering_benchmark_order_ge",
            base_dn: dns.users_ou_dn.clone(),
            filter: format!("({BENCHMARK_ORDER_ATTRIBUTE}>={midpoint_order})"),
            expected_count: args.preloaded_users - midpoint,
            expected_dn: None,
        },
        IndexSearchSpec {
            operation: "index_ordering_benchmark_order_le",
            base_dn: dns.users_ou_dn.clone(),
            filter: format!("({BENCHMARK_ORDER_ATTRIBUTE}<={midpoint_order})"),
            expected_count: midpoint + 1,
            expected_dn: None,
        },
    ]
}

fn concurrent_index_search_specs(args: &Args, dns: &ScenarioDns) -> Vec<IndexSearchSpec> {
    let max_order = args.preloaded_users.saturating_sub(1).to_string();
    let last_user_index = args.preloaded_users.saturating_sub(1);
    let last_user_uid = format!("{}-user-{last_user_index:06}", args.name_prefix);
    let last_user_dn = format!("uid={last_user_uid},{}", dns.users_ou_dn);

    vec![
        IndexSearchSpec {
            operation: "index_equality_uid",
            base_dn: dns.users_ou_dn.clone(),
            filter: format!("(uid={})", dns.control_user_uid),
            expected_count: 1,
            expected_dn: Some(dns.control_user_dn.clone()),
        },
        IndexSearchSpec {
            operation: "index_equality_uid_tail",
            base_dn: dns.users_ou_dn.clone(),
            filter: format!("(uid={last_user_uid})"),
            expected_count: 1,
            expected_dn: Some(last_user_dn),
        },
        IndexSearchSpec {
            operation: "index_ordering_benchmark_order_ge",
            base_dn: dns.users_ou_dn.clone(),
            filter: format!("({BENCHMARK_ORDER_ATTRIBUTE}>={max_order})"),
            expected_count: 1,
            expected_dn: None,
        },
        IndexSearchSpec {
            operation: "index_ordering_benchmark_order_le",
            base_dn: dns.users_ou_dn.clone(),
            filter: format!("({BENCHMARK_ORDER_ATTRIBUTE}<=0)"),
            expected_count: 1,
            expected_dn: Some(dns.control_user_dn.clone()),
        },
    ]
}

async fn verify_index_search(ldap: &mut Ldap, spec: &IndexSearchSpec) -> AppResult<()> {
    let entries = search_entries(
        ldap,
        &spec.base_dn,
        Scope::Subtree,
        &spec.filter,
        vec![
            "uid",
            "cn",
            "sn",
            "mail",
            "description",
            BENCHMARK_ORDER_ATTRIBUTE,
        ],
    )
    .await?;
    ensure(
        entries.len() == spec.expected_count,
        format!(
            "{} expected {} entries for {}, got {}",
            spec.operation,
            spec.expected_count,
            spec.filter,
            entries.len()
        ),
    )?;
    if let Some(expected_dn) = &spec.expected_dn {
        ensure(
            entries
                .iter()
                .any(|entry| entry.dn.eq_ignore_ascii_case(expected_dn)),
            format!(
                "{} result for {} did not include expected DN {}",
                spec.operation, spec.filter, expected_dn
            ),
        )?;
    }
    Ok(())
}

async fn index_search_matches_with_timeout(
    ldap: &mut Ldap,
    spec: &IndexSearchSpec,
    timeout_duration: Duration,
) -> bool {
    match tokio::time::timeout(timeout_duration, verify_index_search(ldap, spec)).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) | Err(_) => false,
    }
}

fn bind_expectation(
    global_attempt: usize,
    valid_percent: u8,
    wrong_password_percent: u8,
) -> BindExpectation {
    let bucket = (global_attempt % 100) as u8;
    if bucket < valid_percent {
        BindExpectation::Valid
    } else if bucket < valid_percent + wrong_password_percent {
        BindExpectation::WrongPassword
    } else {
        BindExpectation::UnknownDn
    }
}

fn fixture_bind_dn(
    global_attempt: usize,
    preloaded_users: usize,
    hot_user_count: usize,
    hot_user_percent: u8,
    name_prefix: &str,
    users_ou_dn: &str,
) -> String {
    let hot_user_count = hot_user_count.min(preloaded_users).max(1);
    let use_hot_user = (global_attempt % 100) < usize::from(hot_user_percent);
    let user_index = if use_hot_user {
        global_attempt % hot_user_count
    } else {
        global_attempt % preloaded_users
    };
    format!("uid={name_prefix}-user-{user_index:06},{users_ou_dn}")
}

async fn connect_with_timeout(
    url: &str,
    starttls: bool,
    insecure: bool,
    timeout_duration: Duration,
) -> AppResult<Ldap> {
    match tokio::time::timeout(timeout_duration, connect(url, starttls, insecure)).await {
        Ok(result) => result,
        Err(_) => Err(other_error("concurrent bind connect timed out")),
    }
}

async fn connect_raw_ldap_with_timeout(
    url: &str,
    starttls: bool,
    insecure: bool,
    timeout_duration: Duration,
) -> AppResult<RawLdapClient> {
    match tokio::time::timeout(
        timeout_duration,
        RawLdapClient::connect(url, starttls, insecure),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(other_error("concurrent SASL PLAIN connect timed out")),
    }
}

async fn simple_bind_with_timeout(
    ldap: &mut Ldap,
    bind_dn: &str,
    password: &str,
    timeout_duration: Duration,
) -> AppResult<()> {
    match tokio::time::timeout(timeout_duration, simple_bind(ldap, bind_dn, password)).await {
        Ok(result) => result,
        Err(_) => Err(other_error("concurrent bind operation timed out")),
    }
}

async fn sasl_plain_bind_with_timeout(
    ldap: &mut RawLdapClient,
    bind_dn: &str,
    authcid: &str,
    password: &str,
    timeout_duration: Duration,
) -> AppResult<()> {
    match tokio::time::timeout(
        timeout_duration,
        ldap.sasl_plain_bind(bind_dn, authcid, password),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(other_error(
            "concurrent SASL PLAIN bind operation timed out",
        )),
    }
}

async fn bind_matches_expectation_with_timeout(
    ldap: &mut Ldap,
    bind_dn: &str,
    password: &str,
    expectation: BindExpectation,
    timeout_duration: Duration,
) -> bool {
    match tokio::time::timeout(timeout_duration, ldap.simple_bind(bind_dn, password)).await {
        Ok(Ok(result)) => match result.success() {
            Ok(_) => expectation == BindExpectation::Valid,
            Err(LdapError::LdapResult { result }) if result.rc == 49 => {
                expectation != BindExpectation::Valid
            }
            Err(_) => false,
        },
        Ok(Err(_)) | Err(_) => false,
    }
}

async fn sasl_plain_bind_matches_expectation_with_timeout(
    ldap: &mut RawLdapClient,
    bind_dn: &str,
    authcid: &str,
    password: &str,
    expectation: BindExpectation,
    timeout_duration: Duration,
) -> bool {
    (tokio::time::timeout(
        timeout_duration,
        ldap.sasl_plain_bind_matches_expectation(bind_dn, authcid, password, expectation),
    )
    .await)
        .unwrap_or_default()
}

async fn create_benchmark_tree(ldap: &mut Ldap, dns: &ScenarioDns) -> AppResult<()> {
    add_organizational_unit(ldap, &dns.benchmark_root_dn).await?;
    add_organizational_unit(ldap, &dns.users_ou_dn).await?;
    add_organizational_unit(ldap, &dns.moved_ou_dn).await?;
    add_organizational_unit(ldap, &dns.writes_ou_dn).await?;
    Ok(())
}

async fn ensure_existing_fixture(
    ldap: &mut Ldap,
    dns: &ScenarioDns,
    expected_users: usize,
) -> AppResult<()> {
    ensure(
        expected_users > 0,
        "--preloaded-users must be greater than zero when reusing a fixture",
    )?;
    for dn in [
        &dns.benchmark_root_dn,
        &dns.users_ou_dn,
        &dns.moved_ou_dn,
        &dns.writes_ou_dn,
    ] {
        let entry = search_single_entry(
            ldap,
            dn,
            Scope::Base,
            "(objectClass=organizationalUnit)",
            vec!["ou"],
        )
        .await?;
        ensure(
            entry.dn.eq_ignore_ascii_case(dn),
            format!("reused fixture returned unexpected DN for {dn}"),
        )?;
    }
    let entry = search_single_entry(
        ldap,
        &dns.control_user_dn,
        Scope::Base,
        &format!("(uid={})", dns.control_user_uid),
        vec!["uid", "cn", "sn", "mail"],
    )
    .await?;
    ensure(
        entry.dn.eq_ignore_ascii_case(&dns.control_user_dn),
        format!(
            "reused fixture is missing expected control user for {expected_users} preloaded users"
        ),
    )?;
    Ok(())
}

async fn preload_users(
    ldap: &mut Ldap,
    dns: &ScenarioDns,
    args: &Args,
    include_index_attributes: bool,
) -> AppResult<()> {
    let count = args.preloaded_users;
    if args.preload_workers > 1 && count > 1 {
        preload_users_parallel(dns, args, include_index_attributes).await?;
    } else {
        for index in 0..count {
            add_preloaded_user(
                ldap,
                dns,
                index,
                &args.user_password,
                &args.name_prefix,
                include_index_attributes,
            )
            .await?;
            report_preload_progress(index + 1, count);
        }
    }

    ensure(
        dns.control_user_uid == format!("{}-user-000000", args.name_prefix),
        "control user UID does not match preload naming pattern",
    )?;
    Ok(())
}

async fn preload_users_parallel(
    dns: &ScenarioDns,
    args: &Args,
    include_index_attributes: bool,
) -> AppResult<()> {
    let count = args.preloaded_users;
    let worker_count = args.preload_workers.min(count);
    let chunk_size = count.div_ceil(worker_count);
    let loaded = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(worker_count);

    for worker_index in 0..worker_count {
        let start = worker_index * chunk_size;
        let end = (start + chunk_size).min(count);
        if start >= end {
            continue;
        }

        let dns = dns.clone();
        let url = args.url.clone();
        let bind_dn = args.bind_dn.clone();
        let password = args.password.clone();
        let user_password = args.user_password.clone();
        let name_prefix = args.name_prefix.clone();
        let starttls = args.starttls;
        let insecure = args.insecure;
        let loaded = Arc::clone(&loaded);

        handles.push(tokio::spawn(async move {
            let mut ldap = connect(&url, starttls, insecure).await?;
            simple_bind(&mut ldap, &bind_dn, &password).await?;

            for index in start..end {
                add_preloaded_user(
                    &mut ldap,
                    &dns,
                    index,
                    &user_password,
                    &name_prefix,
                    include_index_attributes,
                )
                .await?;
                let total_loaded = loaded.fetch_add(1, Ordering::Relaxed) + 1;
                report_preload_progress(total_loaded, count);
            }

            best_effort_unbind("preload_worker", ldap).await;
            AppResult::Ok(())
        }));
    }

    for handle in handles {
        handle
            .await
            .map_err(|err| other_error(format!("preload worker task failed: {err}")))??;
    }

    Ok(())
}

async fn add_preloaded_user(
    ldap: &mut Ldap,
    dns: &ScenarioDns,
    index: usize,
    password: &str,
    name_prefix: &str,
    include_index_attributes: bool,
) -> AppResult<()> {
    let uid = format!("{name_prefix}-user-{index:06}");
    let dn = format!("uid={uid},{}", dns.users_ou_dn);
    let mut object_classes = string_set(["top", "person", "organizationalPerson", "inetOrgPerson"]);
    if include_index_attributes {
        object_classes.insert(BENCHMARK_INDEX_AUXILIARY_CLASS.to_string());
    }
    let mut attributes = vec![
        ("objectClass".to_string(), object_classes),
        ("uid".to_string(), string_set([uid.clone()])),
        (
            "cn".to_string(),
            string_set([format!("Benchmark User {index}")]),
        ),
        (
            "sn".to_string(),
            string_set([format!("BenchmarkUser{index:06}")]),
        ),
        (
            "description".to_string(),
            string_set([format!("Benchmark fixture user {index:06}")]),
        ),
        (
            "mail".to_string(),
            string_set([format!("{uid}@example.com")]),
        ),
        ("userPassword".to_string(), string_set([password])),
    ];
    if include_index_attributes {
        attributes.push((
            BENCHMARK_ORDER_ATTRIBUTE.to_string(),
            string_set([index.to_string()]),
        ));
    }
    ldap.add(&dn, attributes).await?.success()?;
    Ok(())
}

fn report_preload_progress(loaded: usize, count: usize) {
    if count >= 100_000 && (loaded % 100_000 == 0 || loaded == count) {
        progress(&format!("fixture.preload.{loaded}of{count}"));
    }
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

fn expected_fixture_record_count(preloaded_users: usize) -> usize {
    // Base entry plus benchmark root/users/moved/writes organizational units.
    preloaded_users + 5
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
    build_benchmark_stats_with_counts(
        operation,
        latencies_ms,
        total_start,
        iterations,
        iterations,
        0,
        1,
    )
}

fn build_benchmark_stats_with_counts(
    operation: &str,
    latencies_ms: Vec<f64>,
    total_start: Instant,
    attempts: usize,
    successes: usize,
    failures: usize,
    concurrency: usize,
) -> BenchmarkStats {
    let elapsed_ms_total = elapsed_ms(total_start.elapsed().as_secs_f64());
    build_benchmark_stats_with_elapsed(
        operation,
        latencies_ms,
        elapsed_ms_total,
        attempts,
        successes,
        failures,
        concurrency,
    )
}

fn build_benchmark_stats_with_elapsed(
    operation: &str,
    latencies_ms: Vec<f64>,
    elapsed_ms_total: f64,
    attempts: usize,
    successes: usize,
    failures: usize,
    concurrency: usize,
) -> BenchmarkStats {
    let throughput_ops_per_sec = if elapsed_ms_total > 0.0 {
        attempts as f64 / (elapsed_ms_total / 1000.0)
    } else {
        0.0
    };
    let success_throughput_ops_per_sec = if elapsed_ms_total > 0.0 {
        successes as f64 / (elapsed_ms_total / 1000.0)
    } else {
        0.0
    };
    let failure_rate_percent = if attempts > 0 {
        failures as f64 * 100.0 / attempts as f64
    } else {
        0.0
    };
    let latency_count = latencies_ms.len();
    let mean_ms = if latency_count > 0 {
        latencies_ms.iter().sum::<f64>() / latency_count as f64
    } else {
        0.0
    };

    BenchmarkStats {
        operation: operation.to_string(),
        iterations: attempts,
        concurrency,
        successes,
        failures,
        failure_rate_percent,
        elapsed_ms: elapsed_ms_total,
        throughput_ops_per_sec,
        success_throughput_ops_per_sec,
        min_ms: percentile(&latencies_ms, 0.0),
        mean_ms,
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
    println!(
        "| Operation | Concurrency | Attempts | Successes | Failures | Failure % | Mean ms | P50 ms | P95 ms | P99 ms | Max ms | Attempt ops/s | Success ops/s |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for benchmark in &report.benchmarks {
        println!(
            "| {} | {} | {} | {} | {} | {:.2} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.2} | {:.2} |",
            benchmark.operation,
            benchmark.concurrency,
            benchmark.iterations,
            benchmark.successes,
            benchmark.failures,
            benchmark.failure_rate_percent,
            benchmark.mean_ms,
            benchmark.p50_ms,
            benchmark.p95_ms,
            benchmark.p99_ms,
            benchmark.max_ms,
            benchmark.throughput_ops_per_sec,
            benchmark.success_throughput_ops_per_sec,
        );
    }
}

fn parse_concurrent_bind_clients(raw: &str) -> AppResult<Vec<usize>> {
    parse_concurrent_client_list(raw, "--concurrent-bind-clients")
}

fn parse_concurrent_index_search_clients(raw: &str) -> AppResult<Vec<usize>> {
    parse_concurrent_client_list(raw, "--concurrent-index-search-clients")
}

fn parse_ldapcon_clients(raw: &str) -> AppResult<Vec<usize>> {
    parse_concurrent_client_list(raw, "--ldapcon-clients")
}

fn parse_sasl_plain_authcid_format(raw: &str) -> AppResult<SaslPlainAuthcidFormat> {
    match raw {
        "dn" => Ok(SaslPlainAuthcidFormat::Dn),
        "rdn-value" => Ok(SaslPlainAuthcidFormat::RdnValue),
        other => Err(other_error(format!(
            "--sasl-plain-authcid-format must be one of: dn, rdn-value; got {other:?}"
        ))),
    }
}

fn sasl_plain_authcid(bind_dn: &str, format: SaslPlainAuthcidFormat) -> AppResult<String> {
    match format {
        SaslPlainAuthcidFormat::Dn => Ok(bind_dn.to_string()),
        SaslPlainAuthcidFormat::RdnValue => bind_dn
            .split_once('=')
            .and_then(|(_, rest)| rest.split_once(',').map(|(value, _)| value.to_string()))
            .or_else(|| {
                bind_dn
                    .split_once('=')
                    .map(|(_, value)| value.trim().to_string())
            })
            .filter(|value| !value.is_empty())
            .ok_or_else(|| other_error(format!("failed to derive RDN value from {bind_dn:?}"))),
    }
}

fn parse_concurrent_client_list(raw: &str, argument_name: &str) -> AppResult<Vec<usize>> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut values = Vec::new();
    for value in raw.split(',') {
        let value = value.trim();
        ensure(!value.is_empty(), format!("empty {argument_name} value"))?;
        let parsed = value.parse::<usize>().map_err(|err| {
            other_error(format!("invalid {argument_name} value {value:?}: {err}"))
        })?;
        ensure(
            parsed > 0,
            format!("{argument_name} values must be greater than zero"),
        )?;
        values.push(parsed);
    }

    values.sort_unstable();
    values.dedup();
    Ok(values)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_concurrent_bind_clients_accepts_empty_list() {
        let values = parse_concurrent_bind_clients("").unwrap();
        assert!(values.is_empty());
    }

    #[test]
    fn parse_concurrent_bind_clients_sorts_and_deduplicates() {
        let values = parse_concurrent_bind_clients("16, 4, 16, 1").unwrap();
        assert_eq!(values, vec![1, 4, 16]);
    }

    #[test]
    fn parse_concurrent_bind_clients_rejects_zero() {
        assert!(parse_concurrent_bind_clients("1,0,4").is_err());
    }

    #[test]
    fn parse_concurrent_index_search_clients_sorts_and_deduplicates() {
        let values = parse_concurrent_index_search_clients("32, 4, 8, 4").unwrap();
        assert_eq!(values, vec![4, 8, 32]);
    }

    #[test]
    fn parse_concurrent_index_search_clients_rejects_zero() {
        assert!(parse_concurrent_index_search_clients("1,0,4").is_err());
    }

    #[test]
    fn ldapcon_mixed_counts_are_spread_across_small_runs() {
        assert_eq!(ldapcon_mixed_expected_counts(6, 20), (4, 2));
        assert_eq!(ldapcon_mixed_expected_counts(100, 20), (80, 20));
        assert_eq!(ldapcon_mixed_expected_counts(100, 0), (100, 0));
        assert_eq!(ldapcon_mixed_expected_counts(100, 100), (0, 100));
    }

    #[test]
    fn sasl_plain_authcid_can_use_rdn_value() {
        assert_eq!(
            sasl_plain_authcid(
                "uid=bench-user-000001,ou=users,dc=example,dc=com",
                SaslPlainAuthcidFormat::RdnValue
            )
            .unwrap(),
            "bench-user-000001"
        );
        assert_eq!(
            parse_sasl_plain_authcid_format("dn").unwrap(),
            SaslPlainAuthcidFormat::Dn
        );
    }

    #[test]
    fn sasl_plain_bind_request_uses_dn_in_request_name_and_authcid() {
        let request =
            encode_sasl_plain_bind_request(7, "uid=user,dc=example,dc=com", "user", "secret")
                .unwrap();
        let (_, messages) = parse_ldap_messages(&request).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ParserProtocolOp::BindRequest(bind_request) => {
                assert_eq!(bind_request.name.0.as_ref(), "uid=user,dc=example,dc=com");
                match &bind_request.authentication {
                    ldap_parser::ldap::AuthenticationChoice::Sasl(credentials) => {
                        assert_eq!(credentials.mechanism.0.as_ref(), "PLAIN");
                        assert_eq!(
                            credentials.credentials.as_deref(),
                            Some(b"\0user\0secret".as_ref())
                        );
                    }
                    other => panic!("unexpected auth choice: {other:?}"),
                }
            }
            other => panic!("unexpected protocol op: {other:?}"),
        }
    }

    #[test]
    fn bind_expectation_uses_unknown_dn_for_remaining_percent() {
        assert_eq!(bind_expectation(0, 70, 20), BindExpectation::Valid);
        assert_eq!(bind_expectation(75, 70, 20), BindExpectation::WrongPassword);
        assert_eq!(bind_expectation(95, 70, 20), BindExpectation::UnknownDn);
    }

    #[test]
    fn fixture_bind_dn_uses_configured_hot_set() {
        let dn = fixture_bind_dn(5, 1000, 2, 100, "bench", "ou=users,dc=example,dc=com");
        assert_eq!(dn, "uid=bench-user-000001,ou=users,dc=example,dc=com");
    }

    #[test]
    fn benchmark_stats_record_failure_rate_and_success_throughput() {
        let stats = build_benchmark_stats_with_counts(
            "concurrent_bind_fixture_users_c4",
            vec![1.0, 2.0, 3.0, 4.0],
            Instant::now(),
            5,
            4,
            1,
            4,
        );

        assert_eq!(stats.iterations, 5);
        assert_eq!(stats.concurrency, 4);
        assert_eq!(stats.successes, 4);
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.failure_rate_percent, 20.0);
        assert!(stats.throughput_ops_per_sec >= stats.success_throughput_ops_per_sec);
    }
}
