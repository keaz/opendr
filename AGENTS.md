# Repository Guidelines

## Project Structure & Module Organization

Core Rust code lives in `src/`; `src/main.rs` is the server entry point and `src/lib.rs` exposes library modules. Runtime and protocol work is split across `fsm_server.rs`, `server.rs`, `config.rs`, `backend_lmdb.rs`, and `backend_adapters/`. CLI tools live under `src/bin/`. Integration tests are in `tests/`, Criterion benchmarks in `benches/`, demos in `examples/`, and shell flows in `scripts/` and `e2e_tests/`. Config and LDIF fixtures are in `config/`; docs are in `docs/` and the Vite/React site is in `site/`.

## Build, Test, and Development Commands

- `cargo build`: build debug Rust binaries.
- `cargo build --release`: build optimized binaries.
- `cargo test --workspace --no-fail-fast`: run Rust tests.
- `cargo test --doc --quiet`: run doctests.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: lint with warnings denied.
- `cargo fmt --check`: verify Rust formatting.
- `cargo bench`: run Criterion benchmarks.
- `cargo run --bin opendr -- --config config/server.toml --log-config config/log4rs.yml`: run the server locally.
- `pnpm install`, `pnpm check`, `pnpm build`, `pnpm dev`: install, validate, build, and preview docs.

## Coding Style & Naming Conventions

Use Rust 2021 formatting via `rustfmt`; do not hand-align code. Keep modules, files, functions, and variables in `snake_case`, types and traits in `PascalCase`, and constants in `SCREAMING_SNAKE_CASE`. Prefer `thiserror` errors and Tokio.

## Testing Guidelines

Every behavior change should include unit, integration, or e2e coverage as relevant. Place broad coverage in `tests/*_integration.rs` and focused unit tests beside the module under `mod tests`. Use `#[tokio::test]` for async behavior. For targeted checks, run `cargo test replication`, `cargo test --test config_integration`, or `cargo test --test replication_e2e`. Add regression tests for protocol, replication, TLS, config, and backend changes.

## Documentation & Site Updates

When behavior, configuration, architecture, or operations change, update docs, diagrams, and site content. Keep `docs/*.md`, Mermaid diagrams, `replication_docs/`, and `site/` aligned, then run `pnpm check` and `pnpm build` for site changes.

## Commit & Pull Request Guidelines

Recent history uses imperative subjects such as `Add typed LMDB indexes` and `remove poll-based replication`; keep subjects specific and one line. Before opening a PR, run relevant Rust and docs checks. PRs should summarize behavior changes, list validation commands, link issues, and include screenshots only for documentation-site UI changes.

## Security & Configuration Tips

Do not commit real passwords, private keys, or production LDIF data. Prefer `_env` or `_file` secret fields, and keep per-instance data, logs, replication state, ports, and TLS paths isolated for local multi-node runs.
