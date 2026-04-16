#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/production_config_gate.sh <server.toml>

Validates that an OpenDR server TOML follows the production hardening baseline.
The gate checks the committed config values; runtime startup still validates
that referenced TLS, schema, secret, and ACI files exist on the deployment host.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 2
fi

CONFIG_PATH="$1"
if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "production config gate failed: config file not found: ${CONFIG_PATH}" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "production config gate failed: python3 is required" >&2
  exit 1
fi

python3 - "${CONFIG_PATH}" "${ROOT_DIR}" <<'PY'
import pathlib
import sys
import tomllib

config_path = pathlib.Path(sys.argv[1]).resolve()
repo_root = pathlib.Path(sys.argv[2]).resolve()

try:
    with config_path.open("rb") as handle:
        config = tomllib.load(handle)
except tomllib.TOMLDecodeError as exc:
    print(f"production config gate failed: invalid TOML: {exc}", file=sys.stderr)
    sys.exit(1)

failures: list[str] = []


def table(name: str) -> dict:
    value = config.get(name, {})
    return value if isinstance(value, dict) else {}


def non_empty(value) -> bool:
    return value is not None and str(value).strip() != ""


def bool_value(section: str, key: str):
    return table(section).get(key)


def require_true(section: str, key: str, message: str) -> None:
    if bool_value(section, key) is not True:
        failures.append(message)


def reject_true(section: str, key: str, message: str) -> None:
    if bool_value(section, key) is True:
        failures.append(message)


server = table("server")
backend = table("backend")
tls = table("tls")
security = table("security")
replication = table("replication")
audit = table("audit")
access_control = table("access_control")

if str(security.get("profile", "")).lower() != "production":
    failures.append('security.profile must be "production"')

require_true("tls", "enabled", "tls.enabled must be true")
require_true("rate_limit", "enabled", "rate_limit.enabled must be true")
require_true("audit", "enabled", "audit.enabled must be true")
require_true("access_control", "enabled", "access_control.enabled must be true")

if str(access_control.get("default_policy", "")).lower() != "deny":
    failures.append('access_control.default_policy must be "deny"')
if not non_empty(access_control.get("rules_file")):
    failures.append("access_control.rules_file must be configured")

reject_true(
    "security",
    "allow_cleartext_simple_bind",
    "security.allow_cleartext_simple_bind must not be true",
)
reject_true(
    "security",
    "allow_anonymous_bind",
    "security.allow_anonymous_bind must not be true",
)

if "root_password" in server and non_empty(server.get("root_password")):
    failures.append("server.root_password must not be inline in production")
root_sources = [
    name
    for name in ("root_password_env", "root_password_file")
    if non_empty(server.get(name))
]
if len(root_sources) != 1:
    failures.append(
        "configure exactly one production root secret source: "
        "server.root_password_env or server.root_password_file"
    )

if str(backend.get("backend_type", "")).lower() != "lmdb":
    failures.append('backend.backend_type must be "lmdb"')
data_directory = pathlib.Path(str(backend.get("data_directory", "")))
if not data_directory.is_absolute():
    failures.append("backend.data_directory must be an absolute production path")
else:
    try:
        data_directory.resolve().relative_to(repo_root)
    except ValueError:
        pass
    else:
        failures.append("backend.data_directory must not be inside the source tree")

state_path = pathlib.Path(str(replication.get("state_storage_path", "")))
if not state_path.is_absolute():
    failures.append("replication.state_storage_path must be an absolute production path")
else:
    try:
        state_path.resolve().relative_to(repo_root)
    except ValueError:
        pass
    else:
        failures.append("replication.state_storage_path must not be inside the source tree")

for key in (
    "log_authentication",
    "log_authorization",
    "log_modifications",
    "log_connections",
    "log_replication",
):
    if audit.get(key) is False:
        failures.append(f"audit.{key} must not be false")

if replication.get("allow_insecure_provider_bind") is True:
    failures.append("replication.allow_insecure_provider_bind must not be true")
if "bind_password" in replication and non_empty(replication.get("bind_password")):
    failures.append("replication.bind_password must not be inline in production")

if replication.get("enabled") is True and str(replication.get("mode", "")).lower() in {
    "consumer",
    "both",
}:
    provider_url = str(replication.get("provider_url", ""))
    if not provider_url.startswith("ldaps://"):
        failures.append("replication.provider_url must use ldaps:// in production")
    if non_empty(replication.get("bind_dn")):
        bind_sources = [
            name
            for name in ("bind_password_env", "bind_password_file")
            if non_empty(replication.get(name))
        ]
        if len(bind_sources) != 1:
            failures.append(
                "configure exactly one replication bind secret source: "
                "replication.bind_password_env or replication.bind_password_file"
            )

if failures:
    print(f"production config gate failed for {config_path}:", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    sys.exit(1)

print(f"Production config gate passed: {config_path}")
PY
