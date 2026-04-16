#!/usr/bin/env bash
#
# OpenDR fuzz readiness gate.
#
# Runs the LDAP BER decoder and request-handler fuzz targets in a short smoke
# mode for local/CI validation or a long release-candidate mode for production
# readiness evidence.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: FUZZ_GATE_MODE=smoke ./scripts/fuzz_gate.sh

Environment:
  FUZZ_GATE_MODE                    smoke or release (default: smoke)
  FUZZ_GATE_TOOLCHAIN               pinned nightly toolchain (default: nightly-2026-03-01)
  FUZZ_GATE_TARGETS                 space-separated targets (default: ber_decoder ldap_request_handler)
  FUZZ_GATE_OUTPUT_DIR              artifact directory (default: target/fuzz-gate/<mode>-<timestamp>)
  FUZZ_GATE_SMOKE_RUNS              runs per target in smoke mode (default: 64)
  FUZZ_GATE_RELEASE_RUNS            optional run count per target in release mode (default: unset)
  FUZZ_GATE_RELEASE_MAX_TOTAL_TIME_SECS
                                    max seconds per target in release mode (default: 21600)
  FUZZ_GATE_TIMEOUT_SECS            libFuzzer per-input timeout (default: 25)
  FUZZ_GATE_RSS_LIMIT_MB            libFuzzer RSS limit (default: 4096)
  FUZZ_GATE_DICTIONARY              dictionary path (default: fuzz/dictionaries/ldap.dict)
  FUZZ_GATE_EXTRA_ARGS              extra libFuzzer args, shell-split

Artifacts:
  <output>/summary.md
  <output>/logs/<target>.log
  <output>/corpus/<target>/
  <output>/artifacts/<target>/
  <output>/dictionaries/
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${PROJECT_ROOT}"

MODE="${FUZZ_GATE_MODE:-smoke}"
TOOLCHAIN="${FUZZ_GATE_TOOLCHAIN:-nightly-2026-03-01}"
TARGETS="${FUZZ_GATE_TARGETS:-ber_decoder ldap_request_handler}"
SMOKE_RUNS="${FUZZ_GATE_SMOKE_RUNS:-64}"
RELEASE_RUNS="${FUZZ_GATE_RELEASE_RUNS:-}"
RELEASE_MAX_TOTAL_TIME_SECS="${FUZZ_GATE_RELEASE_MAX_TOTAL_TIME_SECS:-21600}"
TIMEOUT_SECS="${FUZZ_GATE_TIMEOUT_SECS:-25}"
RSS_LIMIT_MB="${FUZZ_GATE_RSS_LIMIT_MB:-4096}"
DICTIONARY="${FUZZ_GATE_DICTIONARY:-fuzz/dictionaries/ldap.dict}"
OUTPUT_DIR="${FUZZ_GATE_OUTPUT_DIR:-target/fuzz-gate/${MODE}-$(date +%Y%m%d%H%M%S)}"

case "${MODE}" in
  smoke|release) ;;
  *)
    echo "FUZZ_GATE_MODE must be smoke or release, got ${MODE}" >&2
    exit 1
    ;;
esac

mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"
LOG_DIR="${OUTPUT_DIR}/logs"
CORPUS_DIR="${OUTPUT_DIR}/corpus"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts"
DICTIONARY_DIR="${OUTPUT_DIR}/dictionaries"
SUMMARY_FILE="${OUTPUT_DIR}/summary.md"
mkdir -p "${LOG_DIR}" "${CORPUS_DIR}" "${ARTIFACT_DIR}" "${DICTIONARY_DIR}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required" >&2
  exit 1
fi

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required for pinned fuzz toolchain ${TOOLCHAIN}" >&2
  exit 1
fi

if ! rustup toolchain list | grep -q "^${TOOLCHAIN}"; then
  echo "Rust toolchain ${TOOLCHAIN} is not installed." >&2
  echo "Install it with: rustup toolchain install ${TOOLCHAIN} --profile minimal" >&2
  exit 1
fi

if ! cargo fuzz --help >/dev/null 2>&1; then
  echo "cargo-fuzz is required." >&2
  echo "Install it with: cargo install cargo-fuzz --locked" >&2
  exit 1
fi

if [[ -f "${DICTIONARY}" ]]; then
  cp -f "${DICTIONARY}" "${DICTIONARY_DIR}/$(basename "${DICTIONARY}")"
  DICTIONARY="$(cd "$(dirname "${DICTIONARY}")" && pwd)/$(basename "${DICTIONARY}")"
else
  DICTIONARY=""
fi

write_summary_header() {
  cat > "${SUMMARY_FILE}" <<EOF
# OpenDR Fuzz Gate Summary

- Status: running
- Mode: ${MODE}
- Toolchain: ${TOOLCHAIN}
- Targets: ${TARGETS}
- Started at: ${STARTED_AT}
- Updated at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Output directory: \`${OUTPUT_DIR}\`
- Corpus directory: \`${CORPUS_DIR}\`
- Crash artifact directory: \`${ARTIFACT_DIR}\`
- Log directory: \`${LOG_DIR}\`
- Dictionary: ${DICTIONARY:-none}

## Results

EOF
}

finish_summary() {
  local status="$1"
  local finished_at
  finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  perl -0pi -e "s/- Status: running/- Status: ${status}/" "${SUMMARY_FILE}"
  perl -0pi -e "s/- Updated at: .*/- Updated at: ${finished_at}/" "${SUMMARY_FILE}"
}

target_args() {
  TARGET_ARGS=("-timeout=${TIMEOUT_SECS}" "-rss_limit_mb=${RSS_LIMIT_MB}" "-print_final_stats=1")

  if [[ -n "${DICTIONARY}" ]]; then
    TARGET_ARGS+=("-dict=${DICTIONARY}")
  fi

  case "${MODE}" in
    smoke)
      TARGET_ARGS+=("-runs=${SMOKE_RUNS}")
      ;;
    release)
      if [[ -n "${RELEASE_RUNS}" ]]; then
        TARGET_ARGS+=("-runs=${RELEASE_RUNS}")
      fi
      if [[ -n "${RELEASE_MAX_TOTAL_TIME_SECS}" ]]; then
        TARGET_ARGS+=("-max_total_time=${RELEASE_MAX_TOTAL_TIME_SECS}")
      fi
      ;;
  esac

  if [[ -n "${FUZZ_GATE_EXTRA_ARGS:-}" ]]; then
    # Intentional shell splitting for advanced libFuzzer flags.
    # shellcheck disable=SC2206
    local extra_args=(${FUZZ_GATE_EXTRA_ARGS})
    TARGET_ARGS+=("${extra_args[@]}")
  fi
}

copy_seed_corpus() {
  local target="$1"
  local target_corpus="$2"
  mkdir -p "${target_corpus}"
  if [[ -d "fuzz/corpus/${target}" ]]; then
    cp -R "fuzz/corpus/${target}/." "${target_corpus}/" 2>/dev/null || true
  fi
}

find_repro_artifact() {
  local target_artifacts="$1"
  find "${target_artifacts}" -type f 2>/dev/null | sort | head -n 1 || true
}

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_summary_header

overall_status="passed"

for target in ${TARGETS}; do
  target_log="${LOG_DIR}/${target}.log"
  target_corpus="${CORPUS_DIR}/${target}"
  target_artifacts="${ARTIFACT_DIR}/${target}"
  mkdir -p "${target_artifacts}"
  copy_seed_corpus "${target}" "${target_corpus}"

  TARGET_ARGS=()
  target_args
  TARGET_ARGS+=("-artifact_prefix=${target_artifacts}/")

  cmd=(cargo "+${TOOLCHAIN}" fuzz run "${target}" -- "${TARGET_ARGS[@]}" "${target_corpus}")

  {
    echo "Command: ${cmd[*]}"
    echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "${target_log}"

  echo "Running ${target} fuzz ${MODE} gate..."
  if "${cmd[@]}" >> "${target_log}" 2>&1; then
    {
      echo "- ${target}: passed"
      echo "  - Log: \`${target_log}\`"
      echo "  - Corpus: \`${target_corpus}\`"
      echo "  - Artifacts: \`${target_artifacts}\`"
    } >> "${SUMMARY_FILE}"
  else
    status=$?
    overall_status="failed"
    repro_artifact="$(find_repro_artifact "${target_artifacts}")"
    {
      echo "- ${target}: failed with exit ${status}"
      echo "  - Log: \`${target_log}\`"
      echo "  - Corpus: \`${target_corpus}\`"
      echo "  - Artifacts: \`${target_artifacts}\`"
      if [[ -n "${repro_artifact}" ]]; then
        echo "  - Reproduce: \`cargo +${TOOLCHAIN} fuzz run ${target} ${repro_artifact}\`"
      else
        echo "  - Reproduce: inspect \`${target_log}\`; no crash artifact was written"
      fi
    } >> "${SUMMARY_FILE}"
    echo "Fuzz target ${target} failed. Last log lines:" >&2
    tail -80 "${target_log}" >&2 || true
  fi
done

finish_summary "${overall_status}"

echo "Fuzz gate summary: ${SUMMARY_FILE}"
if [[ "${overall_status}" != "passed" ]]; then
  exit 1
fi
