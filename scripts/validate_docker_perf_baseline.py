#!/usr/bin/env python3
"""Validate Docker performance summaries against the documented baseline."""

from __future__ import annotations

import argparse
import csv
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MarkdownTable:
    section: str
    headers: list[str]
    rows: list[dict[str, str]]


@dataclass(frozen=True)
class BaselineCheck:
    profile: str
    csv_metric: str
    label: str
    baseline: float
    direction: str
    source: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare OpenDR Docker perf summary CSV files against baseline values "
            "recorded in docs/PERFORMANCE_COMPARISON.md."
        )
    )
    parser.add_argument(
        "--baseline-doc",
        type=Path,
        default=Path("docs/PERFORMANCE_COMPARISON.md"),
        help="Markdown document containing baseline tables.",
    )
    parser.add_argument(
        "--summary-csv",
        type=Path,
        action="append",
        required=True,
        help="comparison-summary.csv produced by scripts/perf_docker_matrix.sh; repeatable.",
    )
    parser.add_argument(
        "--threshold-percent",
        type=float,
        default=10.0,
        help="Allowed regression before failing, as a percentage of the baseline.",
    )
    parser.add_argument(
        "--product",
        default="opendr",
        help="Product key to validate from comparison-summary.csv.",
    )
    parser.add_argument(
        "--profile",
        action="append",
        help="Limit validation to one profile; repeatable. Defaults to every parsed baseline profile.",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        help="Optional markdown report path for CI artifacts.",
    )
    parser.add_argument(
        "--stable-gate",
        action="store_true",
        help=(
            "Validate only metrics stable enough for GitHub-hosted Docker release gates. "
            "This keeps total runtime plus concurrency capacity/failure checks and skips "
            "sub-millisecond operation means and peak throughput rows."
        ),
    )
    return parser.parse_args()


def split_markdown_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def is_separator_row(line: str) -> bool:
    cells = split_markdown_row(line)
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell.strip()) for cell in cells)


def iter_markdown_tables(text: str) -> list[MarkdownTable]:
    tables: list[MarkdownTable] = []
    lines = text.splitlines()
    section = ""
    index = 0

    while index < len(lines):
        heading = re.match(r"^#{2,6}\s+(.+?)\s*$", lines[index])
        if heading:
            section = heading.group(1)
            index += 1
            continue

        if not lines[index].lstrip().startswith("|"):
            index += 1
            continue

        raw_rows: list[str] = []
        while index < len(lines) and lines[index].lstrip().startswith("|"):
            raw_rows.append(lines[index].strip())
            index += 1

        if len(raw_rows) < 2 or not is_separator_row(raw_rows[1]):
            continue

        headers = split_markdown_row(raw_rows[0])
        rows = []
        for raw_row in raw_rows[2:]:
            cells = split_markdown_row(raw_row)
            if len(cells) != len(headers):
                continue
            rows.append(dict(zip(headers, cells, strict=True)))
        tables.append(MarkdownTable(section=section, headers=headers, rows=rows))

    return tables


def parse_number(raw: str | None) -> float | None:
    if raw is None:
        return None
    value = raw.strip().strip("`")
    if not value or value.lower() in {"n/a", "na", "timeout", "incomplete"}:
        return None
    match = re.search(r"-?\d[\d,]*(?:\.\d+)?", value)
    if not match:
        return None
    return float(match.group(0).replace(",", ""))


def is_opendr_product(raw: str | None) -> bool:
    return bool(raw and raw.strip().lower().startswith("opendr"))


def add_mapped_checks(
    checks: list[BaselineCheck],
    *,
    row: dict[str, str],
    profile: str,
    source: str,
    mappings: dict[str, tuple[str, str, str]],
) -> None:
    for doc_metric, (csv_metric, label, direction) in mappings.items():
        baseline = parse_number(row.get(doc_metric))
        if baseline is None:
            continue
        checks.append(
            BaselineCheck(
                profile=profile,
                csv_metric=csv_metric,
                label=label,
                baseline=baseline,
                direction=direction,
                source=source,
            )
        )


def extract_baseline_checks(doc: Path) -> list[BaselineCheck]:
    checks: list[BaselineCheck] = []
    tables = iter_markdown_tables(doc.read_text())

    full_profile_mappings = {
        "Total runtime ms": ("total_elapsed_ms", "total runtime", "lower"),
        "Subtree search mean ms": ("search_subtree_mean_ms", "subtree search mean", "lower"),
        "Simple bind mean ms": ("bind_admin_mean_ms", "simple bind mean", "lower"),
        "Add mean ms": ("add_mean_ms", "add mean", "lower"),
        "Modify mean ms": ("modify_mean_ms", "modify mean", "lower"),
        "Delete mean ms": ("delete_mean_ms", "delete mean", "lower"),
        "Password modify mean ms": (
            "password_modify_mean_ms",
            "password modify mean",
            "lower",
        ),
    }
    concurrency_mappings = {
        "Max tested clients": (
            "max_concurrent_bind_clients_tested",
            "max concurrent bind clients tested",
            "higher",
        ),
        "Max 0% failure clients": (
            "max_concurrent_bind_clients_zero_failure",
            "max zero-failure concurrent bind clients",
            "higher",
        ),
        "Failure rate at max tested": (
            "max_concurrent_bind_failure_rate_percent",
            "max-tested concurrent bind failure rate",
            "lower",
        ),
        "Peak success ops/s": (
            "peak_concurrent_bind_success_throughput",
            "peak concurrent bind success throughput",
            "higher",
        ),
    }
    sasl_mappings = {
        "Max tested clients": (
            "max_concurrent_sasl_plain_bind_clients_tested",
            "max concurrent SASL PLAIN bind clients tested",
            "higher",
        ),
        "Max 0% failure clients": (
            "max_concurrent_sasl_plain_bind_clients_zero_failure",
            "max zero-failure concurrent SASL PLAIN bind clients",
            "higher",
        ),
        "Failure rate at max tested": (
            "max_concurrent_sasl_plain_bind_failure_rate_percent",
            "max-tested concurrent SASL PLAIN bind failure rate",
            "lower",
        ),
        "Peak SASL success ops/s": (
            "peak_concurrent_sasl_plain_bind_success_throughput",
            "peak concurrent SASL PLAIN bind success throughput",
            "higher",
        ),
        "Fixture-user mean ms": (
            "sasl_plain_bind_fixture_user_mean_ms",
            "SASL PLAIN fixture-user mean",
            "lower",
        ),
    }
    index_profile_mappings = {
        "Total runtime ms": ("total_elapsed_ms", "index total runtime", "lower"),
        "Subtree search mean ms": (
            "search_subtree_mean_ms",
            "index subtree search mean",
            "lower",
        ),
        "Add mean ms": ("add_mean_ms", "index add mean", "lower"),
        "Modify mean ms": ("modify_mean_ms", "index modify mean", "lower"),
        "Delete mean ms": ("delete_mean_ms", "index delete mean", "lower"),
    }
    index_probe_mappings = {
        "Equality `uid`": ("index_equality_uid_mean_ms", "index uid equality mean"),
        "Presence `mail`": ("index_presence_mail_mean_ms", "index mail presence mean"),
        "Substring `description`": (
            "index_substring_description_mean_ms",
            "index description substring mean",
        ),
        "Ordering `benchmarkOrder >=`": (
            "index_ordering_benchmark_order_ge_mean_ms",
            "index benchmarkOrder >= ordering mean",
        ),
        "Ordering `benchmarkOrder <=`": (
            "index_ordering_benchmark_order_le_mean_ms",
            "index benchmarkOrder <= ordering mean",
        ),
    }

    for table in tables:
        headers = set(table.headers)

        if table.section == "Full Profile Results" and {
            "Product / runtime",
            "Profile",
        }.issubset(headers):
            for row in table.rows:
                if not is_opendr_product(row.get("Product / runtime")):
                    continue
                if row.get("Status", "").lower() != "success":
                    continue
                add_mapped_checks(
                    checks,
                    row=row,
                    profile=row["Profile"],
                    source="Full Profile Results",
                    mappings=full_profile_mappings,
                )

        if table.section == "Simple Bind Concurrency" and {
            "Product / runtime",
            "Profile",
            "Peak success ops/s",
        }.issubset(headers):
            for row in table.rows:
                if not is_opendr_product(row.get("Product / runtime")):
                    continue
                if row.get("Status", "").lower() != "success":
                    continue
                add_mapped_checks(
                    checks,
                    row=row,
                    profile=row["Profile"],
                    source="Simple Bind Concurrency",
                    mappings=concurrency_mappings,
                )

        if table.section == "SASL PLAIN Results" and {
            "Product / runtime",
            "Peak SASL success ops/s",
        }.issubset(headers):
            for row in table.rows:
                if not is_opendr_product(row.get("Product / runtime")):
                    continue
                add_mapped_checks(
                    checks,
                    row=row,
                    profile="sasl-auth",
                    source="SASL PLAIN Results",
                    mappings=sasl_mappings,
                )

        if table.section == "Index Type Results" and {
            "Product / runtime",
            "Profile",
            "Total runtime ms",
        }.issubset(headers):
            for row in table.rows:
                if not is_opendr_product(row.get("Product / runtime")):
                    continue
                if row.get("Status", "").lower() != "success":
                    continue
                add_mapped_checks(
                    checks,
                    row=row,
                    profile=row["Profile"],
                    source="Index Type Results",
                    mappings=index_profile_mappings,
                )

        if table.section == "Index Type Results" and {"Search probe", "Mean ms"}.issubset(headers):
            for row in table.rows:
                mapping = index_probe_mappings.get(row.get("Search probe", ""))
                if mapping is None:
                    continue
                baseline = parse_number(row.get("Mean ms"))
                if baseline is None:
                    continue
                checks.append(
                    BaselineCheck(
                        profile="index",
                        csv_metric=mapping[0],
                        label=mapping[1],
                        baseline=baseline,
                        direction="lower",
                        source="OpenDR indexed search latency",
                    )
                )

        if table.section == "Index Type Results" and {
            "Clients",
            "Failure %",
            "Success ops/s",
        }.issubset(headers):
            client_rows = [
                row
                for row in table.rows
                if parse_number(row.get("Clients")) is not None
                and parse_number(row.get("Success ops/s")) is not None
            ]
            if not client_rows:
                continue
            max_tested = max(parse_number(row["Clients"]) or 0.0 for row in client_rows)
            zero_failure_clients = [
                parse_number(row["Clients"]) or 0.0
                for row in client_rows
                if (parse_number(row.get("Failure %")) or 0.0) == 0.0
            ]
            max_zero_failure = max(zero_failure_clients, default=0.0)
            max_tested_failure = 0.0
            for row in client_rows:
                if parse_number(row["Clients"]) == max_tested:
                    max_tested_failure = parse_number(row.get("Failure %")) or 0.0
                    break
            peak_success = max(parse_number(row["Success ops/s"]) or 0.0 for row in client_rows)
            checks.extend(
                [
                    BaselineCheck(
                        profile="index",
                        csv_metric="max_concurrent_index_search_clients_tested",
                        label="max concurrent index-search clients tested",
                        baseline=max_tested,
                        direction="higher",
                        source="OpenDR mixed concurrent index-search results",
                    ),
                    BaselineCheck(
                        profile="index",
                        csv_metric="max_concurrent_index_search_clients_zero_failure",
                        label="max zero-failure concurrent index-search clients",
                        baseline=max_zero_failure,
                        direction="higher",
                        source="OpenDR mixed concurrent index-search results",
                    ),
                    BaselineCheck(
                        profile="index",
                        csv_metric="max_concurrent_index_search_failure_rate_percent",
                        label="max-tested concurrent index-search failure rate",
                        baseline=max_tested_failure,
                        direction="lower",
                        source="OpenDR mixed concurrent index-search results",
                    ),
                    BaselineCheck(
                        profile="index",
                        csv_metric="peak_concurrent_index_search_success_throughput",
                        label="peak concurrent index-search success throughput",
                        baseline=peak_success,
                        direction="higher",
                        source="OpenDR mixed concurrent index-search results",
                    ),
                ]
            )

    return checks


def read_current_rows(paths: list[Path], product: str) -> dict[str, dict[str, str]]:
    rows_by_profile: dict[str, dict[str, str]] = {}
    for path in paths:
        with path.open(newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row.get("product") != product:
                    continue
                profile = row.get("profile")
                if profile:
                    rows_by_profile[profile] = row
    return rows_by_profile


def degradation_percent(direction: str, current: float, baseline: float) -> float:
    if baseline == 0.0:
        if direction == "lower":
            return 0.0 if current <= baseline else math.inf
        return 0.0 if current >= baseline else math.inf

    if direction == "lower":
        return ((current - baseline) / abs(baseline)) * 100.0
    return ((baseline - current) / abs(baseline)) * 100.0


def check_failed(check: BaselineCheck, current: float, threshold_fraction: float) -> bool:
    if check.direction == "lower":
        if check.baseline == 0.0:
            return current > 0.0
        return current > check.baseline * (1.0 + threshold_fraction)
    if check.baseline == 0.0:
        return current < 0.0
    return current < check.baseline * (1.0 - threshold_fraction)


def format_percent(value: float) -> str:
    if math.isinf(value):
        return "inf"
    return f"{value:.2f}%"


def validate(
    *,
    checks: list[BaselineCheck],
    current_rows: dict[str, dict[str, str]],
    threshold_percent: float,
) -> tuple[bool, list[str]]:
    threshold_fraction = threshold_percent / 100.0
    report_lines = [
        "# Docker Performance Baseline Validation",
        "",
        f"- Threshold: {threshold_percent:.2f}%",
        f"- Checks: {len(checks)}",
        "",
        "| Status | Profile | Metric | Current | Baseline | Direction | Degradation | Source |",
        "|---|---|---|---:|---:|---|---:|---|",
    ]
    failed = False

    for check in checks:
        current_row = current_rows.get(check.profile)
        if current_row is None:
            failed = True
            report_lines.append(
                f"| fail | {check.profile} | {check.label} | missing profile | {check.baseline:.3f} | {check.direction} | n/a | {check.source} |"
            )
            continue

        if current_row.get("status") != "success":
            failed = True
            report_lines.append(
                f"| fail | {check.profile} | {check.label} | status {current_row.get('status', 'missing')} | {check.baseline:.3f} | {check.direction} | n/a | {check.source} |"
            )
            continue

        current = parse_number(current_row.get(check.csv_metric))
        if current is None:
            failed = True
            report_lines.append(
                f"| fail | {check.profile} | {check.label} | missing metric | {check.baseline:.3f} | {check.direction} | n/a | {check.source} |"
            )
            continue

        degradation = degradation_percent(check.direction, current, check.baseline)
        if check_failed(check, current, threshold_fraction):
            failed = True
            status = "fail"
        else:
            status = "pass"

        report_lines.append(
            f"| {status} | {check.profile} | {check.label} | {current:.3f} | {check.baseline:.3f} | {check.direction} | {format_percent(degradation)} | {check.source} |"
        )

    return not failed, report_lines


def main() -> int:
    args = parse_args()

    if args.threshold_percent < 0:
        print("--threshold-percent must be >= 0", file=sys.stderr)
        return 2

    checks = extract_baseline_checks(args.baseline_doc)
    if args.stable_gate:
        stable_metrics = {
            "total_elapsed_ms",
            "max_concurrent_bind_clients_tested",
            "max_concurrent_bind_clients_zero_failure",
            "max_concurrent_bind_failure_rate_percent",
            "max_concurrent_sasl_plain_bind_clients_tested",
            "max_concurrent_sasl_plain_bind_clients_zero_failure",
            "max_concurrent_sasl_plain_bind_failure_rate_percent",
            "max_concurrent_index_search_clients_tested",
            "max_concurrent_index_search_clients_zero_failure",
            "max_concurrent_index_search_failure_rate_percent",
        }
        checks = [check for check in checks if check.csv_metric in stable_metrics]
    if args.profile:
        profiles = set(args.profile)
        checks = [check for check in checks if check.profile in profiles]

    if not checks:
        print(f"No baseline checks parsed from {args.baseline_doc}", file=sys.stderr)
        return 2

    current_rows = read_current_rows(args.summary_csv, args.product)
    ok, report_lines = validate(
        checks=checks,
        current_rows=current_rows,
        threshold_percent=args.threshold_percent,
    )
    report = "\n".join(report_lines) + "\n"

    if args.report_out:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(report)

    print(report)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
