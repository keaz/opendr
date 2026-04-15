#!/usr/bin/env python3
"""Compare two ldap_perf_client JSON reports and fail on regressions."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_METRICS = {
    "success_throughput_ops_per_sec": "higher",
    "mean_ms": "lower",
    "p95_ms": "lower",
    "failure_rate_percent": "lower",
}


@dataclass(frozen=True)
class CheckResult:
    operation: str
    metric: str
    direction: str
    baseline: float
    candidate: float
    change_percent: float
    status: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare ldap_perf_client JSON reports. Intended for CI-friendly "
            "100k/1M fixtures; use the documented 10M profile for manual runs."
        )
    )
    parser.add_argument("--baseline-json", type=Path, required=True)
    parser.add_argument("--candidate-json", type=Path, required=True)
    parser.add_argument(
        "--threshold-percent",
        type=float,
        default=10.0,
        help="Allowed regression before failing.",
    )
    parser.add_argument(
        "--operation",
        action="append",
        help="Operation name to compare; repeatable. Defaults to common operations.",
    )
    parser.add_argument(
        "--metric",
        action="append",
        choices=sorted(DEFAULT_METRICS),
        help="Metric to compare; repeatable. Defaults to key throughput/latency/failure metrics.",
    )
    parser.add_argument("--report-out", type=Path, help="Optional markdown report path.")
    return parser.parse_args()


def load_report(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc


def benchmark_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    benchmarks = report.get("benchmarks")
    if not isinstance(benchmarks, list):
        raise SystemExit("report is missing a benchmarks array")

    result = {}
    for item in benchmarks:
        operation = item.get("operation")
        if isinstance(operation, str):
            result[operation] = item
    return result


def number(item: dict[str, Any], metric: str) -> float | None:
    value = item.get(metric)
    if isinstance(value, (int, float)):
        return float(value)
    return None


def change_percent(baseline: float, candidate: float, direction: str) -> float:
    if baseline == 0:
        if candidate == 0:
            return 0.0
        return float("inf")
    if direction == "higher":
        return (candidate - baseline) * 100.0 / baseline
    return (baseline - candidate) * 100.0 / baseline


def compare_reports(args: argparse.Namespace) -> list[CheckResult]:
    baseline = benchmark_map(load_report(args.baseline_json))
    candidate = benchmark_map(load_report(args.candidate_json))
    operations = args.operation or sorted(set(baseline) & set(candidate))
    metrics = args.metric or list(DEFAULT_METRICS)

    results = []
    for operation in operations:
        if operation not in baseline:
            raise SystemExit(f"baseline is missing operation {operation!r}")
        if operation not in candidate:
            raise SystemExit(f"candidate is missing operation {operation!r}")

        for metric in metrics:
            baseline_value = number(baseline[operation], metric)
            candidate_value = number(candidate[operation], metric)
            if baseline_value is None or candidate_value is None:
                continue

            direction = DEFAULT_METRICS[metric]
            change = change_percent(baseline_value, candidate_value, direction)
            status = "pass" if change >= -args.threshold_percent else "regression"
            results.append(
                CheckResult(
                    operation=operation,
                    metric=metric,
                    direction=direction,
                    baseline=baseline_value,
                    candidate=candidate_value,
                    change_percent=change,
                    status=status,
                )
            )

    return results


def render_markdown(results: list[CheckResult], threshold_percent: float) -> str:
    lines = [
        "# Performance Regression Comparison",
        "",
        f"Allowed regression: `{threshold_percent:.2f}%`",
        "",
        "| Operation | Metric | Direction | Baseline | Candidate | Change % | Status |",
        "|---|---|---|---:|---:|---:|---|",
    ]
    for result in results:
        lines.append(
            "| {operation} | {metric} | {direction} | {baseline:.3f} | "
            "{candidate:.3f} | {change:.2f} | {status} |".format(
                operation=result.operation,
                metric=result.metric,
                direction=result.direction,
                baseline=result.baseline,
                candidate=result.candidate,
                change=result.change_percent,
                status=result.status,
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    results = compare_reports(args)
    report = render_markdown(results, args.threshold_percent)
    print(report)
    if args.report_out:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(report)
    return 1 if any(result.status == "regression" for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
