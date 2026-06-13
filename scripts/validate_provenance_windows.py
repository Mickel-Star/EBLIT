#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.process.benign_workload_driver import load_config
from src.process.log_parser import TraceeLogParser


DEFAULT_CONFIG = ROOT_DIR / "configs" / "benign_corpus_v4_rich.yaml"
DEFAULT_THRESHOLDS = {
    "min_windows": 1,
    "min_nodes": 500,
    "min_edges": 500,
    "min_process_nodes": 100,
    "min_file_nodes": 250,
    "min_net_nodes": 30,
    "min_event_types": 6,
    "min_median_nodes": 0,
    "min_median_edges": 0,
    "min_median_process_nodes": 0,
}


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT_DIR / path


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                rows.append(parsed)
        except Exception:
            continue
    return rows


def node_type(node: dict[str, Any]) -> str:
    node_id = str(node.get("id") or "")
    if node_id.startswith("proc:"):
        return "proc"
    if node_id.startswith("file:"):
        return "file"
    if node_id.startswith("net:"):
        return "net"
    return "other"


def graph_stats(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    nodes = list(payload.get("nodes") or [])
    edges = list(payload.get("edges") or [])
    node_counts = {"proc": 0, "file": 0, "net": 0, "other": 0}
    for node in nodes:
        node_counts[node_type(node)] += 1
    event_types: set[str] = set()
    for edge in edges:
        for name in list(edge.get("event_names") or []):
            if name:
                event_types.add(str(name))
        name = str(edge.get("event_name") or "")
        if name:
            event_types.add(name)
    return {
        "file": path.name,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "process_node_count": node_counts["proc"],
        "file_node_count": node_counts["file"],
        "net_node_count": node_counts["net"],
        "other_node_count": node_counts["other"],
        "event_type_count": len(event_types),
        "event_types": sorted(event_types),
    }


def median_int(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(int(value) for value in values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return int(round((ordered[mid - 1] + ordered[mid]) / 2.0))


def distribution_summary(stats: list[dict[str, Any]]) -> dict[str, Any]:
    fields = [
        "node_count",
        "edge_count",
        "process_node_count",
        "file_node_count",
        "net_node_count",
        "event_type_count",
    ]
    summary: dict[str, Any] = {}
    for field in fields:
        values = [safe_int(row.get(field)) for row in stats]
        summary[field] = {
            "min": min(values) if values else 0,
            "median": median_int(values),
            "max": max(values) if values else 0,
        }
    return summary


def infer_config(windows_dir: Path, explicit: str) -> dict[str, Any]:
    candidates = []
    if explicit:
        candidates.append(resolve_path(explicit))
    candidates.extend([windows_dir.parent / "effective_config.json", DEFAULT_CONFIG])
    for path in candidates:
        if path.exists():
            return load_config(path)
    return {}


def threshold_config(config: dict[str, Any], args: argparse.Namespace) -> dict[str, int]:
    values = dict(DEFAULT_THRESHOLDS)
    if isinstance(config.get("validation_thresholds"), dict):
        for key, value in dict(config["validation_thresholds"]).items():
            if key in values:
                values[key] = safe_int(value, values[key])
    for key in values:
        override = getattr(args, key, None)
        if override is not None:
            values[key] = int(override)
    return values


def validate_windows(stats: list[dict[str, Any]], thresholds: dict[str, int]) -> tuple[dict[str, Any] | None, list[str]]:
    failures: list[str] = []
    if not stats:
        return None, ["no window_*.json files found"]
    best = max(stats, key=lambda row: (safe_int(row.get("node_count")), safe_int(row.get("edge_count"))))
    distribution = distribution_summary(stats)
    if len(stats) < int(thresholds.get("min_windows", 1)):
        failures.append(f"window_count below threshold: {len(stats)} < {thresholds.get('min_windows')}")
    checks = [
        ("node_count", "min_nodes"),
        ("edge_count", "min_edges"),
        ("process_node_count", "min_process_nodes"),
        ("file_node_count", "min_file_nodes"),
        ("net_node_count", "min_net_nodes"),
        ("event_type_count", "min_event_types"),
    ]
    for stat_key, threshold_key in checks:
        observed = safe_int(best.get(stat_key))
        required = int(thresholds[threshold_key])
        if observed < required:
            failures.append(f"{stat_key} below threshold: {observed} < {required}")
    median_checks = [
        ("node_count", "min_median_nodes"),
        ("edge_count", "min_median_edges"),
        ("process_node_count", "min_median_process_nodes"),
    ]
    for stat_key, threshold_key in median_checks:
        required = int(thresholds.get(threshold_key, 0))
        if required <= 0:
            continue
        observed = safe_int(dict(distribution.get(stat_key) or {}).get("median"))
        if observed < required:
            failures.append(f"median {stat_key} below threshold: {observed} < {required}")
    if safe_int(best.get("process_node_count")) <= 0 or safe_int(best.get("file_node_count")) <= 0 or safe_int(best.get("net_node_count")) <= 0:
        failures.append("node type coverage is incomplete; proc/file/net must all be present")
    return best, failures


def validate_request_events(events: list[dict[str, Any]], config: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    actors = {str(row.get("actor") or "") for row in events}
    actions = {str(row.get("action") or "") for row in events}
    expected_actors = [str(item) for item in list(config.get("expected_actors") or [])]
    expected_actions = [str(item) for item in list(config.get("expected_actions") or [])]
    for actor in expected_actors:
        if actor not in actors:
            failures.append(f"missing actor in request_events: {actor}")
    for action in expected_actions:
        if action not in actions:
            failures.append(f"missing action in request_events: {action}")
    if not events:
        failures.append("request_events.jsonl has no parseable rows")
    return failures


def trace_stats_for_run(windows_dir: Path) -> dict[str, Any]:
    trace_path = windows_dir.parent / "trace.log"
    if not trace_path.exists():
        return {"trace_log_exists": False, "trace_lines_failed": 0, "trace_lines_total": 0, "trace_lines_parsed": 0}
    _logs, stats = TraceeLogParser().parse_log_file_with_stats(str(trace_path))
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate rich benign provenance window graphs.")
    parser.add_argument("--windows-dir", required=True)
    parser.add_argument("--request-events", required=True)
    parser.add_argument("--config", default="")
    parser.add_argument("--allow-missing-trace", action="store_true")
    parser.add_argument("--min-nodes", type=int, default=None)
    parser.add_argument("--min-edges", type=int, default=None)
    parser.add_argument("--min-process-nodes", type=int, default=None)
    parser.add_argument("--min-file-nodes", type=int, default=None)
    parser.add_argument("--min-net-nodes", type=int, default=None)
    parser.add_argument("--min-event-types", type=int, default=None)
    parser.add_argument("--min-windows", type=int, default=None)
    parser.add_argument("--min-median-nodes", type=int, default=None)
    parser.add_argument("--min-median-edges", type=int, default=None)
    parser.add_argument("--min-median-process-nodes", type=int, default=None)
    args = parser.parse_args()

    windows_dir = resolve_path(args.windows_dir)
    request_events_path = resolve_path(args.request_events)
    config = infer_config(windows_dir, args.config)
    thresholds = threshold_config(config, args)

    window_files = sorted(windows_dir.glob("window_*.json"))
    stats = [graph_stats(path) for path in window_files]
    best, failures = validate_windows(stats, thresholds)
    events = load_jsonl(request_events_path)
    failures.extend(validate_request_events(events, config))
    trace_stats = trace_stats_for_run(windows_dir)
    if not bool(trace_stats.get("trace_log_exists")) and not args.allow_missing_trace:
        failures.append("trace.log is missing")
    if safe_int(trace_stats.get("trace_lines_non_json")) != 0:
        failures.append(f"trace_lines_non_json is non-zero: {trace_stats.get('trace_lines_non_json')}")
    if safe_int(trace_stats.get("trace_lines_failed")) != 0:
        failures.append(f"trace_lines_failed is non-zero: {trace_stats.get('trace_lines_failed')}")

    summary = {
        "status": "failed" if failures else "passed",
        "windows_dir": str(windows_dir),
        "request_events": str(request_events_path),
        "thresholds": thresholds,
        "window_count": len(stats),
        "best_window": best,
        "window_distribution": distribution_summary(stats),
        "request_event_count": len(events),
        "observed_actors": sorted({str(row.get("actor") or "") for row in events}),
        "observed_actions": sorted({str(row.get("action") or "") for row in events}),
        "trace_stats": trace_stats,
        "failures": failures,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
