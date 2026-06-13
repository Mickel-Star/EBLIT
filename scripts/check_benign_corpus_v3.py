#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.common.io import safe_int
from src.process.log_parser import detect_trace_log_format

VALID_LEVELS = {"empty", "idle", "low_activity", "active", "burst"}
TRACE_FORMAT_COMPATIBILITY = {
    "json": {"jsonl"},
    "jsonl": {"jsonl"},
}
DEFAULT_RUN_SPLITS = {
    "run_a": "train",
    "run_b": "train",
    "run_c": "calibration",
    "run_d": "holdout",
}

REQUIRED_WINDOW_FIELDS = {
    "window_id",
    "run_id",
    "split",
    "start_ts",
    "end_ts",
    "request_count",
    "raw_event_count",
    "node_count",
    "edge_count",
    "activity_level",
}


def _read_json(path: Path, failures: list[str] | None = None, label: str = "") -> dict[str, Any]:
    if not path.is_file():
        if failures is not None:
            failures.append(f"missing {label or path}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        if failures is not None:
            failures.append(f"invalid {label or path}: {exc}")
        return {}
    if not isinstance(payload, dict):
        if failures is not None:
            failures.append(f"invalid {label or path}: expected JSON object")
        return {}
    return payload


def _read_jsonl(path: Path, failures: list[str] | None = None, label: str = "") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        if failures is not None:
            failures.append(f"missing {label or path}: {path}")
        return rows
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        for line_no, line in enumerate(fp, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception as exc:
                if failures is not None:
                    failures.append(f"{label or path}:{line_no}: invalid JSON: {exc}")
                continue
            if not isinstance(payload, dict):
                if failures is not None:
                    failures.append(f"{label or path}:{line_no}: expected JSON object")
                continue
            rows.append(payload)
    return rows


def _count_nonempty_lines(path: Path) -> int:
    if not path.exists() or path.stat().st_size <= 0:
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        return sum(1 for line in fp if line.strip())


def _trace_log_is_jsonl(path: Path) -> bool:
    return str(detect_trace_log_format(path).get("actual_trace_format") or "") == "jsonl"


def _parse_ts(value: Any) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _level_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(str(row.get("activity_level") or "") for row in rows)
    return {level: int(counter.get(level, 0)) for level in sorted(VALID_LEVELS)}


def _split_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(str(row.get("split") or "") for row in rows)
    return dict(sorted(counter.items()))


def _parse_csv(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _selected_run_splits(runs: str) -> dict[str, str]:
    if not runs:
        return dict(DEFAULT_RUN_SPLITS)
    selected = _parse_csv(runs)
    unknown = sorted(run_id for run_id in selected if run_id not in DEFAULT_RUN_SPLITS)
    if unknown:
        raise ValueError(f"unknown run id(s): {','.join(unknown)}")
    return {run_id: DEFAULT_RUN_SPLITS[run_id] for run_id in selected}


def _summary_records_trace_parse_failed(summary: dict[str, Any]) -> bool:
    warnings = [str(item) for item in summary.get("warnings") or []]
    errors = [str(item) for item in summary.get("errors") or []]
    return any("trace_parse_failed" in item for item in warnings + errors)


def check_window_activity(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Check benign corpus v3 window activity outputs.")
    parser.add_argument("--run-dir", required=True, help="Run directory.")
    parser.add_argument("--activity", default="", help="window_activity.jsonl path.")
    parser.add_argument("--summary", default="", help="window_activity_summary.json path.")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).expanduser().resolve()
    activity_path = Path(args.activity).expanduser().resolve() if args.activity else run_dir / "window_activity.jsonl"
    summary_path = Path(args.summary).expanduser().resolve() if args.summary else run_dir / "window_activity_summary.json"
    failures: list[str] = []

    if not activity_path.is_file():
        failures.append(f"missing window_activity.jsonl: {activity_path}")
    if not summary_path.is_file():
        failures.append(f"missing window_activity_summary.json: {summary_path}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    rows: list[dict[str, Any]] = []
    with activity_path.open("r", encoding="utf-8") as fp:
        for line_no, line in enumerate(fp, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception as exc:
                failures.append(f"line {line_no} is not valid JSON: {exc}")
                continue
            if not isinstance(row, dict):
                failures.append(f"line {line_no} is not a JSON object")
                continue
            missing = sorted(REQUIRED_WINDOW_FIELDS - set(row))
            if missing:
                failures.append(f"line {line_no} missing fields: {missing}")
            level = str(row.get("activity_level") or "")
            if level not in VALID_LEVELS:
                failures.append(f"line {line_no} invalid activity_level: {level}")
            rows.append(row)

    try:
        summary = _read_json(summary_path)
    except Exception as exc:
        summary = {}
        failures.append(f"invalid summary JSON: {exc}")

    previous_end: datetime | None = None
    for idx, row in enumerate(rows, start=1):
        try:
            start = _parse_ts(row.get("start_ts"))
            end = _parse_ts(row.get("end_ts"))
        except Exception as exc:
            failures.append(f"line {idx} invalid timestamps: {exc}")
            continue
        if end <= start:
            failures.append(f"line {idx} end_ts is not after start_ts")
        if previous_end is not None and start != previous_end:
            failures.append(f"line {idx} window is not continuous with previous end")
        previous_end = end

    if int(summary.get("window_count") or -1) != len(rows):
        failures.append(f"summary window_count != jsonl rows: {summary.get('window_count')} != {len(rows)}")

    request_events_path = run_dir / "request_events.jsonl"
    if _count_nonempty_lines(request_events_path) > 0:
        total_requests = sum(int(row.get("request_count") or 0) for row in rows)
        if total_requests <= 0:
            failures.append("request_events.jsonl is non-empty but total request_count is 0")

    trace_path = run_dir / "trace.log"
    if trace_path.exists() and trace_path.stat().st_size > 0:
        if not _trace_log_is_jsonl(trace_path):
            failures.append("trace.log is not JSON/JSONL; Tracee table output is not accepted")
        total_raw_events = sum(int(row.get("raw_event_count") or 0) for row in rows)
        if total_raw_events <= 0 and not _summary_records_trace_parse_failed(summary):
            failures.append("trace.log is non-empty but total raw_event_count is 0 and summary has no trace_parse_failed warning")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print(f"OK: window activity output is valid: {activity_path}")
    return 0


def check_manifest(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Check benign corpus v3 manifest outputs.")
    parser.add_argument("--corpus-dir", required=True, help="Benign corpus root directory.")
    parser.add_argument("--strict", action="store_true", help="Also check referenced run_meta/window_activity files.")
    args = parser.parse_args(argv)

    corpus_dir = Path(args.corpus_dir).expanduser().resolve()
    manifest_path = corpus_dir / "corpus_manifest.json"
    summary_path = corpus_dir / "corpus_summary.json"
    full_index_path = corpus_dir / "full_window_index.jsonl"
    sampled_path = corpus_dir / "sampled_train_windows.jsonl"
    failures: list[str] = []

    for path, label in (
        (manifest_path, "corpus_manifest.json"),
        (summary_path, "corpus_summary.json"),
        (full_index_path, "full_window_index.jsonl"),
        (sampled_path, "sampled_train_windows.jsonl"),
    ):
        if not path.is_file():
            failures.append(f"missing {label}: {path}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    try:
        manifest = _read_json(manifest_path)
    except Exception as exc:
        manifest = {}
        failures.append(f"invalid corpus_manifest.json: {exc}")
    try:
        summary = _read_json(summary_path)
    except Exception as exc:
        summary = {}
        failures.append(f"invalid corpus_summary.json: {exc}")

    full_rows = _read_jsonl(full_index_path, failures, "full_window_index.jsonl")
    sampled_rows = _read_jsonl(sampled_path, failures, "sampled_train_windows.jsonl")

    full_keys = {(str(row.get("split") or ""), str(row.get("run_id") or ""), str(row.get("window_id") or "")) for row in full_rows}
    full_window_ids = {str(row.get("window_id") or "") for row in full_rows}

    for idx, row in enumerate(full_rows, start=1):
        level = str(row.get("activity_level") or "")
        if level not in VALID_LEVELS:
            failures.append(f"full_window_index row {idx} invalid activity_level: {level}")
        if not row.get("split") or not row.get("run_id") or not row.get("window_id"):
            failures.append(f"full_window_index row {idx} missing split/run_id/window_id")
        if args.strict:
            for field in ("run_meta_path", "window_activity_path"):
                rel = row.get(field)
                if not rel or not (corpus_dir / str(rel)).is_file():
                    failures.append(f"full_window_index row {idx} missing referenced {field}: {rel}")

    for idx, row in enumerate(sampled_rows, start=1):
        split = str(row.get("split") or "")
        level = str(row.get("activity_level") or "")
        key = (split, str(row.get("run_id") or ""), str(row.get("window_id") or ""))
        if split != "train":
            failures.append(f"sampled row {idx} is not train split: {split}")
        if level == "empty":
            failures.append(f"sampled row {idx} contains empty window: {row.get('window_id')}")
        if level not in VALID_LEVELS:
            failures.append(f"sampled row {idx} invalid activity_level: {level}")
        if key not in full_keys:
            failures.append(f"sampled row {idx} not found in full index: {key}")
        if str(row.get("window_id") or "") not in full_window_ids:
            failures.append(f"sampled row {idx} window_id not found in full index: {row.get('window_id')}")

    manifest_splits = dict(manifest.get("splits") or {})
    actual_split_counts = _split_counts(full_rows)
    for split, payload_raw in sorted(manifest_splits.items()):
        payload = dict(payload_raw or {})
        expected = int(payload.get("full_window_count") or 0)
        actual = int(actual_split_counts.get(split, 0))
        if expected != actual:
            failures.append(f"manifest split {split} full_window_count mismatch: {expected} != {actual}")
    train_manifest = dict(manifest_splits.get("train") or {})
    if int(train_manifest.get("sampled_window_count") or 0) != len(sampled_rows):
        failures.append(
            f"manifest train sampled_window_count mismatch: {train_manifest.get('sampled_window_count')} != {len(sampled_rows)}"
        )

    sampled_non_train = [row for row in sampled_rows if str(row.get("split") or "") != "train"]
    if sampled_non_train:
        failures.append("calibration/holdout or other non-train splits were sampled")

    constraints = dict(manifest.get("sampling") or {})
    max_idle = float(constraints.get("max_idle_fraction_in_sampled_train", 0.10))
    idle_count = sum(1 for row in sampled_rows if row.get("activity_level") == "idle")
    idle_fraction = float(idle_count / len(sampled_rows)) if sampled_rows else 0.0
    if idle_fraction > max_idle + 1e-12:
        failures.append(f"idle fraction exceeds limit: {idle_fraction:.6f} > {max_idle:.6f}")

    sampled_counts = _level_counts(sampled_rows)
    if sampled_counts.get("empty", 0) > 0:
        failures.append("sampled_train_windows contains empty windows")

    if int(summary.get("total_full_windows", -1)) != len(full_rows):
        failures.append(f"summary total_full_windows mismatch: {summary.get('total_full_windows')} != {len(full_rows)}")
    if int(summary.get("total_sampled_train_windows", -1)) != len(sampled_rows):
        failures.append(
            f"summary total_sampled_train_windows mismatch: {summary.get('total_sampled_train_windows')} != {len(sampled_rows)}"
        )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print(f"OK: benign corpus v3 manifest is valid: {corpus_dir}")
    return 0


def _check_run(
    *,
    corpus_dir: Path,
    run_id: str,
    split: str,
    allow_missing_trace: bool,
    strict: bool,
    failures: list[str],
    warnings: list[str],
) -> int:
    run_dir = corpus_dir / split / run_id
    if not run_dir.is_dir():
        failures.append(f"missing run dir: {split}/{run_id}")
        return 0

    required = [
        "effective_config.yaml",
        "run_meta.json",
        "driver.log",
        "request_events.jsonl",
        "workload_summary.json",
        "collection_summary.json",
        "window_activity.jsonl",
        "window_activity_summary.json",
    ]
    if not allow_missing_trace:
        required.append("trace.log")
    for name in required:
        path = run_dir / name
        if not path.is_file():
            failures.append(f"missing {split}/{run_id}/{name}")
        elif name in {"trace.log", "request_events.jsonl", "window_activity.jsonl"} and path.stat().st_size <= 0:
            failures.append(f"empty {split}/{run_id}/{name}")

    request_lines = _count_nonempty_lines(run_dir / "request_events.jsonl")
    if request_lines <= 0:
        failures.append(f"{split}/{run_id}: request_events.jsonl has no rows")

    workload = _read_json(run_dir / "workload_summary.json", failures, f"{split}/{run_id}/workload_summary.json")
    if safe_int(workload.get("total_requests"), 0) <= 0:
        failures.append(f"{split}/{run_id}: workload_summary total_requests <= 0")

    collection = _read_json(run_dir / "collection_summary.json", failures, f"{split}/{run_id}/collection_summary.json")
    driver = dict(collection.get("driver") or {})
    if safe_int(driver.get("exit_code"), -1) != 0:
        failures.append(f"{split}/{run_id}: driver.exit_code != 0 ({driver.get('exit_code')})")
    if not allow_missing_trace:
        trace_path = run_dir / "trace.log"
        if not trace_path.is_file() or trace_path.stat().st_size <= 0:
            failures.append(f"{split}/{run_id}: trace.log missing or empty")
        elif not _trace_log_is_jsonl(trace_path):
            failures.append(f"{split}/{run_id}: trace.log is not JSON/JSONL; table output is not accepted")

    activity_rows = _read_jsonl(run_dir / "window_activity.jsonl", failures, f"{split}/{run_id}/window_activity.jsonl")
    if not activity_rows:
        failures.append(f"{split}/{run_id}: window_activity.jsonl has no rows")
    for idx, row in enumerate(activity_rows, start=1):
        level = str(row.get("activity_level") or "")
        if level not in VALID_LEVELS:
            failures.append(f"{split}/{run_id}: window {idx} invalid activity_level={level}")
        if str(row.get("split") or "") != split:
            failures.append(f"{split}/{run_id}: window {idx} split mismatch: {row.get('split')}")
        if str(row.get("run_id") or "") != run_id:
            failures.append(f"{split}/{run_id}: window {idx} run_id mismatch: {row.get('run_id')}")

    effective = _read_json(run_dir / "effective_config.yaml", failures, f"{split}/{run_id}/effective_config.yaml")
    collection_cfg = dict(effective.get("collection") or {})
    configured_output_format = str(collection_cfg.get("tracee_output_format") or "json").strip().lower()
    if configured_output_format not in TRACE_FORMAT_COMPATIBILITY:
        failures.append(
            f"{split}/{run_id}: effective_config collection.tracee_output_format must be json/jsonl, got {configured_output_format}"
        )
    tracee_summary = dict(collection.get("tracee") or {})
    summary_format = str(tracee_summary.get("output_format") or "json").strip().lower()
    if summary_format not in {"json", "jsonl"}:
        failures.append(f"{split}/{run_id}: collection_summary tracee.output_format must be json/jsonl, got {summary_format}")
    summary_configured_output_format = str(tracee_summary.get("configured_output_format") or "").strip().lower()
    if summary_configured_output_format and summary_configured_output_format != configured_output_format:
        warnings.append(
            f"{split}/{run_id}: collection_summary configured_output_format mismatch: "
            f"{summary_configured_output_format} != {configured_output_format}"
        )
    trace_detection = dict(tracee_summary.get("trace_format_detection") or detect_trace_log_format(run_dir / "trace.log"))
    actual_trace_format = str(tracee_summary.get("actual_trace_format") or trace_detection.get("actual_trace_format") or "missing").strip().lower()
    if not allow_missing_trace and configured_output_format in TRACE_FORMAT_COMPATIBILITY:
        compatible_actual_formats = TRACE_FORMAT_COMPATIBILITY.get(configured_output_format, set())
        if actual_trace_format not in compatible_actual_formats:
            failures.append(
                f"{split}/{run_id}: trace format mismatch: configured_output_format={configured_output_format}, "
                f"actual_trace_format={actual_trace_format}"
            )
        elif configured_output_format != actual_trace_format:
            warnings.append(
                f"{split}/{run_id}: trace format alias: configured_output_format={configured_output_format}, "
                f"actual_trace_format={actual_trace_format}"
            )
    run_meta = _read_json(run_dir / "run_meta.json", failures, f"{split}/{run_id}/run_meta.json")
    if str(run_meta.get("split") or "") != split:
        failures.append(f"{split}/{run_id}: run_meta split mismatch: {run_meta.get('split')}")
    if safe_int(run_meta.get("random_seed"), -1) != safe_int(effective.get("random_seed"), -2):
        failures.append(f"{split}/{run_id}: run_meta random_seed != effective_config random_seed")
    if str(effective.get("split") or "") != split:
        failures.append(f"{split}/{run_id}: effective_config split mismatch: {effective.get('split')}")
    if str(effective.get("run_id") or "") != run_id:
        failures.append(f"{split}/{run_id}: effective_config run_id mismatch: {effective.get('run_id')}")

    if strict and collection.get("errors"):
        failures.append(f"{split}/{run_id}: collection_summary has errors: {collection.get('errors')}")
    elif collection.get("errors"):
        warnings.append(f"{split}/{run_id}: collection_summary has errors: {collection.get('errors')}")
    return sum(1 for row in activity_rows if str(row.get("activity_level") or "") != "empty")


def check_formal(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Check formal benign corpus v3 outputs.")
    parser.add_argument("--corpus-dir", required=True, help="Formal benign corpus root.")
    parser.add_argument("--allow-missing-trace", action="store_true", help="Allow skip-tracee collection outputs.")
    parser.add_argument("--strict", action="store_true", help="Promote quality warnings to failures.")
    parser.add_argument("--min-nonempty-windows", type=int, default=120, help="Minimum non-empty windows across checked runs.")
    parser.add_argument("--max-idle-empty-fraction", type=float, default=0.30, help="Warn/fail if full corpus idle+empty fraction exceeds this.")
    parser.add_argument("--runs", default="", help="Optional comma-separated run IDs to check.")
    args = parser.parse_args(argv)

    corpus_dir = Path(args.corpus_dir).expanduser().resolve()
    failures: list[str] = []
    warnings: list[str] = []
    try:
        run_splits = _selected_run_splits(args.runs)
    except Exception as exc:
        print(f"FAIL: {exc}")
        return 2

    if not corpus_dir.is_dir():
        print(f"FAIL: corpus_dir does not exist: {corpus_dir}")
        return 1

    nonempty_windows = 0
    for run_id, split in run_splits.items():
        nonempty_windows += _check_run(
            corpus_dir=corpus_dir,
            run_id=run_id,
            split=split,
            allow_missing_trace=bool(args.allow_missing_trace),
            strict=bool(args.strict),
            failures=failures,
            warnings=warnings,
        )

    manifest = _read_json(corpus_dir / "corpus_manifest.json", failures, "corpus_manifest.json")
    summary = _read_json(corpus_dir / "corpus_summary.json", failures, "corpus_summary.json")
    full_rows = _read_jsonl(corpus_dir / "full_window_index.jsonl", failures, "full_window_index.jsonl")
    sampled_rows = _read_jsonl(corpus_dir / "sampled_train_windows.jsonl", failures, "sampled_train_windows.jsonl")

    for idx, row in enumerate(full_rows, start=1):
        level = str(row.get("activity_level") or "")
        if level not in VALID_LEVELS:
            failures.append(f"full_window_index row {idx} invalid activity_level={level}")
    sampled_run_ids = {str(row.get("run_id") or "") for row in sampled_rows}
    for idx, row in enumerate(sampled_rows, start=1):
        split = str(row.get("split") or "")
        level = str(row.get("activity_level") or "")
        if split != "train":
            failures.append(f"sampled_train_windows row {idx} is not train: {split}")
        if str(row.get("run_id") or "") not in {"run_a", "run_b"}:
            failures.append(f"sampled_train_windows row {idx} has non-train run_id: {row.get('run_id')}")
        if level == "empty":
            failures.append(f"sampled_train_windows row {idx} contains empty window")
        if level not in VALID_LEVELS:
            failures.append(f"sampled_train_windows row {idx} invalid activity_level={level}")
    if any(run_id in sampled_run_ids for run_id in {"run_c", "run_d"}):
        failures.append("calibration or holdout run was sampled into sampled_train_windows")

    train_full = sum(1 for row in full_rows if str(row.get("split") or "") == "train")
    if train_full <= 0:
        failures.append("train full_window_count <= 0")
    if len(sampled_rows) <= 0:
        failures.append("sampled_train_windows has no rows")
    if nonempty_windows < int(args.min_nonempty_windows):
        failures.append(f"nonempty window count below minimum: {nonempty_windows} < {args.min_nonempty_windows}")

    full_counts = _level_counts(full_rows)
    idle_empty_count = int(full_counts.get("idle", 0)) + int(full_counts.get("empty", 0))
    idle_empty_fraction = float(idle_empty_count / len(full_rows)) if full_rows else 0.0
    if idle_empty_fraction > float(args.max_idle_empty_fraction):
        message = f"idle+empty fraction high: {idle_empty_fraction:.6f} > {args.max_idle_empty_fraction:.6f}"
        (failures if args.strict else warnings).append(message)

    manifest_splits = dict(manifest.get("splits") or {})
    train_manifest = dict(manifest_splits.get("train") or {})
    if safe_int(train_manifest.get("sampled_window_count"), -1) != len(sampled_rows):
        failures.append(
            f"manifest train sampled_window_count mismatch: {train_manifest.get('sampled_window_count')} != {len(sampled_rows)}"
        )
    if safe_int(summary.get("total_sampled_train_windows"), -1) != len(sampled_rows):
        failures.append(
            f"corpus_summary total_sampled_train_windows mismatch: {summary.get('total_sampled_train_windows')} != {len(sampled_rows)}"
        )

    report = _read_json(corpus_dir / "formal_benign_collection_report.json", failures, "formal_benign_collection_report.json")
    report_errors = list(report.get("errors") or [])
    if report_errors:
        failures.append(f"formal report has errors: {report_errors}")
    for run_id, expected_split in run_splits.items():
        run_report = dict((report.get("runs") or {}).get(run_id) or {})
        if str(run_report.get("split") or "") != expected_split:
            failures.append(f"report {run_id} split mismatch: {run_report.get('split')}")
        if str(run_report.get("status") or "") not in {"success", "skipped"}:
            failures.append(f"report {run_id} status is not success/skipped: {run_report.get('status')}")
        configured_output_format = str(run_report.get("configured_output_format") or "").strip().lower()
        actual_trace_format = str(run_report.get("actual_trace_format") or "").strip().lower()
        if not configured_output_format:
            failures.append(f"report {run_id} missing configured_output_format")
        if not args.allow_missing_trace and not actual_trace_format:
            failures.append(f"report {run_id} missing actual_trace_format")
        if not args.allow_missing_trace and configured_output_format in TRACE_FORMAT_COMPATIBILITY and actual_trace_format:
            if actual_trace_format not in TRACE_FORMAT_COMPATIBILITY.get(configured_output_format, set()):
                failures.append(
                    f"report {run_id} trace format mismatch: "
                    f"configured_output_format={configured_output_format}, actual_trace_format={actual_trace_format}"
                )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        for warning in warnings:
            print(f"WARN: {warning}")
        return 1
    for warning in warnings:
        print(f"WARN: {warning}")
    print(f"OK: formal benign corpus v3 is valid: {corpus_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(argv if argv is not None else sys.argv[1:])
    if not raw or raw[0] not in ("window-activity", "manifest", "formal"):
        print("Usage: check_benign_corpus_v3.py {window-activity|manifest|formal} [options]")
        return 2
    cmd, rest = raw[0], raw[1:]
    if cmd == "window-activity":
        return check_window_activity(rest)
    if cmd == "manifest":
        return check_manifest(rest)
    if cmd == "formal":
        return check_formal(rest)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
