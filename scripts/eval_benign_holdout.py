#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.analysis.report_generator import AnalysisEngine
from src.common.defaults import (
    DEFAULT_ALERT_THRESHOLD,
    DEFAULT_BBK_TRAIN_WINDOW_SECONDS,
    DEFAULT_BENIGN_CORPUS_DIR,
    DEFAULT_BENIGN_HOLDOUT_RUN_ID,
    DEFAULT_TIME_BIN_SECONDS,
)
from src.common.io import read_json, write_json
from src.process.log_parser import TraceeLogParser
from src.process.streaming_reduction import StreamingReductionConfig, StreamingReducer
from src.process.window_io import dump_window_graph


def materialize_windows(trace_path: Path, windows_dir: Path, window_seconds: int, time_bin_seconds: int) -> int:
    parser = TraceeLogParser()
    logs = parser.parse_log_file(str(trace_path))
    reducer = StreamingReducer(
        config=StreamingReductionConfig(
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
        )
    )
    windows_dir.mkdir(parents=True, exist_ok=True)

    for stale in sorted(windows_dir.glob("window_*.json")):
        stale.unlink()

    count = 0
    for graph, _metas in reducer.ingest_logs(logs):
        count += 1
        dump_window_graph(str(windows_dir / f"window_{count:04d}.json"), graph)
    return count


def _window_index(window_id: str) -> int:
    match = re.search(r"(\d+)$", str(window_id or ""))
    if not match:
        return 0
    return int(match.group(1))


def _phase_for_offset(phases: list[dict[str, Any]], offset_seconds: float) -> dict[str, Any]:
    for phase in phases:
        start = float(phase.get("start_offset_seconds") or 0.0)
        end = float(phase.get("end_offset_seconds") or 0.0)
        if start <= float(offset_seconds) < end:
            return dict(phase)
    return {}


def _increment(mapping: dict[str, int], key: str) -> None:
    mapping[str(key)] = int(mapping.get(str(key), 0)) + 1


def evaluate_holdout_run(
    *,
    corpus_dir: Path,
    run_id: str,
    threshold: float,
    window_seconds: int,
    time_bin_seconds: int,
) -> dict[str, Any]:
    run_dir = resolve_holdout_run_dir(corpus_dir, run_id)
    trace_path = run_dir / "trace.log"
    run_meta_path = run_dir / "run_meta.json"
    if not trace_path.exists():
        raise FileNotFoundError(f"holdout trace not found: {trace_path}")
    if not run_meta_path.exists():
        raise FileNotFoundError(f"holdout run_meta not found: {run_meta_path}")

    run_meta = read_json(str(run_meta_path)) or {}
    split_role = str(run_meta.get("split_role") or run_meta.get("split") or "").strip().lower()
    if split_role != "holdout":
        raise ValueError(f"requested run is not marked holdout: {run_id} ({split_role})")
    warnings: list[str] = []
    meta_window_seconds = int(run_meta.get("window_seconds") or 0)
    meta_time_bin_seconds = int(run_meta.get("time_bin_seconds") or 0)
    if meta_window_seconds and int(meta_window_seconds) != int(window_seconds):
        warnings.append(
            f"window_seconds mismatch: run_meta={meta_window_seconds} requested={int(window_seconds)}"
        )
    if meta_time_bin_seconds and int(meta_time_bin_seconds) != int(time_bin_seconds):
        warnings.append(
            f"time_bin_seconds mismatch: run_meta={meta_time_bin_seconds} requested={int(time_bin_seconds)}"
        )

    existing_windows_dir = run_dir / "windows"
    if existing_windows_dir.is_dir() and list(existing_windows_dir.glob("window_*.json")):
        windows_dir = existing_windows_dir
        total_windows = len(list(existing_windows_dir.glob("window_*.json")))
    else:
        windows_dir = run_dir / f"windows_{int(window_seconds):02d}s"
        total_windows = materialize_windows(
            trace_path,
            windows_dir,
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
        )

    engine = AnalysisEngine()
    alerts = engine.detect_window_alerts_from_windows(str(windows_dir), threshold=float(threshold))
    false_positive_windows = int(len(alerts))
    duration_seconds = int(run_meta.get("duration_seconds") or (total_windows * int(window_seconds)))
    false_alarms_per_hour = (
        float(false_positive_windows) / max(float(duration_seconds) / 3600.0, 1e-9)
        if duration_seconds > 0
        else 0.0
    )
    phases = list(run_meta.get("phases") or [])
    false_positives_by_profile: dict[str, int] = {}
    false_positives_by_phase: dict[str, int] = {}
    total_windows_by_profile: dict[str, int] = {}
    total_windows_by_phase: dict[str, int] = {}
    for idx in range(1, int(total_windows) + 1):
        offset = float(idx - 1) * float(window_seconds)
        phase = _phase_for_offset(phases, offset)
        profile_id = str(phase.get("profile_id") or "unknown")
        phase_id = str(phase.get("phase_id") or "unknown")
        _increment(total_windows_by_profile, profile_id)
        _increment(total_windows_by_phase, phase_id)
    for alert in alerts:
        idx = _window_index(str(alert.window_id))
        offset = float(max(idx - 1, 0)) * float(window_seconds)
        phase = _phase_for_offset(phases, offset)
        _increment(false_positives_by_profile, str(phase.get("profile_id") or "unknown"))
        _increment(false_positives_by_phase, str(phase.get("phase_id") or "unknown"))

    return {
        "schema_version": 1,
        "metric_type": "benign_holdout",
        "run_id": run_id,
        "split_role": split_role or "holdout",
        "trace_out": str(trace_path),
        "windows_dir": str(windows_dir),
        "window_seconds": int(window_seconds),
        "time_bin_seconds": int(time_bin_seconds),
        "threshold": float(threshold),
        "configuration_warnings": warnings,
        "duration_seconds": int(duration_seconds),
        "total_windows": int(total_windows),
        "false_positive_windows": int(false_positive_windows),
        "false_positive_rate": (
            float(false_positive_windows) / float(total_windows)
            if total_windows > 0
            else 0.0
        ),
        "false_alarms_per_hour": float(false_alarms_per_hour),
        "alerts_per_minute": float(false_alarms_per_hour) / 60.0,
        "false_positives_by_profile": dict(sorted(false_positives_by_profile.items())),
        "false_positives_by_phase": dict(sorted(false_positives_by_phase.items())),
        "total_windows_by_profile": dict(sorted(total_windows_by_profile.items())),
        "total_windows_by_phase": dict(sorted(total_windows_by_phase.items())),
        "alert_window_ids": [str(alert.window_id) for alert in alerts],
        "alert_scores": {
            str(alert.window_id): float(alert.window_score)
            for alert in alerts
        },
    }


def resolve_holdout_run_dir(corpus_dir: Path, run_id: str) -> Path:
    requested = Path(str(run_id))
    candidates: list[Path] = []
    if requested.is_absolute():
        candidates.append(requested)
    else:
        candidates.extend(
            [
                corpus_dir / "holdout" / requested,
                corpus_dir / requested,
            ]
        )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", default=DEFAULT_BENIGN_CORPUS_DIR)
    ap.add_argument("--run-id", default=DEFAULT_BENIGN_HOLDOUT_RUN_ID)
    ap.add_argument("--threshold", type=float, default=DEFAULT_ALERT_THRESHOLD)
    ap.add_argument("--window-seconds", type=int, default=DEFAULT_BBK_TRAIN_WINDOW_SECONDS)
    ap.add_argument("--time-bin-seconds", type=int, default=DEFAULT_TIME_BIN_SECONDS)
    ap.add_argument(
        "--output",
        default="data/benchmarks_v3/benign_holdout/run_d_metrics.json",
        help="JSON summary output path",
    )
    args = ap.parse_args()

    summary = evaluate_holdout_run(
        corpus_dir=Path(args.corpus_dir),
        run_id=str(args.run_id),
        threshold=float(args.threshold),
        window_seconds=int(args.window_seconds),
        time_bin_seconds=int(args.time_bin_seconds),
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(str(output_path), summary)
    for warning in summary.get("configuration_warnings") or []:
        print(f"[benign-holdout] warning: {warning}", file=sys.stderr)

    print(
        "[benign-holdout] run=%s false_positive_windows=%d total_windows=%d false_alarms_per_hour=%.4f output=%s"
        % (
            summary["run_id"],
            int(summary["false_positive_windows"]),
            int(summary["total_windows"]),
            float(summary["false_alarms_per_hour"]),
            os.path.abspath(str(output_path)),
        )
    )


if __name__ == "__main__":
    main()
