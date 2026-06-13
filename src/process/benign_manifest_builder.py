#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from src.common.io import (
    ACTIVITY_LEVELS,
    activity_counts,
    load_mapping,
    parse_csv,
    read_json,
    read_jsonl,
    relpath,
    safe_bool,
    safe_float,
    safe_int,
    utc_now_str,
    write_json,
    write_jsonl,
)
from src.process.benign_workload_driver import load_config
from src.process.log_parser import detect_trace_log_format


DEFAULT_INCLUDE_SPLITS = ("train", "calibration", "holdout")
DEFAULT_POLICY_VERSION = "benign_manifest_v3_default"
DEFAULT_TRAIN_POLICY: dict[str, float] = {
    "active": 1.0,
    "burst": 1.0,
    "low_activity": 0.5,
    "idle": 0.1,
    "empty": 0.0,
}
DEFAULT_SAMPLING = {
    "min_train_windows": 100,
    "max_idle_fraction_in_sampled_train": 0.10,
    "max_empty_fraction_in_sampled_train": 0.00,
    "stratified_by_run": True,
    "stratified_by_activity_level": True,
}
KNOWN_WINDOWS_DIRS = ("windows", "processed_windows", "debug_windows", "persisted_windows", "realtime_windows")
DEFAULT_RUN_ORDER = ("run_a", "run_b", "run_c", "run_d")
SPLITS = ("train", "calibration", "holdout")
TRACE_FORMAT_COMPATIBILITY = {
    "json": {"jsonl"},
    "jsonl": {"jsonl"},
}


def path_for_manifest(path: Path) -> str:
    try:
        return os.path.relpath(str(path.resolve()), os.getcwd())
    except Exception:
        return str(path)


def stable_random(seed: int, *parts: str) -> random.Random:
    digest = hashlib.sha256((":".join([str(seed), *parts])).encode("utf-8")).hexdigest()
    return random.Random(int(digest[:16], 16))


def output_exists(paths: list[Path]) -> list[Path]:
    return [path for path in paths if path.exists()]


def load_sampling_config(path: Path, warnings: list[str]) -> dict[str, Any]:
    if not path.exists():
        warnings.append(f"sampling_config_not_found_using_defaults:{path}")
        return {}
    payload = load_mapping(path)
    if not payload:
        warnings.append(f"sampling_config_parse_failed_using_defaults:{path}")
    return payload


def split_config(payload: dict[str, Any], split: str) -> dict[str, Any]:
    splits = payload.get("splits")
    if isinstance(splits, dict) and isinstance(splits.get(split), dict):
        return dict(splits.get(split) or {})
    return {}


def train_sampling_policy(config: dict[str, Any]) -> dict[str, float]:
    raw = split_config(config, "train").get("sampling_policy")
    policy = dict(DEFAULT_TRAIN_POLICY)
    if isinstance(raw, dict):
        for level in ACTIVITY_LEVELS:
            if level in raw:
                policy[level] = max(min(safe_float(raw.get(level), policy[level]), 1.0), 0.0)
    return policy


def sampling_constraints(config: dict[str, Any]) -> dict[str, Any]:
    constraints = dict(DEFAULT_SAMPLING)
    raw = config.get("sampling")
    if isinstance(raw, dict):
        for key in list(constraints):
            if key not in raw:
                continue
            if isinstance(constraints[key], bool):
                constraints[key] = safe_bool(raw.get(key), bool(constraints[key]))
            elif isinstance(constraints[key], int):
                constraints[key] = safe_int(raw.get(key), int(constraints[key]))
            else:
                constraints[key] = safe_float(raw.get(key), float(constraints[key]))
    return constraints


def configured_runs(config: dict[str, Any], split: str) -> list[str]:
    raw = split_config(config, split).get("runs")
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    if isinstance(raw, str):
        return parse_csv(raw)
    return []


def discover_run_dirs(corpus_dir: Path, split: str, config: dict[str, Any], warnings: list[str], errors: list[str], strict: bool) -> list[Path]:
    split_dir = corpus_dir / split
    requested = configured_runs(config, split)
    run_dirs: list[Path] = []
    if requested:
        for run_id in requested:
            path = split_dir / run_id
            if path.is_dir():
                run_dirs.append(path)
            else:
                message = f"configured_run_missing:{split}/{run_id}"
                (errors if strict else warnings).append(message)
        return sorted(run_dirs, key=lambda item: item.name)

    if not split_dir.exists():
        warnings.append(f"split_dir_missing:{split}")
        return []
    if not split_dir.is_dir():
        message = f"split_path_not_directory:{split}"
        (errors if strict else warnings).append(message)
        return []
    return sorted([path for path in split_dir.iterdir() if path.is_dir()], key=lambda item: item.name)


def maybe_add_smoke_split(corpus_dir: Path, include_splits: list[str], warnings: list[str]) -> list[str]:
    if any((corpus_dir / split).is_dir() for split in include_splits):
        return include_splits
    if "smoke" not in include_splits and (corpus_dir / "smoke").is_dir():
        warnings.append("default_splits_missing_using_smoke_split")
        return [*include_splits, "smoke"]
    return include_splits


def infer_window_graph_path(run_dir: Path, window_id: str, sequence: int) -> tuple[Path | None, Path | None]:
    candidates: list[Path] = []
    for name in KNOWN_WINDOWS_DIRS:
        windows_dir = run_dir / name
        if not windows_dir.is_dir():
            continue
        candidates.extend(
            [
                windows_dir / f"window_{sequence:04d}.json",
                windows_dir / f"window_{sequence:06d}.json",
                windows_dir / f"{window_id}.json",
            ]
        )
        for candidate in candidates:
            if candidate.is_file():
                return candidate, windows_dir
    return None, None


def normalize_window_record(
    *,
    corpus_dir: Path,
    split: str,
    run_dir: Path,
    run_meta: dict[str, Any],
    row: dict[str, Any],
    sequence: int,
    warnings: list[str],
) -> dict[str, Any]:
    run_id = str(row.get("run_id") or run_meta.get("run_id") or run_dir.name)
    window_id = str(row.get("window_id") or f"{run_id}_w{sequence:06d}")
    trace_path = run_dir / "trace.log"
    run_meta_path = run_dir / "run_meta.json"
    activity_path = run_dir / "window_activity.jsonl"
    activity_summary = read_json(run_dir / "window_activity_summary.json")
    graph_path, windows_dir = infer_window_graph_path(run_dir, window_id, sequence)
    graph_stats_source = str(activity_summary.get("graph_stats_source") or row.get("graph_stats_source") or "")
    if graph_path is None:
        warnings.append(f"window_graph_path_unavailable:{split}/{run_dir.name}/{window_id}")

    if not trace_path.exists():
        trace_log_path: str | None = None
    else:
        trace_log_path = relpath(trace_path, corpus_dir)
    return {
        "dataset": str(row.get("dataset") or run_meta.get("dataset") or "benign_corpus_v3"),
        "split": split,
        "run_id": run_id,
        "window_id": window_id,
        "window_sequence": int(sequence),
        "start_ts": row.get("start_ts"),
        "end_ts": row.get("end_ts"),
        "duration_seconds": safe_int(row.get("duration_seconds"), 30),
        "activity_level": str(row.get("activity_level") or "empty"),
        "dominant_phase": row.get("dominant_phase"),
        "active_roles": list(row.get("active_roles") or []),
        "dominant_profiles": list(row.get("dominant_profiles") or []),
        "request_count": safe_int(row.get("request_count"), 0),
        "success_count": safe_int(row.get("success_count"), 0),
        "failure_count": safe_int(row.get("failure_count"), 0),
        "retry_count": safe_int(row.get("retry_count"), 0),
        "raw_event_count": safe_int(row.get("raw_event_count"), 0),
        "node_count": safe_int(row.get("node_count"), 0),
        "edge_count": safe_int(row.get("edge_count"), 0),
        "unique_process_count": safe_int(row.get("unique_process_count"), 0),
        "unique_file_count": safe_int(row.get("unique_file_count"), 0),
        "unique_net_count": safe_int(row.get("unique_net_count"), 0),
        "window_activity_path": relpath(activity_path, corpus_dir),
        "window_activity_summary_path": relpath(run_dir / "window_activity_summary.json", corpus_dir)
        if (run_dir / "window_activity_summary.json").exists()
        else None,
        "trace_log_path": trace_log_path,
        "run_meta_path": relpath(run_meta_path, corpus_dir) if run_meta_path.exists() else None,
        "window_graph_path": relpath(graph_path, corpus_dir) if graph_path else None,
        "windows_dir": relpath(windows_dir, corpus_dir) if windows_dir else None,
        "graph_stats_source": graph_stats_source or ("windows_dir" if graph_path else "unavailable"),
    }


def load_run_windows(
    *,
    corpus_dir: Path,
    split: str,
    run_dir: Path,
    strict: bool,
    warnings: list[str],
    errors: list[str],
) -> list[dict[str, Any]]:
    activity_path = run_dir / "window_activity.jsonl"
    run_meta_path = run_dir / "run_meta.json"
    if not run_meta_path.exists():
        message = f"missing_run_meta:{split}/{run_dir.name}"
        (errors if strict else warnings).append(message)
    run_meta = read_json(run_meta_path)

    if not activity_path.exists() or activity_path.stat().st_size <= 0:
        message = f"missing_window_activity:{split}/{run_dir.name}"
        (errors if strict else warnings).append(message)
        return []

    try:
        rows = read_jsonl(activity_path)
    except Exception as exc:
        message = f"window_activity_parse_failed:{split}/{run_dir.name}:{type(exc).__name__}"
        (errors if strict else warnings).append(message)
        return []

    records = []
    for sequence, row in enumerate(rows, start=1):
        record = normalize_window_record(
            corpus_dir=corpus_dir,
            split=split,
            run_dir=run_dir,
            run_meta=run_meta,
            row=row,
            sequence=sequence,
            warnings=warnings,
        )
        if record["activity_level"] not in ACTIVITY_LEVELS:
            message = f"invalid_activity_level:{split}/{run_dir.name}/{record['window_id']}:{record['activity_level']}"
            (errors if strict else warnings).append(message)
        if str(row.get("split") or split) != split:
            warnings.append(f"window_split_mismatch:{split}/{run_dir.name}/{record['window_id']}:{row.get('split')}")
        records.append(record)
    return records


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    per_run = Counter(str(record.get("run_id") or "") for record in records)
    per_role: Counter[str] = Counter()
    per_profile: Counter[str] = Counter()
    for record in records:
        for role in list(record.get("active_roles") or []):
            if str(role):
                per_role[str(role)] += 1
        for profile in list(record.get("dominant_profiles") or []):
            if str(profile):
                per_profile[str(profile)] += 1
    return {
        "full_window_count": int(len(records)),
        "activity_level_counts_full": activity_counts(records),
        "per_run_counts": dict(sorted(per_run.items())),
        "per_role_counts": dict(sorted(per_role.items())),
        "per_profile_counts": dict(sorted(per_profile.items())),
        "request_count_total": int(sum(safe_int(record.get("request_count"), 0) for record in records)),
        "raw_event_count_total": int(sum(safe_int(record.get("raw_event_count"), 0) for record in records)),
        "edge_count_total": int(sum(safe_int(record.get("edge_count"), 0) for record in records)),
        "node_count_total": int(sum(safe_int(record.get("node_count"), 0) for record in records)),
    }


def sample_train_windows(
    train_records: list[dict[str, Any]],
    *,
    seed: int,
    policy: dict[str, float],
    constraints: dict[str, Any],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in train_records:
        grouped[(str(record.get("run_id") or ""), str(record.get("activity_level") or "empty"))].append(record)

    sampled: list[dict[str, Any]] = []
    for (run_id, level), records in sorted(grouped.items()):
        ordered = sorted(records, key=lambda item: str(item.get("window_id") or ""))
        ratio = max(min(float(policy.get(level, 0.0)), 1.0), 0.0)
        if ratio >= 1.0:
            chosen = ordered
        elif ratio <= 0.0:
            chosen = []
        else:
            rng = stable_random(seed, run_id, level)
            chosen = [record for record in ordered if rng.random() < ratio]
        for record in chosen:
            out = sampled_record(record, ratio)
            sampled.append(out)

    sampled = enforce_idle_fraction(sampled, seed=seed, max_idle_fraction=safe_float(constraints.get("max_idle_fraction_in_sampled_train"), 0.10))
    return sorted(sampled, key=lambda item: (str(item.get("run_id") or ""), str(item.get("window_id") or "")))


def sampled_record(record: dict[str, Any], ratio: float) -> dict[str, Any]:
    level = str(record.get("activity_level") or "empty")
    return {
        "dataset": record.get("dataset"),
        "split": "train",
        "run_id": record.get("run_id"),
        "window_id": record.get("window_id"),
        "window_sequence": record.get("window_sequence"),
        "activity_level": level,
        "start_ts": record.get("start_ts"),
        "end_ts": record.get("end_ts"),
        "sampled": True,
        "sampling_reason": f"policy_{level}_{float(ratio):.3g}",
        "sampling_policy_version": DEFAULT_POLICY_VERSION,
        "window_activity_path": record.get("window_activity_path"),
        "trace_log_path": record.get("trace_log_path"),
        "run_meta_path": record.get("run_meta_path"),
        "window_graph_path": record.get("window_graph_path"),
        "windows_dir": record.get("windows_dir"),
        "graph_stats_source": record.get("graph_stats_source"),
        "node_count": safe_int(record.get("node_count"), 0),
        "edge_count": safe_int(record.get("edge_count"), 0),
        "request_count": safe_int(record.get("request_count"), 0),
        "raw_event_count": safe_int(record.get("raw_event_count"), 0),
    }


def enforce_idle_fraction(sampled: list[dict[str, Any]], *, seed: int, max_idle_fraction: float) -> list[dict[str, Any]]:
    if max_idle_fraction < 0:
        max_idle_fraction = 0.0
    if max_idle_fraction >= 1.0:
        return sampled
    idle = [record for record in sampled if record.get("activity_level") == "idle"]
    non_idle = [record for record in sampled if record.get("activity_level") != "idle"]
    if not idle:
        return sampled
    max_idle_count = int((max_idle_fraction * len(non_idle)) // max(1e-12, (1.0 - max_idle_fraction)))
    max_idle_count = max(max_idle_count, 0)
    if len(idle) <= max_idle_count:
        return sampled
    ordered = sorted(idle, key=lambda item: str(item.get("window_id") or ""))
    rng = stable_random(seed, "idle_fraction_cap")
    rng.shuffle(ordered)
    kept_idle_ids = {str(item.get("window_id") or "") for item in ordered[:max_idle_count]}
    return [record for record in sampled if record.get("activity_level") != "idle" or str(record.get("window_id") or "") in kept_idle_ids]


def detect_split_collisions(records: list[dict[str, Any]], warnings: list[str], errors: list[str], strict: bool) -> None:
    run_splits: dict[str, set[str]] = defaultdict(set)
    window_splits: dict[str, set[str]] = defaultdict(set)
    for record in records:
        run_splits[str(record.get("run_id") or "")].add(str(record.get("split") or ""))
        window_splits[str(record.get("window_id") or "")].add(str(record.get("split") or ""))
    for run_id, splits in sorted(run_splits.items()):
        if run_id and len(splits) > 1:
            message = f"run_id_in_multiple_splits:{run_id}:{','.join(sorted(splits))}"
            (errors if strict else warnings).append(message)
    for window_id, splits in sorted(window_splits.items()):
        if window_id and len(splits) > 1:
            message = f"window_id_in_multiple_splits:{window_id}:{','.join(sorted(splits))}"
            (errors if strict else warnings).append(message)


def build_split_manifest(
    split: str,
    records: list[dict[str, Any]],
    sampled: list[dict[str, Any]],
    train_policy: dict[str, float],
) -> dict[str, Any]:
    runs = sorted({str(record.get("run_id") or "") for record in records if str(record.get("run_id") or "")})
    payload = {
        "runs": runs,
        "keep_all_windows": split != "train",
        "full_window_count": int(len(records)),
        "activity_level_counts_full": activity_counts(records),
    }
    if split == "train":
        payload.update(
            {
                "keep_all_windows": False,
                "sampled_window_count": int(len(sampled)),
                "activity_level_counts_sampled": activity_counts(sampled),
                "sampling_policy": dict(sorted(train_policy.items())),
            }
        )
    return payload


def quality_checks(sampled: list[dict[str, Any]], constraints: dict[str, Any]) -> dict[str, Any]:
    total = len(sampled)
    empty_count = sum(1 for record in sampled if record.get("activity_level") == "empty")
    idle_count = sum(1 for record in sampled if record.get("activity_level") == "idle")
    active_or_burst = sum(1 for record in sampled if record.get("activity_level") in {"active", "burst"})
    return {
        "contains_empty_windows": bool(empty_count > 0),
        "idle_fraction": float(idle_count / total) if total else 0.0,
        "active_or_burst_fraction": float(active_or_burst / total) if total else 0.0,
        "min_train_windows_satisfied": bool(total >= safe_int(constraints.get("min_train_windows"), 100)),
    }


def build_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    corpus_dir = Path(args.corpus_dir).expanduser().resolve()
    output_manifest = Path(args.output_manifest).expanduser().resolve() if args.output_manifest else corpus_dir / "corpus_manifest.json"
    output_summary = Path(args.output_summary).expanduser().resolve() if args.output_summary else corpus_dir / "corpus_summary.json"
    output_full_index = Path(args.output_full_index).expanduser().resolve() if args.output_full_index else corpus_dir / "full_window_index.jsonl"
    output_sampled_train = (
        Path(args.output_sampled_train).expanduser().resolve() if args.output_sampled_train else corpus_dir / "sampled_train_windows.jsonl"
    )
    outputs = [output_manifest, output_summary, output_full_index, output_sampled_train]
    existing = output_exists(outputs)
    if existing and not bool(args.force):
        raise FileExistsError("output exists, pass --force to overwrite: " + ", ".join(str(path) for path in existing))

    warnings: list[str] = []
    errors: list[str] = []
    config_path = Path(args.sampling_config).expanduser().resolve() if args.sampling_config else Path("configs/benign_manifest_v3.yaml").resolve()
    config = load_sampling_config(config_path, warnings)
    include_splits = parse_csv(args.include_splits) if args.include_splits else list(DEFAULT_INCLUDE_SPLITS)
    if include_splits == list(DEFAULT_INCLUDE_SPLITS):
        include_splits = maybe_add_smoke_split(corpus_dir, include_splits, warnings)

    train_policy = train_sampling_policy(config)
    constraints = sampling_constraints(config)
    all_records: list[dict[str, Any]] = []
    records_by_split: dict[str, list[dict[str, Any]]] = {split: [] for split in include_splits}

    if not corpus_dir.exists():
        message = f"corpus_dir_missing:{corpus_dir}"
        if bool(args.allow_missing_runs):
            warnings.append(message)
        else:
            errors.append(message)
    else:
        for split in include_splits:
            run_dirs = discover_run_dirs(corpus_dir, split, config, warnings, errors, strict=bool(args.strict))
            if not run_dirs and bool(args.strict):
                errors.append(f"no_runs_for_split:{split}")
            for run_dir in run_dirs:
                records = load_run_windows(
                    corpus_dir=corpus_dir,
                    split=split,
                    run_dir=run_dir,
                    strict=bool(args.strict),
                    warnings=warnings,
                    errors=errors,
                )
                records_by_split.setdefault(split, []).extend(records)
                all_records.extend(records)

    detect_split_collisions(all_records, warnings, errors, strict=bool(args.strict))
    sampled_train = sample_train_windows(
        records_by_split.get("train", []),
        seed=int(args.seed),
        policy=train_policy,
        constraints=constraints,
    )

    if any(record.get("activity_level") == "empty" for record in sampled_train):
        errors.append("sampled_train_contains_empty_windows")
    if not quality_checks(sampled_train, constraints)["min_train_windows_satisfied"]:
        warnings.append(
            f"sampled_train_below_min_train_windows:{len(sampled_train)}<{safe_int(constraints.get('min_train_windows'), 100)}"
        )
    if any(record.get("window_graph_path") is None for record in all_records):
        warnings.append("window_graph_path_unavailable")

    created_at = utc_now_str()
    splits_manifest: dict[str, Any] = {}
    splits_summary: dict[str, Any] = {}
    for split in include_splits:
        split_records = records_by_split.get(split, [])
        split_sampled = sampled_train if split == "train" else []
        splits_manifest[split] = build_split_manifest(split, split_records, split_sampled, train_policy)
        split_summary = summarize_records(split_records)
        if split == "train":
            split_summary["sampled_window_count"] = int(len(sampled_train))
            split_summary["activity_level_counts_sampled"] = activity_counts(sampled_train)
        splits_summary[split] = split_summary

    manifest = {
        "dataset": str(config.get("dataset") or "benign_corpus_v3"),
        "version": "v3",
        "created_at": created_at,
        "window_seconds": int(args.window_seconds),
        "time_bin_seconds": int(args.time_bin_seconds),
        "random_seed": int(args.seed),
        "corpus_dir": path_for_manifest(corpus_dir),
        "files": {
            "full_window_index": relpath(output_full_index, corpus_dir),
            "sampled_train_windows": relpath(output_sampled_train, corpus_dir),
            "corpus_summary": relpath(output_summary, corpus_dir),
        },
        "splits": splits_manifest,
        "sampling": constraints,
        "sampling_policy_version": DEFAULT_POLICY_VERSION,
        "sampling_config": path_for_manifest(config_path) if config_path.exists() else None,
        "policy_notes": [
            "Only train split is sampled.",
            "Calibration and holdout preserve all windows.",
            "Attack data is not included.",
        ],
        "warnings": sorted(set(warnings)),
        "errors": sorted(set(errors)),
    }
    summary = {
        "dataset": manifest["dataset"],
        "created_at": created_at,
        "total_full_windows": int(len(all_records)),
        "total_sampled_train_windows": int(len(sampled_train)),
        "splits": splits_summary,
        "sampled_train_quality_checks": quality_checks(sampled_train, constraints),
        "warnings": sorted(set(warnings)),
        "errors": sorted(set(errors)),
    }

    write_jsonl(output_full_index, sorted(all_records, key=lambda item: (str(item.get("split")), str(item.get("run_id")), str(item.get("window_id")))))
    write_jsonl(output_sampled_train, sampled_train)
    write_json(output_manifest, manifest)
    write_json(output_summary, summary)

    if errors:
        raise RuntimeError("; ".join(sorted(set(errors))))
    return manifest, summary, all_records, sampled_train


def normalize_corpus_dir(config: dict[str, Any], corpus_dir: str, rehearsal: bool) -> Path:
    if corpus_dir:
        return Path(corpus_dir)
    key = "rehearsal_corpus_dir" if rehearsal else "corpus_dir"
    return Path(str(config.get(key) or config.get("corpus_dir") or "data/benign_corpus_v3"))


def ordered_run_ids(config: dict[str, Any]) -> list[str]:
    raw = config.get("runs")
    if not isinstance(raw, dict):
        return []
    known = [run_id for run_id in DEFAULT_RUN_ORDER if run_id in raw]
    extras = sorted(run_id for run_id in raw if run_id not in set(known))
    return [*known, *extras]


def selected_run_ids(config: dict[str, Any], runs: str) -> list[str]:
    all_ids = ordered_run_ids(config)
    if not runs:
        return all_ids
    requested = parse_csv(runs)
    known = set(all_ids)
    unknown = sorted(run_id for run_id in requested if run_id not in known)
    if unknown:
        raise ValueError(f"unknown run id(s): {','.join(unknown)}")
    return requested


def scaled_duration(value: Any, scale: float) -> int:
    return max(int(round(safe_float(value, 0.0) * float(scale))), 1)


def normalize_phases(run_id: str, run_cfg: dict[str, Any], scale: float) -> list[dict[str, Any]]:
    phases: list[dict[str, Any]] = []
    cursor = 0.0
    raw_phases = list(run_cfg.get("phases") or [])
    for idx, raw in enumerate(raw_phases, start=1):
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or raw.get("phase_id") or f"phase_{idx:02d}")
        duration = scaled_duration(raw.get("duration_seconds"), scale)
        phase = {
            "name": name,
            "phase_id": str(raw.get("phase_id") or name),
            "profile_id": str(raw.get("profile_id") or raw.get("profile") or name),
            "duration_seconds": int(duration),
            "source_duration_seconds": safe_int(raw.get("duration_seconds"), duration),
            "start_offset_seconds": float(cursor),
            "end_offset_seconds": float(cursor + duration),
        }
        phase_actors = raw.get("actors")
        if phase_actors and isinstance(phase_actors, dict):
            phase["actors"] = phase_actors
        phases.append(phase)
        cursor += duration
    if phases:
        return phases
    duration = scaled_duration(run_cfg.get("duration_seconds"), scale)
    return [
        {
            "name": f"{run_id}_single_phase",
            "phase_id": f"{run_id}_single_phase",
            "profile_id": f"{run_id}_single_phase",
            "duration_seconds": int(duration),
            "source_duration_seconds": safe_int(run_cfg.get("duration_seconds"), duration),
            "start_offset_seconds": 0.0,
            "end_offset_seconds": float(duration),
        }
    ]


def build_run_config(
    *,
    config: dict[str, Any],
    run_id: str,
    corpus_dir: Path,
    duration_scale: float,
    skip_tracee: bool,
    skip_compose_up: bool,
) -> dict[str, Any]:
    runs = dict(config.get("runs") or {})
    if run_id not in runs or not isinstance(runs.get(run_id), dict):
        raise ValueError(f"unknown run id: {run_id}")
    run_cfg = dict(runs[run_id] or {})
    split = str(run_cfg.get("split") or "")
    if not split:
        raise ValueError(f"run {run_id} missing split")

    phases = normalize_phases(run_id, run_cfg, duration_scale)
    duration_seconds = int(sum(safe_int(phase.get("duration_seconds"), 0) for phase in phases))
    output_dir = corpus_dir / split / run_id
    collection = dict(config.get("collection") or {})
    if skip_tracee:
        collection["tracee_enabled"] = False
    if skip_compose_up:
        collection["skip_compose_up"] = True

    actors = dict(config.get("actors") or {})
    for actor_name, override in dict(run_cfg.get("actors") or {}).items():
        if isinstance(override, dict) and isinstance(actors.get(actor_name), dict):
            merged = dict(actors.get(actor_name) or {})
            merged.update(override)
            actors[actor_name] = merged
        else:
            actors[actor_name] = override
    endpoints = dict(run_cfg.get("endpoints") or config.get("endpoints") or {})
    payload = {
        "dataset": str(config.get("dataset") or "benign_corpus_v3"),
        "version": str(config.get("version") or "v3"),
        "run_id": run_id,
        "split": split,
        "phase": "formal_benign_collection_v3",
        "base_url": str(run_cfg.get("base_url") or config.get("base_url") or "http://127.0.0.1:5000"),
        "duration_seconds": duration_seconds,
        "source_duration_seconds": safe_int(run_cfg.get("duration_seconds"), duration_seconds),
        "duration_scale": float(duration_scale),
        "random_seed": safe_int(run_cfg.get("random_seed"), safe_int(config.get("random_seed"), 0)),
        "output_dir": output_dir.as_posix(),
        "workload_model": str(config.get("workload_model") or "multi_actor_arrival_rate"),
        "request_timeout_seconds": safe_float(config.get("request_timeout_seconds"), 5.0),
        "window_seconds": safe_int(config.get("window_seconds"), 30),
        "time_bin_seconds": safe_int(config.get("time_bin_seconds"), 2),
        "collection": collection,
        "auth": dict(run_cfg.get("auth") or config.get("auth") or {}),
        "actors": actors,
        "endpoints": endpoints,
        "phases": phases,
        "split_semantics": {
            "train": "Use only for BBK/GMAE benign training sampling.",
            "calibration": "Use only for threshold or score calibration.",
            "holdout": "Use only for final benign false-positive evaluation.",
        }.get(split, ""),
    }
    return payload


def emit_plan(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    corpus_dir = normalize_corpus_dir(config, args.corpus_dir, bool(args.rehearsal))
    scale = safe_float(args.duration_scale, 1.0)
    if bool(args.rehearsal) and scale == 1.0:
        scale = 0.1
    for run_id in selected_run_ids(config, args.runs):
        run_cfg = build_run_config(
            config=config,
            run_id=run_id,
            corpus_dir=corpus_dir,
            duration_scale=scale,
            skip_tracee=bool(args.skip_tracee),
            skip_compose_up=bool(args.skip_compose_up),
        )
        print(
            "\t".join(
                [
                    str(run_cfg["run_id"]),
                    str(run_cfg["split"]),
                    str(run_cfg["output_dir"]),
                    str(run_cfg["duration_seconds"]),
                ]
            )
        )
    return 0


def write_run_config(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    corpus_dir = normalize_corpus_dir(config, args.corpus_dir, bool(args.rehearsal))
    scale = safe_float(args.duration_scale, 1.0)
    if bool(args.rehearsal) and scale == 1.0:
        scale = 0.1
    run_cfg = build_run_config(
        config=config,
        run_id=args.run_id,
        corpus_dir=corpus_dir,
        duration_scale=scale,
        skip_tracee=bool(args.skip_tracee),
        skip_compose_up=bool(args.skip_compose_up),
    )
    write_json(Path(args.output), run_cfg)
    return 0


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except Exception:
        return os.path.relpath(str(path), str(Path.cwd()))


def count_lines(path: Path) -> int:
    if not path.exists() or path.stat().st_size <= 0:
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        return sum(1 for line in fp if line.strip())


def split_rows(rows: list[dict[str, Any]], split: str) -> list[dict[str, Any]]:
    return [row for row in rows if str(row.get("split") or "") == split]


def validate_run_artifacts(
    *,
    corpus_dir: Path,
    run_id: str,
    selected: bool,
    run_cfg: dict[str, Any],
    no_window_activity: bool,
    allow_missing_trace: bool,
) -> dict[str, Any]:
    run_dir = Path(str(run_cfg.get("output_dir") or ""))
    if not run_dir.is_absolute():
        run_dir = (Path.cwd() / run_dir).resolve()
    collection = dict(run_cfg.get("collection") or {})
    tracee_enabled = safe_bool(collection.get("tracee_enabled"), True) and not allow_missing_trace
    warnings: list[str] = []
    errors: list[str] = []

    effective_config = read_json(run_dir / "effective_config.yaml")
    run_meta = read_json(run_dir / "run_meta.json")
    workload_summary = read_json(run_dir / "workload_summary.json")
    collection_summary = read_json(run_dir / "collection_summary.json")
    activity_rows = read_jsonl(run_dir / "window_activity.jsonl")
    activity_summary = read_json(run_dir / "window_activity_summary.json")
    effective_collection = dict(effective_config.get("collection") or {})
    tracee_summary = dict(collection_summary.get("tracee") or {})
    configured_output_format = str(
        effective_collection.get("tracee_output_format")
        or collection.get("tracee_output_format")
        or tracee_summary.get("configured_output_format")
        or tracee_summary.get("output_format")
        or "json"
    ).strip().lower()
    summary_configured_output_format = str(tracee_summary.get("configured_output_format") or "").strip().lower()
    cli_output_format = str(tracee_summary.get("cli_output_format") or tracee_summary.get("output_format") or "").strip().lower()
    trace_format_detection = dict(tracee_summary.get("trace_format_detection") or {})
    if not trace_format_detection:
        trace_format_detection = detect_trace_log_format(run_dir / "trace.log")
    actual_trace_format = str(
        tracee_summary.get("actual_trace_format")
        or trace_format_detection.get("actual_trace_format")
        or "missing"
    ).strip().lower()
    compatible_actual_formats = TRACE_FORMAT_COMPATIBILITY.get(configured_output_format, set())
    trace_format_consistent = bool(actual_trace_format in compatible_actual_formats)

    required = [
        ("effective_config.yaml", run_dir / "effective_config.yaml"),
        ("run_meta.json", run_dir / "run_meta.json"),
        ("driver.log", run_dir / "driver.log"),
        ("request_events.jsonl", run_dir / "request_events.jsonl"),
        ("workload_summary.json", run_dir / "workload_summary.json"),
        ("collection_summary.json", run_dir / "collection_summary.json"),
    ]
    if tracee_enabled:
        required.append(("trace.log", run_dir / "trace.log"))
    if not no_window_activity:
        required.extend(
            [
                ("window_activity.jsonl", run_dir / "window_activity.jsonl"),
                ("window_activity_summary.json", run_dir / "window_activity_summary.json"),
            ]
        )
    if selected:
        for label, path in required:
            if not path.is_file():
                errors.append(f"missing_artifact:{label}")
            elif label in {"trace.log", "request_events.jsonl", "window_activity.jsonl"} and path.stat().st_size <= 0:
                errors.append(f"empty_artifact:{label}")

    request_count = safe_int(workload_summary.get("total_requests"), 0)
    success_count = safe_int(workload_summary.get("success_count"), 0)
    failure_count = safe_int(workload_summary.get("failure_count"), 0)
    if selected and count_lines(run_dir / "request_events.jsonl") <= 0:
        errors.append("request_events_empty")
    if selected and request_count <= 0:
        errors.append("workload_total_requests_not_positive")

    if selected and not no_window_activity:
        if not activity_rows:
            errors.append("window_activity_empty")
        invalid_levels = sorted(
            {
                str(row.get("activity_level") or "")
                for row in activity_rows
                if str(row.get("activity_level") or "") not in ACTIVITY_LEVELS
            }
        )
        if invalid_levels:
            errors.append(f"invalid_activity_levels:{','.join(invalid_levels)}")

    if selected and tracee_enabled and (not (run_dir / "trace.log").is_file() or (run_dir / "trace.log").stat().st_size <= 0):
        errors.append("trace_log_missing_or_empty")
    if selected and tracee_enabled:
        if configured_output_format not in TRACE_FORMAT_COMPATIBILITY:
            errors.append(f"configured_output_format_invalid:{configured_output_format}")
        elif not trace_format_consistent:
            errors.append(f"trace_format_mismatch:configured={configured_output_format}:actual={actual_trace_format}")
        elif configured_output_format != actual_trace_format:
            warnings.append(f"trace_format_alias:configured={configured_output_format}:actual={actual_trace_format}")
        if summary_configured_output_format and summary_configured_output_format != configured_output_format:
            warnings.append(
                f"collection_summary_configured_output_format_mismatch:"
                f"{summary_configured_output_format}!={configured_output_format}"
            )

    driver = dict(collection_summary.get("driver") or {})
    if selected and collection_summary and safe_int(driver.get("exit_code"), -1) != 0:
        errors.append(f"driver_exit_code:{safe_int(driver.get('exit_code'), -1)}")
    for item in list(collection_summary.get("warnings") or []):
        warnings.append(str(item))
    for item in list(collection_summary.get("errors") or []):
        errors.append(f"collection_error:{item}")

    if selected and run_meta:
        if str(run_meta.get("split") or "") != str(run_cfg.get("split") or ""):
            errors.append(f"run_meta_split_mismatch:{run_meta.get('split')}!={run_cfg.get('split')}")
        if safe_int(run_meta.get("random_seed"), -1) != safe_int(run_cfg.get("random_seed"), -2):
            errors.append("run_meta_random_seed_mismatch")
        meta_output_dir = str(run_meta.get("output_dir") or "")
        if meta_output_dir:
            try:
                if Path(meta_output_dir).resolve() != run_dir.resolve():
                    errors.append("run_meta_output_dir_mismatch")
            except Exception:
                errors.append("run_meta_output_dir_mismatch")
        else:
            warnings.append("run_meta_output_dir_missing")
    elif selected:
        errors.append("run_meta_missing_or_invalid")

    if selected and effective_config:
        if safe_int(effective_config.get("random_seed"), -1) != safe_int(run_cfg.get("random_seed"), -2):
            errors.append("effective_config_random_seed_mismatch")
        if safe_int(effective_config.get("duration_seconds"), -1) != safe_int(run_cfg.get("duration_seconds"), -2):
            errors.append("effective_config_duration_mismatch")

    status = "skipped"
    if selected:
        status = "failed" if errors else "success"

    return {
        "split": str(run_cfg.get("split") or ""),
        "duration_seconds_requested": safe_int(run_cfg.get("duration_seconds"), 0),
        "duration_seconds_source": safe_int(run_cfg.get("source_duration_seconds"), 0),
        "duration_seconds_actual": safe_int(collection_summary.get("duration_seconds_actual"), 0),
        "output_dir": relpath(run_dir, corpus_dir),
        "request_count": request_count,
        "success_count": success_count,
        "failure_count": failure_count,
        "window_count": safe_int(activity_summary.get("window_count"), len(activity_rows)),
        "activity_level_counts": activity_counts(activity_rows),
        "trace_log_size_bytes": (run_dir / "trace.log").stat().st_size if (run_dir / "trace.log").exists() else 0,
        "configured_output_format": configured_output_format,
        "cli_output_format": cli_output_format,
        "actual_trace_format": actual_trace_format,
        "trace_format_consistent": trace_format_consistent,
        "trace_format_detection": trace_format_detection,
        "status": status,
        "warnings": sorted(set(warnings)),
        "errors": sorted(set(errors)),
    }


def build_split_summary(full_rows: list[dict[str, Any]], sampled_rows: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    runs_cfg = dict(config.get("runs") or {})
    for split in SPLITS:
        rows = split_rows(full_rows, split)
        sampled = split_rows(sampled_rows, split)
        configured_runs = sorted(run_id for run_id, raw in runs_cfg.items() if isinstance(raw, dict) and str(raw.get("split") or "") == split)
        payload = {
            "runs": configured_runs,
            "full_window_count": int(len(rows)),
            "activity_level_counts_full": activity_counts(rows),
        }
        if split == "train":
            payload["sampled_window_count"] = int(len(sampled_rows))
            payload["activity_level_counts_sampled"] = activity_counts(sampled_rows)
        summary[split] = payload
    return summary


def build_profile_coverage(full_rows: list[dict[str, Any]]) -> dict[str, Any]:
    per_profile: Counter[str] = Counter()
    per_role: Counter[str] = Counter()
    per_phase: Counter[str] = Counter()
    for row in full_rows:
        for profile in list(row.get("dominant_profiles") or []):
            if str(profile):
                per_profile[str(profile)] += 1
        for role in list(row.get("active_roles") or []):
            if str(role):
                per_role[str(role)] += 1
        phase = str(row.get("dominant_phase") or "")
        if phase:
            per_phase[phase] += 1
    return {
        "per_profile_window_count": dict(sorted(per_profile.items())),
        "per_role_window_count": dict(sorted(per_role.items())),
        "per_phase_window_count": dict(sorted(per_phase.items())),
    }


def build_quality_checks(
    *,
    selected: set[str],
    run_reports: dict[str, Any],
    full_rows: list[dict[str, Any]],
    sampled_rows: list[dict[str, Any]],
    no_window_activity: bool,
) -> dict[str, Any]:
    sampled_train_excludes_empty = all(str(row.get("activity_level") or "") != "empty" for row in sampled_rows)
    calibration_holdout_not_sampled = all(str(row.get("split") or "") == "train" for row in sampled_rows)
    idle_empty = sum(1 for row in full_rows if str(row.get("activity_level") or "") in {"idle", "empty"})
    nonempty = sum(1 for row in full_rows if str(row.get("activity_level") or "") != "empty")
    return {
        "all_required_runs_present": all(run_id in run_reports for run_id in DEFAULT_RUN_ORDER),
        "all_runs_have_request_events": all(
            safe_int(run_reports.get(run_id, {}).get("request_count"), 0) > 0 for run_id in selected
        ),
        "all_runs_have_window_activity": bool(no_window_activity)
        or all(safe_int(run_reports.get(run_id, {}).get("window_count"), 0) > 0 for run_id in selected),
        "sampled_train_excludes_empty": bool(sampled_train_excludes_empty),
        "calibration_holdout_not_sampled": bool(calibration_holdout_not_sampled),
        "idle_empty_fraction": float(idle_empty / len(full_rows)) if full_rows else 0.0,
        "nonempty_window_count": int(nonempty),
    }


def build_paper_stats(
    *,
    split_summary: dict[str, Any],
    full_rows: list[dict[str, Any]],
    sampled_rows: list[dict[str, Any]],
    run_reports: dict[str, Any],
) -> dict[str, Any]:
    total_full = len(full_rows)
    active_count = sum(1 for row in full_rows if str(row.get("activity_level") or "") in {"active", "burst"})
    idle_empty = sum(1 for row in full_rows if str(row.get("activity_level") or "") in {"idle", "empty"})
    total_requests = sum(safe_int(payload.get("request_count"), 0) for payload in run_reports.values())
    total_success = sum(safe_int(payload.get("success_count"), 0) for payload in run_reports.values())
    return {
        "benign_train_full_windows": safe_int(split_summary.get("train", {}).get("full_window_count"), 0),
        "benign_train_sampled_windows": int(len(sampled_rows)),
        "benign_calibration_windows": safe_int(split_summary.get("calibration", {}).get("full_window_count"), 0),
        "benign_holdout_windows": safe_int(split_summary.get("holdout", {}).get("full_window_count"), 0),
        "active_window_fraction": float(active_count / total_full) if total_full else 0.0,
        "idle_empty_window_fraction": float(idle_empty / total_full) if total_full else 0.0,
        "total_requests": int(total_requests),
        "success_rate": float(total_success / total_requests) if total_requests else 0.0,
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(Path(args.config))
    corpus_dir = normalize_corpus_dir(config, args.corpus_dir, bool(args.rehearsal))
    corpus_dir_resolved = corpus_dir.resolve()
    scale = safe_float(args.duration_scale, 1.0)
    if bool(args.rehearsal) and scale == 1.0:
        scale = 0.1
    selected = set(selected_run_ids(config, args.runs))
    run_reports: dict[str, Any] = {}
    top_warnings: list[str] = []
    top_errors: list[str] = []

    for run_id in ordered_run_ids(config):
        run_cfg = build_run_config(
            config=config,
            run_id=run_id,
            corpus_dir=corpus_dir,
            duration_scale=scale,
            skip_tracee=bool(args.allow_missing_trace),
            skip_compose_up=False,
        )
        run_report = validate_run_artifacts(
            corpus_dir=corpus_dir_resolved,
            run_id=run_id,
            selected=run_id in selected,
            run_cfg=run_cfg,
            no_window_activity=bool(args.no_window_activity),
            allow_missing_trace=bool(args.allow_missing_trace),
        )
        run_reports[run_id] = run_report
        for warning in list(run_report.get("warnings") or []):
            top_warnings.append(f"{run_id}:{warning}")
        for error in list(run_report.get("errors") or []):
            if run_id in selected:
                top_errors.append(f"{run_id}:{error}")

    full_rows = read_jsonl(corpus_dir_resolved / "full_window_index.jsonl")
    sampled_rows = read_jsonl(corpus_dir_resolved / "sampled_train_windows.jsonl")
    manifest = read_json(corpus_dir_resolved / "corpus_manifest.json")
    corpus_summary = read_json(corpus_dir_resolved / "corpus_summary.json")
    if not manifest and not bool(args.no_manifest):
        top_errors.append("missing_or_invalid_corpus_manifest")
    if not corpus_summary and not bool(args.no_manifest):
        top_errors.append("missing_or_invalid_corpus_summary")
    if any(str(row.get("split") or "") != "train" for row in sampled_rows):
        top_errors.append("sampled_train_contains_non_train_split")
    if any(str(row.get("activity_level") or "") == "empty" for row in sampled_rows):
        top_errors.append("sampled_train_contains_empty_window")

    split_summary = build_split_summary(full_rows, sampled_rows, config)
    quality = build_quality_checks(
        selected=selected,
        run_reports=run_reports,
        full_rows=full_rows,
        sampled_rows=sampled_rows,
        no_window_activity=bool(args.no_window_activity),
    )
    paper_stats = build_paper_stats(
        split_summary=split_summary,
        full_rows=full_rows,
        sampled_rows=sampled_rows,
        run_reports=run_reports,
    )
    collection = dict(config.get("collection") or {})
    tracee_enabled = safe_bool(collection.get("tracee_enabled"), True) and not bool(args.allow_missing_trace)
    configured_output_format = str(collection.get("tracee_output_format") or "json").strip().lower()
    report = {
        "dataset": str(config.get("dataset") or "benign_corpus_v3"),
        "version": str(config.get("version") or "v3"),
        "created_at": utc_now_str(),
        "corpus_dir": display_path(corpus_dir),
        "rehearsal": bool(args.rehearsal),
        "duration_scale": float(scale),
        "window_seconds": safe_int(config.get("window_seconds"), 30),
        "time_bin_seconds": safe_int(config.get("time_bin_seconds"), 2),
        "tracee_enabled": bool(tracee_enabled),
        "configured_output_format": configured_output_format,
        "actual_trace_formats": {
            run_id: str(payload.get("actual_trace_format") or "")
            for run_id, payload in sorted(run_reports.items())
            if run_id in selected
        },
        "runs": run_reports,
        "split_summary": split_summary,
        "profile_coverage": build_profile_coverage(full_rows),
        "quality_checks": quality,
        "paper_ready_statistics": paper_stats,
        "manifest_files": {
            "full_window_index": "full_window_index.jsonl",
            "sampled_train_windows": "sampled_train_windows.jsonl",
            "corpus_manifest": "corpus_manifest.json",
            "corpus_summary": "corpus_summary.json",
            "formal_benign_collection_report": "formal_benign_collection_report.json",
        },
        "warnings": sorted(set(top_warnings)),
        "errors": sorted(set(top_errors)),
    }
    return report


def report_command(args: argparse.Namespace) -> int:
    report = build_report(args)
    config = load_config(Path(args.config))
    corpus_dir = normalize_corpus_dir(config, args.corpus_dir, bool(args.rehearsal))
    output = Path(args.output) if args.output else corpus_dir / "formal_benign_collection_report.json"
    write_json(output, report)
    if args.print_summary:
        print_summary(report)
    return 0


def fmt_counts(counts: dict[str, Any]) -> str:
    parts = [f"{level}={safe_int(counts.get(level), 0)}" for level in ACTIVITY_LEVELS if safe_int(counts.get(level), 0) > 0]
    return ", ".join(parts) if parts else "none"


def print_summary(report: dict[str, Any]) -> None:
    print("Benign Corpus v3 collection complete")
    print("")
    print("Corpus dir:")
    print(f"  {report.get('corpus_dir')}")
    print("Trace format:")
    print(f"  configured output format: {report.get('configured_output_format')}")
    actual_formats = dict(report.get("actual_trace_formats") or {})
    if actual_formats:
        print(f"  actual trace format: {', '.join(f'{run_id}={fmt}' for run_id, fmt in actual_formats.items())}")
    print("")
    print("Runs:")
    for run_id, payload in dict(report.get("runs") or {}).items():
        output_dir = payload.get("output_dir")
        print(
            f"  {output_dir}: status={payload.get('status')} "
            f"windows={safe_int(payload.get('window_count'), 0)}, {fmt_counts(dict(payload.get('activity_level_counts') or {}))}"
        )
    split_summary = dict(report.get("split_summary") or {})
    train = dict(split_summary.get("train") or {})
    holdout = dict(split_summary.get("holdout") or {})
    sampled_counts = dict(train.get("activity_level_counts_sampled") or {})
    quality = dict(report.get("quality_checks") or {})
    print("")
    print("Train:")
    print(f"  full windows: {safe_int(train.get('full_window_count'), 0)}")
    print(f"  sampled windows: {safe_int(train.get('sampled_window_count'), 0)}")
    print(f"  empty in sampled train: {safe_int(sampled_counts.get('empty'), 0)}")
    print("")
    print("Holdout:")
    print(f"  full windows: {safe_int(holdout.get('full_window_count'), 0)}")
    print(f"  idle+empty fraction: {safe_float(quality.get('idle_empty_fraction'), 0.0):.4f}")
    print("")
    print("Artifacts:")
    for name in (
        "corpus_manifest.json",
        "corpus_summary.json",
        "sampled_train_windows.jsonl",
        "formal_benign_collection_report.json",
    ):
        print(f"  {name}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benign corpus v3 manifest builder and plan/config helpers.")
    sub = parser.add_subparsers(dest="command")

    build = sub.add_parser("build-manifest", help="Build sampled training manifest from collected corpus.")
    build.add_argument("--corpus-dir", required=True, help="Benign corpus root directory.")
    build.add_argument("--window-seconds", type=int, default=30, help="Window size in seconds.")
    build.add_argument("--time-bin-seconds", type=int, default=2, help="Time bin size in seconds.")
    build.add_argument("--seed", type=int, default=20260501, help="Sampling random seed.")
    build.add_argument("--sampling-config", default="configs/benign_manifest_v3.yaml", help="Optional sampling config.")
    build.add_argument("--output-manifest", default="", help="Output corpus_manifest.json path.")
    build.add_argument("--output-summary", default="", help="Output corpus_summary.json path.")
    build.add_argument("--output-full-index", default="", help="Output full_window_index.jsonl path.")
    build.add_argument("--output-sampled-train", default="", help="Output sampled_train_windows.jsonl path.")
    build.add_argument("--include-splits", default="train,calibration,holdout", help="Comma-separated split names.")
    build.add_argument("--force", action="store_true", help="Overwrite existing manifest outputs.")
    build.add_argument("--strict", action="store_true", help="Fail on missing run_meta/window_activity or split collisions.")
    build.add_argument("--allow-missing-runs", action="store_true", help="Allow missing corpus or configured runs with warnings.")

    plan_common = argparse.ArgumentParser(add_help=False)
    plan_common.add_argument("--config", default="configs/benign_corpus_v3_formal.yaml")
    plan_common.add_argument("--corpus-dir", default="")
    plan_common.add_argument("--runs", default="")
    plan_common.add_argument("--duration-scale", type=float, default=1.0)
    plan_common.add_argument("--rehearsal", action="store_true")
    plan_common.add_argument("--skip-tracee", action="store_true")
    plan_common.add_argument("--skip-compose-up", action="store_true")

    plan = sub.add_parser("emit-plan", parents=[plan_common], help="Print selected run plan as TSV.")
    plan.set_defaults(func=emit_plan)

    write = sub.add_parser("write-run-config", parents=[plan_common], help="Write one effective run config.")
    write.add_argument("--run-id", required=True)
    write.add_argument("--output", required=True)
    write.set_defaults(func=write_run_config)

    report = sub.add_parser("report", parents=[plan_common], help="Write formal_benign_collection_report.json.")
    report.add_argument("--output", default="")
    report.add_argument("--allow-missing-trace", action="store_true")
    report.add_argument("--no-window-activity", action="store_true")
    report.add_argument("--no-manifest", action="store_true")
    report.add_argument("--print-summary", action="store_true")
    report.set_defaults(func=report_command)

    known_commands = {"build-manifest", "emit-plan", "write-run-config", "report"}
    if argv and argv[0] not in known_commands:
        argv = ["build-manifest"] + argv

    args = parser.parse_args(argv)
    if args.command is None:
        args.command = "build-manifest"
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    try:
        if args.command in ("emit-plan", "write-run-config", "report") and hasattr(args, "func"):
            return int(args.func(args))
        manifest, summary, _full, sampled = build_manifest(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        "benign manifest built: "
        f"dataset={manifest.get('dataset')} full_windows={summary.get('total_full_windows')} "
        f"sampled_train={len(sampled)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
