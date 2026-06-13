#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.analysis.report_generator import AnalysisEngine
from src.common.benchmarking import (
    ALLOWED_ROLES,
    DEFAULT_SWEEP_THRESHOLDS,
    DEFAULT_THRESHOLD,
    IGNORED_LABEL,
    NEGATIVE_LABEL,
    POSITIVE_LABEL,
    normalize_container_id,
    role_label,
    short_container_id,
    validate_labels_payload,
    load_scenario_manifest,
)
from src.common.io import read_json, write_json
from src.process.analysis_engine import TwoStageDetectionConfig, detect_two_stage_window
from src.process.window_io import load_window_graph


@dataclass(frozen=True)
class RunArtifacts:
    run_id: str
    run_dir: Path
    windows_dir: Path
    scenario_id: str
    repeat_id: int
    kind: str
    labels_path: Optional[Path]
    run_meta_path: Optional[Path]


@dataclass(frozen=True)
class EvalDetectionConfig:
    two_stage: bool = False
    bbk_trigger_threshold: float = DEFAULT_THRESHOLD
    top_k: int = 3
    disable_gmae: bool = False
    force_gmae_all_windows: bool = False


def load_run_meta(path: str | Path | None) -> Dict[str, Any]:
    if not path:
        return {}
    meta_path = Path(path)
    if not meta_path.exists():
        return {}
    return read_json(str(meta_path)) or {}


def iter_window_files(windows_dir: str | Path, limit: int = 0) -> List[Path]:
    paths = sorted(Path(windows_dir).glob("window_*.json"))
    if limit and limit > 0:
        paths = paths[: int(limit)]
    return paths


def proc_nodes(g) -> List[tuple[str, Dict[str, Any]]]:
    out = []
    for node_id, data in g.nodes(data=True):
        if isinstance(node_id, str) and node_id.startswith("proc:"):
            out.append((node_id, (data or {}).get("meta", {}) or {}))
    return out


def compute_metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, float | int]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    acc = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": acc,
        "false_positive_rate": false_positive_rate,
        "support": tp + fp + fn + tn,
        "positive_support": tp + fn,
        "negative_support": fp + tn,
    }


def _match_container_record(container_id: str, containers: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    needle = short_container_id(container_id)
    if not needle:
        return None
    for record in containers:
        candidate = short_container_id(record.get("container_id") or "")
        if not candidate:
            continue
        if needle == candidate or needle.startswith(candidate) or candidate.startswith(needle):
            return record
    return None


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _infer_repeat_id(run_dir: Path, run_meta: Dict[str, Any]) -> int:
    repeat_id = _safe_int(run_meta.get("repeat_id"))
    if repeat_id > 0:
        return repeat_id
    match = re.search(r"(\d+)$", run_dir.name)
    if match:
        return int(match.group(1))
    return 1


def _infer_window_sequence(window_file: Path) -> int:
    match = re.search(r"window_(\d+)\.json$", window_file.name)
    if not match:
        return 0
    return int(match.group(1))


def _overlaps(start_a: float, end_a: float, start_b: float, end_b: float) -> bool:
    return float(start_a) < float(end_b) and float(end_a) > float(start_b)


def _overlap_seconds(start_a: float, end_a: float, start_b: float, end_b: float) -> float:
    return max(0.0, min(float(end_a), float(end_b)) - max(float(start_a), float(start_b)))


ABSOLUTE_SECONDS_THRESHOLD = 1_000_000_000.0


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _optional_float(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except Exception:
        return None


def _looks_absolute_seconds(value: Any) -> bool:
    numeric = _optional_float(value)
    return bool(numeric is not None and abs(float(numeric)) >= ABSOLUTE_SECONDS_THRESHOLD)


def _parse_time_reference_seconds(value: Any) -> Optional[float]:
    """Return an epoch-second reference from numeric or ISO-8601 run metadata."""

    numeric = _optional_float(value)
    if numeric is not None:
        return float(numeric)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return float(parsed.timestamp())
    except Exception:
        return None


def _run_time_reference_seconds(run_meta: Dict[str, Any]) -> Optional[float]:
    for key in (
        "trace_start_time",
        "trace_start_ts",
        "trace_start_epoch",
        "run_start_time",
        "run_start_ts",
        "run_start_epoch",
    ):
        reference = _parse_time_reference_seconds(run_meta.get(key))
        if reference is not None:
            return reference
    return None


def _offset_seconds(value: Any, reference_seconds: Optional[float]) -> float:
    numeric = _safe_float(value, 0.0)
    if reference_seconds is not None and _looks_absolute_seconds(numeric):
        return float(numeric) - float(reference_seconds)
    return float(numeric)


def _window_metadata(graph: Any) -> Dict[str, Any]:
    metadata = getattr(graph, "graph", {}) or {}
    return dict(metadata) if isinstance(metadata, dict) else {}


def _config_value(metadata: Dict[str, Any], run_meta: Dict[str, Any], key: str, default: float = 0.0) -> float:
    for container_key in ("sliding_window_config", "reduction_config"):
        cfg = metadata.get(container_key)
        if isinstance(cfg, dict) and cfg.get(key) not in (None, ""):
            return _safe_float(cfg.get(key), default)
    if run_meta.get(key) not in (None, ""):
        return _safe_float(run_meta.get(key), default)
    return float(default)


def _window_timing_for_window(
    run_meta: Dict[str, Any],
    window_file: Path,
    graph: Any = None,
) -> Dict[str, Any]:
    """Resolve true window timing.

    Sliding windows persisted by window_io carry graph metadata with real
    window_start/window_end. Those values may be relative seconds or absolute
    epoch seconds, depending on the Tracee timestamp source. Benchmark stage
    boundaries are usually relative to run start, so absolute window timestamps
    are converted to run-relative offsets when run_meta provides trace/run start
    time. If no reference exists, values are retained and the warning is exposed
    in the output JSON instead of silently mixing time bases.
    """

    loaded_graph = graph
    metadata: Dict[str, Any] = _window_metadata(loaded_graph)
    if loaded_graph is None:
        try:
            loaded_graph = load_window_graph(str(window_file))
            metadata = _window_metadata(loaded_graph)
        except Exception:
            metadata = {}

    sequence = _infer_window_sequence(window_file)
    configured_window_seconds = _config_value(metadata, run_meta, "window_seconds", 30.0) or 30.0
    raw_start = _optional_float(metadata.get("window_start"))
    raw_end = _optional_float(metadata.get("window_end"))
    source = "metadata"
    if raw_start is None or raw_end is None or raw_end <= raw_start:
        source = "sequence_fallback"
        start = float(max(sequence - 1, 0)) * float(configured_window_seconds)
        end = start + float(configured_window_seconds)
        raw_start = start
        raw_end = end

    reference = _run_time_reference_seconds(run_meta)
    raw_values = [raw_start, raw_end]
    warnings: List[str] = []
    if any(_looks_absolute_seconds(value) for value in raw_values) and reference is None:
        warnings.append(
            "window_start/window_end look like absolute epoch seconds, but run_meta has no "
            "trace_start_time/run_start_time reference; values were retained without conversion"
        )

    window_start = _offset_seconds(raw_start, reference)
    window_end = _offset_seconds(raw_end, reference)
    window_duration = max(float(window_end) - float(window_start), 0.0)
    if window_duration <= 0.0:
        window_duration = float(configured_window_seconds)
        window_end = float(window_start) + window_duration

    window_mode = str(metadata.get("window_mode") or run_meta.get("window_mode") or "fixed").strip().lower() or "fixed"
    stride_seconds = _config_value(metadata, run_meta, "stride_seconds", window_duration)
    if stride_seconds <= 0.0:
        stride_seconds = window_duration
    overlap_seconds = max(0.0, float(window_duration) - float(stride_seconds)) if window_mode == "sliding" else 0.0

    return {
        "window_start_offset_seconds": float(window_start),
        "window_end_offset_seconds": float(window_end),
        "window_seconds": float(window_duration),
        "stride_seconds": float(stride_seconds),
        "overlap_seconds": float(overlap_seconds),
        "window_mode": window_mode,
        "window_time_source": source,
        "time_base_warnings": warnings,
        "raw_window_start_seconds": float(raw_start),
        "raw_window_end_seconds": float(raw_end),
    }


def _stage_boundaries_offsets(run_meta: Dict[str, Any], timing: Dict[str, Any]) -> Tuple[Dict[str, float], List[str], bool]:
    boundaries = dict(run_meta.get("stage_boundaries") or {})
    has_attack_bounds = any(key in boundaries for key in ("attack_start", "attack_end")) or any(
        key in run_meta for key in ("attack_start", "attack_end")
    )
    reference = _run_time_reference_seconds(run_meta)
    raw_values = []
    for key in ("warmup_start", "warmup_end", "attack_start", "attack_end", "cooldown_start", "cooldown_end"):
        if key in boundaries:
            raw_values.append(boundaries.get(key))
    for key in ("attack_start", "attack_end"):
        if key in run_meta:
            raw_values.append(run_meta.get(key))

    warnings: List[str] = []
    if any(_looks_absolute_seconds(value) for value in raw_values) and reference is None:
        warnings.append(
            "stage boundary or attack_start/attack_end values look like absolute epoch seconds, but run_meta "
            "has no trace_start_time/run_start_time reference; values were retained without conversion"
        )

    def boundary(name: str, default: float = 0.0) -> float:
        if name in boundaries:
            return _offset_seconds(boundaries.get(name), reference)
        if name in run_meta:
            return _offset_seconds(run_meta.get(name), reference)
        return float(default)

    attack_start = boundary("attack_start", 0.0)
    attack_end = boundary("attack_end", 0.0)
    if attack_end <= attack_start and run_meta.get("attack_seconds") not in (None, ""):
        attack_end = attack_start + max(0.0, _safe_float(run_meta.get("attack_seconds"), 0.0))

    out = {
        "warmup_start": boundary("warmup_start", 0.0),
        "warmup_end": boundary("warmup_end", attack_start),
        "attack_start": attack_start,
        "attack_end": attack_end,
        "cooldown_start": boundary("cooldown_start", attack_end),
        "cooldown_end": boundary("cooldown_end", attack_end + max(0.0, _safe_float(run_meta.get("cooldown_seconds"), 0.0))),
    }

    mixed_without_reference = (
        reference is None
        and any(_looks_absolute_seconds(value) for value in (timing.get("raw_window_start_seconds"), timing.get("raw_window_end_seconds")))
        and any(not _looks_absolute_seconds(value) for value in raw_values if value not in (None, ""))
    )
    if mixed_without_reference:
        warnings.append(
            "window metadata appears absolute while attack/stage boundaries appear relative; no run time reference was available"
        )
    return out, warnings, bool(has_attack_bounds and attack_end > attack_start)


def _empty_stage_info(run_meta: Dict[str, Any], window_file: Path, graph: Any = None) -> Dict[str, Any]:
    timing = _window_timing_for_window(run_meta, window_file, graph=graph)
    timing.update(
        {
            "label": "",
            "stage": "",
            "window_stage_label": "",
            "attack_overlap_seconds": 0.0,
            "attack_overlap_ratio": 0.0,
            "attack_start_offset_seconds": 0.0,
            "attack_end_offset_seconds": 0.0,
        }
    )
    return timing


def _stage_label_for_window(
    run: RunArtifacts,
    run_meta: Dict[str, Any],
    window_file: Path,
    graph: Any = None,
) -> Dict[str, Any]:
    timing = _window_timing_for_window(run_meta, window_file, graph=graph)
    if str(run.kind) != "attack":
        return _empty_stage_info(run_meta, window_file, graph=graph)

    boundaries, boundary_warnings, has_attack_bounds = _stage_boundaries_offsets(run_meta, timing)
    timing["time_base_warnings"] = list(timing.get("time_base_warnings") or []) + list(boundary_warnings or [])
    if not has_attack_bounds:
        timing.update(
            {
                "label": "",
                "stage": "",
                "window_stage_label": "",
                "attack_overlap_seconds": 0.0,
                "attack_overlap_ratio": 0.0,
                "attack_start_offset_seconds": float(boundaries.get("attack_start", 0.0)),
                "attack_end_offset_seconds": float(boundaries.get("attack_end", 0.0)),
            }
        )
        return timing

    window_start = float(timing.get("window_start_offset_seconds") or 0.0)
    window_end = float(timing.get("window_end_offset_seconds") or 0.0)
    attack_start = float(boundaries.get("attack_start", 0.0))
    attack_end = float(boundaries.get("attack_end", 0.0))
    warmup_start = float(boundaries.get("warmup_start", 0.0))
    warmup_end = float(boundaries.get("warmup_end", 0.0))
    cooldown_start = float(boundaries.get("cooldown_start", 0.0))
    cooldown_end = float(boundaries.get("cooldown_end", 0.0))
    attack_overlap = _overlap_seconds(window_start, window_end, attack_start, attack_end)
    window_duration = max(float(timing.get("window_seconds") or (window_end - window_start)), 1e-9)
    attack_overlap_ratio = float(attack_overlap) / float(window_duration)

    if attack_overlap <= 0.0:
        stage = "benign"
        if warmup_end > warmup_start and _overlaps(window_start, window_end, warmup_start, warmup_end):
            stage = "warmup"
        elif cooldown_end > cooldown_start and _overlaps(window_start, window_end, cooldown_start, cooldown_end):
            stage = "cooldown"
        timing.update(
            {
                "label": NEGATIVE_LABEL,
                "stage": stage,
                "window_stage_label": "benign_window",
                "attack_overlap_seconds": 0.0,
                "attack_overlap_ratio": 0.0,
                "attack_start_offset_seconds": float(attack_start),
                "attack_end_offset_seconds": float(attack_end),
            }
        )
        return timing

    if attack_overlap_ratio >= 0.5 or attack_overlap >= 15.0:
        label = POSITIVE_LABEL
        stage = "attack"
        window_stage_label = "attack_window"
    else:
        label = IGNORED_LABEL
        stage = "transition"
        window_stage_label = "transition_window"
    timing.update(
        {
            "label": label,
            "stage": stage,
            "window_stage_label": window_stage_label,
            "attack_overlap_seconds": float(attack_overlap),
            "attack_overlap_ratio": float(attack_overlap_ratio),
            "attack_start_offset_seconds": float(attack_start),
            "attack_end_offset_seconds": float(attack_end),
        }
    )
    return timing


def _legacy_labels_from_run_meta(run_meta: Dict[str, Any], scenario_id: str, kind: str) -> Dict[str, Any]:
    positive_roles = ["attacker"] if run_meta.get("attacker_container_id") else []
    negative_roles = ["benign"] if run_meta.get("benign_container_id") else []
    containers = []
    role_fields = {
        "attacker": "attacker_container_id",
        "benign": "benign_container_id",
        "target": "target_container_id",
        "target_dsock": "target_dsock_container_id",
        "c2": "c2_container_id",
    }
    for role, field in role_fields.items():
        container_id = normalize_container_id(run_meta.get(field) or "")
        if not container_id:
            continue
        containers.append(
            {
                "role": role,
                "container_id": container_id,
                "container_name": "",
                "label": role_label(role, positive_roles, negative_roles),
            }
        )
    return validate_labels_payload(
        {
            "schema_version": 1,
            "scenario_id": scenario_id,
            "kind": kind,
            "positive_roles": positive_roles,
            "negative_roles": negative_roles,
            "containers": containers,
        }
    )


def load_labels_for_run(run: RunArtifacts) -> Dict[str, Any]:
    if run.labels_path and run.labels_path.exists():
        return validate_labels_payload(read_json(str(run.labels_path)) or {})
    run_meta = load_run_meta(run.run_meta_path)
    return _legacy_labels_from_run_meta(run_meta, run.scenario_id, run.kind)


def load_scenario_lookup(scenario_set: str | Path | None) -> Dict[str, Dict[str, Any]]:
    if not scenario_set:
        return {}
    try:
        manifest = load_scenario_manifest(str(ROOT_DIR), str(scenario_set))
    except Exception as exc:
        print(f"warning: scenario manifest unavailable for Top-k evidence labels: {exc}", file=sys.stderr)
        return {}
    lookup: Dict[str, Dict[str, Any]] = {}
    for scenario in manifest.get("scenarios", []) or []:
        if not isinstance(scenario, dict):
            continue
        scenario_id = str(scenario.get("id") or "").strip()
        family_id = str(scenario.get("family_id") or "").strip()
        if scenario_id:
            lookup[scenario_id] = scenario
        if family_id and family_id not in lookup:
            lookup[family_id] = scenario
    return lookup


def _expected_evidence_for_run(
    run: RunArtifacts,
    run_meta: Dict[str, Any],
    scenario_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, List[str]]:
    sources: List[Any] = [run_meta.get("expected_evidence")]
    scenario_payload = run_meta.get("scenario")
    if isinstance(scenario_payload, dict):
        sources.append(scenario_payload.get("expected_evidence"))
    lookup = scenario_lookup or {}
    for key in (run.scenario_id, str(run_meta.get("family_id") or "")):
        scenario = lookup.get(str(key or ""))
        if isinstance(scenario, dict):
            sources.append(scenario.get("expected_evidence"))

    for source in sources:
        if not isinstance(source, dict):
            continue
        normalized: Dict[str, List[str]] = {}
        for key in ("process_patterns", "file_patterns", "net_patterns", "edge_types"):
            values = [str(item).strip() for item in (source.get(key) or []) if str(item or "").strip()]
            normalized[key] = values
        if any(normalized.values()):
            return normalized
    return {"process_patterns": [], "file_patterns": [], "net_patterns": [], "edge_types": []}


def _has_expected_evidence(expected_evidence: Dict[str, List[str]]) -> bool:
    return any(expected_evidence.get(key) for key in ("process_patterns", "file_patterns", "net_patterns", "edge_types"))


def _candidate_text_parts(candidate: Dict[str, Any]) -> Tuple[str, str]:
    meta = dict(candidate.get("process_meta", {}) or {})
    process_parts = [
        candidate.get("node"),
        candidate.get("evidence_key"),
        candidate.get("display_name"),
        meta.get("name"),
        meta.get("pathname"),
        meta.get("container_image"),
        meta.get("pod_name"),
        str(meta.get("pid") or candidate.get("pid") or ""),
    ]
    evidence_parts = list(process_parts)
    evidence_parts.append(candidate.get("graph_context") or "")
    for rare_path in candidate.get("rare_paths") or []:
        if not isinstance(rare_path, dict):
            continue
        evidence_parts.append(rare_path.get("text") or "")
        evidence_parts.extend([str(item) for item in rare_path.get("keywords") or []])
        for step in rare_path.get("chain") or []:
            if isinstance(step, (list, tuple)):
                evidence_parts.extend([str(item) for item in step])
            else:
                evidence_parts.append(str(step))
    process_text = "\n".join(str(item) for item in process_parts if item not in (None, "")).lower()
    evidence_text = "\n".join(str(item) for item in evidence_parts if item not in (None, "")).lower()
    return process_text, evidence_text


def _match_patterns(text: str, patterns: Sequence[str]) -> List[str]:
    haystack = str(text or "").lower()
    matches: List[str] = []
    for pattern in patterns or []:
        needle = str(pattern or "").strip().lower()
        if needle and needle in haystack:
            matches.append(str(pattern))
    return matches


def _candidate_expected_evidence_matches(candidate: Dict[str, Any], expected_evidence: Dict[str, List[str]]) -> Dict[str, Any]:
    process_text, evidence_text = _candidate_text_parts(candidate)
    matches = {
        "process_patterns": _match_patterns(process_text, expected_evidence.get("process_patterns") or []),
        "file_patterns": _match_patterns(evidence_text, expected_evidence.get("file_patterns") or []),
        "net_patterns": _match_patterns(evidence_text, expected_evidence.get("net_patterns") or []),
        "edge_types": _match_patterns(evidence_text, expected_evidence.get("edge_types") or []),
    }
    return {
        "hit": any(matches.values()),
        "matches": matches,
    }


def _topk_not_available(reason: str) -> Dict[str, Any]:
    return {
        "status": "not_available",
        "reason": reason,
        "candidate_count": 0,
        "top1_evidence_hit": "not_available",
        "top3_evidence_hit": "not_available",
        "top5_evidence_hit": "not_available",
        "top1_matched_patterns": [],
        "top3_matched_patterns": [],
        "top5_matched_patterns": [],
    }


def _evaluate_topk_localization(candidates: Sequence[Dict[str, Any]], expected_evidence: Dict[str, List[str]]) -> Dict[str, Any]:
    if not _has_expected_evidence(expected_evidence):
        return _topk_not_available("expected_evidence_not_available")
    ranked = [dict(item) for item in candidates or []]
    if not ranked:
        return _topk_not_available("candidate_nodes_not_available")

    per_candidate = [_candidate_expected_evidence_matches(item, expected_evidence) for item in ranked]

    def hit_for(k: int) -> Tuple[bool, List[Dict[str, Any]]]:
        details: List[Dict[str, Any]] = []
        hit = False
        for idx, item in enumerate(per_candidate[: int(k)], start=1):
            if not item.get("hit"):
                continue
            hit = True
            details.append({"rank": idx, "matches": item.get("matches") or {}})
        return hit, details

    top1_hit, top1_details = hit_for(1)
    top3_hit, top3_details = hit_for(3)
    top5_hit, top5_details = hit_for(5)
    return {
        "status": "available",
        "reason": "",
        "candidate_count": int(len(ranked)),
        "top1_evidence_hit": bool(top1_hit),
        "top3_evidence_hit": bool(top3_hit),
        "top5_evidence_hit": bool(top5_hit),
        "top1_matched_patterns": top1_details,
        "top3_matched_patterns": top3_details,
        "top5_matched_patterns": top5_details,
    }


def collect_benchmark_runs(benchmark_root: str | Path) -> List[RunArtifacts]:
    root = Path(benchmark_root)
    if not root.exists():
        raise FileNotFoundError(f"benchmark root not found: {root}")

    runs: List[RunArtifacts] = []
    for windows_dir in sorted(root.rglob("windows")):
        run_dir = windows_dir.parent
        labels_path = run_dir / "labels.json"
        run_meta_path = run_dir / "run_meta.json"
        if not labels_path.exists() and not run_meta_path.exists():
            continue
        run_meta = load_run_meta(run_meta_path)
        scenario_id = str(run_meta.get("scenario_id") or run_dir.parent.name).strip() or run_dir.parent.name
        repeat_id = _infer_repeat_id(run_dir, run_meta)
        kind = str(run_meta.get("kind") or "").strip().lower()
        if not kind and labels_path.exists():
            kind = str((read_json(str(labels_path)) or {}).get("kind") or "").strip().lower()
        kind = kind or "unknown"
        runs.append(
            RunArtifacts(
                run_id=str(run_dir.relative_to(root)),
                run_dir=run_dir,
                windows_dir=windows_dir,
                scenario_id=scenario_id,
                repeat_id=repeat_id,
                kind=kind,
                labels_path=labels_path if labels_path.exists() else None,
                run_meta_path=run_meta_path if run_meta_path.exists() else None,
            )
        )
    return runs


def _empty_dataset(runs: Sequence[RunArtifacts]) -> Dict[str, Any]:
    return {
        "runs": [
            {
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "repeat_id": run.repeat_id,
                "kind": run.kind,
                "run_dir": str(run.run_dir),
            }
            for run in runs
        ],
        "process_samples": [],
        "window_samples": [],
        "role_samples": [],
        "scenario_samples": [],
        "run_debug": {},
    }


def build_run_samples(
    run: RunArtifacts,
    engine: AnalysisEngine,
    limit: int = 0,
    include_debug: bool = False,
    scenario_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    detection_config: Optional[EvalDetectionConfig] = None,
) -> Dict[str, Any]:
    labels = load_labels_for_run(run)
    run_meta = load_run_meta(run.run_meta_path)
    family_id = str(run_meta.get("family_id") or run.scenario_id)
    expected_evidence = _expected_evidence_for_run(run, run_meta, scenario_lookup=scenario_lookup)
    expected_evidence_available = _has_expected_evidence(expected_evidence)
    variant_id = str(run_meta.get("variant_id") or "")
    command_template_id = str(run_meta.get("command_template_id") or "")
    containers = [c for c in labels.get("containers", []) if c.get("label") in {POSITIVE_LABEL, NEGATIVE_LABEL}]
    process_truth: Dict[str, Dict[str, Any]] = {}
    window_samples: List[Dict[str, Any]] = []
    debug_windows: List[Dict[str, Any]] = []
    detection_cfg = detection_config or EvalDetectionConfig()

    for window_file in iter_window_files(run.windows_dir, limit=limit):
        graph = load_window_graph(str(window_file))
        window_pos_keys = set()
        window_neg_keys = set()
        window_scores: Dict[str, float] = {}

        for _, meta in proc_nodes(graph):
            pid = _safe_int(meta.get("pid"))
            container_record = _match_container_record(meta.get("container_id") or "", containers)
            if not pid or not container_record:
                continue
            label = str(container_record.get("label") or "")
            if label not in {POSITIVE_LABEL, NEGATIVE_LABEL}:
                continue
            container_short = short_container_id(container_record.get("container_id") or "")
            proc_key = f"{run.run_id}:{container_short}:{pid}"
            process_truth.setdefault(
                proc_key,
                {
                    "sample_id": proc_key,
                    "run_id": run.run_id,
                    "scenario_id": run.scenario_id,
                    "family_id": family_id,
                    "variant_id": variant_id,
                    "command_template_id": command_template_id,
                    "repeat_id": run.repeat_id,
                    "kind": run.kind,
                    "role": str(container_record.get("role") or ""),
                    "container_id": container_short,
                    "label": label,
                    "pid": pid,
                    "process_name": str(meta.get("name") or meta.get("pathname") or "unknown"),
                    "score": 0.0,
                },
            )
            if label == POSITIVE_LABEL:
                window_pos_keys.add(proc_key)
            else:
                window_neg_keys.add(proc_key)

        alert = None
        if detection_cfg.two_stage:
            detection_result = detect_two_stage_window(
                graph,
                {
                    "window_id": window_file.stem,
                    "window_mode": str(run_meta.get("window_mode") or "sliding"),
                    "window_seconds": int(run_meta.get("window_seconds") or 1800),
                    "stride_seconds": int(run_meta.get("stride_seconds") or 600),
                },
                engine.benign_kb,
                None if detection_cfg.disable_gmae else engine,
                TwoStageDetectionConfig(
                    bbk_trigger_threshold=float(detection_cfg.bbk_trigger_threshold),
                    top_k=int(detection_cfg.top_k),
                    disable_gmae=bool(detection_cfg.disable_gmae),
                    force_gmae_all_windows=bool(detection_cfg.force_gmae_all_windows),
                    window_mode=str(run_meta.get("window_mode") or "sliding"),
                    window_seconds=int(run_meta.get("window_seconds") or 1800),
                    stride_seconds=int(run_meta.get("stride_seconds") or 600),
                ),
            )
            candidates = [
                {
                    "pid": item.get("pid"),
                    "node": item.get("node"),
                    "process_score": item.get("process_score", 0.0),
                    "rarity_score": item.get("process_score", 0.0),
                    "process_meta": item.get("process_meta", {}) or {},
                    "display_name": item.get("display_name"),
                    "rare_paths": list(detection_result.get("top_rare_paths") or []),
                    "graph_context": "",
                    "evidence_key": str(item.get("node") or ""),
                }
                for item in (detection_result.get("top_processes") or [])
            ]
            if bool(detection_result.get("bbk_triggered")):
                alert = SimpleNamespace(window_score=float(detection_result.get("bbk_score") or 0.0))
        else:
            window_alerts = engine.detect_window_alerts_in_window(graph, threshold=0.0, window_hint=window_file.name)
            alert = window_alerts[0] if window_alerts else None
            candidates = engine.detect_suspicious_processes_in_window(graph, threshold=0.0, window_hint=window_file.name)
        candidate_debug: List[Dict[str, Any]] = []
        for item in candidates or []:
            meta = item.get("process_meta", {}) or {}
            pid = _safe_int(meta.get("pid"))
            container_record = _match_container_record(meta.get("container_id") or "", containers)
            if not pid or not container_record:
                continue
            label = str(container_record.get("label") or "")
            if label not in {POSITIVE_LABEL, NEGATIVE_LABEL}:
                continue
            container_short = short_container_id(container_record.get("container_id") or "")
            proc_key = f"{run.run_id}:{container_short}:{pid}"
            score = float(item.get("process_score", item.get("rarity_score", 0.0)) or 0.0)
            process_truth.setdefault(
                proc_key,
                {
                    "sample_id": proc_key,
                    "run_id": run.run_id,
                    "scenario_id": run.scenario_id,
                    "family_id": family_id,
                    "variant_id": variant_id,
                    "command_template_id": command_template_id,
                    "repeat_id": run.repeat_id,
                    "kind": run.kind,
                    "role": str(container_record.get("role") or ""),
                    "container_id": container_short,
                    "label": label,
                    "pid": pid,
                    "process_name": str(meta.get("name") or meta.get("pathname") or "unknown"),
                    "score": 0.0,
                },
            )
            process_truth[proc_key]["score"] = max(float(process_truth[proc_key].get("score", 0.0)), score)
            window_scores[proc_key] = max(float(window_scores.get(proc_key, 0.0)), score)
            if include_debug:
                candidate_debug.append(
                    {
                        "pid": pid,
                        "role": str(container_record.get("role") or ""),
                        "label": label,
                        "score": score,
                        "name": str(meta.get("name") or meta.get("pathname") or "unknown"),
                    }
                )

        window_label = ""
        relevant_keys = set()
        if window_pos_keys:
            window_label = POSITIVE_LABEL
            relevant_keys = window_pos_keys
        elif window_neg_keys:
            window_label = NEGATIVE_LABEL
            relevant_keys = window_neg_keys

        stage_info = _stage_label_for_window(run, run_meta, window_file, graph=graph)
        topk_eval = _evaluate_topk_localization(candidates, expected_evidence)
        stage_label = str(stage_info.get("label") or "")
        stage_name = str(stage_info.get("stage") or "")
        if stage_label:
            window_label = stage_label
            if stage_label == POSITIVE_LABEL:
                relevant_keys = window_pos_keys
            elif stage_label == NEGATIVE_LABEL:
                relevant_keys = window_neg_keys
            else:
                relevant_keys = set()

        if window_label:
            window_score = float(alert.window_score) if alert is not None else max((float(window_scores.get(key, 0.0)) for key in relevant_keys), default=0.0)
            window_samples.append(
                {
                    "sample_id": f"{run.run_id}:{window_file.name}",
                    "run_id": run.run_id,
                    "scenario_id": run.scenario_id,
                    "family_id": family_id,
                    "variant_id": variant_id,
                    "command_template_id": command_template_id,
                    "repeat_id": run.repeat_id,
                    "kind": run.kind,
                    "window_file": window_file.name,
                    "label": window_label,
                    "stage": stage_name,
                    "window_stage_label": str(stage_info.get("window_stage_label") or ""),
                    "window_start_offset_seconds": float(stage_info.get("window_start_offset_seconds") or 0.0),
                    "window_end_offset_seconds": float(stage_info.get("window_end_offset_seconds") or 0.0),
                    "window_seconds": float(stage_info.get("window_seconds") or 0.0),
                    "stride_seconds": float(stage_info.get("stride_seconds") or 0.0),
                    "overlap_seconds": float(stage_info.get("overlap_seconds") or 0.0),
                    "window_mode": str(stage_info.get("window_mode") or ""),
                    "window_time_source": str(stage_info.get("window_time_source") or ""),
                    "time_base_warnings": list(stage_info.get("time_base_warnings") or []),
                    "attack_overlap_seconds": float(stage_info.get("attack_overlap_seconds") or 0.0),
                    "attack_overlap_ratio": float(stage_info.get("attack_overlap_ratio") or 0.0),
                    "attack_start_offset_seconds": float(stage_info.get("attack_start_offset_seconds") or 0.0),
                    "attack_end_offset_seconds": float(stage_info.get("attack_end_offset_seconds") or 0.0),
                    "topk_evidence_status": str(topk_eval.get("status") or "not_available"),
                    "topk_evidence_reason": str(topk_eval.get("reason") or ""),
                    "expected_evidence_available": bool(expected_evidence_available),
                    "topk_candidate_count": int(topk_eval.get("candidate_count") or 0),
                    "top1_evidence_hit": topk_eval.get("top1_evidence_hit", "not_available"),
                    "top3_evidence_hit": topk_eval.get("top3_evidence_hit", "not_available"),
                    "top5_evidence_hit": topk_eval.get("top5_evidence_hit", "not_available"),
                    "top1_matched_patterns": list(topk_eval.get("top1_matched_patterns") or []),
                    "top3_matched_patterns": list(topk_eval.get("top3_matched_patterns") or []),
                    "top5_matched_patterns": list(topk_eval.get("top5_matched_patterns") or []),
                    "score": window_score,
                    "alerted": bool(alert is not None),
                }
            )

        if include_debug:
            debug_windows.append(
                {
                    "window_file": window_file.name,
                    "window_alert": alert.to_dict() if alert is not None else None,
                    "stage": stage_name,
                    "window_stage_label": str(stage_info.get("window_stage_label") or ""),
                    "window_start_offset_seconds": float(stage_info.get("window_start_offset_seconds") or 0.0),
                    "window_end_offset_seconds": float(stage_info.get("window_end_offset_seconds") or 0.0),
                    "window_mode": str(stage_info.get("window_mode") or ""),
                    "attack_overlap_seconds": float(stage_info.get("attack_overlap_seconds") or 0.0),
                    "attack_overlap_ratio": float(stage_info.get("attack_overlap_ratio") or 0.0),
                    "topk_evidence": topk_eval,
                    "expected_evidence": expected_evidence,
                    "ground_truth_positive": sorted(list(window_pos_keys)),
                    "ground_truth_negative": sorted(list(window_neg_keys)),
                    "candidate_processes": sorted(candidate_debug, key=lambda item: float(item.get("score", 0.0)), reverse=True),
                }
            )

    process_samples = sorted(process_truth.values(), key=lambda item: (item["run_id"], item["container_id"], item["pid"]))
    role_best_scores: Dict[str, float] = {}
    for item in process_samples:
        role_key = f"{item['run_id']}:{item['role']}:{item['container_id']}"
        role_best_scores[role_key] = max(float(role_best_scores.get(role_key, 0.0)), float(item.get("score", 0.0)))

    role_samples: List[Dict[str, Any]] = []
    for container in containers:
        container_short = short_container_id(container.get("container_id") or "")
        if not container_short:
            continue
        label = str(container.get("label") or "")
        if label not in {POSITIVE_LABEL, NEGATIVE_LABEL}:
            continue
        role_name = str(container.get("role") or "")
        role_key = f"{run.run_id}:{role_name}:{container_short}"
        role_samples.append(
            {
                "sample_id": role_key,
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "family_id": family_id,
                "variant_id": variant_id,
                "command_template_id": command_template_id,
                "repeat_id": run.repeat_id,
                "kind": run.kind,
                "role": role_name,
                "container_id": container_short,
                "label": label,
                "score": float(role_best_scores.get(role_key, 0.0)),
            }
        )

    attack_window_scores = [
        float(item.get("score", 0.0) or 0.0)
        for item in window_samples
        if str(item.get("window_stage_label") or "") == "attack_window"
    ]
    pos_role_scores = [float(item.get("score", 0.0)) for item in role_samples if item.get("label") == POSITIVE_LABEL]
    neg_role_scores = [float(item.get("score", 0.0)) for item in role_samples if item.get("label") == NEGATIVE_LABEL]
    scenario_samples: List[Dict[str, Any]] = []
    if str(run.kind) == "attack" and attack_window_scores:
        scenario_samples.append(
            {
                "sample_id": run.run_id,
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "family_id": family_id,
                "variant_id": variant_id,
                "command_template_id": command_template_id,
                "repeat_id": run.repeat_id,
                "kind": run.kind,
                "label": POSITIVE_LABEL,
                "score": max(attack_window_scores),
            }
        )
    elif pos_role_scores:
        scenario_samples.append(
            {
                "sample_id": run.run_id,
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "family_id": family_id,
                "variant_id": variant_id,
                "command_template_id": command_template_id,
                "repeat_id": run.repeat_id,
                "kind": run.kind,
                "label": POSITIVE_LABEL,
                "score": max(pos_role_scores),
            }
        )
    elif neg_role_scores:
        scenario_samples.append(
            {
                "sample_id": run.run_id,
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "family_id": family_id,
                "variant_id": variant_id,
                "command_template_id": command_template_id,
                "repeat_id": run.repeat_id,
                "kind": run.kind,
                "label": NEGATIVE_LABEL,
                "score": max(neg_role_scores),
            }
        )

    run_debug = {
        "run_id": run.run_id,
        "scenario_id": run.scenario_id,
        "repeat_id": run.repeat_id,
        "kind": run.kind,
        "labels": labels,
        "expected_evidence": expected_evidence,
        "window_candidates": debug_windows,
        "process_samples": process_samples,
        "role_samples": role_samples,
        "scenario_samples": scenario_samples,
    }

    return {
        "process_samples": process_samples,
        "window_samples": window_samples,
        "role_samples": role_samples,
        "scenario_samples": scenario_samples,
        "run_debug": run_debug,
    }


def build_dataset(
    runs: Sequence[RunArtifacts],
    engine: Optional[AnalysisEngine] = None,
    limit: int = 0,
    include_debug: bool = False,
    scenario_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    detection_config: Optional[EvalDetectionConfig] = None,
) -> Dict[str, Any]:
    dataset = _empty_dataset(runs)
    shared_engine = engine or AnalysisEngine()
    for run in runs:
        run_data = build_run_samples(
            run,
            shared_engine,
            limit=limit,
            include_debug=include_debug,
            scenario_lookup=scenario_lookup,
            detection_config=detection_config,
        )
        for key in ("process_samples", "window_samples", "role_samples", "scenario_samples"):
            dataset[key].extend(run_data[key])
        if include_debug:
            dataset["run_debug"][run.run_id] = run_data["run_debug"]
    return dataset


def _summarize_samples(samples: Iterable[Dict[str, Any]], threshold: float) -> Dict[str, Any]:
    tp = fp = fn = tn = 0
    for sample in samples:
        label = str(sample.get("label") or "")
        if label not in {POSITIVE_LABEL, NEGATIVE_LABEL}:
            continue
        pred_positive = float(sample.get("score", 0.0) or 0.0) >= float(threshold)
        if label == POSITIVE_LABEL and pred_positive:
            tp += 1
        elif label == NEGATIVE_LABEL and pred_positive:
            fp += 1
        elif label == POSITIVE_LABEL and not pred_positive:
            fn += 1
        else:
            tn += 1
    return compute_metrics(tp, fp, fn, tn)


def _median_or_none(values: Sequence[float]) -> float | None:
    clean = [float(item) for item in values if item is not None]
    if not clean:
        return None
    return float(median(clean))


def _summarize_topk_localization(samples: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    available = [item for item in samples if str(item.get("topk_evidence_status") or "") == "available"]
    not_available = [item for item in samples if str(item.get("topk_evidence_status") or "") == "not_available"]
    if not available:
        return {
            "status": "not_available",
            "reason": "no_windows_with_expected_evidence_and_candidate_nodes",
            "evaluated_window_count": 0,
            "not_available_window_count": int(len(not_available)),
            "top1_hits": "not_available",
            "top3_hits": "not_available",
            "top5_hits": "not_available",
            "top1_hit_rate": "not_available",
            "top3_hit_rate": "not_available",
            "top5_hit_rate": "not_available",
        }

    def hit_count(key: str) -> int:
        return sum(1 for item in available if item.get(key) is True)

    denom = float(len(available))
    top1_hits = hit_count("top1_evidence_hit")
    top3_hits = hit_count("top3_evidence_hit")
    top5_hits = hit_count("top5_evidence_hit")
    return {
        "status": "available",
        "reason": "",
        "evaluated_window_count": int(len(available)),
        "not_available_window_count": int(len(not_available)),
        "top1_hits": int(top1_hits),
        "top3_hits": int(top3_hits),
        "top5_hits": int(top5_hits),
        "top1_hit_rate": float(top1_hits) / denom,
        "top3_hit_rate": float(top3_hits) / denom,
        "top5_hit_rate": float(top5_hits) / denom,
    }


def _window_mode_counts(samples: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in samples:
        mode = str(item.get("window_mode") or "unknown")
        out[mode] = int(out.get(mode, 0)) + 1
    return out


def _scenario_detection_records(window_samples: Sequence[Dict[str, Any]], threshold: float) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    run_ids = sorted(
        {
            str(item.get("run_id") or "")
            for item in window_samples
            if str(item.get("kind") or "") == "attack" and str(item.get("run_id") or "")
        }
    )
    for run_id in run_ids:
        run_windows = [item for item in window_samples if str(item.get("run_id") or "") == run_id]
        attack_windows = [
            item
            for item in run_windows
            if str(item.get("window_stage_label") or "") == "attack_window"
        ]
        if not attack_windows:
            continue
        attack_windows = sorted(
            attack_windows,
            key=lambda item: (
                float(item.get("window_start_offset_seconds") or 0.0),
                str(item.get("window_file") or ""),
            ),
        )
        detected_windows = [
            item for item in attack_windows
            if float(item.get("score", 0.0) or 0.0) >= float(threshold)
        ]
        first_detected = detected_windows[0] if detected_windows else None
        attack_start = float(attack_windows[0].get("attack_start_offset_seconds") or 0.0)
        time_to_detect = None
        if first_detected is not None:
            time_to_detect = max(
                0.0,
                float(first_detected.get("window_start_offset_seconds") or 0.0) - float(attack_start),
            )
        records.append(
            {
                "run_id": run_id,
                "scenario_id": str(attack_windows[0].get("scenario_id") or ""),
                "family_id": str(attack_windows[0].get("family_id") or attack_windows[0].get("scenario_id") or ""),
                "repeat_id": int(attack_windows[0].get("repeat_id") or 0),
                "variant_id": str(attack_windows[0].get("variant_id") or ""),
                "command_template_id": str(attack_windows[0].get("command_template_id") or ""),
                "attack_window_count": int(len(attack_windows)),
                "detected": bool(first_detected is not None),
                "max_attack_window_score": max(float(item.get("score", 0.0) or 0.0) for item in attack_windows),
                "first_detected_window": str((first_detected or {}).get("window_file") or ""),
                "time_to_detect_seconds": time_to_detect,
                "time_to_detect_basis": "attack_window_start",
            }
        )
    return records


def _subset_dataset(dataset: Dict[str, Any], run_ids: set[str]) -> Dict[str, Any]:
    subset = {
        "runs": [run for run in dataset.get("runs", []) if run.get("run_id") in run_ids],
        "process_samples": [item for item in dataset.get("process_samples", []) if item.get("run_id") in run_ids],
        "window_samples": [item for item in dataset.get("window_samples", []) if item.get("run_id") in run_ids],
        "role_samples": [item for item in dataset.get("role_samples", []) if item.get("run_id") in run_ids],
        "scenario_samples": [item for item in dataset.get("scenario_samples", []) if item.get("run_id") in run_ids],
        "run_debug": {run_id: debug for run_id, debug in (dataset.get("run_debug") or {}).items() if run_id in run_ids},
    }
    return subset


def evaluate_dataset(dataset: Dict[str, Any], threshold: float) -> Dict[str, Any]:
    process_samples = dataset.get("process_samples", []) or []
    window_samples = dataset.get("window_samples", []) or []
    role_samples = dataset.get("role_samples", []) or []
    scenario_samples = dataset.get("scenario_samples", []) or []
    benign_window_samples = [
        item
        for item in window_samples
        if str(item.get("window_stage_label") or "") == "benign_window"
    ]
    attack_window_samples = [
        item
        for item in window_samples
        if str(item.get("window_stage_label") or "") == "attack_window"
    ]
    transition_window_samples = [
        item
        for item in window_samples
        if str(item.get("window_stage_label") or "") == "transition_window"
    ]
    benign_window_summary = _summarize_samples(benign_window_samples, threshold)
    attack_window_summary = _summarize_samples(attack_window_samples, threshold)
    topk_localization_summary = _summarize_topk_localization(attack_window_samples)
    scenario_detection_records = _scenario_detection_records(window_samples, threshold)
    scenario_count = len(scenario_detection_records)
    detected_scenario_count = sum(1 for item in scenario_detection_records if item.get("detected"))
    time_to_detect_values = [
        float(item.get("time_to_detect_seconds"))
        for item in scenario_detection_records
        if item.get("time_to_detect_seconds") is not None
    ]

    summary: Dict[str, Any] = {
        "threshold": float(threshold),
        "run_count": len(dataset.get("runs", []) or []),
        "scenario_ids": sorted({str(item.get("scenario_id") or "") for item in process_samples + window_samples + role_samples + scenario_samples if item.get("scenario_id")}),
        "process_level": _summarize_samples(process_samples, threshold),
        "window_level": _summarize_samples(window_samples, threshold),
        "benign_window_level": benign_window_summary,
        "attack_window_level": attack_window_summary,
        "role_level": _summarize_samples(role_samples, threshold),
        "scenario_level": _summarize_samples(scenario_samples, threshold),
        "scenario_level_recall": (
            float(detected_scenario_count) / float(scenario_count)
            if scenario_count > 0
            else 0.0
        ),
        "window_level_recall": float(attack_window_summary.get("recall", 0.0)),
        "benign_window_false_positive_rate": (
            float(benign_window_summary.get("fp", 0)) / float(benign_window_summary.get("negative_support", 0))
            if int(benign_window_summary.get("negative_support", 0)) > 0
            else 0.0
        ),
        "transition_window_count": int(len(transition_window_samples)),
        "median_time_to_detect_seconds": _median_or_none(time_to_detect_values),
        "scenario_detection_records": scenario_detection_records,
        "topk_localization": topk_localization_summary,
        "window_mode_counts": _window_mode_counts(window_samples),
        "window_samples": list(window_samples),
        "by_scenario": {},
        "by_role": {},
        "by_stage": {},
        "by_family": {},
    }

    for scenario_id in sorted({item.get("scenario_id") for item in process_samples + window_samples + role_samples + scenario_samples if item.get("scenario_id")}):
        scenario_window_samples = [item for item in window_samples if item.get("scenario_id") == scenario_id]
        scenario_attack_windows = [item for item in scenario_window_samples if str(item.get("window_stage_label") or "") == "attack_window"]
        summary["by_scenario"][scenario_id] = {
            "process_level": _summarize_samples([item for item in process_samples if item.get("scenario_id") == scenario_id], threshold),
            "window_level": _summarize_samples(scenario_window_samples, threshold),
            "role_level": _summarize_samples([item for item in role_samples if item.get("scenario_id") == scenario_id], threshold),
            "scenario_level": _summarize_samples([item for item in scenario_samples if item.get("scenario_id") == scenario_id], threshold),
            "topk_localization": _summarize_topk_localization(scenario_attack_windows),
            "window_mode_counts": _window_mode_counts(scenario_window_samples),
        }

    for role_name in ALLOWED_ROLES:
        process_subset = [item for item in process_samples if item.get("role") == role_name]
        role_subset = [item for item in role_samples if item.get("role") == role_name]
        if not process_subset and not role_subset:
            continue
        summary["by_role"][role_name] = {
            "process_level": _summarize_samples(process_subset, threshold),
            "role_level": _summarize_samples(role_subset, threshold),
        }

    for stage_name in sorted({str(item.get("stage") or "") for item in window_samples if item.get("stage")}):
        stage_subset = [item for item in window_samples if str(item.get("stage") or "") == stage_name]
        summary["by_stage"][stage_name] = {
            "window_level": _summarize_samples(stage_subset, threshold),
            "sample_count": int(len(stage_subset)),
            "alert_count": int(sum(1 for item in stage_subset if float(item.get("score", 0.0) or 0.0) >= float(threshold))),
            "window_stage_labels": sorted({str(item.get("window_stage_label") or "") for item in stage_subset if item.get("window_stage_label")}),
            "mean_score": (
                sum(float(item.get("score", 0.0) or 0.0) for item in stage_subset) / float(len(stage_subset))
                if stage_subset
                else 0.0
            ),
        }

    for family_id in sorted({str(item.get("family_id") or "") for item in scenario_detection_records if item.get("family_id")}):
        family_records = [item for item in scenario_detection_records if str(item.get("family_id") or "") == family_id]
        family_attack_windows = [item for item in attack_window_samples if str(item.get("family_id") or "") == family_id]
        family_ttd = [
            float(item.get("time_to_detect_seconds"))
            for item in family_records
            if item.get("time_to_detect_seconds") is not None
        ]
        family_scenario_count = len(family_records)
        family_detected_count = sum(1 for item in family_records if item.get("detected"))
        summary["by_family"][family_id] = {
            "scenario_count": int(family_scenario_count),
            "detected_scenario_count": int(family_detected_count),
            "scenario_recall": (
                float(family_detected_count) / float(family_scenario_count)
                if family_scenario_count > 0
                else 0.0
            ),
            "window_recall": float(_summarize_samples(family_attack_windows, threshold).get("recall", 0.0)),
            "median_time_to_detect_seconds": _median_or_none(family_ttd),
        }

    return summary


def evaluate_single_run(
    windows_dir: str | Path,
    labels_path: str | Path | None = None,
    run_meta_path: str | Path | None = None,
    threshold: float = DEFAULT_THRESHOLD,
    limit: int = 0,
    engine: Optional[AnalysisEngine] = None,
    include_debug: bool = False,
    scenario_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    detection_config: Optional[EvalDetectionConfig] = None,
) -> Dict[str, Any]:
    windows_path = Path(windows_dir)
    run_dir = windows_path.parent
    run_meta = load_run_meta(run_meta_path)
    scenario_id = str(run_meta.get("scenario_id") or run_dir.parent.name or "adhoc").strip()
    kind = str(run_meta.get("kind") or "unknown").strip().lower() or "unknown"
    repeat_id = _infer_repeat_id(run_dir, run_meta)
    run = RunArtifacts(
        run_id=run_dir.name,
        run_dir=run_dir,
        windows_dir=windows_path,
        scenario_id=scenario_id,
        repeat_id=repeat_id,
        kind=kind,
        labels_path=Path(labels_path) if labels_path else None,
        run_meta_path=Path(run_meta_path) if run_meta_path else None,
    )
    dataset = build_dataset(
        [run],
        engine=engine,
        limit=limit,
        include_debug=include_debug,
        scenario_lookup=scenario_lookup,
        detection_config=detection_config,
    )
    result = evaluate_dataset(dataset, threshold)
    if include_debug:
        result["debug"] = dataset.get("run_debug", {}).get(run.run_id, {})
    return result


def _pick_best_threshold(sweep: Sequence[Dict[str, Any]]) -> float:
    if not sweep:
        return DEFAULT_THRESHOLD
    ranked = sorted(
        sweep,
        key=lambda item: (
            float(((item.get("summary") or {}).get("scenario_level_recall") or 0.0)),
            float(((item.get("summary") or {}).get("window_level_recall") or 0.0)),
            -float(((item.get("summary") or {}).get("benign_window_false_positive_rate") or 0.0)),
            -abs(float(item.get("threshold", DEFAULT_THRESHOLD)) - DEFAULT_THRESHOLD),
        ),
        reverse=True,
    )
    return float(ranked[0].get("threshold", DEFAULT_THRESHOLD))


def evaluate_benchmark_root(
    benchmark_root: str | Path,
    threshold: float = DEFAULT_THRESHOLD,
    threshold_sweep: bool = False,
    engine: Optional[AnalysisEngine] = None,
    run_id_filter: Optional[set[str]] = None,
    scenario_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    detection_config: Optional[EvalDetectionConfig] = None,
) -> Dict[str, Any]:
    runs = collect_benchmark_runs(benchmark_root)
    if run_id_filter:
        runs = [run for run in runs if run.run_id in set(run_id_filter)]
    if not runs:
        raise ValueError(f"no benchmark runs found under {benchmark_root}")

    dataset = build_dataset(
        runs,
        engine=engine,
        include_debug=False,
        scenario_lookup=scenario_lookup,
        detection_config=detection_config,
    )
    fixed_all = evaluate_dataset(dataset, threshold)
    if not threshold_sweep:
        return fixed_all

    validation_run_ids = {run.run_id for run in runs if int(run.repeat_id) == 1}
    if not validation_run_ids:
        validation_run_ids = {run.run_id for run in runs}
    test_run_ids = {run.run_id for run in runs if run.run_id not in validation_run_ids}
    validation_dataset = _subset_dataset(dataset, validation_run_ids)
    test_dataset = _subset_dataset(dataset, test_run_ids or validation_run_ids)

    sweep_results = []
    for candidate in DEFAULT_SWEEP_THRESHOLDS:
        sweep_results.append(
            {
                "threshold": float(candidate),
                "summary": evaluate_dataset(validation_dataset, float(candidate)),
            }
        )

    tuned_threshold = _pick_best_threshold(sweep_results)
    return {
        "threshold_sweep_warning": (
            "Attack benchmark threshold sweeps are debug-only. Formal GMAE threshold "
            "calibration must use the benign calibration split, not attack_dev or attack_holdout."
        ),
        "split": {
            "validation_run_ids": sorted(validation_run_ids),
            "test_run_ids": sorted(test_run_ids),
            "test_fallback_to_validation": not bool(test_run_ids),
        },
        "threshold_sweep": sweep_results,
        "fixed_threshold": {
            "threshold": float(threshold),
            "validation": evaluate_dataset(validation_dataset, float(threshold)),
            "test": evaluate_dataset(test_dataset, float(threshold)),
            "all": fixed_all,
        },
        "tuned_threshold": {
            "threshold": tuned_threshold,
            "validation": evaluate_dataset(validation_dataset, tuned_threshold),
            "test": evaluate_dataset(test_dataset, tuned_threshold),
            "all": evaluate_dataset(dataset, tuned_threshold),
        },
    }


def _print_level(title: str, payload: Dict[str, Any]) -> None:
    print(title, json.dumps(payload, ensure_ascii=False))


def print_summary(summary: Dict[str, Any]) -> None:
    if "fixed_threshold" in summary and "tuned_threshold" in summary:
        fixed_test = (summary.get("fixed_threshold") or {}).get("test") or {}
        tuned_test = (summary.get("tuned_threshold") or {}).get("test") or {}
        print("fixed_threshold", float((summary.get("fixed_threshold") or {}).get("threshold", DEFAULT_THRESHOLD)))
        _print_level("fixed_primary_metrics", {
            "scenario_level_recall": fixed_test.get("scenario_level_recall", 0.0),
            "window_level_recall": fixed_test.get("window_level_recall", 0.0),
            "benign_window_false_positive_rate": fixed_test.get("benign_window_false_positive_rate", 0.0),
            "transition_window_count": fixed_test.get("transition_window_count", 0),
            "median_time_to_detect_seconds": fixed_test.get("median_time_to_detect_seconds"),
        })
        _print_level("fixed_window_level", fixed_test.get("window_level") or {})
        _print_level("fixed_scenario_level", fixed_test.get("scenario_level") or {})
        _print_level("fixed_by_family", fixed_test.get("by_family") or {})
        _print_level("fixed_topk_localization", fixed_test.get("topk_localization") or {})
        _print_level("fixed_role_level", fixed_test.get("role_level") or {})
        _print_level("fixed_process_level", fixed_test.get("process_level") or {})
        print("")
        print("tuned_threshold", float((summary.get("tuned_threshold") or {}).get("threshold", DEFAULT_THRESHOLD)))
        _print_level("tuned_primary_metrics", {
            "scenario_level_recall": tuned_test.get("scenario_level_recall", 0.0),
            "window_level_recall": tuned_test.get("window_level_recall", 0.0),
            "benign_window_false_positive_rate": tuned_test.get("benign_window_false_positive_rate", 0.0),
            "transition_window_count": tuned_test.get("transition_window_count", 0),
            "median_time_to_detect_seconds": tuned_test.get("median_time_to_detect_seconds"),
        })
        _print_level("tuned_window_level", tuned_test.get("window_level") or {})
        _print_level("tuned_scenario_level", tuned_test.get("scenario_level") or {})
        _print_level("tuned_by_family", tuned_test.get("by_family") or {})
        _print_level("tuned_topk_localization", tuned_test.get("topk_localization") or {})
        _print_level("tuned_role_level", tuned_test.get("role_level") or {})
        _print_level("tuned_process_level", tuned_test.get("process_level") or {})
        return

    print("threshold", float(summary.get("threshold", DEFAULT_THRESHOLD)))
    _print_level("primary_metrics", {
        "scenario_level_recall": summary.get("scenario_level_recall", 0.0),
        "window_level_recall": summary.get("window_level_recall", 0.0),
        "benign_window_false_positive_rate": summary.get("benign_window_false_positive_rate", 0.0),
        "transition_window_count": summary.get("transition_window_count", 0),
        "median_time_to_detect_seconds": summary.get("median_time_to_detect_seconds"),
    })
    _print_level("window_level", summary.get("window_level") or {})
    _print_level("scenario_level", summary.get("scenario_level") or {})
    _print_level("by_family", summary.get("by_family") or {})
    _print_level("topk_localization", summary.get("topk_localization") or {})
    _print_level("role_level", summary.get("role_level") or {})
    _print_level("process_level", summary.get("process_level") or {})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--windows-dir", default="data/processed/realtime_windows")
    ap.add_argument("--run-meta", default="data/processed/realtime_debug/run_meta.json")
    ap.add_argument("--labels-path", default="")
    ap.add_argument("--benchmark-root", default="")
    ap.add_argument("--scenario-set", default="config/benchmark_scenarios.atomic.json", help="Scenario manifest used for expected_evidence Top-k localization labels")
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--threshold-sweep", action="store_true", default=False)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--output-json", default="")
    ap.add_argument("--two-stage", action="store_true", default=False)
    ap.add_argument("--bbk-trigger-threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--top-k", type=int, default=3)
    ap.add_argument("--disable-gmae", action="store_true", default=False)
    ap.add_argument("--force-gmae-all-windows", action="store_true", default=False)
    args = ap.parse_args()

    threshold = float(args.threshold) if args.threshold is not None else DEFAULT_THRESHOLD
    detection_config = EvalDetectionConfig(
        two_stage=bool(args.two_stage),
        bbk_trigger_threshold=float(args.bbk_trigger_threshold),
        top_k=int(args.top_k),
        disable_gmae=bool(args.disable_gmae),
        force_gmae_all_windows=bool(args.force_gmae_all_windows),
    )
    scenario_lookup = load_scenario_lookup(args.scenario_set) if args.scenario_set else {}
    if args.benchmark_root:
        summary = evaluate_benchmark_root(
            args.benchmark_root,
            threshold=threshold,
            threshold_sweep=bool(args.threshold_sweep),
            scenario_lookup=scenario_lookup,
            detection_config=detection_config,
        )
    else:
        run_meta = load_run_meta(args.run_meta)
        if args.threshold is None:
            threshold = float(run_meta.get("threshold") or DEFAULT_THRESHOLD)
        summary = evaluate_single_run(
            args.windows_dir,
            labels_path=(args.labels_path or None),
            run_meta_path=(args.run_meta or None),
            threshold=threshold,
            limit=int(args.limit),
            include_debug=False,
            scenario_lookup=scenario_lookup,
            detection_config=detection_config,
        )

    print_summary(summary)
    if args.output_json:
        write_json(args.output_json, summary)


if __name__ == "__main__":
    main()
