#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.common.io import (
    ACTIVITY_LEVELS,
    load_mapping,
    read_json,
    safe_bool,
    safe_float,
    safe_int,
    write_json,
    write_jsonl,
)
from src.process.log_parser import TraceeLogParser
from src.process.provenance_model import ProvenanceEventMapper
from src.process.window_io import load_window_graph


DEFAULT_POLICY: dict[str, int] = {
    "empty_edge_threshold": 0,
    "idle_request_threshold": 1,
    "idle_edge_threshold": 5,
    "low_request_threshold": 5,
    "low_edge_threshold": 30,
    "burst_request_threshold": 30,
    "burst_edge_threshold": 150,
}
KNOWN_WINDOWS_DIRS = ("windows", "processed_windows", "debug_windows", "persisted_windows", "realtime_windows")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_ts(value: datetime) -> str:
    dt = value.astimezone(timezone.utc)
    timespec = "microseconds" if dt.microsecond else "seconds"
    return dt.isoformat(timespec=timespec).replace("+00:00", "Z")


def parse_datetime(value: Any, warnings: list[str], *, field_name: str = "timestamp") -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e17:
            seconds /= 1e9
        elif seconds > 1e14:
            seconds /= 1e6
        elif seconds > 1e11:
            seconds /= 1e3
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except Exception:
            warnings.append(f"invalid_numeric_{field_name}:{value}")
            return None

    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except Exception:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except Exception:
                parsed = None  # type: ignore[assignment]
        if parsed is None:
            warnings.append(f"invalid_{field_name}:{str(value)[:80]}")
            return None
    if parsed.tzinfo is None:
        warnings.append(f"naive_{field_name}_assumed_utc")
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def event_datetime_from_trace(parsed: dict[str, Any], anchor: datetime | None, warnings: list[str]) -> datetime | None:
    try:
        seconds = float(parsed.get("timestamp", 0.0))
        if seconds <= 1e8:
            warnings.append("invalid_trace_json_timestamp_without_epoch")
            return None
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except Exception as exc:
        warnings.append(f"trace_timestamp_parse_failed:{type(exc).__name__}")
        return None


def top_keys(counter: Counter[str], limit: int = 3) -> list[str]:
    return [key for key, _count in counter.most_common(limit) if key]


def window_index_for(ts: datetime, run_start: datetime, window_seconds: int, window_count: int) -> int | None:
    offset = (ts - run_start).total_seconds()
    if offset < 0:
        return None
    idx = int(math.floor(offset / float(window_seconds)))
    if idx < 0 or idx >= window_count:
        return None
    return idx


def active_second_for(ts: datetime, window_start: datetime, window_seconds: int) -> int | None:
    offset = int(math.floor((ts - window_start).total_seconds()))
    if offset < 0 or offset >= int(window_seconds):
        return None
    return offset


def normalize_duration(value: float) -> int | float:
    rounded = round(float(value), 6)
    if abs(rounded - int(rounded)) < 1e-6:
        return int(rounded)
    return rounded


def build_phase_schedule(run_dir: Path, run_meta: dict[str, Any], warnings: list[str]) -> list[dict[str, Any]]:
    raw_phases: list[Any] = []
    if isinstance(run_meta.get("phases"), list):
        raw_phases = list(run_meta.get("phases") or [])
    elif (run_dir / "phase_schedule.json").exists():
        try:
            payload = json.loads((run_dir / "phase_schedule.json").read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        if isinstance(payload, dict) and isinstance(payload.get("phases"), list):
            raw_phases = list(payload.get("phases") or [])
        elif isinstance(payload, list):
            raw_phases = list(payload)

    phases: list[dict[str, Any]] = []
    cursor = 0.0
    for idx, raw in enumerate(raw_phases, start=1):
        if not isinstance(raw, dict):
            continue
        duration = safe_float(raw.get("duration_seconds") or raw.get("seconds"), 0.0)
        start_offset = raw.get("start_offset_seconds")
        end_offset = raw.get("end_offset_seconds")
        start = safe_float(start_offset, cursor) if start_offset is not None else cursor
        end = safe_float(end_offset, start + duration) if end_offset is not None else start + duration
        if end <= start:
            continue
        phase_id = str(raw.get("phase") or raw.get("phase_id") or raw.get("id") or f"phase_{idx:02d}").strip()
        profile_id = str(raw.get("profile") or raw.get("profile_id") or raw.get("source_profile") or "").strip()
        phases.append(
            {
                "phase_id": phase_id,
                "profile_id": profile_id,
                "start_offset_seconds": float(start),
                "end_offset_seconds": float(end),
            }
        )
        cursor = end
    if raw_phases and not phases:
        warnings.append("phase_schedule_found_but_not_usable")
    return phases


def infer_phase(ts: datetime, run_start: datetime, phases: list[dict[str, Any]]) -> str | None:
    if not phases:
        return None
    offset = (ts - run_start).total_seconds()
    for phase in phases:
        start = safe_float(phase.get("start_offset_seconds"), 0.0)
        end = safe_float(phase.get("end_offset_seconds"), start)
        if start <= offset < end:
            return str(phase.get("phase_id") or phase.get("profile_id") or "").strip() or None
    return None


def load_request_events(path: Path, warnings: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    stats = {
        "request_events_total": 0,
        "request_lines_total": 0,
        "request_lines_failed": 0,
        "success_count": 0,
        "failure_count": 0,
        "retry_count": 0,
        "per_actor_count": {},
        "per_profile_count": {},
    }
    events: list[dict[str, Any]] = []
    if not path.exists() or path.stat().st_size <= 0:
        return events, stats

    per_actor: Counter[str] = Counter()
    per_profile: Counter[str] = Counter()
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            stats["request_lines_total"] = int(stats["request_lines_total"]) + 1
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise ValueError("request event is not an object")
            except Exception as exc:
                stats["request_lines_failed"] = int(stats["request_lines_failed"]) + 1
                if int(stats["request_lines_failed"]) <= 5:
                    warnings.append(f"request_event_parse_failed:{type(exc).__name__}:{line[:120]}")
                continue

            ts = parse_datetime(payload.get("ts") or payload.get("timestamp") or payload.get("time"), warnings, field_name="request_ts")
            if ts is None:
                stats["request_lines_failed"] = int(stats["request_lines_failed"]) + 1
                continue
            payload["_dt"] = ts
            events.append(payload)
            stats["request_events_total"] = int(stats["request_events_total"]) + 1
            if safe_bool(payload.get("success")):
                stats["success_count"] = int(stats["success_count"]) + 1
            else:
                stats["failure_count"] = int(stats["failure_count"]) + 1
            if safe_bool(payload.get("retry")):
                stats["retry_count"] = int(stats["retry_count"]) + 1
            actor = str(payload.get("actor") or "").strip()
            profile = str(payload.get("profile") or "").strip()
            if actor:
                per_actor[actor] += 1
            if profile:
                per_profile[profile] += 1
    stats["per_actor_count"] = dict(sorted(per_actor.items()))
    stats["per_profile_count"] = dict(sorted(per_profile.items()))
    return events, stats


def choose_first_datetime(values: list[datetime | None]) -> datetime | None:
    for value in values:
        if value is not None:
            return value
    return None


def choose_time_bounds(
    *,
    run_meta: dict[str, Any],
    collection_summary: dict[str, Any],
    request_events: list[dict[str, Any]],
    trace_times: list[datetime],
    warnings: list[str],
) -> tuple[datetime, datetime, str, str]:
    run_meta_start = parse_datetime(
        run_meta.get("start_ts") or run_meta.get("start_time") or run_meta.get("started_at"),
        warnings,
        field_name="run_meta_start_ts",
    )
    collection_start = parse_datetime(collection_summary.get("start_ts"), warnings, field_name="collection_start_ts")
    request_start = min((event["_dt"] for event in request_events), default=None)
    trace_start = min(trace_times, default=None)

    run_start = choose_first_datetime([run_meta_start, collection_start, request_start, trace_start])
    if run_start is None:
        raise ValueError("cannot determine run start timestamp from run_meta, collection_summary, request_events, or trace.log")
    if run_start == run_meta_start:
        start_source = "run_meta"
    elif run_start == collection_start:
        start_source = "collection_summary"
    elif run_start == request_start:
        start_source = "request_events"
    else:
        start_source = "trace_log"

    run_meta_end = parse_datetime(
        run_meta.get("end_ts") or run_meta.get("end_time") or run_meta.get("ended_at"),
        warnings,
        field_name="run_meta_end_ts",
    )
    collection_end = parse_datetime(collection_summary.get("end_ts"), warnings, field_name="collection_end_ts")
    request_end = max((event["_dt"] for event in request_events), default=None)
    trace_end = max(trace_times, default=None)
    duration_seconds = safe_float(
        run_meta.get("duration_seconds")
        or collection_summary.get("duration_seconds_requested")
        or collection_summary.get("duration_seconds_actual"),
        0.0,
    )
    duration_end = run_start + timedelta(seconds=duration_seconds) if duration_seconds > 0 else None

    run_end = choose_first_datetime([run_meta_end, collection_end, request_end, trace_end, duration_end])
    if run_end is None or run_end <= run_start:
        if duration_end is not None and duration_end > run_start:
            run_end = duration_end
            end_source = "duration_seconds"
        elif request_end is not None and request_end > run_start:
            run_end = request_end
            end_source = "request_events"
        elif trace_end is not None and trace_end > run_start:
            run_end = trace_end
            end_source = "trace_log"
        else:
            run_end = run_start + timedelta(seconds=30)
            end_source = "default_one_window"
            warnings.append("run_end_missing_or_not_after_start_defaulted_to_one_window")
    elif run_end == run_meta_end:
        end_source = "run_meta"
    elif run_end == collection_end:
        end_source = "collection_summary"
    elif run_end == request_end:
        end_source = "request_events"
    elif run_end == trace_end:
        end_source = "trace_log"
    else:
        end_source = "duration_seconds"

    return run_start, run_end, start_source, end_source


def new_window(run_id: str, split: str, dataset: str, idx: int, start: datetime, window_seconds: int) -> dict[str, Any]:
    end = start + timedelta(seconds=int(window_seconds))
    return {
        "window_id": f"{run_id}_w{idx + 1:06d}",
        "run_id": run_id,
        "split": split,
        "dataset": dataset,
        "start_ts": format_ts(start),
        "end_ts": format_ts(end),
        "duration_seconds": int(window_seconds),
        "dominant_phase": None,
        "active_roles": [],
        "dominant_profiles": [],
        "request_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "retry_count": 0,
        "per_actor_count": {},
        "per_profile_count": {},
        "per_action_count": {},
        "raw_event_count": 0,
        "node_count": 0,
        "edge_count": 0,
        "unique_process_count": 0,
        "unique_file_count": 0,
        "unique_net_count": 0,
        "active_seconds_estimate": 0.0,
        "activity_level": "empty",
        "notes": [],
        "_start_dt": start,
        "_active_seconds": set(),
        "_actors": Counter(),
        "_profiles": Counter(),
        "_actions": Counter(),
        "_phases": Counter(),
        "_process_nodes": set(),
        "_file_nodes": set(),
        "_net_nodes": set(),
        "_approx_edges": 0,
        "_graph_stats_from_windows_dir": False,
    }


def finalize_window(window: dict[str, Any], policy: dict[str, int], graph_stats_source: str) -> dict[str, Any]:
    actors: Counter[str] = window.pop("_actors")
    profiles: Counter[str] = window.pop("_profiles")
    actions: Counter[str] = window.pop("_actions")
    phases: Counter[str] = window.pop("_phases")
    process_nodes: set[str] = window.pop("_process_nodes")
    file_nodes: set[str] = window.pop("_file_nodes")
    net_nodes: set[str] = window.pop("_net_nodes")
    active_seconds: set[int] = window.pop("_active_seconds")
    approx_edges = int(window.pop("_approx_edges"))
    window.pop("_start_dt", None)

    graph_stats_from_windows_dir = bool(window.pop("_graph_stats_from_windows_dir", False))
    if not graph_stats_from_windows_dir:
        window["unique_process_count"] = len(process_nodes)
        window["unique_file_count"] = len(file_nodes)
        window["unique_net_count"] = len(net_nodes)
        window["node_count"] = len(process_nodes) + len(file_nodes) + len(net_nodes)
        window["edge_count"] = approx_edges
    window["per_actor_count"] = dict(sorted(actors.items()))
    window["per_profile_count"] = dict(sorted(profiles.items()))
    window["per_action_count"] = dict(sorted(actions.items()))
    window["active_roles"] = sorted(actors.keys())
    window["dominant_profiles"] = top_keys(profiles, 3)
    if phases:
        window["dominant_phase"] = phases.most_common(1)[0][0]
    window["active_seconds_estimate"] = float(len(active_seconds))
    window["activity_level"] = classify_activity(window, policy, graph_stats_source)
    if graph_stats_source == "trace_approximation" or (graph_stats_source == "windows_dir" and not graph_stats_from_windows_dir):
        notes = list(window.get("notes") or [])
        if "approximate_graph_stats" not in notes:
            notes.append("approximate_graph_stats")
        window["notes"] = notes
    return window


def classify_activity(window: dict[str, Any], policy: dict[str, int], graph_stats_source: str = "trace_approximation") -> str:
    request_count = safe_int(window.get("request_count"), 0)
    edge_count = safe_int(window.get("edge_count"), 0)
    raw_event_count = safe_int(window.get("raw_event_count"), 0)
    active_roles = set(window.get("active_roles") or [])
    per_actor = dict(window.get("per_actor_count") or {})
    per_action = dict(window.get("per_action_count") or {})
    dominant_phase = str(window.get("dominant_phase") or "").lower()

    if raw_event_count == 0 and request_count == 0 and edge_count <= int(policy["empty_edge_threshold"]):
        return "empty"

    if active_roles and active_roles == {"health_checker"}:
        return "idle"

    background_report = safe_int(per_actor.get("background_worker"), 0) > 0 and any(
        safe_int(per_action.get(action), 0) > 0 for action in ("report_export", "legal_backup_read")
    )

    is_burst_phase = "burst" in dominant_phase
    has_burst_retry_user = safe_int(per_actor.get("burst_retry_user"), 0) > 0

    if is_burst_phase:
        return "burst"

    if has_burst_retry_user and request_count > int(policy["low_request_threshold"]):
        return "burst"

    if graph_stats_source != "trace_approximation" and edge_count >= int(policy["burst_edge_threshold"]):
        return "burst"

    if not background_report and request_count <= int(policy["idle_request_threshold"]) and edge_count <= int(policy["idle_edge_threshold"]):
        return "idle"

    if request_count <= int(policy["low_request_threshold"]) and edge_count <= int(policy["low_edge_threshold"]):
        return "low_activity"

    return "active"


def add_node_to_window(window: dict[str, Any], node: str, meta: dict[str, Any] | None = None) -> None:
    value = str(node or "")
    if value.startswith("proc:"):
        window["_process_nodes"].add(value)
    elif value.startswith("file:"):
        window["_file_nodes"].add(value)
    elif value.startswith("net:"):
        if meta and meta.get("is_unspec_net"):
            return
        window["_net_nodes"].add(value)


def add_trace_fallback_entities(window: dict[str, Any], parsed: dict[str, Any]) -> None:
    container_id = str(parsed.get("container_id") or "host")[:12] or "host"
    pid = safe_int(parsed.get("pid"), 0)
    comm = str(parsed.get("comm") or "unknown")
    if pid:
        window["_process_nodes"].add(f"proc:container:{container_id}:pid:{pid}:{comm}")
    args = dict(parsed.get("args") or {})
    path = str(args.get("pathname") or args.get("path") or args.get("mountpoint") or "")
    if path:
        window["_file_nodes"].add(f"file:{path}")
    for key in ("remote_addr", "dest_addr", "src_addr", "addr", "local_addr"):
        value = args.get(key)
        if value:
            window["_net_nodes"].add(f"net:{json.dumps(value, sort_keys=True) if isinstance(value, dict) else value}")


def parse_trace_log(
    path: Path,
    *,
    anchor: datetime | None,
    allow_missing: bool,
    warnings: list[str],
    errors: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    stats = {
        "trace_log_exists": path.exists(),
        "trace_log_size_bytes": path.stat().st_size if path.exists() else 0,
        "trace_lines_total": 0,
        "trace_lines_parsed": 0,
        "trace_lines_failed": 0,
        "trace_lines_non_json": 0,
        "parse_error_examples": [],
    }
    if not path.exists() or path.stat().st_size <= 0:
        message = "missing_trace_log"
        if allow_missing:
            warnings.append(message)
        else:
            errors.append(message)
        return [], stats

    parser = TraceeLogParser()
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            stats["trace_lines_total"] = int(stats["trace_lines_total"]) + 1
            if not raw.lstrip().startswith("{"):
                stats["trace_lines_non_json"] = int(stats["trace_lines_non_json"]) + 1
            parsed = None
            try:
                parsed = parser.parse_line(raw)
            except Exception as exc:
                parsed = None
                if len(stats["parse_error_examples"]) < 5:
                    stats["parse_error_examples"].append(f"{type(exc).__name__}:{raw[:160]}")

            if parsed is None:
                stats["trace_lines_failed"] = int(stats["trace_lines_failed"]) + 1
                if len(stats["parse_error_examples"]) < 5:
                    stats["parse_error_examples"].append(raw[:160])
                continue

            dt = event_datetime_from_trace(parsed, anchor, warnings)
            if dt is None:
                stats["trace_lines_failed"] = int(stats["trace_lines_failed"]) + 1
                continue
            parsed["_dt"] = dt
            events.append(parsed)
            stats["trace_lines_parsed"] = int(stats["trace_lines_parsed"]) + 1

    if int(stats["trace_lines_total"]) > 0 and int(stats["trace_lines_parsed"]) == 0:
        warnings.append("trace_parse_failed")
    return events, stats


def discover_windows_dir(run_dir: Path, explicit: str) -> Path | None:
    if explicit:
        path = Path(explicit)
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        return path
    for name in KNOWN_WINDOWS_DIRS:
        candidate = run_dir / name
        if candidate.exists() and candidate.is_dir():
            return candidate
    return None


def window_index_from_name(path: Path) -> int | None:
    name = path.stem
    patterns = [
        r"(?:^|[_-])window[_-]?0*([0-9]+)$",
        r"(?:^|[_-])w0*([0-9]+)$",
        r"0*([0-9]+)$",
    ]
    for pattern in patterns:
        match = re.search(pattern, name)
        if match:
            idx = safe_int(match.group(1), 0)
            if idx > 0:
                return idx - 1
    return None


def graph_stats_from_nodes_edges(nodes: list[Any], edges: list[Any]) -> dict[str, int]:
    process_count = 0
    file_count = 0
    net_count = 0
    for raw in nodes:
        if isinstance(raw, dict):
            node_id = str(raw.get("id") or raw.get("name") or raw.get("node") or "")
        else:
            node_id = str(raw or "")
        if node_id.startswith("proc:"):
            process_count += 1
        elif node_id.startswith("file:"):
            file_count += 1
        elif node_id.startswith("net:"):
            net_count += 1
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "unique_process_count": process_count,
        "unique_file_count": file_count,
        "unique_net_count": net_count,
    }


def load_graph_stats(path: Path) -> dict[str, int] | None:
    if path.suffix.lower() == ".jsonl":
        with path.open("r", encoding="utf-8", errors="ignore") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    return None
                return stats_from_graph_payload(payload)
        return None

    try:
        graph = load_window_graph(str(path))
        nodes = list(graph.nodes())
        edges = list(graph.edges())
        stats = graph_stats_from_nodes_edges(nodes, edges)
        stats["node_count"] = int(graph.number_of_nodes())
        stats["edge_count"] = int(graph.number_of_edges())
        return stats
    except Exception:
        pass

    payload = read_json(path)
    if not payload:
        return None
    return stats_from_graph_payload(payload)


def stats_from_graph_payload(payload: dict[str, Any]) -> dict[str, int] | None:
    for key in ("node_count", "edge_count"):
        if key in payload:
            return {
                "node_count": safe_int(payload.get("node_count"), 0),
                "edge_count": safe_int(payload.get("edge_count"), 0),
                "unique_process_count": safe_int(payload.get("unique_process_count") or payload.get("process_node_count"), 0),
                "unique_file_count": safe_int(payload.get("unique_file_count") or payload.get("file_node_count"), 0),
                "unique_net_count": safe_int(payload.get("unique_net_count") or payload.get("net_node_count"), 0),
            }
    nodes = payload.get("nodes")
    edges = payload.get("edges") if "edges" in payload else payload.get("links")
    if isinstance(nodes, list) and isinstance(edges, list):
        return graph_stats_from_nodes_edges(nodes, edges)
    graph_payload = payload.get("graph")
    if isinstance(graph_payload, dict):
        return stats_from_graph_payload(graph_payload)
    return None


def apply_windows_dir_stats(windows: list[dict[str, Any]], windows_dir: Path | None, warnings: list[str]) -> str:
    if windows_dir is None:
        return "trace_approximation"
    if not windows_dir.exists() or not windows_dir.is_dir():
        warnings.append(f"windows_dir_not_found:{windows_dir}")
        return "trace_approximation"

    candidates = sorted([p for p in windows_dir.iterdir() if p.is_file() and p.suffix.lower() in {".json", ".jsonl"}])
    if not candidates:
        warnings.append("windows_dir_found_but_empty")
        return "trace_approximation"

    aligned = 0
    for path in candidates:
        idx = window_index_from_name(path)
        if idx is None or idx < 0 or idx >= len(windows):
            continue
        try:
            stats = load_graph_stats(path)
        except Exception as exc:
            warnings.append(f"window_graph_load_failed:{path.name}:{type(exc).__name__}")
            continue
        if stats is None:
            continue
        for key in ("node_count", "edge_count", "unique_process_count", "unique_file_count", "unique_net_count"):
            windows[idx][key] = safe_int(stats.get(key), 0)
        windows[idx]["_graph_stats_from_windows_dir"] = True
        aligned += 1

    if aligned <= 0:
        warnings.append("windows_dir_found_but_not_aligned")
        return "trace_approximation"
    if aligned < len(windows):
        warnings.append(f"windows_dir_partial_alignment:{aligned}/{len(windows)}")
    return "windows_dir"


def build_policy(config_path: str, warnings: list[str]) -> dict[str, int]:
    policy = dict(DEFAULT_POLICY)
    if not config_path:
        return policy
    payload = load_mapping(Path(config_path), warnings)
    raw = payload.get("classification_policy") if isinstance(payload.get("classification_policy"), dict) else payload
    if isinstance(raw, dict):
        for key in list(policy):
            if key in raw:
                policy[key] = safe_int(raw.get(key), policy[key])
    return policy


def build_window_activity(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    run_dir = Path(args.run_dir).expanduser().resolve()
    trace_log = Path(args.trace_log).expanduser().resolve() if args.trace_log else run_dir / "trace.log"
    request_events_path = Path(args.request_events).expanduser().resolve() if args.request_events else run_dir / "request_events.jsonl"
    run_meta_path = Path(args.run_meta).expanduser().resolve() if args.run_meta else run_dir / "run_meta.json"
    collection_summary_path = (
        Path(args.collection_summary).expanduser().resolve() if args.collection_summary else run_dir / "collection_summary.json"
    )
    output_path = Path(args.output).expanduser().resolve() if args.output else run_dir / "window_activity.jsonl"
    summary_path = Path(args.summary_output).expanduser().resolve() if args.summary_output else run_dir / "window_activity_summary.json"

    warnings: list[str] = []
    errors: list[str] = []
    if output_path.exists() and not args.force:
        raise FileExistsError(f"output already exists, pass --force to overwrite: {output_path}")

    run_meta = read_json(run_meta_path)
    collection_summary = read_json(collection_summary_path)
    request_events, request_stats = load_request_events(request_events_path, warnings)
    if (not request_events_path.exists() or request_events_path.stat().st_size <= 0) and not args.allow_missing_request_events:
        errors.append("missing_request_events")
    elif not request_events:
        warnings.append("missing_request_events")

    preliminary_start = choose_first_datetime(
        [
            parse_datetime(run_meta.get("start_ts") or run_meta.get("start_time") or run_meta.get("started_at"), warnings, field_name="run_meta_start_ts"),
            parse_datetime(collection_summary.get("start_ts"), warnings, field_name="collection_start_ts"),
            min((event["_dt"] for event in request_events), default=None),
        ]
    )
    trace_events, trace_stats = parse_trace_log(
        trace_log,
        anchor=preliminary_start,
        allow_missing=bool(args.allow_missing_trace),
        warnings=warnings,
        errors=errors,
    )

    if errors:
        summary = {
            "dataset": str(run_meta.get("dataset") or collection_summary.get("dataset") or "benign_corpus_v3"),
            "run_id": str(run_meta.get("run_id") or collection_summary.get("run_id") or run_dir.name),
            "split": str(run_meta.get("split") or collection_summary.get("split") or ""),
            "run_dir": str(run_dir),
            "window_seconds": int(args.window_seconds),
            "time_bin_seconds": int(args.time_bin_seconds),
            "start_ts": "",
            "end_ts": "",
            "window_count": 0,
            "activity_level_counts": {level: 0 for level in ACTIVITY_LEVELS},
            "request_event_stats": request_stats,
            "trace_stats": trace_stats,
            "graph_stats_source": "unavailable",
            "classification_policy": build_policy(args.config, warnings),
            "warnings": sorted(set(warnings)),
            "errors": errors,
        }
        write_json(summary_path, summary)
        raise RuntimeError("; ".join(errors))

    trace_times = [event["_dt"] for event in trace_events]
    run_start, run_end, start_source, end_source = choose_time_bounds(
        run_meta=run_meta,
        collection_summary=collection_summary,
        request_events=request_events,
        trace_times=trace_times,
        warnings=warnings,
    )
    window_seconds = max(int(args.window_seconds), 1)
    time_bin_seconds = max(int(args.time_bin_seconds), 1)
    duration = max((run_end - run_start).total_seconds(), float(window_seconds))
    window_count = max(int(math.ceil(duration / float(window_seconds))), 1)

    dataset = str(run_meta.get("dataset") or collection_summary.get("dataset") or "benign_corpus_v3")
    run_id = str(run_meta.get("run_id") or collection_summary.get("run_id") or run_dir.name)
    split = str(run_meta.get("split") or collection_summary.get("split") or "")
    phases = build_phase_schedule(run_dir, run_meta, warnings)

    windows = [
        new_window(run_id, split, dataset, idx, run_start + timedelta(seconds=idx * window_seconds), window_seconds)
        for idx in range(window_count)
    ]
    if not trace_events:
        for window in windows:
            notes = list(window.get("notes") or [])
            if "missing_trace_log" not in notes:
                notes.append("missing_trace_log")
            window["notes"] = notes
    if not request_events:
        for window in windows:
            notes = list(window.get("notes") or [])
            if "missing_request_events" not in notes:
                notes.append("missing_request_events")
            window["notes"] = notes

    for event in request_events:
        dt = event["_dt"]
        idx = window_index_for(dt, run_start, window_seconds, window_count)
        if idx is None:
            continue
        window = windows[idx]
        window["request_count"] = safe_int(window.get("request_count"), 0) + 1
        if safe_bool(event.get("success")):
            window["success_count"] = safe_int(window.get("success_count"), 0) + 1
        else:
            window["failure_count"] = safe_int(window.get("failure_count"), 0) + 1
        if safe_bool(event.get("retry")):
            window["retry_count"] = safe_int(window.get("retry_count"), 0) + 1
        actor = str(event.get("actor") or "").strip()
        profile = str(event.get("profile") or "").strip()
        action = str(event.get("action") or "").strip()
        phase = str(event.get("phase") or "").strip() or infer_phase(dt, run_start, phases)
        if actor:
            window["_actors"][actor] += 1
        if profile:
            window["_profiles"][profile] += 1
        if action:
            window["_actions"][action] += 1
        if phase:
            window["_phases"][phase] += 1
        second = active_second_for(dt, window["_start_dt"], window_seconds)
        if second is not None:
            window["_active_seconds"].add(second)

    mapper = ProvenanceEventMapper()
    for event in trace_events:
        dt = event["_dt"]
        idx = window_index_for(dt, run_start, window_seconds, window_count)
        if idx is None:
            continue
        window = windows[idx]
        window["raw_event_count"] = safe_int(window.get("raw_event_count"), 0) + 1
        add_trace_fallback_entities(window, event)
        edge = mapper.parse_log_event(event)
        if edge is not None:
            window["_approx_edges"] = safe_int(window.get("_approx_edges"), 0) + 1
            add_node_to_window(window, edge.src, edge.src_meta)
            add_node_to_window(window, edge.dst, edge.dst_meta)
        second = active_second_for(dt, window["_start_dt"], window_seconds)
        if second is not None:
            window["_active_seconds"].add(second)

    windows_dir = discover_windows_dir(run_dir, args.windows_dir)
    graph_stats_source = apply_windows_dir_stats(windows, windows_dir, warnings)
    if graph_stats_source == "trace_approximation" and not trace_events:
        graph_stats_source = "unavailable"

    policy = build_policy(args.config, warnings)
    final_rows = [finalize_window(window, policy, graph_stats_source) for window in windows]
    level_counts = Counter(str(row.get("activity_level") or "") for row in final_rows)

    if graph_stats_source == "trace_approximation":
        warnings.append("approximate_graph_stats")

    summary = {
        "dataset": dataset,
        "run_id": run_id,
        "split": split,
        "run_dir": str(run_dir),
        "window_seconds": window_seconds,
        "time_bin_seconds": time_bin_seconds,
        "start_ts": format_ts(run_start),
        "end_ts": format_ts(run_end),
        "window_count": len(final_rows),
        "activity_level_counts": {level: int(level_counts.get(level, 0)) for level in ACTIVITY_LEVELS},
        "request_event_stats": request_stats,
        "trace_stats": trace_stats,
        "graph_stats_source": graph_stats_source,
        "classification_policy": policy,
        "time_bounds": {
            "start_source": start_source,
            "end_source": end_source,
            "window_coverage_end_ts": final_rows[-1]["end_ts"] if final_rows else "",
        },
        "windows_dir": str(windows_dir) if windows_dir else "",
        "generated_at": format_ts(utc_now()),
        "warnings": sorted(set(warnings)),
        "errors": errors,
    }

    write_jsonl(output_path, final_rows)
    write_json(summary_path, summary)
    return final_rows, summary


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build benign corpus v3 window activity metadata.")
    parser.add_argument("--run-dir", required=True, help="Run directory containing trace.log and request_events.jsonl.")
    parser.add_argument("--window-seconds", type=int, default=30, help="Stable window size in seconds.")
    parser.add_argument("--time-bin-seconds", type=int, default=2, help="Time bin size recorded in summary.")
    parser.add_argument("--trace-log", default="", help="Tracee trace log path. Default: <run-dir>/trace.log.")
    parser.add_argument("--request-events", default="", help="Request events JSONL path. Default: <run-dir>/request_events.jsonl.")
    parser.add_argument("--run-meta", default="", help="Run metadata path. Default: <run-dir>/run_meta.json.")
    parser.add_argument("--collection-summary", default="", help="Collection summary path. Default: <run-dir>/collection_summary.json.")
    parser.add_argument("--windows-dir", default="", help="Optional persisted window graph directory.")
    parser.add_argument("--output", default="", help="Output JSONL path. Default: <run-dir>/window_activity.jsonl.")
    parser.add_argument("--summary-output", default="", help="Summary JSON path. Default: <run-dir>/window_activity_summary.json.")
    parser.add_argument("--config", default="", help="Optional JSON/YAML policy config.")
    parser.add_argument("--allow-missing-trace", action="store_true", help="Build from request_events.jsonl when trace.log is missing.")
    parser.add_argument(
        "--allow-missing-request-events",
        action="store_true",
        help="Build from trace.log when request_events.jsonl is missing.",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite existing output files.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    try:
        rows, summary = build_window_activity(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        "window activity built: "
        f"run_id={summary.get('run_id')} windows={len(rows)} "
        f"graph_stats_source={summary.get('graph_stats_source')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
