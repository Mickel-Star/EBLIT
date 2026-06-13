#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from statistics import mean
import time
from typing import Any, Dict, List

import networkx as nx

from src.analysis.bbk_window_scorer import score_bbk_window
from src.common.defaults import (
    DEFAULT_ALERT_THRESHOLD,
    DEFAULT_DETECT_STRIDE_SECONDS,
    DEFAULT_TOPK_NODE_REPORTS,
    DEFAULT_WINDOW_SECONDS,
)


@dataclass(frozen=True)
class TwoStageDetectionConfig:
    bbk_trigger_threshold: float = DEFAULT_ALERT_THRESHOLD
    top_k: int = DEFAULT_TOPK_NODE_REPORTS
    disable_gmae: bool = False
    force_gmae_all_windows: bool = False
    window_mode: str = "sliding"
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    stride_seconds: int = DEFAULT_DETECT_STRIDE_SECONDS


def _graph_meta(graph: nx.MultiDiGraph, key: str, default: Any = None) -> Any:
    metadata = getattr(graph, "graph", {}) or {}
    return metadata.get(key, default) if isinstance(metadata, dict) else default


def _config_value(graph: nx.MultiDiGraph, key: str, default: Any = None) -> Any:
    metadata = getattr(graph, "graph", {}) or {}
    for container in ("sliding_window_config", "reduction_config"):
        cfg = metadata.get(container) if isinstance(metadata, dict) else None
        if isinstance(cfg, dict) and cfg.get(key) not in (None, ""):
            return cfg.get(key)
    return default


def _window_identity(
    graph: nx.MultiDiGraph,
    window_meta: Dict[str, Any] | None,
    config: TwoStageDetectionConfig,
) -> Dict[str, Any]:
    meta = dict(window_meta or {})
    return {
        "window_id": str(meta.get("window_id") or _graph_meta(graph, "window_id", "window_in_memory")),
        "window_start": meta.get("window_start", _graph_meta(graph, "window_start")),
        "window_end": meta.get("window_end", _graph_meta(graph, "window_end")),
        "window_mode": str(meta.get("window_mode") or _graph_meta(graph, "window_mode", config.window_mode)),
        "window_seconds": int(meta.get("window_seconds") or _config_value(graph, "window_seconds", config.window_seconds)),
        "stride_seconds": int(meta.get("stride_seconds") or _config_value(graph, "stride_seconds", config.stride_seconds)),
    }


def _process_display_name(meta: Dict[str, Any]) -> str:
    return str(meta.get("name") or meta.get("pathname") or "unknown")


def _top_gmae_processes(
    graph: nx.MultiDiGraph,
    gmae_scores: Dict[str, float],
    top_k: int,
    supporting_rare_paths: List[Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for node_id, score in (gmae_scores or {}).items():
        if not str(node_id).startswith("proc:"):
            continue
        if node_id not in graph:
            continue
        meta = dict(graph.nodes[node_id].get("meta", {}) or {})
        rows.append(
            {
                "node": str(node_id),
                "node_id": str(node_id),
                "pid": meta.get("pid"),
                "host_pid": meta.get("pid"),
                "container_id": str(meta.get("container_id") or ""),
                "display_name": _process_display_name(meta),
                "process_name": _process_display_name(meta),
                "pathname": meta.get("pathname") or "",
                "process_score": float(score),
                "gmae_score": float(score),
                "score_source": "gmae",
                "process_meta": meta,
                "supporting_rare_paths": list(supporting_rare_paths or [])[:3],
            }
        )
    rows.sort(key=lambda item: (float(item.get("process_score", 0.0)), str(item.get("node") or "")), reverse=True)
    limited = rows[: max(int(top_k), 0)]
    for idx, item in enumerate(limited, start=1):
        item["rank"] = int(idx)
    return limited


def _resolve_gmae_runner(gmae_runtime: Any):
    if gmae_runtime is None:
        return None, False, "gmae_unavailable"

    score_fn = getattr(gmae_runtime, "score_process_nodes", None)
    wrapped_runtime = getattr(gmae_runtime, "gmae_runtime", None)
    load_error = str(getattr(gmae_runtime, "gmae_load_error", "") or "")
    if callable(score_fn):
        if wrapped_runtime is None and not callable(gmae_runtime):
            return score_fn, False, load_error or "gmae_runtime_not_loaded"
        return score_fn, True, ""
    if callable(gmae_runtime):
        return gmae_runtime, True, ""
    return None, False, load_error or "gmae_unavailable"


def detect_two_stage_window(
    graph: nx.MultiDiGraph,
    window_meta: Dict[str, Any] | None,
    bbk: Any,
    gmae_runtime: Any,
    config: TwoStageDetectionConfig | Dict[str, Any],
) -> Dict[str, Any]:
    if isinstance(config, dict):
        cfg = TwoStageDetectionConfig(**config)
    else:
        cfg = config

    identity = _window_identity(graph, window_meta, cfg)
    started = time.perf_counter()
    bbk_result = score_bbk_window(graph, bbk)
    after_bbk = time.perf_counter()
    bbk_score = float(bbk_result.get("bbk_score", 0.0) or 0.0)
    threshold = float(cfg.bbk_trigger_threshold)
    bbk_triggered = bool(bbk_score >= threshold)
    score_fn, gmae_available, unavailable_reason = _resolve_gmae_runner(gmae_runtime)
    should_run_gmae = bool(cfg.force_gmae_all_windows or bbk_triggered)
    gmae_triggered = False
    gmae_reason = ""
    top_processes: List[Dict[str, Any]] = []

    if bool(cfg.disable_gmae):
        gmae_reason = "gmae_disabled"
    elif not should_run_gmae:
        gmae_reason = "bbk_score_below_trigger_threshold"
    elif not gmae_available:
        gmae_reason = str(unavailable_reason or "gmae_unavailable")
    else:
        try:
            gmae_scores = score_fn(graph) if callable(score_fn) else {}
            top_processes = _top_gmae_processes(
                graph,
                dict(gmae_scores or {}),
                int(cfg.top_k),
                supporting_rare_paths=list(bbk_result.get("top_rare_paths") or []),
            )
            gmae_triggered = True
            if not top_processes:
                gmae_reason = "gmae_returned_no_process_scores"
        except Exception as exc:
            gmae_reason = f"gmae_scoring_failed:{type(exc).__name__}: {exc}"
    ended = time.perf_counter()

    status = "anomalous" if bbk_triggered else "normal"
    if gmae_triggered and not bbk_triggered and bool(cfg.force_gmae_all_windows):
        stage = "gmae_forced"
    else:
        stage = "bbk_gmae" if gmae_triggered else "bbk_only"

    return {
        **identity,
        "node_count": int(graph.number_of_nodes()) if graph is not None else 0,
        "edge_count": int(graph.number_of_edges()) if graph is not None else 0,
        "bbk_score": float(bbk_score),
        "bbk_trigger_threshold": float(threshold),
        "bbk_triggered": bool(bbk_triggered),
        "gmae_triggered": bool(gmae_triggered),
        "gmae_available": bool(gmae_available),
        "gmae_reason_if_skipped": "" if gmae_triggered else str(gmae_reason or ""),
        "top_processes": top_processes,
        "process_node_count": int(bbk_result.get("process_node_count", 0) or 0),
        "candidate_process_count": int(bbk_result.get("candidate_process_count", 0) or 0),
        "top_candidate_processes": list(bbk_result.get("top_candidate_processes") or []),
        "process_novelty_threshold": float(bbk_result.get("process_novelty_threshold", 0.0) or 0.0),
        "novelty_stats": dict(bbk_result.get("novelty_stats") or {}),
        "top_rare_paths": list(bbk_result.get("top_rare_paths") or []),
        "rare_edge_ratio": float(bbk_result.get("rare_edge_ratio", 0.0) or 0.0),
        "top_rare_mean": float(bbk_result.get("top_rare_mean", 0.0) or 0.0),
        "rare_edge_count": int(bbk_result.get("rare_edge_count", 0) or 0),
        "total_edge_count": int(bbk_result.get("total_edge_count", 0) or 0),
        "bbk_reason": bbk_result.get("reason"),
        "status": status,
        "stage": stage,
        "score": float(bbk_score),
        "average_topk_gmae_score": float(mean([float(item.get("gmae_score") or 0.0) for item in top_processes])) if top_processes else 0.0,
        "timing": {
            "bbk_time_ms": float((after_bbk - started) * 1000.0),
            "gmae_time_ms": float((ended - after_bbk) * 1000.0) if gmae_triggered else 0.0,
            "total_window_time_ms": float((ended - started) * 1000.0),
        },
    }


def summarize_two_stage_results(
    results: List[Dict[str, Any]],
    *,
    top_k: int,
    window_seconds: int,
    stride_seconds: int,
    window_mode: str,
) -> Dict[str, Any]:
    total_windows = int(len(results))
    bbk_triggered_windows = int(sum(1 for item in results if bool(item.get("bbk_triggered"))))
    gmae_triggered_windows = int(sum(1 for item in results if bool(item.get("gmae_triggered"))))
    reduction_ratio = 1.0 - (float(gmae_triggered_windows) / float(total_windows)) if total_windows else 0.0
    bbk_times = [float((item.get("timing") or {}).get("bbk_time_ms") or 0.0) for item in results]
    gmae_times = [float((item.get("timing") or {}).get("gmae_time_ms") or 0.0) for item in results]
    total_times = [float((item.get("timing") or {}).get("total_window_time_ms") or 0.0) for item in results]
    total_times_sorted = sorted(total_times)
    p95_idx = max(0, min(len(total_times_sorted) - 1, int(len(total_times_sorted) * 0.95) - 1)) if total_times_sorted else 0
    return {
        "total_windows": total_windows,
        "bbk_triggered_windows": bbk_triggered_windows,
        "gmae_triggered_windows": gmae_triggered_windows,
        "gmae_reduction_ratio": float(reduction_ratio),
        "average_bbk_time_ms": float(mean(bbk_times)) if bbk_times else 0.0,
        "average_gmae_time_ms": float(mean(gmae_times)) if gmae_times else 0.0,
        "average_total_window_time_ms": float(mean(total_times)) if total_times else 0.0,
        "p95_total_window_time_ms": float(total_times_sorted[p95_idx]) if total_times_sorted else 0.0,
        "topk": int(top_k),
        "window_seconds": int(window_seconds),
        "stride_seconds": int(stride_seconds),
        "window_mode": str(window_mode),
    }
