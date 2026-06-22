#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import asdict, dataclass
from statistics import mean
import time
from typing import Any, Dict, List, Optional

import networkx as nx

from src.analysis.anomalous_subgraph_builder import build_anomalous_subgraphs
from src.analysis.bbk_window_scorer import score_bbk_window
from src.common.defaults import (
    DEFAULT_ALERT_THRESHOLD,
    DEFAULT_DETECT_STRIDE_SECONDS,
    DEFAULT_GMAE_NODE_THRESHOLD,
    DEFAULT_GMAE_THRESHOLD_QUANTILE,
    DEFAULT_MAX_ANOMALOUS_NODES,
    DEFAULT_TOPK_NODE_REPORTS,
    DEFAULT_WINDOW_SECONDS,
)


@dataclass(frozen=True)
class TwoStageDetectionConfig:
    bbk_trigger_threshold: float = DEFAULT_ALERT_THRESHOLD
    top_k: int = DEFAULT_TOPK_NODE_REPORTS
    disable_gmae: bool = False
    force_gmae_all_windows: bool = False
    gmae_node_threshold: float = DEFAULT_GMAE_NODE_THRESHOLD
    gmae_threshold_quantile: float = DEFAULT_GMAE_THRESHOLD_QUANTILE
    max_anomalous_nodes: int = DEFAULT_MAX_ANOMALOUS_NODES
    window_mode: str = "sliding"
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    stride_seconds: int = DEFAULT_DETECT_STRIDE_SECONDS


@dataclass(frozen=True)
class NodeAnomalyResult:
    node_id: str
    node_type: str
    display_name: str
    gmae_score: float
    gmae_raw_error: float | None
    gmae_threshold: float
    is_anomalous: bool
    rank: int
    evidence: Dict[str, Any]


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


def _node_type_from_id(node_id: str) -> str:
    node = str(node_id or "")
    if node.startswith("proc:"):
        return "process"
    if node.startswith("file:"):
        return "file"
    if node.startswith("net:"):
        return "network"
    return "unknown"


def _load_threshold_from_calibration(runtime: Any, default_threshold: float, quantile: float) -> tuple[float, str]:
    calibration = getattr(runtime, "gmae_runtime", None)
    if isinstance(calibration, dict):
        calibration = calibration.get("process_error_calibration")
    if isinstance(runtime, dict):
        calibration = runtime.get("process_error_calibration")
    if not isinstance(calibration, dict):
        return float(default_threshold), "default"
    if str(calibration.get("type") or "") != "empirical_cdf":
        return float(default_threshold), "default"
    scores = calibration.get("scores") or []
    if not scores:
        return float(default_threshold), "default"
    try:
        q = float(quantile)
    except Exception:
        q = 0.95
    q = max(0.0, min(1.0, q))
    return float(q), "calibration_quantile"


def _top_gmae_processes(
    graph: nx.MultiDiGraph,
    gmae_results: List[NodeAnomalyResult],
    top_k: int,
    supporting_rare_paths: List[Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in (gmae_results or []):
        node_id = str(item.node_id)
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
                "process_score": float(item.gmae_score),
                "gmae_score": float(item.gmae_score),
                "gmae_raw_error": item.gmae_raw_error,
                "gmae_threshold": float(item.gmae_threshold),
                "is_anomalous": bool(item.is_anomalous),
                "score_source": "gmae",
                "process_meta": meta,
                "supporting_rare_paths": list(supporting_rare_paths or [])[:3],
                "evidence": dict(item.evidence or {}),
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
    structured_fn = getattr(gmae_runtime, "score_process_node_results", None)
    wrapped_runtime = getattr(gmae_runtime, "gmae_runtime", None)
    load_error = str(getattr(gmae_runtime, "gmae_load_error", "") or "")
    if callable(score_fn):
        if wrapped_runtime is None and not callable(gmae_runtime):
            return score_fn, False, load_error or "gmae_runtime_not_loaded"
        return score_fn, True, ""
    if callable(structured_fn):
        if wrapped_runtime is None and not callable(gmae_runtime):
            return structured_fn, True, ""
        return structured_fn, True, ""
    if callable(gmae_runtime):
        return gmae_runtime, True, ""
    return None, False, load_error or "gmae_unavailable"


def _build_node_anomaly_results(
    graph: nx.MultiDiGraph,
    raw_scores: Dict[str, float],
    *,
    raw_errors: Optional[Dict[str, float]] = None,
    threshold: float,
    max_anomalous_nodes: int,
) -> List[NodeAnomalyResult]:
    ranked = sorted(
        [(str(node_id), float(score)) for node_id, score in (raw_scores or {}).items() if str(node_id).startswith("proc:")],
        key=lambda item: (float(item[1]), str(item[0])),
        reverse=True,
    )
    results: List[NodeAnomalyResult] = []
    anomalous_budget = max(int(max_anomalous_nodes), 0)
    kept_anomalous = 0
    for rank, (node_id, score) in enumerate(ranked, start=1):
        if node_id not in graph:
            continue
        meta = dict(graph.nodes[node_id].get("meta", {}) or {})
        is_anomalous = bool(score >= float(threshold))
        if is_anomalous and anomalous_budget > 0 and kept_anomalous >= anomalous_budget:
            is_anomalous = False
        if is_anomalous:
            kept_anomalous += 1
        results.append(
            NodeAnomalyResult(
                node_id=node_id,
                node_type=_node_type_from_id(node_id),
                display_name=_process_display_name(meta),
                gmae_score=float(score),
                gmae_raw_error=float((raw_errors or {}).get(node_id)) if raw_errors and node_id in raw_errors else None,
                gmae_threshold=float(threshold),
                is_anomalous=is_anomalous,
                rank=int(rank),
                evidence={
                    "pid": meta.get("pid"),
                    "container_id": str(meta.get("container_id") or ""),
                    "pathname": meta.get("pathname") or "",
                    "process_name": _process_display_name(meta),
                },
            )
        )
    return results


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
    gmae_warning = ""
    gmae_node_threshold = float(cfg.gmae_node_threshold)
    top_processes: List[Dict[str, Any]] = []
    anomalous_nodes: List[Dict[str, Any]] = []
    anomalous_subgraphs: List[Dict[str, Any]] = []
    supported_node_types = ["process"]

    if bool(cfg.disable_gmae):
        gmae_reason = "gmae_disabled"
    elif not should_run_gmae:
        gmae_reason = "bbk_score_below_trigger_threshold"
    elif not gmae_available:
        gmae_reason = str(unavailable_reason or "gmae_unavailable")
    else:
        try:
            structured_score_fn = getattr(gmae_runtime, "score_process_node_results", None)
            if callable(structured_score_fn):
                gmae_scores = structured_score_fn(
                    graph,
                    threshold=float(cfg.gmae_node_threshold),
                    threshold_quantile=float(cfg.gmae_threshold_quantile),
                    max_anomalous_nodes=int(cfg.max_anomalous_nodes),
                )
            else:
                gmae_scores = score_fn(graph) if callable(score_fn) else {}

            if isinstance(gmae_scores, dict) and "node_results" in gmae_scores:
                raw_results = list(gmae_scores.get("node_results") or [])
                top_processes = _top_gmae_processes(
                    graph,
                    [
                        NodeAnomalyResult(
                            node_id=str(item.get("node_id") or item.get("node") or ""),
                            node_type=str(item.get("node_type") or "process"),
                            display_name=str(item.get("display_name") or "unknown"),
                            gmae_score=float(item.get("gmae_score") or 0.0),
                            gmae_raw_error=float(item["gmae_raw_error"]) if item.get("gmae_raw_error") is not None else None,
                            gmae_threshold=float(item.get("gmae_threshold") or cfg.gmae_node_threshold),
                            is_anomalous=bool(item.get("is_anomalous")),
                            rank=int(item.get("rank") or 0),
                            evidence=dict(item.get("evidence") or {}),
                        )
                        for item in raw_results
                        if str(item.get("node_id") or item.get("node") or "").startswith("proc:")
                    ],
                    int(cfg.top_k),
                    supporting_rare_paths=list(bbk_result.get("top_rare_paths") or []),
                )
                anomalous_nodes = [
                    dict(item)
                    for item in raw_results
                    if bool(item.get("is_anomalous"))
                ][: max(int(cfg.max_anomalous_nodes), 0) or len(raw_results)]
                threshold_values = [float(item.get("gmae_threshold") or 0.0) for item in raw_results if item.get("gmae_threshold") is not None]
                if threshold_values:
                    gmae_node_threshold = float(threshold_values[0])
                supported_node_types = list(gmae_scores.get("supported_node_types") or supported_node_types)
                gmae_warning = str(gmae_scores.get("warning") or "")
                gmae_triggered = True
            else:
                raw_errors: Dict[str, float] = {}
                threshold_source = "default"
                if gmae_runtime is not None:
                    gmae_node_threshold, threshold_source = _load_threshold_from_calibration(
                        getattr(gmae_runtime, "gmae_runtime", gmae_runtime),
                        float(cfg.gmae_node_threshold),
                        float(cfg.gmae_threshold_quantile),
                    )
                if not str(threshold_source).startswith("calibration"):
                    gmae_warning = "missing_gmae_calibration_threshold: using default node threshold"
                node_results = _build_node_anomaly_results(
                    graph,
                    dict(gmae_scores or {}),
                    raw_errors=raw_errors,
                    threshold=float(gmae_node_threshold),
                    max_anomalous_nodes=int(cfg.max_anomalous_nodes),
                )
                top_processes = _top_gmae_processes(
                    graph,
                    node_results,
                    int(cfg.top_k),
                    supporting_rare_paths=list(bbk_result.get("top_rare_paths") or []),
                )
                anomalous_nodes = [asdict(item) for item in node_results if bool(item.is_anomalous)]
                gmae_triggered = True
            if not top_processes:
                gmae_reason = "gmae_returned_no_process_scores"
        except Exception as exc:
            gmae_reason = f"gmae_scoring_failed:{type(exc).__name__}: {exc}"

    if anomalous_nodes:
        try:
            score_map: Dict[str, float] = {}
            for item in anomalous_nodes:
                node_id = str(item.get("node_id") or item.get("node") or "")
                if not node_id:
                    continue
                if item.get("gmae_raw_error") is not None:
                    score_map[node_id] = float(item.get("gmae_raw_error") or 0.0)
                else:
                    score_map[node_id] = float(item.get("gmae_score") or 0.0)
            anomalous_subgraphs = build_anomalous_subgraphs(
                graph,
                anomalous_nodes,
                score_map,
            )
        except Exception as exc:
            gmae_warning = (str(gmae_warning).strip() + f"; anomalous_subgraph_build_failed:{type(exc).__name__}: {exc}").strip("; ")
    ended = time.perf_counter()

    status = "anomalous" if bbk_triggered else "normal"
    if gmae_triggered and not bbk_triggered and bool(cfg.force_gmae_all_windows):
        stage = "gmae_forced"
    else:
        stage = "bbk_gmae" if gmae_triggered else "bbk_only"

    return {
        **identity,
        "pipeline_mode": "two_stage",
        "node_count": int(graph.number_of_nodes()) if graph is not None else 0,
        "edge_count": int(graph.number_of_edges()) if graph is not None else 0,
        "bbk_score": float(bbk_score),
        "bbk_threshold": float(threshold),
        "bbk_trigger_threshold": float(threshold),
        "bbk_triggered": bool(bbk_triggered),
        "gmae_triggered": bool(gmae_triggered),
        "gmae_ran": bool(gmae_triggered),
        "gmae_available": bool(gmae_available),
        "gmae_warning": str(gmae_warning or ""),
        "gmae_reason_if_skipped": "" if gmae_triggered else str(gmae_reason or ""),
        "gmae_node_threshold": float(gmae_node_threshold),
        "supported_node_types": list(supported_node_types),
        "anomalous_nodes": list(anomalous_nodes),
        "anomalous_subgraphs": list(anomalous_subgraphs),
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
