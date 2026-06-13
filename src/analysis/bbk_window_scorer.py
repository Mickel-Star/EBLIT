#!/usr/bin/env python3
from __future__ import annotations

import math
from statistics import mean
from typing import Any, Callable, Dict, List

import networkx as nx

from src.process.provenance_model import RarePathSelector


DEFAULT_RARE_SUPPORT_THRESHOLD = 1e-3
DEFAULT_TOP_M_RARE_EDGES = 10
DEFAULT_PROCESS_NOVELTY_THRESHOLD = 0.15


def _normalize_rarity(raw_score: float) -> float:
    score = max(float(raw_score or 0.0), 0.0)
    if score <= 0.0:
        return 0.0
    return max(0.0, min(1.0, 1.0 - math.exp(-score * math.log(2.0))))


def _edge_label(g: nx.MultiDiGraph, src: str, dst: str, edge_type: str) -> str:
    src_meta = g.nodes.get(src, {}).get("meta", {}) or {}
    dst_meta = g.nodes.get(dst, {}).get("meta", {}) or {}
    src_name = src_meta.get("pathname") or src_meta.get("name") or src
    dst_name = dst_meta.get("pathname") or dst_meta.get("name") or dst
    return f"{src_name} {edge_type}-> {dst_name}"


def _resolve_method(obj: Any, name: str) -> Callable[..., Any] | None:
    fn = getattr(obj, name, None)
    return fn if callable(fn) else None


def _percentile(sorted_values: List[float], ratio: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    idx = max(0, min(len(sorted_values) - 1, int(math.ceil(float(ratio) * len(sorted_values))) - 1))
    return float(sorted_values[idx])


def _rare_path_payload(graph: nx.MultiDiGraph, seed: str, item: Dict[str, Any], *, process_score: float, novelty: float) -> Dict[str, Any]:
    payload = {
        "process_node": str(seed),
        "process_score": float(process_score),
        "process_novelty": float(novelty),
        "text": item.get("text"),
        "score": float(_normalize_rarity(float(item.get("score", 0.0) or 0.0))),
        "raw_score": float(item.get("score", 0.0) or 0.0),
        "keywords": list(item.get("keywords") or []),
        "chain": list(item.get("chain") or []),
    }
    if payload["chain"]:
        first_edge = payload["chain"][0]
        payload["edge_text"] = _edge_label(graph, str(first_edge[0]), str(first_edge[2]), str(first_edge[1]))
    return payload


def score_bbk_window(
    graph: nx.MultiDiGraph,
    bbk: Any,
    *,
    rare_support_threshold: float = DEFAULT_RARE_SUPPORT_THRESHOLD,
    top_m: int = DEFAULT_TOP_M_RARE_EDGES,
    process_novelty_threshold: float | None = None,
) -> Dict[str, Any]:
    """Score a single window graph with node-driven BBK Stage-1 logic."""

    node_count = int(graph.number_of_nodes()) if graph is not None else 0
    total_edge_count = int(graph.number_of_edges()) if graph is not None else 0
    base = {
        "bbk_score": 0.0,
        "rare_edge_ratio": 0.0,
        "top_rare_mean": 0.0,
        "rare_edge_count": 0,
        "total_edge_count": total_edge_count,
        "process_node_count": 0,
        "candidate_process_count": 0,
        "top_candidate_processes": [],
        "process_novelty_threshold": float(process_novelty_threshold or DEFAULT_PROCESS_NOVELTY_THRESHOLD),
        "novelty_stats": {
            "count": 0,
            "candidate_count": 0,
            "mean": 0.0,
            "min": 0.0,
            "max": 0.0,
            "p95": 0.0,
        },
        "top_rare_paths": [],
        "reason": None,
    }
    if graph is None or node_count <= 0 or total_edge_count <= 0:
        base["reason"] = "empty_window_graph"
        return base

    support_fn = _resolve_method(bbk, "support")
    canonical_signature_fn = _resolve_method(bbk, "canonical_signature")
    novelty_fn = _resolve_method(bbk, "novelty_score")
    has_signature_fn = _resolve_method(bbk, "has_signature")
    threshold_fn = _resolve_method(bbk, "get_process_novelty_threshold")
    if support_fn is None or canonical_signature_fn is None:
        base["reason"] = "bbk_unavailable: missing canonical_signature/support"
        return base

    novelty_threshold = float(process_novelty_threshold or DEFAULT_PROCESS_NOVELTY_THRESHOLD)
    if process_novelty_threshold is None and threshold_fn is not None:
        try:
            novelty_threshold = float(threshold_fn(DEFAULT_PROCESS_NOVELTY_THRESHOLD))
        except Exception:
            novelty_threshold = float(process_novelty_threshold or DEFAULT_PROCESS_NOVELTY_THRESHOLD)
    novelty_threshold = max(1e-6, min(1.0, novelty_threshold))
    base["process_novelty_threshold"] = float(novelty_threshold)

    process_nodes: List[str] = [str(node) for node in graph.nodes if str(node).startswith("proc:")]
    base["process_node_count"] = int(len(process_nodes))
    if not process_nodes:
        base["reason"] = "no_process_nodes"
        return base

    raw_novelties: List[float] = []
    candidate_rows: List[Dict[str, Any]] = []
    rare_selector = RarePathSelector(k1=10, k2=max(int(top_m), 1))
    rare_support_threshold = max(float(rare_support_threshold), 1e-12)

    for node in process_nodes:
        meta = dict(graph.nodes[node].get("meta", {}) or {})
        try:
            signature = canonical_signature_fn(node, meta)
        except Exception:
            signature = None
        exact_seen = False
        if has_signature_fn is not None and signature:
            try:
                exact_seen = bool(has_signature_fn(signature, "proc"))
            except Exception:
                exact_seen = False
        if novelty_fn is not None:
            try:
                novelty = float(novelty_fn(node, meta))
            except Exception:
                novelty = 1.0
        else:
            novelty = 1.0 if not exact_seen else 0.0
        novelty = max(0.0, min(1.0, novelty))
        raw_novelties.append(novelty)

        is_candidate = (not exact_seen) or (novelty >= novelty_threshold)
        if not is_candidate:
            continue

        rare_paths = rare_selector.select_with_chains(graph, node, support_fn)
        rare_paths = [rp for rp in rare_paths if float(rp.get("score", 0.0) or 0.0) >= 0.0]
        top_raw_score = float((rare_paths[0] or {}).get("score", 0.0)) if rare_paths else 0.0
        process_score = _normalize_rarity(top_raw_score)
        candidate_rows.append(
            {
                "node": str(node),
                "node_id": str(node),
                "pid": meta.get("pid"),
                "host_pid": meta.get("pid"),
                "container_id": str(meta.get("container_id") or ""),
                "display_name": str(meta.get("name") or meta.get("pathname") or "unknown"),
                "process_name": str(meta.get("name") or meta.get("pathname") or "unknown"),
                "pathname": meta.get("pathname") or "",
                "signature": signature,
                "exact_signature_seen": bool(exact_seen),
                "novelty": float(novelty),
                "process_novelty_threshold": float(novelty_threshold),
                "candidate_reason": "exact_signature_unseen" if not exact_seen else "novelty_above_threshold",
                "process_bbk_score": float(process_score),
                "top_path_score": float(process_score),
                "bbk_score": float(process_score),
                "score_source": "bbk",
                "process_meta": meta,
                "rare_paths": [
                    {
                        "text": rp.get("text"),
                        "score": _normalize_rarity(float(rp.get("score", 0.0) or 0.0)),
                        "raw_score": float(rp.get("score", 0.0) or 0.0),
                        "keywords": list(rp.get("keywords") or []),
                        "chain": list(rp.get("chain") or []),
                    }
                    for rp in rare_paths
                ],
                "top_rare_path": _rare_path_payload(graph, node, rare_paths[0], process_score=process_score, novelty=novelty)
                if rare_paths
                else None,
            }
        )

    if not raw_novelties:
        base["reason"] = "no_process_nodes"
        return base

    raw_novelties_sorted = sorted(raw_novelties)
    base["novelty_stats"] = {
        "count": int(len(raw_novelties_sorted)),
        "candidate_count": int(len(candidate_rows)),
        "mean": float(mean(raw_novelties_sorted)) if raw_novelties_sorted else 0.0,
        "min": float(raw_novelties_sorted[0]) if raw_novelties_sorted else 0.0,
        "max": float(raw_novelties_sorted[-1]) if raw_novelties_sorted else 0.0,
        "p95": float(_percentile(raw_novelties_sorted, 0.95)),
    }

    candidate_rows.sort(
        key=lambda row: (
            float(row.get("process_bbk_score", 0.0)),
            float(row.get("novelty", 0.0)),
            str(row.get("node") or ""),
        ),
        reverse=True,
    )

    top_candidate_processes = candidate_rows[: max(int(top_m), 1)]
    top_rare_paths: List[Dict[str, Any]] = []
    for row in top_candidate_processes:
        if row.get("top_rare_path") is not None:
            top_rare_paths.append(dict(row["top_rare_path"]))

    bbk_score = max((float(row.get("process_bbk_score", 0.0)) for row in candidate_rows), default=0.0)
    rare_edge_count = len(top_rare_paths)
    rare_edge_ratio = float(rare_edge_count) / float(max(total_edge_count, 1))
    top_rare_mean = float(mean([float(row.get("process_bbk_score", 0.0)) for row in top_candidate_processes])) if top_candidate_processes else 0.0

    reason = None
    if not candidate_rows:
        reason = "no_suspicious_processes"
    elif rare_edge_count == 0:
        reason = "candidate_processes_without_rare_paths"

    return {
        "bbk_score": float(bbk_score),
        "rare_edge_ratio": float(rare_edge_ratio),
        "top_rare_mean": float(top_rare_mean),
        "rare_edge_count": int(rare_edge_count),
        "total_edge_count": int(total_edge_count),
        "process_node_count": int(len(process_nodes)),
        "candidate_process_count": int(len(candidate_rows)),
        "top_candidate_processes": top_candidate_processes,
        "process_novelty_threshold": float(novelty_threshold),
        "novelty_stats": base["novelty_stats"],
        "top_rare_paths": top_rare_paths,
        "reason": reason,
    }
