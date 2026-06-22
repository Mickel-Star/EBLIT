#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

import networkx as nx


ABNORMALITY_LEVELS = ("minor", "moderate", "significant", "critical")
ABNORMALITY_RANK = {name: idx for idx, name in enumerate(ABNORMALITY_LEVELS)}


@dataclass(frozen=True)
class AnomalousNodeRecord:
    node_id: str
    node_type: str
    display_name: str
    score: float
    raw_error: float | None
    is_anomalous: bool
    rank: int
    evidence: Dict[str, Any]


def _node_type(node_id: str, meta: Dict[str, Any] | None = None) -> str:
    node = str(node_id or "")
    if node.startswith("proc:"):
        return "process"
    if node.startswith("file:"):
        return "file"
    if node.startswith("net:"):
        return "network"
    meta = dict(meta or {})
    return str(meta.get("node_type") or "unknown")


def _display_name(node_id: str, meta: Dict[str, Any] | None = None) -> str:
    info = dict(meta or {})
    return str(info.get("display_name") or info.get("pathname") or info.get("name") or node_id or "unknown")


def _score_value(record: Dict[str, Any], node_scores: Dict[str, float]) -> float:
    node_id = str(record.get("node_id") or record.get("node") or "")
    if node_id in node_scores:
        return float(node_scores[node_id])
    if record.get("gmae_raw_error") is not None:
        return float(record.get("gmae_raw_error") or 0.0)
    return float(record.get("gmae_score") or 0.0)


def _normalize_anomalous_nodes(
    anomalous_nodes: Sequence[Dict[str, Any]] | Sequence[str],
    node_scores: Dict[str, float],
    graph: nx.MultiDiGraph,
) -> List[AnomalousNodeRecord]:
    records: List[AnomalousNodeRecord] = []
    for idx, item in enumerate(anomalous_nodes or [], start=1):
        if isinstance(item, str):
            node_id = str(item)
            if node_id not in graph:
                continue
            meta = dict(graph.nodes[node_id].get("meta", {}) or {})
            records.append(
                AnomalousNodeRecord(
                    node_id=node_id,
                    node_type=_node_type(node_id, meta),
                    display_name=_display_name(node_id, meta),
                    score=float(node_scores.get(node_id, 0.0)),
                    raw_error=None,
                    is_anomalous=True,
                    rank=int(idx),
                    evidence={},
                )
            )
            continue

        row = dict(item or {})
        if not bool(row.get("is_anomalous", True)):
            continue
        node_id = str(row.get("node_id") or row.get("node") or "")
        if not node_id or node_id not in graph:
            continue
        meta = dict(graph.nodes[node_id].get("meta", {}) or {})
        records.append(
            AnomalousNodeRecord(
                node_id=node_id,
                node_type=str(row.get("node_type") or _node_type(node_id, meta)),
                display_name=str(row.get("display_name") or _display_name(node_id, meta)),
                score=float(_score_value(row, node_scores)),
                raw_error=float(row["gmae_raw_error"]) if row.get("gmae_raw_error") is not None else None,
                is_anomalous=bool(row.get("is_anomalous", True)),
                rank=int(row.get("rank") or idx),
                evidence=dict(row.get("evidence") or {}),
            )
        )
    records.sort(key=lambda item: (float(item.score), -int(item.rank), str(item.node_id)), reverse=True)
    return records


def _select_seed_nodes(records: Sequence[AnomalousNodeRecord], nseed_per_type: int) -> List[str]:
    grouped: Dict[str, List[AnomalousNodeRecord]] = {}
    for item in records:
        grouped.setdefault(str(item.node_type or "unknown"), []).append(item)
    seeds: List[str] = []
    for node_type in sorted(grouped):
        items = sorted(grouped[node_type], key=lambda row: (float(row.score), -int(row.rank), str(row.node_id)), reverse=True)
        seeds.extend([str(row.node_id) for row in items[: max(int(nseed_per_type), 0)]])
    deduped: List[str] = []
    seen: Set[str] = set()
    for node_id in seeds:
        if node_id not in seen:
            seen.add(node_id)
            deduped.append(node_id)
    return deduped


def _local_nodes(graph: nx.MultiDiGraph, anomalous_ids: Set[str]) -> Set[str]:
    selected = set(anomalous_ids)
    for node_id in list(anomalous_ids):
        if node_id not in graph:
            continue
        selected.update(str(pred) for pred in graph.predecessors(node_id))
        selected.update(str(succ) for succ in graph.successors(node_id))
    return selected


def _path_support_nodes(component: nx.MultiDiGraph, seeds: Sequence[str], anomalous_ids: Set[str]) -> Set[str]:
    undirected = component.to_undirected()
    support_nodes: Set[str] = set()
    useful_seeds = [str(node_id) for node_id in seeds if str(node_id) in component and str(node_id) in anomalous_ids]
    if not useful_seeds:
        useful_seeds = sorted(anomalous_ids & set(component.nodes))
    for seed in useful_seeds:
        for other in sorted((anomalous_ids & set(component.nodes)) - {seed}):
            try:
                path = nx.shortest_path(undirected, seed, other)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if len(path) < 2:
                continue
            support_nodes.update(str(node_id) for node_id in path)
    return support_nodes


def _edge_sort_key(edge: Tuple[str, str, int, Dict[str, Any]]) -> Tuple[int, int, str, str]:
    src, dst, _key, data = edge
    attrs = dict(data or {})
    return (
        int(attrs.get("first_ts", 0) or 0),
        int(attrs.get("last_ts", 0) or 0),
        str(src),
        str(dst),
    )


def _edge_payload(src: str, dst: str, data: Dict[str, Any]) -> Dict[str, Any]:
    attrs = dict(data or {})
    return {
        "src": str(src),
        "dst": str(dst),
        "event_type": str(attrs.get("type") or ""),
        "type": str(attrs.get("type") or ""),
        "event_name": str(attrs.get("event_name") or ""),
        "event_names": list(attrs.get("event_names") or []),
        "count": int(attrs.get("count", 1) or 1),
        "frequency": int(attrs.get("count", 1) or 1),
        "direction": "src_to_dst",
        "first_ts": int(attrs.get("first_ts", 0) or 0),
        "last_ts": int(attrs.get("last_ts", 0) or 0),
        "timestamp": int(attrs.get("first_ts", 0) or 0),
        "bin_idx": int(attrs.get("bin_idx", 0) or 0),
        "segments": list(attrs.get("segments") or []),
        "source_semantic_version": int(attrs.get("source_semantic_version", 0) or 0),
    }


def _node_payload(node_id: str, graph: nx.MultiDiGraph, anomalous_ids: Set[str], score_map: Dict[str, float]) -> Dict[str, Any]:
    meta = dict(graph.nodes[node_id].get("meta", {}) or {})
    return {
        "node_id": str(node_id),
        "node_type": _node_type(node_id, meta),
        "display_name": _display_name(node_id, meta),
        "is_anomalous": bool(node_id in anomalous_ids),
        "score": float(score_map.get(str(node_id), 0.0)),
        "meta": meta,
        "role": "anomalous" if node_id in anomalous_ids else "context_bridge",
    }


def _abnormality_level(score: float) -> str:
    value = float(score or 0.0)
    if value >= 1000.0:
        return "critical"
    if value >= 100.0:
        return "significant"
    if value >= 10.0:
        return "moderate"
    return "minor"


def _min_level_ok(level: str, minimum: str) -> bool:
    return int(ABNORMALITY_RANK.get(str(level), 0)) >= int(ABNORMALITY_RANK.get(str(minimum), 0))


def _subgraph_signature(subgraph: nx.MultiDiGraph) -> Tuple[Tuple[str, ...], Tuple[Tuple[str, str, str, int, int, int], ...]]:
    nodes = tuple(sorted(str(node_id) for node_id in subgraph.nodes))
    edges: List[Tuple[str, str, str, int, int, int]] = []
    for src, dst, _key, data in sorted(subgraph.edges(keys=True, data=True), key=_edge_sort_key):
        attrs = dict(data or {})
        edges.append(
            (
                str(src),
                str(dst),
                str(attrs.get("type") or ""),
                int(attrs.get("first_ts", 0) or 0),
                int(attrs.get("last_ts", 0) or 0),
                int(attrs.get("count", 1) or 1),
            )
        )
    return nodes, tuple(edges)


def _community_partitions(subgraph: nx.MultiDiGraph) -> List[Set[str]]:
    weighted = nx.Graph()
    for src, dst, data in subgraph.edges(data=True):
        weight = float((data or {}).get("count", 1) or 1)
        if weighted.has_edge(src, dst):
            weighted[src][dst]["weight"] += weight
        else:
            weighted.add_edge(src, dst, weight=weight)
    if weighted.number_of_nodes() == 0:
        return []
    louvain_fn = getattr(nx.community, "louvain_communities", None)
    if callable(louvain_fn):
        try:
            return [set(map(str, nodes)) for nodes in louvain_fn(weighted, weight="weight", seed=42)]
        except Exception:
            return []
    return []


def _fallback_bfs_partitions(subgraph: nx.MultiDiGraph, anomalous_ids: Set[str], max_edges: int, score_map: Dict[str, float]) -> List[Set[str]]:
    undirected = subgraph.to_undirected()
    seeds = sorted(anomalous_ids & set(subgraph.nodes), key=lambda node_id: (float(score_map.get(str(node_id), 0.0)), str(node_id)), reverse=True)
    partitions: List[Set[str]] = []
    seen_signatures: Set[Tuple[str, ...]] = set()
    for seed in seeds:
        nodes: List[str] = []
        seen: Set[str] = set()
        for node_id in nx.bfs_tree(undirected, seed):
            node_id = str(node_id)
            if node_id in seen:
                continue
            trial_nodes = set(nodes)
            trial_nodes.add(node_id)
            if nodes:
                trial_edges = subgraph.subgraph(trial_nodes).number_of_edges()
                if int(trial_edges) > int(max_edges):
                    break
            nodes.append(node_id)
            seen.add(node_id)
        node_set = set(nodes)
        if len(node_set & anomalous_ids) < 2:
            continue
        signature = tuple(sorted(node_set))
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        partitions.append(node_set)
    return partitions


def _partition_large_subgraph(
    subgraph: nx.MultiDiGraph,
    anomalous_ids: Set[str],
    max_edges: int,
    partition_method: str,
    score_map: Dict[str, float],
) -> List[nx.MultiDiGraph]:
    if int(subgraph.number_of_edges()) <= int(max_edges):
        return [subgraph]

    candidate_node_sets: List[Set[str]] = []
    if str(partition_method or "").lower() == "louvain":
        candidate_node_sets.extend(_community_partitions(subgraph))

    if not candidate_node_sets:
        for nodes in nx.connected_components(subgraph.to_undirected()):
            candidate_node_sets.append(set(map(str, nodes)))

    if not candidate_node_sets:
        candidate_node_sets = _fallback_bfs_partitions(subgraph, anomalous_ids, max_edges, score_map)

    partitions: List[nx.MultiDiGraph] = []
    seen: Set[Tuple[Tuple[str, ...], Tuple[Tuple[str, str, str, int, int, int], ...]]] = set()
    for node_set in candidate_node_sets:
        piece = subgraph.subgraph(node_set).copy()
        if piece.number_of_edges() <= 0:
            continue
        if len(set(piece.nodes) & anomalous_ids) < 2:
            continue
        if piece.number_of_edges() > int(max_edges):
            for bfs_nodes in _fallback_bfs_partitions(piece, anomalous_ids, max_edges, score_map):
                bfs_piece = piece.subgraph(bfs_nodes).copy()
                signature = _subgraph_signature(bfs_piece)
                if signature in seen:
                    continue
                seen.add(signature)
                partitions.append(bfs_piece)
            continue
        signature = _subgraph_signature(piece)
        if signature in seen:
            continue
        seen.add(signature)
        partitions.append(piece)
    return partitions


def _serialize_subgraph(
    subgraph: nx.MultiDiGraph,
    *,
    subgraph_id: str,
    anomalous_ids: Set[str],
    score_map: Dict[str, float],
    seed_nodes: Sequence[str],
    construction_reason: str,
) -> Dict[str, Any]:
    nodes = sorted((_node_payload(str(node_id), subgraph, anomalous_ids, score_map) for node_id in subgraph.nodes), key=lambda item: str(item["node_id"]))
    edges = [_edge_payload(str(src), str(dst), dict(data or {})) for src, dst, _key, data in sorted(subgraph.edges(keys=True, data=True), key=_edge_sort_key)]
    anomalous_node_ids = sorted(str(node_id) for node_id in subgraph.nodes if str(node_id) in anomalous_ids)
    normal_bridge_node_ids = sorted(str(node_id) for node_id in subgraph.nodes if str(node_id) not in anomalous_ids)
    score = float(sum(float(score_map.get(node_id, 0.0)) for node_id in anomalous_node_ids))
    timestamps = [int(edge.get("first_ts", 0) or 0) for edge in edges] + [int(edge.get("last_ts", 0) or 0) for edge in edges]
    level = _abnormality_level(score)
    return {
        "subgraph_id": str(subgraph_id),
        "nodes": nodes,
        "edges": edges,
        "node_count": int(len(nodes)),
        "edge_count": int(len(edges)),
        "anomalous_node_ids": anomalous_node_ids,
        "normal_bridge_node_ids": normal_bridge_node_ids,
        "score": float(score),
        "abnormality_level": str(level),
        "seed_nodes": [str(node_id) for node_id in seed_nodes if str(node_id) in subgraph],
        "time_start": int(min(timestamps)) if timestamps else None,
        "time_end": int(max(timestamps)) if timestamps else None,
        "construction_reason": str(construction_reason),
    }


def build_anomalous_subgraphs(
    graph: nx.MultiDiGraph,
    anomalous_nodes: Sequence[Dict[str, Any]] | Sequence[str],
    node_scores: Dict[str, float],
    nseed_per_type: int = 15,
    max_edges: int = 5000,
    min_abnormality_level: str = "moderate",
    partition_method: str = "louvain",
) -> List[Dict[str, Any]]:
    records = _normalize_anomalous_nodes(anomalous_nodes, dict(node_scores or {}), graph)
    anomalous_ids = {str(item.node_id) for item in records if bool(item.is_anomalous)}
    if graph is None or graph.number_of_nodes() <= 0 or len(anomalous_ids) < 2:
        return []

    score_map = {str(item.node_id): float(item.score) for item in records}
    local_graph = graph.subgraph(_local_nodes(graph, anomalous_ids)).copy()
    if local_graph.number_of_edges() <= 0:
        return []

    seed_nodes = _select_seed_nodes(records, int(nseed_per_type))
    serialized: List[Dict[str, Any]] = []
    seen_signatures: Set[Tuple[Tuple[str, ...], Tuple[Tuple[str, str, str, int, int, int], ...]]] = set()
    subgraph_index = 0

    for component_nodes in nx.connected_components(local_graph.to_undirected()):
        component = local_graph.subgraph(component_nodes).copy()
        component_anomalous = anomalous_ids & set(map(str, component.nodes))
        if len(component_anomalous) < 2:
            continue
        component_seeds = [node_id for node_id in seed_nodes if node_id in component_anomalous]
        path_nodes = _path_support_nodes(component, component_seeds, component_anomalous)
        if len(path_nodes & component_anomalous) < 2:
            continue
        candidate = component.subgraph(path_nodes).copy()
        if candidate.number_of_edges() <= 0:
            continue
        pieces = _partition_large_subgraph(candidate, component_anomalous, int(max_edges), str(partition_method), score_map)
        for piece in pieces:
            if piece.number_of_edges() <= 0:
                continue
            piece_anomalous = component_anomalous & set(map(str, piece.nodes))
            if len(piece_anomalous) < 2:
                continue
            signature = _subgraph_signature(piece)
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            subgraph_index += 1
            payload = _serialize_subgraph(
                piece,
                subgraph_id=f"asg_{subgraph_index:04d}",
                anomalous_ids=piece_anomalous,
                score_map=score_map,
                seed_nodes=[node_id for node_id in component_seeds if node_id in piece],
                construction_reason="anomalous_paths_partitioned" if piece.number_of_edges() < candidate.number_of_edges() else "anomalous_paths_component",
            )
            if not _min_level_ok(str(payload.get("abnormality_level") or "minor"), str(min_abnormality_level or "moderate")):
                continue
            serialized.append(payload)

    serialized.sort(key=lambda item: (float(item.get("score", 0.0)), int(item.get("edge_count", 0)), str(item.get("subgraph_id") or "")), reverse=True)
    return serialized
