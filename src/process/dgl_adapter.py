from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any, Dict, List

import networkx as nx
import torch

from src.common.text import tokenize_identifier

try:
    import dgl
except Exception:  # pragma: no cover - runtime optional dependency
    dgl = None


DEFAULT_NODE_ATTR_DIM = 64
DEFAULT_EDGE_ATTR_DIM = 16
DEFAULT_GMAE_FEATURE_PROFILE = "legacy"
TRANSFER_GMAE_FEATURE_PROFILE = "transfer_v1"

_NODE_TYPE_INDEX = {
    "proc:": 0,
    "file:": 1,
    "net:": 2,
}
_EDGE_TYPE_INDEX = {
    "Read": 0,
    "Receive": 1,
    "Mmap": 2,
    "Write": 3,
    "Send": 4,
    "Execute": 5,
    "Fork": 6,
}


@dataclass
class DGLWindowGraph:
    graph: Any
    node_ids: List[str]
    node_id_to_idx: Dict[str, int]
    idx_to_node_id: Dict[int, str]
    node_metas: List[Dict[str, Any]]
    process_node_indices: List[int]


def _require_dgl() -> None:
    if dgl is None:
        raise RuntimeError("DGL is not installed. Install dgl before using the GMAE graph adapter.")


def _stable_digest(value: str) -> bytes:
    return hashlib.blake2b(str(value).encode("utf-8", "ignore"), digest_size=16).digest()


def _hash_tokens(tokens: List[str], dim: int) -> torch.Tensor:
    vec = torch.zeros(dim, dtype=torch.float32)
    if dim <= 0:
        return vec
    for token in tokens:
        digest = _stable_digest(token)
        idx = int.from_bytes(digest[:8], "little") % dim
        sign = 1.0 if (digest[8] & 1) else -1.0
        vec[idx] += sign
    if tokens:
        vec /= math.sqrt(float(len(tokens)))
    return vec


def _normalized_node_tokens(node_id: str, meta: Dict[str, Any], feature_profile: str) -> List[str]:
    tokens: List[str] = []
    values: List[Any]
    if str(feature_profile or DEFAULT_GMAE_FEATURE_PROFILE) == TRANSFER_GMAE_FEATURE_PROFILE:
        values = [
            meta.get("pathname"),
            meta.get("name"),
            meta.get("src_ip"),
            meta.get("dst_ip"),
            meta.get("protocol"),
            meta.get("socket_type"),
            meta.get("cadets_file_type"),
        ]
    else:
        values = [
            node_id,
            meta.get("uuid"),
            meta.get("pathname"),
            meta.get("name"),
            meta.get("src_ip"),
            meta.get("dst_ip"),
            meta.get("container_id"),
            meta.get("container_image"),
            meta.get("pod_name"),
        ]
    for value in values:
        if value:
            tokens.extend(tokenize_identifier(str(value)))
    return tokens


def _node_feature(node_id: str, meta: Dict[str, Any], dim: int, feature_profile: str = DEFAULT_GMAE_FEATURE_PROFILE) -> torch.Tensor:
    vec = torch.zeros(dim, dtype=torch.float32)
    if dim <= 0:
        return vec

    prefix = next((p for p in _NODE_TYPE_INDEX if str(node_id).startswith(p)), None)
    if prefix is not None and _NODE_TYPE_INDEX[prefix] < dim:
        vec[_NODE_TYPE_INDEX[prefix]] = 1.0

    cursor = len(_NODE_TYPE_INDEX)
    stats = [
        1.0 if meta.get("pathname") else 0.0,
        1.0 if meta.get("name") else 0.0,
        1.0 if meta.get("src_ip") or meta.get("dst_ip") else 0.0,
        min(math.log1p(abs(int(meta.get("pid") or 0))) / 10.0, 1.0),
        min(len(str(meta.get("pathname") or "")) / 256.0, 1.0),
        min(len(str(meta.get("name") or "")) / 64.0, 1.0),
        1.0 if meta.get("is_unspec_net") else 0.0,
    ]
    for offset, value in enumerate(stats):
        idx = cursor + offset
        if idx < dim:
            vec[idx] = float(value)

    hash_start = min(dim, cursor + len(stats))
    tokens = _normalized_node_tokens(node_id, meta, feature_profile)
    if hash_start < dim:
        vec[hash_start:] = _hash_tokens(tokens, dim - hash_start)
    return vec


def _normalized_edge_tokens(edge_type: str, data: Dict[str, Any], feature_profile: str) -> List[str]:
    count = int(data.get("count", 1) or 1)
    segments = data.get("segments") or []
    bin_idx = int(data.get("bin_idx") or (segments[0].get("bin") if segments else 0) or 0)
    event_names = list(data.get("event_names") or [])
    event_name = str(data.get("event_name") or "")
    if event_name and event_name not in event_names:
        event_names.append(event_name)
    tokens = [str(edge_type), f"count:{count}", f"bin:{bin_idx}"]
    if str(feature_profile or DEFAULT_GMAE_FEATURE_PROFILE) != TRANSFER_GMAE_FEATURE_PROFILE:
        tokens.extend([f"event:{name}" for name in event_names if str(name).strip()])
    for seg in segments[:8]:
        tokens.append(f"bin:{seg.get('bin', 0)}")
        tokens.append(f"seg_count:{seg.get('count', 0)}")
    return tokens


def _edge_feature(edge_type: str, data: Dict[str, Any], dim: int, feature_profile: str = DEFAULT_GMAE_FEATURE_PROFILE) -> torch.Tensor:
    vec = torch.zeros(dim, dtype=torch.float32)
    if dim <= 0:
        return vec

    edge_idx = _EDGE_TYPE_INDEX.get(str(edge_type), len(_EDGE_TYPE_INDEX))
    if edge_idx < dim:
        vec[edge_idx] = 1.0

    cursor = len(_EDGE_TYPE_INDEX) + 1
    count = int(data.get("count", 1) or 1)
    segments = data.get("segments") or []
    bin_idx = int(data.get("bin_idx") or (segments[0].get("bin") if segments else 0) or 0)
    duration_ns = max(0, int(data.get("last_ts", 0)) - int(data.get("first_ts", 0)))
    stats = [
        min(math.log1p(count) / 10.0, 1.0),
        min(math.log1p(duration_ns) / 30.0, 1.0),
        min(len(segments) / 32.0, 1.0),
        min((count / max(len(segments), 1)) / 32.0, 1.0),
        min(max(bin_idx, 0) / 128.0, 1.0),
    ]
    for offset, value in enumerate(stats):
        idx = cursor + offset
        if idx < dim:
            vec[idx] = float(value)

    hash_start = min(dim, cursor + len(stats))
    tokens = _normalized_edge_tokens(edge_type, data, feature_profile)
    if hash_start < dim:
        vec[hash_start:] = _hash_tokens(tokens, dim - hash_start)
    return vec


def window_to_dgl_graph(
    nx_graph: nx.MultiDiGraph,
    node_attr_dim: int = DEFAULT_NODE_ATTR_DIM,
    edge_attr_dim: int = DEFAULT_EDGE_ATTR_DIM,
    device: str | torch.device = "cpu",
    filter_unspec_net: bool = True,
    feature_profile: str = DEFAULT_GMAE_FEATURE_PROFILE,
) -> DGLWindowGraph:
    _require_dgl()

    unspec_net_nodes: set[str] = set()
    if filter_unspec_net:
        for node_id in nx_graph.nodes():
            meta = nx_graph.nodes[node_id].get("meta") or {}
            if meta.get("is_unspec_net"):
                unspec_net_nodes.add(str(node_id))

    if unspec_net_nodes:
        filtered_graph = nx.MultiDiGraph()
        for node_id in nx_graph.nodes():
            if str(node_id) in unspec_net_nodes:
                continue
            filtered_graph.add_node(node_id, **nx_graph.nodes[node_id])
        for src, dst, key, data in nx_graph.edges(keys=True, data=True):
            if str(src) in unspec_net_nodes or str(dst) in unspec_net_nodes:
                continue
            filtered_graph.add_edge(src, dst, key=key, **data)
        nx_graph = filtered_graph

    node_ids = list(nx_graph.nodes())
    node_id_to_idx = {node_id: idx for idx, node_id in enumerate(node_ids)}
    idx_to_node_id = {idx: node_id for node_id, idx in node_id_to_idx.items()}
    node_metas = [(nx_graph.nodes[node_id].get("meta") or {}) for node_id in node_ids]
    process_node_indices = [idx for idx, node_id in enumerate(node_ids) if str(node_id).startswith("proc:")]

    src_idx: List[int] = []
    dst_idx: List[int] = []
    edge_attrs: List[torch.Tensor] = []
    for src, dst, _key, data in nx_graph.edges(keys=True, data=True):
        src_idx.append(node_id_to_idx[src])
        dst_idx.append(node_id_to_idx[dst])
        edge_attrs.append(
            _edge_feature(
                str((data or {}).get("type") or "UNKNOWN"),
                data or {},
                int(edge_attr_dim),
                feature_profile=str(feature_profile or DEFAULT_GMAE_FEATURE_PROFILE),
            )
        )

    node_attrs = torch.stack(
        [
            _node_feature(
                node_id,
                meta,
                int(node_attr_dim),
                feature_profile=str(feature_profile or DEFAULT_GMAE_FEATURE_PROFILE),
            )
            for node_id, meta in zip(node_ids, node_metas)
        ],
        dim=0,
    ) if node_ids else torch.zeros((0, int(node_attr_dim)), dtype=torch.float32)

    src_tensor = torch.tensor(src_idx, dtype=torch.int64)
    dst_tensor = torch.tensor(dst_idx, dtype=torch.int64)
    graph = dgl.graph((src_tensor, dst_tensor), num_nodes=len(node_ids))
    graph.ndata["attr"] = node_attrs
    process_mask = torch.zeros(len(node_ids), dtype=torch.bool)
    if process_node_indices:
        process_mask[process_node_indices] = True
    graph.ndata["is_process"] = process_mask
    graph.edata["attr"] = (
        torch.stack(edge_attrs, dim=0) if edge_attrs else torch.zeros((0, int(edge_attr_dim)), dtype=torch.float32)
    )
    graph = graph.to(device)

    return DGLWindowGraph(
        graph=graph,
        node_ids=node_ids,
        node_id_to_idx=node_id_to_idx,
        idx_to_node_id=idx_to_node_id,
        node_metas=node_metas,
        process_node_indices=process_node_indices,
    )
