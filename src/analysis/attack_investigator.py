#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import networkx as nx
import numpy as np

from src.analysis.llm_client import LLMClient, MockLLMClient, get_llm_client
from src.common.io import write_json
from src.knowledge.kb_paths import KB_PATHS

try:
    from src.process.vector_db import VectorDatabase
except Exception:  # pragma: no cover - optional dependency
    VectorDatabase = None  # type: ignore[assignment]


STAGE_ORDER = {
    "reconnaissance": 10,
    "initial_access": 20,
    "execution": 30,
    "persistence": 40,
    "privilege_escalation": 50,
    "defense_evasion": 60,
    "credential_access": 70,
    "discovery": 80,
    "lateral_movement": 90,
    "collection": 100,
    "command_and_control": 110,
    "exfiltration": 120,
    "impact": 130,
    "unknown": 999,
}


def _hash_embedding(text: str, dim: int = 64) -> np.ndarray:
    vec = np.zeros(int(dim), dtype=np.float32)
    for token in re.findall(r"[A-Za-z0-9_./:-]+", str(text or "").lower()):
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        idx = int(digest[:8], 16) % int(dim)
        sign = 1.0 if int(digest[8:10], 16) % 2 == 0 else -1.0
        vec[idx] += sign
    norm = float(np.linalg.norm(vec))
    return vec if norm == 0.0 else vec / norm


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0.0:
        return 0.0
    return float(np.dot(a, b) / denom)


def _normalize_text(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _token_overlap_score(left: str, right: str) -> float:
    left_tokens = set(re.findall(r"[A-Za-z0-9_./:-]+", str(left or "").lower()))
    right_tokens = set(re.findall(r"[A-Za-z0-9_./:-]+", str(right or "").lower()))
    if not left_tokens or not right_tokens:
        return 0.0
    return float(len(left_tokens & right_tokens)) / float(len(left_tokens | right_tokens))


def _contains_candidate(text: str, candidate: Any) -> bool:
    cand = str(candidate or "").strip()
    if not cand:
        return False
    doc = str(text or "")
    if cand in doc:
        return True
    norm_doc = _normalize_text(doc)
    norm_cand = _normalize_text(cand)
    return bool(norm_cand and norm_cand in norm_doc)


def _node_label(node_id: str, meta: Dict[str, Any] | None = None) -> str:
    meta = dict(meta or {})
    return str(
        meta.get("display_name")
        or meta.get("pathname")
        or meta.get("name")
        or meta.get("command")
        or meta.get("cmdline")
        or node_id
        or "unknown"
    )


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


def _edge_sentence(src: str, event_type: str, dst: str, timestamp: int, count: int) -> str:
    suffix = f" ({count} times)" if int(count or 1) > 1 else ""
    return f"{src} {event_type} {dst} at {int(timestamp)}{suffix}."


def _safe_json_loads(text: str) -> Dict[str, Any] | None:
    if not text:
        return None
    raw = str(text).strip()
    candidates = [raw]
    if "{" in raw and "}" in raw:
        candidates.append(raw[raw.find("{") : raw.rfind("}") + 1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    return None


def _unique_extend(target: List[str], values: Iterable[Any]) -> None:
    seen = set(target)
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            target.append(text)


def _ordered_stage_names(stages: Iterable[str]) -> List[str]:
    values = [str(stage or "unknown").strip().lower() or "unknown" for stage in stages]
    values = list(dict.fromkeys(values))
    values.sort(key=lambda item: (STAGE_ORDER.get(item, 999), item))
    return values


def _infer_stages_from_subgraph(subgraph: Dict[str, Any]) -> List[str]:
    stages: List[str] = []
    edges = subgraph.get("edges") or []
    if any(str(edge.get("event_type") or edge.get("type") or "").lower() in {"execute", "fork"} for edge in edges):
        stages.append("execution")
    if any(str(edge.get("event_type") or edge.get("type") or "").lower() in {"write", "send"} for edge in edges):
        stages.append("persistence")
    if any(str(edge.get("event_type") or edge.get("type") or "").lower() in {"read", "receive", "mmap"} for edge in edges):
        stages.append("discovery")
    if any(str(edge.get("event_type") or edge.get("type") or "").lower() in {"send", "receive"} for edge in edges):
        stages.append("command_and_control")
    if not stages:
        stages.append("unknown")
    return _ordered_stage_names(stages)


def _serialize_subgraph_nodes_edges(subgraph: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    nodes = list(subgraph.get("nodes") or [])
    edges = list(subgraph.get("edges") or [])
    return nodes, edges


def _log_document_from_subgraph(subgraph: Dict[str, Any]) -> str:
    nodes, edges = _serialize_subgraph_nodes_edges(subgraph)
    node_lookup = {str(node.get("node_id") or node.get("id") or ""): dict(node or {}) for node in nodes}
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        key = (
            str(edge.get("src") or ""),
            str(edge.get("event_type") or edge.get("type") or ""),
            str(edge.get("dst") or ""),
        )
        grouped[key].append(dict(edge or {}))

    sentences: List[str] = []
    for (src, event_type, dst), items in sorted(grouped.items(), key=lambda item: min(int(edge.get("first_ts", edge.get("timestamp", 0)) or 0) for edge in item[1])):
        items.sort(key=lambda edge: int(edge.get("first_ts", edge.get("timestamp", 0)) or 0))
        merged: List[List[Dict[str, Any]]] = []
        for edge in items:
            if not merged:
                merged.append([edge])
                continue
            prev = merged[-1][-1]
            prev_ts = int(prev.get("first_ts", prev.get("timestamp", 0)) or 0)
            ts = int(edge.get("first_ts", edge.get("timestamp", 0)) or 0)
            if ts - prev_ts <= 1_000_000_000:
                merged[-1].append(edge)
            else:
                merged.append([edge])
        for chunk in merged:
            head = chunk[0]
            ts = int(head.get("first_ts", head.get("timestamp", 0)) or 0)
            count = sum(int(item.get("count", item.get("frequency", 1)) or 1) for item in chunk)
            src_label = _node_label(src, node_lookup.get(src) or {})
            dst_label = _node_label(dst, node_lookup.get(dst) or {})
            sentences.append(_edge_sentence(src_label, event_type or "event", dst_label, ts, count))
    return "\n".join(sentences)


def _candidate_iocs_from_subgraph(subgraph: Dict[str, Any], log_document: str) -> Dict[str, List[str]]:
    candidates: Dict[str, List[str]] = {
        "ip": [],
        "domain": [],
        "file": [],
        "process": [],
        "command": [],
        "hash": [],
    }
    nodes = list(subgraph.get("nodes") or [])
    for node in nodes:
        meta = dict(node.get("meta") or {})
        node_type = str(node.get("node_type") or _node_type(str(node.get("node_id") or node.get("id") or ""), meta))
        display_name = str(node.get("display_name") or _node_label(str(node.get("node_id") or ""), meta))
        pathname = str(meta.get("pathname") or "")
        name = str(meta.get("name") or "")
        command = str(meta.get("command") or meta.get("cmdline") or meta.get("command_line") or "")
        for value in [display_name, name, pathname, command, str(meta.get("dst_ip") or ""), str(meta.get("remote_addr") or ""), str(meta.get("src_ip") or ""), str(meta.get("dst_port") or ""), str(meta.get("hash") or "")]:
            value = str(value or "").strip()
            if not value:
                continue
            if node_type == "process":
                _unique_extend(candidates["process"], [value])
                if command:
                    _unique_extend(candidates["command"], [command])
            elif node_type == "file":
                _unique_extend(candidates["file"], [value])
            elif node_type == "network":
                if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
                    _unique_extend(candidates["ip"], [value])
                elif ":" in value and any(ch.isdigit() for ch in value):
                    _unique_extend(candidates["ip"], [value.split(":", 1)[0]])
                else:
                    _unique_extend(candidates["domain"], [value])
        if command:
            _unique_extend(candidates["command"], [command])

    text = str(log_document or "")
    _unique_extend(candidates["ip"], re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    _unique_extend(candidates["domain"], re.findall(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", text))
    _unique_extend(candidates["file"], re.findall(r"(?:(?:/|~)[A-Za-z0-9_./:-]{2,})", text))
    _unique_extend(candidates["hash"], re.findall(r"\b[a-fA-F0-9]{32,64}\b", text))
    return candidates


def _verify_iocs(candidates: Dict[str, List[str]], doc_text: str, warnings: List[str]) -> Dict[str, List[str]]:
    verified: Dict[str, List[str]] = {key: [] for key in candidates}
    for kind, values in (candidates or {}).items():
        for value in values:
            if _contains_candidate(doc_text, value):
                if value not in verified[kind]:
                    verified[kind].append(value)
            else:
                warnings.append(f"filtered_ioc:{kind}:{value}")
    return verified


def _aggregate_iocs_by_stage(subgraph_reports: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, List[str]]]:
    stage_map: Dict[str, Dict[str, List[str]]] = {}
    for report in subgraph_reports or []:
        stages = _ordered_stage_names(report.get("possible_apt_stages") or ["unknown"])
        iocs = report.get("verified_iocs") or {}
        for stage in stages:
            bucket = stage_map.setdefault(stage, {"ip": [], "domain": [], "file": [], "process": [], "command": [], "hash": []})
            for kind in bucket:
                _unique_extend(bucket[kind], iocs.get(kind, []))
    return stage_map


def _choose_critical_iocs(
    verified_by_subgraph: Dict[str, Dict[str, List[str]]],
    llm_client: LLMClient,
    warnings: List[str],
) -> Dict[str, Any]:
    verified_pool = {"ip": [], "process": [], "file": []}
    source_map: Dict[str, Dict[str, str]] = {"ip": {}, "process": {}, "file": {}}
    for subgraph_id, iocs in verified_by_subgraph.items():
        for kind in verified_pool:
            for value in iocs.get(kind, []) or []:
                if value not in verified_pool[kind]:
                    verified_pool[kind].append(value)
                    source_map[kind][value] = subgraph_id

    prompt = (
        "Select one critical IOC for each category from verified evidence only.\n"
        "Return strict JSON with keys ip, process, file, and for each key output an object with value and reason.\n"
        f"Verified IOC candidates:\n{json.dumps(verified_pool, ensure_ascii=False)}\n"
    )
    raw = ""
    parsed: Dict[str, Any] | None = None
    try:
        raw = llm_client.generate_report(prompt)
        parsed = _safe_json_loads(raw)
    except Exception as exc:
        warnings.append(f"critical_ioc_llm_failed:{type(exc).__name__}: {exc}")

    critical: Dict[str, Any] = {"ip": None, "process": None, "file": None}
    if isinstance(parsed, dict):
        for kind in critical:
            item = parsed.get(kind)
            if isinstance(item, dict):
                value = str(item.get("value") or item.get("ioc") or "").strip()
                if value and value in verified_pool[kind]:
                    critical[kind] = {
                        "value": value,
                        "reason": str(item.get("reason") or ""),
                        "subgraph_id": source_map[kind].get(value),
                    }
        if all(critical[k] is not None for k in critical):
            return {"critical_iocs": critical, "llm_raw_response": raw}
        warnings.append("critical_ioc_llm_output_invalid_or_unverified")

    for kind in critical:
        if verified_pool[kind]:
            value = verified_pool[kind][0]
            critical[kind] = {
                "value": value,
                "reason": "fallback_first_verified_ioc",
                "subgraph_id": source_map[kind].get(value),
            }
    return {"critical_iocs": critical, "llm_raw_response": raw}


def _find_matching_nodes(graph: nx.MultiDiGraph, ioc_type: str, value: str) -> List[str]:
    matches: List[str] = []
    target = str(value or "").strip()
    if not target:
        return matches
    for node_id, data in graph.nodes(data=True):
        meta = dict((data or {}).get("meta", {}) or {})
        candidates = [node_id, meta.get("pathname"), meta.get("name"), meta.get("display_name"), meta.get("command"), meta.get("cmdline"), meta.get("command_line"), meta.get("dst_ip"), meta.get("src_ip"), meta.get("remote_addr")]
        if ioc_type == "ip":
            candidates.extend([f"{meta.get('dst_ip')}:{meta.get('dst_port')}", meta.get("remote_addr")])
        if ioc_type == "file":
            candidates.append(meta.get("pathname"))
        if ioc_type == "process":
            candidates.extend([meta.get("name"), meta.get("pathname")])
        if any(_contains_candidate(str(candidate or ""), target) for candidate in candidates if candidate is not None):
            matches.append(str(node_id))
    return sorted(set(matches))


def _context_subgraph(graph: nx.MultiDiGraph, seed_nodes: Sequence[str], max_hops: int = 1) -> nx.MultiDiGraph:
    selected = set(str(node_id) for node_id in seed_nodes if str(node_id) in graph)
    frontier = set(selected)
    for _ in range(max(int(max_hops), 0)):
        next_frontier: set[str] = set()
        for node_id in frontier:
            next_frontier.update(str(pred) for pred in graph.predecessors(node_id))
            next_frontier.update(str(succ) for succ in graph.successors(node_id))
        next_frontier.difference_update(selected)
        selected.update(next_frontier)
        frontier = next_frontier
        if not frontier:
            break
    return graph.subgraph(selected).copy()


def _serialize_context_subgraph(graph: nx.MultiDiGraph, ioc_type: str, ioc_value: str, subgraph: nx.MultiDiGraph) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    for node_id, data in sorted(subgraph.nodes(data=True), key=lambda item: str(item[0])):
        meta = dict((data or {}).get("meta", {}) or {})
        nodes.append(
            {
                "node_id": str(node_id),
                "node_type": _node_type(str(node_id), meta),
                "display_name": _node_label(str(node_id), meta),
                "meta": meta,
            }
        )
    edges: List[Dict[str, Any]] = []
    for src, dst, _key, data in sorted(subgraph.edges(keys=True, data=True), key=lambda item: (int((item[3] or {}).get("first_ts", 0) or 0), str(item[0]), str(item[1]))):
        attrs = dict(data or {})
        edges.append(
            {
                "src": str(src),
                "dst": str(dst),
                "event_type": str(attrs.get("type") or ""),
                "event_name": str(attrs.get("event_name") or ""),
                "count": int(attrs.get("count", 1) or 1),
                "first_ts": int(attrs.get("first_ts", 0) or 0),
                "last_ts": int(attrs.get("last_ts", 0) or 0),
                "direction": "src_to_dst",
            }
        )
    return {
        "ioc_type": str(ioc_type),
        "ioc_value": str(ioc_value),
        "nodes": nodes,
        "edges": edges,
        "node_count": int(len(nodes)),
        "edge_count": int(len(edges)),
        "time_start": min((int(edge.get("first_ts", 0) or 0) for edge in edges), default=None),
        "time_end": max((int(edge.get("last_ts", 0) or 0) for edge in edges), default=None),
        "construction_reason": f"context_for_{ioc_type}",
    }


def _context_summary(context_subgraphs: Sequence[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for item in context_subgraphs or []:
        lines.append(
            f"[context] {item.get('ioc_type')}={item.get('ioc_value')} nodes={int(item.get('node_count') or 0)} edges={int(item.get('edge_count') or 0)}"
        )
        for edge in item.get("edges") or []:
            lines.append(
                f"  - {edge.get('src')} {edge.get('event_type')} {edge.get('dst')} at {edge.get('first_ts')}"
            )
    return "\n".join(lines)


def _make_deterministic_subgraph_report(
    subgraph: Dict[str, Any],
    verified_iocs: Dict[str, List[str]],
    rag_hits: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    summary = (
        f"Subgraph {subgraph.get('subgraph_id')} contains {int(subgraph.get('node_count') or 0)} nodes, "
        f"{int(subgraph.get('edge_count') or 0)} edges, and score {float(subgraph.get('score') or 0.0):.3f}."
    )
    timeline = [
        f"{edge.get('first_ts')} {edge.get('src')} {edge.get('event_type')} {edge.get('dst')}"
        for edge in sorted(subgraph.get("edges") or [], key=lambda edge: int(edge.get("first_ts", 0) or 0))
    ]
    involved_entities = sorted({node.get("display_name") or node.get("node_id") for node in subgraph.get("nodes") or []})
    suspicious_behaviors = [
        f"Anomalous node count={len(subgraph.get('anomalous_node_ids') or [])}",
        f"Bridge nodes={len(subgraph.get('normal_bridge_node_ids') or [])}",
    ]
    stages = _infer_stages_from_subgraph(subgraph)
    evidence_refs = [f"{hit.get('id')}:{hit.get('text', '')[:80]}" for hit in rag_hits[:5]]
    report_text = "\n".join(
        [
            f"## {subgraph.get('subgraph_id')}",
            f"- Summary: {summary}",
            f"- Timeline: {' | '.join(timeline[:12]) if timeline else 'None'}",
            f"- Involved entities: {', '.join(involved_entities[:20]) if involved_entities else 'None'}",
            f"- Suspicious behaviors: {', '.join(suspicious_behaviors)}",
            f"- Possible APT stages: {', '.join(stages)}",
            f"- Evidence references: {', '.join(evidence_refs) if evidence_refs else 'None'}",
        ]
    )
    return {
        "summary": summary,
        "timeline": timeline,
        "involved_entities": involved_entities,
        "suspicious_behaviors": suspicious_behaviors,
        "possible_apt_stages": stages,
        "evidence_references": evidence_refs,
        "report_text": report_text,
        "llm_raw_response": "",
    }


def _make_comprehensive_report(subgraph_reports: Sequence[Dict[str, Any]], iocs_by_stage: Dict[str, Dict[str, List[str]]]) -> str:
    lines: List[str] = [
        "# Attack Report",
        "",
        "## Executive Summary",
        f"- subgraphs={len(subgraph_reports)}",
    ]
    for report in subgraph_reports:
        lines.append(f"- {report.get('subgraph_id')}: {report.get('summary')}")
    lines.extend(["", "## APT Stages"])
    for stage in _ordered_stage_names(iocs_by_stage.keys()):
        bucket = iocs_by_stage.get(stage, {})
        lines.append(
            f"- {stage}: ips={len(bucket.get('ip') or [])} files={len(bucket.get('file') or [])} processes={len(bucket.get('process') or [])}"
        )
    lines.extend(["", "## IOCs"])
    for stage in _ordered_stage_names(iocs_by_stage.keys()):
        bucket = iocs_by_stage.get(stage, {})
        lines.append(f"### {stage}")
        lines.append(f"- IP: {', '.join(bucket.get('ip') or []) or 'None'}")
        lines.append(f"- File: {', '.join(bucket.get('file') or []) or 'None'}")
        lines.append(f"- Process: {', '.join(bucket.get('process') or []) or 'None'}")
        lines.append(f"- Domain: {', '.join(bucket.get('domain') or []) or 'None'}")
        lines.append(f"- Command: {', '.join(bucket.get('command') or []) or 'None'}")
        lines.append(f"- Hash: {', '.join(bucket.get('hash') or []) or 'None'}")
    lines.extend(["", "## Evidence-Backed Reasoning"])
    for report in subgraph_reports:
        lines.append(f"- {report.get('subgraph_id')}: {report.get('summary')}")
    lines.extend(["", "## Recommended Next Steps", "- Contain the affected workload", "- Review surrounding provenance context", "- Validate the retained IOCs against host telemetry"])
    return "\n".join(lines)


def _make_enriched_report(comprehensive_report: str, context_summary: str) -> str:
    if not context_summary.strip():
        return comprehensive_report
    return comprehensive_report + "\n\n## Context Enrichment\n" + context_summary


def _default_store(db_path: str | None = None):
    return LocalAttackVectorStore(db_path=db_path or KB_PATHS.tik_db_dir)


@dataclass
class AttackInvestigationConfig:
    llm_min_confidence: float = 0.6
    keep_uncertain_subgraphs: bool = True
    rag_top_k_bbk: int = 3
    rag_top_k_tik: int = 3
    rag_top_k_ark: int = 3
    vector_db_path: str = KB_PATHS.tik_db_dir
    logs_collection_name: str = "attack_logs"
    reports_collection_name: str = "attack_reports"
    max_context_hops: int = 1
    enabled_llm: bool = True


@dataclass
class AttackInvestigationResult:
    attack_subgraphs: List[Dict[str, Any]] = field(default_factory=list)
    subgraph_reports: List[Dict[str, Any]] = field(default_factory=list)
    comprehensive_report: str = ""
    enriched_report: str = ""
    iocs_by_subgraph: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    iocs_by_stage: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    critical_iocs: Dict[str, Any] = field(default_factory=dict)
    ioc_context_subgraphs: List[Dict[str, Any]] = field(default_factory=list)
    validation_warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LocalAttackVectorStore:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or KB_PATHS.tik_db_dir
        self._backend: Dict[str, Any] = {}
        self._docs: Dict[str, List[Dict[str, Any]]] = {"logs": [], "reports": []}
        if VectorDatabase is not None:
            try:
                self._backend["logs"] = VectorDatabase(db_path=self.db_path, collection_name="attack_logs")
                self._backend["reports"] = VectorDatabase(db_path=self.db_path, collection_name="attack_reports")
            except Exception:
                self._backend = {}

    def _embed(self, text: str) -> np.ndarray:
        return _hash_embedding(text or "")

    def add_document(self, collection: str, text: str, metadata: Dict[str, Any] | None = None) -> str:
        kind = "logs" if str(collection or "logs").lower().startswith("log") else "reports"
        doc_id = str((metadata or {}).get("id") or f"{kind}_{len(self._docs[kind]) + 1}_{hashlib.md5((text or '').encode('utf-8')).hexdigest()[:8]}")
        record = {
            "id": doc_id,
            "text": str(text or ""),
            "metadata": dict(metadata or {}),
            "vector": self._embed(text or ""),
        }
        self._docs[kind].append(record)
        backend = self._backend.get(kind)
        if backend is not None:
            try:
                backend.add_vectors(
                    [
                        {
                            "id": doc_id,
                            "vector": record["vector"].tolist(),
                            "metadata": record["metadata"],
                            "feature_string": record["text"],
                        }
                    ]
                )
            except Exception:
                pass
        return doc_id

    def query(self, collection: str, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        kind = "logs" if str(collection or "logs").lower().startswith("log") else "reports"
        query_vec = self._embed(query or "")
        scored: List[Tuple[float, Dict[str, Any]]] = []
        for record in self._docs.get(kind, []):
            score = _cosine(query_vec, record["vector"]) + _token_overlap_score(query or "", record["text"]) * 0.1
            scored.append((score, record))
        scored.sort(key=lambda item: (float(item[0]), str(item[1]["id"])), reverse=True)
        return [
            {
                "id": item[1]["id"],
                "score": float(item[0]),
                "text": item[1]["text"],
                "metadata": dict(item[1]["metadata"]),
            }
            for item in scored[: max(int(top_k), 0)]
        ]


def _coerce_config(config: AttackInvestigationConfig | Dict[str, Any] | None) -> AttackInvestigationConfig:
    if isinstance(config, AttackInvestigationConfig):
        return config
    data = dict(config or {})
    return AttackInvestigationConfig(
        llm_min_confidence=float(data.get("llm_min_confidence", 0.6)),
        keep_uncertain_subgraphs=bool(data.get("keep_uncertain_subgraphs", True)),
        rag_top_k_bbk=int(data.get("rag_top_k_bbk", 3)),
        rag_top_k_tik=int(data.get("rag_top_k_tik", 3)),
        rag_top_k_ark=int(data.get("rag_top_k_ark", 3)),
        vector_db_path=str(data.get("vector_db_path") or KB_PATHS.tik_db_dir),
        logs_collection_name=str(data.get("logs_collection_name") or "attack_logs"),
        reports_collection_name=str(data.get("reports_collection_name") or "attack_reports"),
        max_context_hops=int(data.get("max_context_hops", 1)),
        enabled_llm=bool(data.get("enabled_llm", True)),
    )


def generate_attack_report(
    graph: nx.MultiDiGraph,
    attack_subgraphs: Sequence[Dict[str, Any]] | None,
    llm_client: LLMClient | None,
    vector_store: Any | None,
    config: AttackInvestigationConfig | Dict[str, Any] | None,
) -> Dict[str, Any]:
    attack_subgraphs = list(attack_subgraphs or [])
    cfg = _coerce_config(config)
    if not attack_subgraphs:
        return AttackInvestigationResult(
            attack_subgraphs=[],
            subgraph_reports=[],
            comprehensive_report="no_attack_report",
            enriched_report="no_attack_report",
            iocs_by_subgraph={},
            iocs_by_stage={},
            critical_iocs={},
            ioc_context_subgraphs=[],
            validation_warnings=[],
        ).to_dict()

    llm = llm_client or get_llm_client()
    store = vector_store if vector_store is not None and hasattr(vector_store, "add_document") else _default_store(cfg.vector_db_path)
    warnings: List[str] = []
    subgraph_reports: List[Dict[str, Any]] = []
    iocs_by_subgraph: Dict[str, Dict[str, List[str]]] = {}

    # Stage 1: serialize subgraphs and index log documents
    for subgraph in attack_subgraphs:
        subgraph = dict(subgraph or {})
        subgraph_id = str(subgraph.get("subgraph_id") or f"subgraph_{len(subgraph_reports) + 1:04d}")
        log_document = _log_document_from_subgraph(subgraph)
        store.add_document(
            cfg.logs_collection_name,
            log_document,
            {
                "id": f"log_{subgraph_id}",
                "subgraph_id": subgraph_id,
                "kind": "attack_log",
                "node_count": int(subgraph.get("node_count") or 0),
                "edge_count": int(subgraph.get("edge_count") or 0),
            },
        )

        # Stage 2: extract IOC candidates and validate against the log document
        candidates = _candidate_iocs_from_subgraph(subgraph, log_document)
        llm_raw_ioc = ""
        parsed_ioc = None
        prompt = (
            "Extract IOCs from the following provenance log document. Return strict JSON with keys "
            '{"iocs":{"ip":[],"domain":[],"file":[],"process":[],"command":[],"hash":[]}}.\n'
            f"Log document:\n{log_document}\n"
        )
        try:
            llm_raw_ioc = llm.generate_report(prompt)
            parsed_ioc = _safe_json_loads(llm_raw_ioc)
        except Exception as exc:
            warnings.append(f"ioc_extraction_llm_failed:{subgraph_id}:{type(exc).__name__}: {exc}")
        if isinstance(parsed_ioc, dict) and isinstance(parsed_ioc.get("iocs"), dict):
            llm_candidates = parsed_ioc.get("iocs") or {}
            for kind in candidates:
                _unique_extend(candidates[kind], llm_candidates.get(kind, []))
        verified_iocs = _verify_iocs(candidates, log_document, warnings)
        iocs_by_subgraph[subgraph_id] = verified_iocs

        # Stage 3: generate subgraph report
        rag_hits = store.query(cfg.logs_collection_name, log_document, top_k=max(cfg.rag_top_k_bbk, 1))
        report_prompt = (
            "Generate a grounded subgraph report in strict JSON with keys summary, timeline, involved_entities, "
            "suspicious_behaviors, possible_apt_stages, evidence_references.\n"
            f"Log document:\n{log_document}\n"
            f"Verified IOCs:\n{json.dumps(verified_iocs, ensure_ascii=False)}\n"
            f"RAG evidence:\n{json.dumps(rag_hits, ensure_ascii=False)}\n"
        )
        llm_raw_report = ""
        parsed_report = None
        try:
            llm_raw_report = llm.generate_report(report_prompt)
            parsed_report = _safe_json_loads(llm_raw_report)
        except Exception as exc:
            warnings.append(f"subgraph_report_llm_failed:{subgraph_id}:{type(exc).__name__}: {exc}")
        fallback_report = _make_deterministic_subgraph_report(subgraph, verified_iocs, rag_hits)
        subgraph_report = dict(fallback_report)
        if isinstance(parsed_report, dict):
            for key in ("summary", "timeline", "involved_entities", "suspicious_behaviors", "possible_apt_stages", "evidence_references"):
                if key in parsed_report and parsed_report[key]:
                    subgraph_report[key] = parsed_report[key]
            if isinstance(parsed_report.get("report_text"), str) and parsed_report.get("report_text").strip():
                subgraph_report["report_text"] = str(parsed_report.get("report_text"))
        subgraph_report["subgraph_id"] = subgraph_id
        subgraph_report["verified_iocs"] = verified_iocs
        subgraph_report["log_document"] = log_document
        subgraph_report["llm_raw_response"] = llm_raw_report
        subgraph_report["rag_hits"] = rag_hits
        store.add_document(
            cfg.reports_collection_name,
            subgraph_report.get("report_text") or json.dumps(subgraph_report, ensure_ascii=False),
            {
                "id": f"report_{subgraph_id}",
                "subgraph_id": subgraph_id,
                "kind": "attack_report",
                "summary": subgraph_report.get("summary"),
            },
        )
        subgraph_reports.append(subgraph_report)

    # Stage 4: aggregate stage IOCs and generate comprehensive report
    iocs_by_stage = _aggregate_iocs_by_stage(subgraph_reports)
    comprehensive_report = _make_comprehensive_report(subgraph_reports, iocs_by_stage)
    stage_rag_hits = store.query(cfg.reports_collection_name, comprehensive_report, top_k=max(cfg.rag_top_k_tik, 1))
    if stage_rag_hits:
        comprehensive_report += "\n\n## RAG Similar Reports\n"
        for hit in stage_rag_hits[: max(cfg.rag_top_k_tik, 1)]:
            comprehensive_report += f"- {hit['id']}: {str(hit['text'])[:160]}\n"

    # Stage 5: select critical IOC set
    critical_result = _choose_critical_iocs(iocs_by_subgraph, llm, warnings)
    critical_iocs = critical_result.get("critical_iocs") or {}

    # Stage 6: query context around critical IOCs and enrich report
    ioc_context_subgraphs: List[Dict[str, Any]] = []
    for ioc_type, payload in critical_iocs.items():
        if not isinstance(payload, dict):
            continue
        value = str(payload.get("value") or "").strip()
        if not value:
            continue
        matched_nodes = _find_matching_nodes(graph, str(ioc_type), value)
        if not matched_nodes:
            warnings.append(f"context_match_missing:{ioc_type}:{value}")
            continue
        ctx_graph = _context_subgraph(graph, matched_nodes, max_hops=cfg.max_context_hops)
        ctx_payload = _serialize_context_subgraph(graph, str(ioc_type), value, ctx_graph)
        ctx_payload["seed_nodes"] = matched_nodes
        ctx_payload["summary"] = f"{ioc_type}={value} matches={len(matched_nodes)}"
        ioc_context_subgraphs.append(ctx_payload)
        store.add_document(
            cfg.logs_collection_name,
            _log_document_from_subgraph(ctx_payload),
            {
                "id": f"context_{ioc_type}_{hashlib.md5(value.encode('utf-8')).hexdigest()[:8]}",
                "kind": "ioc_context",
                "ioc_type": ioc_type,
                "ioc_value": value,
            },
        )

    context_summary = _context_summary(ioc_context_subgraphs)
    enriched_report = _make_enriched_report(comprehensive_report, context_summary)

    return AttackInvestigationResult(
        attack_subgraphs=list(attack_subgraphs),
        subgraph_reports=subgraph_reports,
        comprehensive_report=comprehensive_report,
        enriched_report=enriched_report,
        iocs_by_subgraph=iocs_by_subgraph,
        iocs_by_stage=iocs_by_stage,
        critical_iocs=critical_iocs,
        ioc_context_subgraphs=ioc_context_subgraphs,
        validation_warnings=warnings + ([str(critical_result.get("llm_raw_response") or "")] if critical_result.get("llm_raw_response") else []),
    ).to_dict()
