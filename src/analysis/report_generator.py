#!/usr/bin/env python3
"""
报告生成器模块
负责收集上下文并调用LLM生成分析报告
"""

from bisect import bisect_right
from dataclasses import dataclass, field
import math
import os
from types import SimpleNamespace
from typing import Dict, Any, List, Optional

from src.analysis.llm_client import get_llm_client, MockLLMClient
from src.common.defaults import (
    DEFAULT_ALERT_THRESHOLD,
    DEFAULT_DETECT_STRIDE_SECONDS,
    DEFAULT_TIME_BIN_SECONDS,
    DEFAULT_TOP_EVIDENCE_ITEMS,
    DEFAULT_WINDOW_SECONDS,
)
from src.knowledge.logic_graph_builder import LogicGraphBuilder
from src.knowledge.benign_behavior_kb import BenignBehaviorKnowledgeBase
from src.knowledge.kb_paths import KB_PATHS
from src.process.provenance_model import ProvenanceEventMapper, RarePathSelector
from src.process.vector_db import VectorDatabase
from src.process.vectorizer import TraceeVectorizer
from src.process.streaming_reduction import iter_reduced_edges, iter_window_graphs
from src.process.window_io import dump_window_graph, load_window_graph
import networkx as nx
import json
import re
import time
import uuid
from src.common.io import read_json, write_json, write_text


@dataclass
class WindowAlert:
    window_id: str
    window_file: str | None
    window_score: float
    threshold: float
    top_processes: List[Dict[str, Any]] = field(default_factory=list)
    top_rare_paths: List[Dict[str, Any]] = field(default_factory=list)
    impacted_containers: List[str] = field(default_factory=list)
    evidence_summary: str = ""
    top3_mean_process_score: float = 0.0
    suspicious_process_count: int = 0
    top_process_name: str = ""
    top_path_score: float = 0.0
    window_graph: nx.MultiDiGraph | None = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_id": self.window_id,
            "window_file": self.window_file,
            "window_score": float(self.window_score),
            "threshold": float(self.threshold),
            "top_processes": list(self.top_processes),
            "top_rare_paths": list(self.top_rare_paths),
            "impacted_containers": list(self.impacted_containers),
            "evidence_summary": self.evidence_summary,
            "top3_mean_process_score": float(self.top3_mean_process_score),
            "suspicious_process_count": int(self.suspicious_process_count),
            "top_process_name": self.top_process_name,
            "top_path_score": float(self.top_path_score),
        }


class AnalysisEngine:
    """分析引擎"""
    
    def __init__(self, enable_enrichment: bool = False):
        KB_PATHS.ensure_layout()
        self.benign_kb = BenignBehaviorKnowledgeBase(db_path=KB_PATHS.bbk_db_path, model_path=KB_PATHS.bbk_word2vec_path)
        self.provenance_mapper = ProvenanceEventMapper()
        self.rare_selector = RarePathSelector(k1=10, k2=10)
        self.gmae_load_error = ""
        self.gmae_runtime = self._load_gmae_runtime()

        self.llm_client = None
        self.tik_db = None
        self.tik_vectorizer = None
        self.case_db = None
        self.logic_builder = None

        if enable_enrichment:
            self._ensure_enrichment()

    def _ensure_enrichment(self) -> None:
        if self.llm_client is None:
            try:
                self.llm_client = get_llm_client()
            except Exception:
                self.llm_client = MockLLMClient()

        if self.tik_vectorizer is None:
            try:
                self.tik_vectorizer = TraceeVectorizer()
            except Exception:
                self.tik_vectorizer = None

        if self.tik_db is None:
            try:
                self.tik_db = VectorDatabase(db_path=KB_PATHS.tik_db_dir, collection_name="tik_knowledge")
            except Exception:
                self.tik_db = None

        if self.case_db is None:
            try:
                self.case_db = VectorDatabase(db_path=KB_PATHS.tik_db_dir, collection_name="case_memory")
            except Exception:
                self.case_db = None

        if self.logic_builder is not None:
            return

        self.logic_builder = LogicGraphBuilder()
        try:
            if os.path.exists(KB_PATHS.ark_graph_path):
                from src.common.io import read_json
                payload = read_json(KB_PATHS.ark_graph_path)
                self.logic_builder.logic_graph = self._load_logic_graph(payload)
        except Exception:
            self.logic_builder = LogicGraphBuilder()
        
    def analyze_suspicious_process(
        self,
        process_meta: Dict[str, Any],
        graph_context: str,
        rare_paths: List[Dict[str, Any]],
        source_graph: nx.MultiDiGraph | None = None,
        dump_dir: str | None = None,
        return_debug: bool = False,
        max_attack_graph_edges_print: int = 80,
    ):
        """分析可疑进程"""
        self._ensure_enrichment()

        tik_context_parts = []
        detected_tech_ids = []
        if self.tik_vectorizer is not None and self.tik_db is not None:
            for rp in (rare_paths or [])[:5]:
                path_text = rp.get("text", "")
                if not path_text:
                    continue
                qv = self.tik_vectorizer.vectorize_path_doc2vec(path_text)
                results = self.tik_db.query_vectors(qv, n_results=3)
                for i in range(len(results.get("ids", []))):
                    meta = results["metadatas"][i]
                    detected_tech_ids.append(meta.get("technique_id"))
                    tik_context_parts.append(f"- [TIK] {results['documents'][i]} (Tech: {meta.get('name')}, Tactic: {meta.get('tactic')})")
        knowledge_context = "\n".join([p for p in tik_context_parts if p])
        
        # 3. 逻辑重构 (Logic Reconstruction)
        # 检查检测到的技术是否构成合理的攻击链
        reconstructed_chain = []
        uniq = [x for x in set(detected_tech_ids) if x]
        if uniq:
            reconstructed_chain = self.logic_builder.reconstruct_attack_chain(list(uniq))
            
        chain_context = ""
        if len(reconstructed_chain) > 1:
            chain_context = f"\n⚠️ Potential Attack Chain Detected: {' -> '.join(reconstructed_chain)}"
        
        # 5. 构建Prompt
        target_description = self._format_target(process_meta, graph_context)
        rare_context = self._format_rare_paths_compact(rare_paths, source_graph)
        bbk_context = self._format_bbk_context(rare_paths)

        debug_payload: Dict[str, Any] = {}
        attack_graph_text = ""
        if source_graph is not None and rare_paths:
            sg, attack_graph_text = self._reconstruct_attack_provenance_graph(
                source_graph,
                process_meta,
                rare_paths,
                max_edges_print=max_attack_graph_edges_print,
            )
            debug_payload["attack_provenance_graph_edges"] = attack_graph_text
            debug_payload["attack_chain"] = reconstructed_chain
            debug_payload["detected_technique_ids_raw"] = detected_tech_ids
            debug_payload["detected_technique_ids_uniq"] = uniq
            debug_payload["tik_context"] = knowledge_context
            debug_payload["bbk_context"] = bbk_context
            debug_payload["rare_paths_context"] = rare_context
        prompt = self._construct_prompt(
            target_event=target_description,
            bbk=bbk_context,
            rare_paths=rare_context,
            knowledge=knowledge_context + chain_context,
            attack_graph=attack_graph_text,
            history="",
        )
        debug_payload["prompt"] = prompt

        if dump_dir:
            try:
                os.makedirs(dump_dir, exist_ok=True)
                pid = process_meta.get("pid", "unknown")
                name = process_meta.get("name") or "unknown"
                safe_name = "".join([c if c.isalnum() or c in ("-", "_") else "_" for c in str(name)])[:50]
                base = os.path.join(dump_dir, f"pid_{pid}_{safe_name}")
                write_text(base + "_prompt.txt", str(prompt))
            except Exception:
                pass
        
        report, stage_debug = self._generate_report_staged(
            process_meta=process_meta,
            graph_context=graph_context,
            bbk_context=bbk_context,
            rare_paths_context=rare_context,
            tik_context=knowledge_context,
            attack_chain=reconstructed_chain,
            attack_graph_text=attack_graph_text,
        )
        debug_payload.update(stage_debug)

        if dump_dir and debug_payload:
            os.makedirs(dump_dir, exist_ok=True)
            pid = process_meta.get("pid", "unknown")
            name = process_meta.get("name") or "unknown"
            safe_name = "".join([c if c.isalnum() or c in ("-", "_") else "_" for c in str(name)])[:50]
            base = os.path.join(dump_dir, f"pid_{pid}_{safe_name}")
            stage3_prompt = debug_payload.get("llm_stage3_prompt") or prompt
            write_text(base + "_prompt.txt", str(stage3_prompt))
            if debug_payload.get("llm_stage1_prompt"):
                write_text(base + "_prompt_stage1.txt", str(debug_payload.get("llm_stage1_prompt")))
            if debug_payload.get("llm_stage2_prompt"):
                write_text(base + "_prompt_stage2.txt", str(debug_payload.get("llm_stage2_prompt")))
            if attack_graph_text:
                write_text(base + "_attack_graph.txt", attack_graph_text)
            write_text(base + "_report.md", str(report))
            write_json(base + "_debug.json", debug_payload)
        
        if return_debug:
            return report, debug_payload
        return report

    def analyze_window_alert(
        self,
        alert: WindowAlert,
        dump_dir: str | None = None,
        return_debug: bool = False,
        max_attack_graph_edges_print: int = 80,
    ):
        """对单条窗口告警做富化分析，仅生成一份报告。"""

        top_processes = list(alert.top_processes or [])
        lead = dict(top_processes[0]) if top_processes else {}
        process_meta = dict(lead.get("process_meta", {}) or {})
        if lead.get("node"):
            process_meta["node"] = lead.get("node")
        process_meta["window_id"] = alert.window_id
        process_meta["window_file"] = alert.window_file
        process_meta["window_score"] = float(alert.window_score)
        process_meta["impacted_containers"] = list(alert.impacted_containers or [])
        process_meta["target_name"] = f"{alert.window_id} / {lead.get('display_name') or process_meta.get('name') or process_meta.get('pathname') or 'unknown'}"

        graph_parts = [f"WindowAlert: {alert.evidence_summary}"]
        seen_contexts = set()
        for item in top_processes[:DEFAULT_TOP_EVIDENCE_ITEMS]:
            context = str(item.get("graph_context") or "").strip()
            if context and context not in seen_contexts:
                seen_contexts.add(context)
                graph_parts.append(context)

        graph_context = "\n\n".join(graph_parts)
        return self.analyze_suspicious_process(
            process_meta=process_meta,
            graph_context=graph_context,
            rare_paths=list(alert.top_rare_paths or []),
            source_graph=alert.window_graph,
            dump_dir=dump_dir,
            return_debug=return_debug,
            max_attack_graph_edges_print=max_attack_graph_edges_print,
        )

    def _extract_entities_from_text(self, text: str) -> Dict[str, List[str]]:
        t = text or ""
        paths = sorted(set(re.findall(r"(?:(?:/|~)[A-Za-z0-9_./:-]{2,})", t)))
        ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t)))
        tech = sorted(set(re.findall(r"\bT\d{4}\b", t)))
        procs = sorted(set(re.findall(r"\b[A-Za-z0-9_./-]{2,}\b", t)))
        procs = [p for p in procs if p not in {"You", "are", "a", "the", "and", "with", "for"}]
        return {"paths": paths[:200], "ips": ips[:200], "techniques": tech[:200], "tokens": procs[:200]}

    def _extract_iocs(
        self,
        process_meta: Dict[str, Any],
        graph_context: str,
        attack_graph_text: str,
        rare_paths_context: str,
    ) -> Dict[str, List[str]]:
        seed = []
        for v in [
            process_meta.get("name"),
            process_meta.get("pathname"),
            str(process_meta.get("pid") or ""),
            graph_context,
            attack_graph_text,
            rare_paths_context,
        ]:
            if v:
                seed.append(str(v))
        merged = "\n".join(seed)
        ents = self._extract_entities_from_text(merged)
        iocs: List[str] = []
        for p in ents["paths"]:
            if p.startswith(("/tmp/", "/var/run/docker.sock", "/etc/", "/root/")) or "shadow" in p or "docker.sock" in p:
                iocs.append(p)
        for ip in ents["ips"]:
            iocs.append(ip)
        name = (process_meta.get("name") or "").strip()
        if name:
            iocs.append(name)
        uniq: List[str] = []
        seen = set()
        for x in iocs:
            if x and x not in seen:
                seen.add(x)
                uniq.append(x)
        return {"iocs": uniq[:50], "entities": (ents["paths"] + ents["ips"] + ents["techniques"])[:300]}

    def _validate_report(self, report: str, allowed_paths: List[str], allowed_ips: List[str], allowed_tech: List[str]) -> Dict[str, Any]:
        found = self._extract_entities_from_text(report or "")
        bad_paths = [p for p in found["paths"] if p not in set(allowed_paths)]
        bad_ips = [ip for ip in found["ips"] if ip not in set(allowed_ips)]
        bad_tech = [t for t in found["techniques"] if t not in set(allowed_tech)]
        return {
            "found_paths": found["paths"],
            "found_ips": found["ips"],
            "found_techniques": found["techniques"],
            "unverified_paths": bad_paths[:50],
            "unverified_ips": bad_ips[:50],
            "unverified_techniques": bad_tech[:50],
        }

    def _generate_report_staged(
        self,
        process_meta: Dict[str, Any],
        graph_context: str,
        bbk_context: str,
        rare_paths_context: str,
        tik_context: str,
        attack_chain: List[str],
        attack_graph_text: str,
    ) -> tuple[str, Dict[str, Any]]:
        dbg: Dict[str, Any] = {}
        case_doc = self._make_case_document(process_meta, attack_graph_text, rare_paths_context, graph_context)
        similar = {"ids": [], "metadatas": [], "documents": []}
        if self.tik_vectorizer is not None and self.case_db is not None and case_doc.strip():
            qv_case = self.tik_vectorizer.vectorize_path_doc2vec(case_doc)
            similar = self.case_db.query_vectors(qv_case, n_results=3)
        similar_lines: List[str] = []
        for i in range(len(similar.get("ids", []))):
            meta = (similar.get("metadatas") or [])[i] or {}
            doc = (similar.get("documents") or [])[i] or ""
            similar_lines.append(
                f"- case_id={similar['ids'][i]} pid={meta.get('pid')} name={meta.get('name')} score={meta.get('rarity_score')} doc={self._shorten_entity_label(doc, 120)}"
            )
        dbg["similar_cases"] = similar_lines
        ioc_pack = self._extract_iocs(process_meta, graph_context, attack_graph_text, rare_paths_context)
        dbg["extracted_iocs"] = ioc_pack.get("iocs", [])
        allowed = self._extract_entities_from_text("\n".join([graph_context or "", attack_graph_text or "", rare_paths_context or ""]))
        allowed_paths = allowed["paths"]
        allowed_ips = allowed["ips"]
        allowed_tech = sorted(set(attack_chain or []) | set(self._extract_entities_from_text(tik_context or "").get("techniques", [])))
        llm_client = self.llm_client or MockLLMClient()

        if isinstance(llm_client, MockLLMClient):
            report = self._fallback_report(process_meta, bbk_context, rare_paths_context, tik_context, attack_chain, attack_graph_text, ioc_pack.get("iocs", []))
            dbg["report_validation"] = self._validate_report(report, allowed_paths, allowed_ips, allowed_tech)
            self._store_case(process_meta, rare_paths_context, attack_graph_text, graph_context)
            return report, dbg

        stage1 = (
            "You are an incident response analyst. Extract a concise IOC list strictly from the provided Evidence.\n"
            "Rules: Only output items that literally appear in Evidence. Output Markdown with sections: IOCs.Files, IOCs.Network, IOCs.Processes.\n\n"
            f"Evidence:\n{attack_graph_text}\n\n{rare_paths_context}\n\n{graph_context}\n"
        )
        stage1_out = llm_client.generate_report(stage1)

        stage2 = (
            "You are an APT investigator. Map the evidence to ATT&CK tactics/techniques.\n"
            "Rules: You may only reference technique IDs present in AllowedTechniques. If uncertain, write Unknown.\n"
            "Output a Markdown table: Stage | TechniqueID | Confidence | EvidenceSnippet.\n\n"
            f"AllowedTechniques: {', '.join(allowed_tech) if allowed_tech else 'None'}\n"
            f"SuggestedChain: {' -> '.join(attack_chain) if attack_chain else 'None'}\n\n"
            f"Evidence:\n{attack_graph_text}\n\n{rare_paths_context}\n\nTIK:\n{tik_context}\n"
        )
        stage2_out = llm_client.generate_report(stage2)

        stage3 = (
            "You are a security analyst. Write a grounded incident report.\n"
            "Rules:\n"
            "1) Only reference entities that appear in AllowedEntities.\n"
            "2) Only reference technique IDs in AllowedTechniques.\n"
            "3) Provide a verdict (Malicious/Benign/Unknown) and recommended actions.\n"
            "Output Markdown with sections: Summary, Evidence, ATT&CK Mapping, Impact, Recommended Actions, Confidence.\n\n"
            f"TargetAlert: {process_meta.get('target_name') or process_meta.get('name') or process_meta.get('pathname') or process_meta.get('window_id') or 'unknown'} pid={process_meta.get('pid')}\n"
            f"AllowedEntities:\n{json.dumps({'paths': allowed_paths[:120], 'ips': allowed_ips[:60], 'iocs': ioc_pack.get('iocs', [])}, ensure_ascii=False)}\n"
            f"AllowedTechniques: {', '.join(allowed_tech) if allowed_tech else 'None'}\n\n"
            f"SimilarCases:\n{chr(10).join(similar_lines) if similar_lines else 'None'}\n\n"
            f"BBK:\n{bbk_context}\n\n"
            f"EvidenceGraph:\n{attack_graph_text}\n\n"
            f"RarePaths:\n{rare_paths_context}\n\n"
            f"IOCList:\n{stage1_out}\n\n"
            f"StageMapping:\n{stage2_out}\n"
        )
        report = llm_client.generate_report(stage3)

        dbg["llm_stage1_prompt"] = stage1
        dbg["llm_stage1_output"] = stage1_out
        dbg["llm_stage2_prompt"] = stage2
        dbg["llm_stage2_output"] = stage2_out
        dbg["llm_stage3_prompt"] = stage3
        dbg["llm_stage3_output"] = report

        dbg["report_validation"] = self._validate_report(report, allowed_paths, allowed_ips, allowed_tech)
        rv = dbg["report_validation"]
        if rv.get("unverified_paths") or rv.get("unverified_ips") or rv.get("unverified_techniques"):
            report = report.rstrip() + "\n\n## Unverified Mentions\n" + json.dumps(
                {
                    "paths": rv.get("unverified_paths"),
                    "ips": rv.get("unverified_ips"),
                    "techniques": rv.get("unverified_techniques"),
                },
                ensure_ascii=False,
                indent=2,
            )

        self._store_case(process_meta, rare_paths_context, attack_graph_text, graph_context)
        return report, dbg

    def _fallback_report(
        self,
        process_meta: Dict[str, Any],
        bbk_context: str,
        rare_paths_context: str,
        tik_context: str,
        attack_chain: List[str],
        attack_graph_text: str,
        iocs: List[str],
    ) -> str:
        name = process_meta.get("target_name") or process_meta.get("name") or process_meta.get("pathname") or process_meta.get("window_id") or "unknown"
        pid = process_meta.get("pid")
        chain = " -> ".join(attack_chain) if attack_chain else "Unknown"
        ioc_lines = "\n".join([f"- {x}" for x in (iocs or [])[:30]])
        target_line = f"- Target: {name}"
        if pid is not None:
            target_line += f" (pid={pid})"
        if process_meta.get("window_score") is not None:
            target_line += f" window_score={float(process_meta.get('window_score', 0.0)):.3f}"
        return (
            f"# Incident Report (Mock/Offline)\n\n"
            f"## Summary\n{target_line}\n- Potential chain: {chain}\n\n"
            f"## Evidence\n### Attack Graph\n{attack_graph_text}\n\n"
            f"### Rare Paths\n{rare_paths_context}\n\n"
            f"### BBK Comparison\n{bbk_context}\n\n"
            f"## IOCs\n{ioc_lines if ioc_lines else '- None'}\n\n"
            f"## Threat Intelligence (TIK)\n{tik_context if tik_context else 'None'}\n\n"
            f"## Recommended Actions\n- Isolate the container or workload if confirmed malicious\n- Collect full process tree, command history, and network connections\n- Search for dropped files under /tmp and modified system paths\n- Review access to sensitive files and Docker socket exposure\n"
        )

    def _make_case_document(self, process_meta: Dict[str, Any], attack_graph_text: str, rare_paths_context: str, graph_context: str) -> str:
        name = process_meta.get("target_name") or process_meta.get("name") or process_meta.get("pathname") or process_meta.get("window_id") or "unknown"
        pid = process_meta.get("pid")
        parts = [
            f"process={name} pid={pid}",
            attack_graph_text or "",
            rare_paths_context or "",
            (graph_context or "")[:2000],
        ]
        return "\n".join([p for p in parts if p])

    def _store_case(self, process_meta: Dict[str, Any], rare_paths_context: str, attack_graph_text: str, graph_context: str) -> None:
        doc = self._make_case_document(process_meta, attack_graph_text, rare_paths_context, graph_context)
        if not doc.strip() or self.tik_vectorizer is None or self.case_db is None:
            return
        vec = self.tik_vectorizer.vectorize_path_doc2vec(doc)
        pid = process_meta.get("pid")
        name = process_meta.get("target_name") or process_meta.get("name") or process_meta.get("pathname") or process_meta.get("window_id") or "unknown"
        rarity_score = None
        try:
            for line in (rare_paths_context or "").splitlines():
                if line.startswith("- score="):
                    rarity_score = float(line.split("score=")[1].split()[0])
                    break
        except Exception:
            rarity_score = None
        self.case_db.add_vectors(
            [
                {
                    "id": f"case_{int(time.time())}_{uuid.uuid4().hex[:8]}",
                    "vector": vec.tolist(),
                    "metadata": {"type": "case", "pid": pid, "name": name, "rarity_score": rarity_score},
                    "feature_string": doc,
                }
            ]
        )

    def _format_target(self, process_meta: Dict[str, Any], graph_context: str) -> str:
        name = process_meta.get("target_name") or process_meta.get("name") or process_meta.get("pathname") or process_meta.get("window_id") or "unknown"
        pid = process_meta.get("pid")
        header = f"Alert Target: {name}"
        if pid is not None:
            header += f" (pid={pid})"
        if process_meta.get("window_score") is not None:
            header += f" window_score={float(process_meta.get('window_score', 0.0)):.3f}"
        return f"{header}\n\nGraph Context:\n{graph_context}"

    def _abbr_edge_type(self, et: str) -> str:
        m = {
            "Execute": "EX",
            "Fork": "FR",
            "Read": "RD",
            "Write": "WR",
            "Send": "SD",
            "Receive": "RC",
            "Mmap": "MM",
        }
        s = str(et or "")
        return m.get(s, s[:3].upper() if s else "UNK")

    def _shorten_entity_label(self, s: str, max_len: int = 64) -> str:
        if s is None:
            return ""
        v = str(s)
        v = v.strip()
        if not v:
            return v
        if v.startswith(("proc:", "file:", "net:", "pid:", "fd:")):
            return v if len(v) <= max_len else (v[: max_len - 3] + "...")
        if "/" in v and len(v) > max_len:
            base = v.rsplit("/", 1)[-1]
            if base and len(base) + 4 <= max_len:
                return ".../" + base
        return v if len(v) <= max_len else (v[: max_len - 3] + "...")

    def _format_rare_paths_compact(
        self,
        rare_paths: List[Dict[str, Any]] | None,
        source_graph: nx.MultiDiGraph | None,
        max_items: int = 10,
        max_steps: int = 12,
    ) -> str:
        if not rare_paths:
            return ""
        lines: List[str] = []
        for rp in rare_paths[:max_items]:
            score = float(rp.get("score", 0.0))
            chain = rp.get("chain") or []
            if source_graph is None or not chain:
                text = rp.get("text") or ""
                if text:
                    lines.append(f"- score={score:.3f} path={self._shorten_entity_label(text, 120)}")
                continue
            parts: List[str] = []
            u0, _et0, _v0, _dir0 = chain[0]
            seed_meta = source_graph.nodes.get(u0, {}).get("meta", {})
            seed_name = seed_meta.get("pathname") or seed_meta.get("name") or u0
            parts.append(self._shorten_entity_label(seed_name, 48))
            for u, et, v, direction in chain[:max_steps]:
                v_meta = source_graph.nodes.get(v, {}).get("meta", {})
                v_name = v_meta.get("pathname") or v_meta.get("name") or v
                parts.append(f"{self._abbr_edge_type(str(et))}{'<-' if direction == 'in' else '->'}")
                parts.append(self._shorten_entity_label(v_name, 48))
            if len(chain) > max_steps:
                parts.append("...")
            lines.append(f"- score={score:.3f} path={' '.join(parts)}")
        uniq: List[str] = []
        seen = set()
        for l in lines:
            if l not in seen:
                seen.add(l)
                uniq.append(l)
        return "\n".join(uniq)

    def _format_bbk_context(self, rare_paths: List[Dict[str, Any]] | None, max_items: int = 5) -> str:
        if not rare_paths:
            return ""
        lines: List[str] = []
        for rp in rare_paths[:max_items]:
            score = float(rp.get("score", 0.0))
            text = rp.get("text") or ""
            chain = rp.get("chain") or []
            supports: List[float] = []
            for u, et, v, direction in chain:
                src = u if direction == "out" else v
                dst = v if direction == "out" else u
                try:
                    supports.append(float(self.benign_kb.support(src, dst, str(et))))
                except Exception:
                    supports.append(0.0)
            if supports:
                mn = min(supports)
                avg = sum(supports) / max(len(supports), 1)
                supports_str = ", ".join([f"{s:.3e}" for s in supports[:12]])
                if len(supports) > 12:
                    supports_str += ", ..."
                lines.append(f"- path_score={score:.3f} min_support={mn:.3e} avg_support={avg:.3e} supports=[{supports_str}]")
            elif text:
                lines.append(f"- path_score={score:.3f} supports=[]")
        return "\n".join(lines)

    def _construct_prompt(
        self,
        target_event: str,
        bbk: str,
        rare_paths: str,
        knowledge: str,
        attack_graph: str,
        history: str,
    ) -> str:
        return f"""
You are a security analyst. Analyze the following suspicious alert behavior based on the provided knowledge base and historical context.

TARGET SUSPICIOUS BEHAVIOR:
{target_event}

BENIGN BEHAVIOR KNOWLEDGE (BBK):
{bbk}

RARE PATHS (from BBK rarity scoring):
{rare_paths}

RELEVANT KNOWLEDGE (from Security Reports/Papers):
{knowledge}

RECONSTRUCTED ATTACK PROVENANCE GRAPH (for this alert):
{attack_graph}

SIMILAR HISTORICAL CASES (from Local Database):
{history}

INSTRUCTIONS:
1. Explain why this behavior is suspicious based on the knowledge base.
2. Compare it with historical cases if available.
3. Provide a verdict (Malicious/Benign/Unknown) and recommended actions.
4. Output the report in Markdown format.
"""

    def detect_window_alerts(
        self,
        log_file: str,
        threshold: float = DEFAULT_ALERT_THRESHOLD,
        update_bbk: bool = False,
        persist_windows_dir: str | None = None,
        window_mode: str = "sliding",
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        stride_seconds: int = DEFAULT_DETECT_STRIDE_SECONDS,
        time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS,
    ) -> List[WindowAlert]:
        """主检测接口：按窗口产出 0 或 1 条窗口级告警。"""
        from src.process.log_parser import TraceeLogParser

        parser = TraceeLogParser()
        logs = parser.parse_log_file(log_file)

        alerts: List[WindowAlert] = []
        window_idx = 0
        if persist_windows_dir:
            os.makedirs(persist_windows_dir, exist_ok=True)
        for g, metas in iter_window_graphs(
            logs,
            window_mode=str(window_mode),
            window_seconds=int(window_seconds),
            stride_seconds=int(stride_seconds),
            time_bin_seconds=int(time_bin_seconds),
            mapper=self.provenance_mapper,
            emit_partial=True,
        ):
            window_idx += 1
            window_file = f"window_{window_idx:04d}.json"
            if persist_windows_dir:
                dump_window_graph(os.path.join(persist_windows_dir, window_file), g)
            alerts.extend(self.detect_window_alerts_in_window(g, threshold=float(threshold), window_hint=window_file))
            if update_bbk:
                self.benign_kb.update_from_edges(iter_reduced_edges(g), metas)
                self.benign_kb.update_word2vec_from_metas(metas)

        alerts.sort(key=lambda item: (float(item.window_score), item.window_id), reverse=True)
        return alerts

    def detect_window_alerts_in_window(
        self,
        g: nx.MultiDiGraph,
        threshold: float = DEFAULT_ALERT_THRESHOLD,
        window_hint: str | None = None,
    ) -> List[WindowAlert]:
        window_id = self._window_id_from_hint(window_hint)
        candidates = self._process_candidates_from_graph(g, threshold=0.0, window_file=window_hint)
        alert = self._build_window_alert(
            candidates=candidates,
            g=g,
            threshold=float(threshold),
            window_id=window_id,
            window_file=window_hint,
        )
        return [alert] if alert is not None else []

    def detect_window_alerts_from_windows(
        self,
        windows_dir: str,
        threshold: float = DEFAULT_ALERT_THRESHOLD,
        update_bbk: bool = False,
    ) -> List[WindowAlert]:
        paths = []
        for name in os.listdir(windows_dir):
            if name.startswith("window_") and name.endswith(".json"):
                paths.append(os.path.join(windows_dir, name))
        paths.sort()

        alerts: List[WindowAlert] = []
        for p in paths:
            g = load_window_graph(p)
            metas = {n: (g.nodes[n].get("meta") or {}) for n in g.nodes}
            alerts.extend(self.detect_window_alerts_in_window(g, float(threshold), window_hint=os.path.basename(p)))
            if update_bbk:
                self.benign_kb.update_from_edges(iter_reduced_edges(g), metas)
                self.benign_kb.update_word2vec_from_metas(metas)

        alerts.sort(key=lambda item: (float(item.window_score), item.window_id), reverse=True)
        return alerts

    def detect_suspicious_processes(
        self,
        log_file: str,
        threshold: float = DEFAULT_ALERT_THRESHOLD,
        update_bbk: bool = False,
        persist_windows_dir: str | None = None,
        window_mode: str = "sliding",
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        stride_seconds: int = DEFAULT_DETECT_STRIDE_SECONDS,
        time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS,
    ) -> List[Dict[str, Any]]:
        """兼容接口：返回窗口内命中的进程证据列表，不再作为主告警输出。"""
        from src.process.log_parser import TraceeLogParser

        parser = TraceeLogParser()
        logs = parser.parse_log_file(log_file)

        suspicious_nodes: List[Dict[str, Any]] = []
        window_idx = 0
        if persist_windows_dir:
            os.makedirs(persist_windows_dir, exist_ok=True)
        for g, metas in iter_window_graphs(
            logs,
            window_mode=str(window_mode),
            window_seconds=int(window_seconds),
            stride_seconds=int(stride_seconds),
            time_bin_seconds=int(time_bin_seconds),
            mapper=self.provenance_mapper,
            emit_partial=True,
        ):
            window_idx += 1
            window_file = f"window_{window_idx:04d}.json"
            if persist_windows_dir:
                dump_window_graph(os.path.join(persist_windows_dir, window_file), g)
            suspicious_nodes.extend(self.detect_suspicious_processes_in_window(g, float(threshold), window_hint=window_file))
            if update_bbk:
                self.benign_kb.update_from_edges(iter_reduced_edges(g), metas)
                self.benign_kb.update_word2vec_from_metas(metas)

        suspicious_nodes.sort(
            key=lambda item: (
                float(item.get("process_score", item.get("rarity_score", 0.0))),
                float(item.get("top_path_score", 0.0)),
                str(item.get("evidence_key") or ""),
            ),
            reverse=True,
        )
        return suspicious_nodes

    def detect_suspicious_processes_in_window(
        self,
        g: nx.MultiDiGraph,
        threshold: float = DEFAULT_ALERT_THRESHOLD,
        window_hint: str | None = None,
    ) -> List[Dict[str, Any]]:
        return self._process_candidates_from_graph(g, float(threshold), window_file=window_hint)

    def detect_suspicious_processes_from_windows(
        self,
        windows_dir: str,
        threshold: float = DEFAULT_ALERT_THRESHOLD,
        update_bbk: bool = False,
    ) -> List[Dict[str, Any]]:
        paths = []
        for name in os.listdir(windows_dir):
            if name.startswith("window_") and name.endswith(".json"):
                paths.append(os.path.join(windows_dir, name))
        paths.sort()

        suspicious_nodes: List[Dict[str, Any]] = []
        for p in paths:
            g = load_window_graph(p)
            metas = {n: (g.nodes[n].get("meta") or {}) for n in g.nodes}
            suspicious_nodes.extend(self.detect_suspicious_processes_in_window(g, float(threshold), window_hint=os.path.basename(p)))
            if update_bbk:
                self.benign_kb.update_from_edges(iter_reduced_edges(g), metas)
                self.benign_kb.update_word2vec_from_metas(metas)

        suspicious_nodes.sort(
            key=lambda item: (
                float(item.get("process_score", item.get("rarity_score", 0.0))),
                float(item.get("top_path_score", 0.0)),
                str(item.get("evidence_key") or ""),
            ),
            reverse=True,
        )
        return suspicious_nodes

    def _process_candidates_from_graph(
        self,
        g: nx.MultiDiGraph,
        threshold: float = 0.0,
        window_file: str | None = None,
    ) -> List[Dict[str, Any]]:
        gmae_scores = self._gmae_process_scores(g)  # 计算进程节点重构误差分数
        use_gmae = bool(gmae_scores)
        candidates: List[Dict[str, Any]] = []

        for node in g.nodes:
            if not str(node).startswith("proc:"):
                continue

            meta = dict(g.nodes[node].get("meta", {}) or {})
            pid = meta.get("pid")
            if pid is None:
                continue

            rp_items = self.rare_selector.select_with_chains(g, node, self.benign_kb.support)
            if not use_gmae and not rp_items:
                continue

            raw_process_score = float(gmae_scores.get(node, 0.0)) if use_gmae else float((rp_items[0] or {}).get("score", 0.0))
            process_score = raw_process_score if use_gmae else self._normalize_bbk_rarity_score(raw_process_score)
            if process_score < float(threshold):
                continue

            rare_paths = []
            for rp in rp_items:
                raw_path_score = float(rp.get("score", 0.0) or 0.0)
                rare_paths.append(
                    {
                        "text": rp.get("text"),
                        "score": self._normalize_bbk_rarity_score(raw_path_score),
                        "raw_score": raw_path_score,
                        "keywords": rp.get("keywords", []),
                        "chain": rp.get("chain", []),
                    }
                )

            meta["node"] = node
            container_id = str(meta.get("container_id") or "").strip()
            graph_context = self._linearize_context(g, node)
            top_path_score = float(rare_paths[0].get("score", 0.0)) if rare_paths else 0.0
            candidate = {
                "pid": int(pid),
                "node": node,
                "process_score": float(process_score),
                "rarity_score": float(process_score),
                "raw_process_score": float(raw_process_score),
                "score_source": "gmae" if use_gmae else "bbk",
                "process_meta": meta,
                "rare_paths": rare_paths,
                "graph_context": graph_context,
                "window_graph": g,
                "window_file": window_file,
                "container_id": container_id,
                "evidence_key": self._process_evidence_key(node, meta),
                "display_name": self._process_display_name(meta),
                "top_path_score": float(top_path_score),
            }
            candidates.append(candidate)

        candidates.sort(
            key=lambda item: (
                float(item.get("process_score", 0.0)),
                float(item.get("top_path_score", 0.0)),
                str(item.get("evidence_key") or ""),
            ),
            reverse=True,
        )
        return candidates

    def _build_window_alert(
        self,
        candidates: List[Dict[str, Any]],
        g: nx.MultiDiGraph,
        threshold: float,
        window_id: str,
        window_file: str | None,
    ) -> WindowAlert | None:
        if not candidates:
            return None

        top_score = float(candidates[0].get("process_score", 0.0))
        if top_score < float(threshold):
            return None

        alert_processes = [item for item in candidates if float(item.get("process_score", 0.0)) >= float(threshold)]
        if not alert_processes:
            alert_processes = [candidates[0]]

        top_processes = [self._compact_process_evidence(item) for item in candidates[:DEFAULT_TOP_EVIDENCE_ITEMS]]
        top_rare_paths = self._top_rare_paths(alert_processes, limit=DEFAULT_TOP_EVIDENCE_ITEMS)
        impacted_containers = self._impacted_containers(alert_processes)
        top_scores = [float(item.get("process_score", 0.0)) for item in candidates[:DEFAULT_TOP_EVIDENCE_ITEMS]]
        top_process_name = str(top_processes[0].get("display_name") or "unknown") if top_processes else "unknown"
        top_path_score = float(top_rare_paths[0].get("score", 0.0)) if top_rare_paths else 0.0

        return WindowAlert(
            window_id=window_id,
            window_file=window_file,
            window_score=float(top_score),
            threshold=float(threshold),
            top_processes=top_processes,
            top_rare_paths=top_rare_paths,
            impacted_containers=impacted_containers,
            evidence_summary=self._summarize_window_alert(
                window_id=window_id,
                window_score=top_score,
                top_processes=top_processes,
                impacted_containers=impacted_containers,
                top_rare_paths=top_rare_paths,
            ),
            top3_mean_process_score=(sum(top_scores) / float(len(top_scores))) if top_scores else 0.0,
            suspicious_process_count=len(alert_processes),
            top_process_name=top_process_name,
            top_path_score=top_path_score,
            window_graph=g,
        )

    def _compact_process_evidence(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        meta = dict(candidate.get("process_meta", {}) or {})
        return {
            "node": candidate.get("node"),
            "evidence_key": candidate.get("evidence_key"),
            "pid": candidate.get("pid"),
            "container_id": str(meta.get("container_id") or ""),
            "display_name": self._process_display_name(meta),
            "pathname": meta.get("pathname") or "",
            "process_score": float(candidate.get("process_score", 0.0)),
            "top_path_score": float(candidate.get("top_path_score", 0.0)),
            "score_source": candidate.get("score_source"),
            "process_meta": meta,
            "rare_paths": list(candidate.get("rare_paths") or [])[:DEFAULT_TOP_EVIDENCE_ITEMS],
            "graph_context": candidate.get("graph_context") or "",
            "window_file": candidate.get("window_file"),
        }

    def _top_rare_paths(self, candidates: List[Dict[str, Any]], limit: int = DEFAULT_TOP_EVIDENCE_ITEMS) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen = set()
        for item in candidates:
            for rp in item.get("rare_paths") or []:
                chain_key = tuple(tuple(step) for step in (rp.get("chain") or []))
                text_key = str(rp.get("text") or "").strip()
                key = text_key or str(chain_key)
                if key in seen:
                    continue
                seen.add(key)
                out.append(dict(rp))
        out.sort(key=lambda item: (float(item.get("score", 0.0)), float(item.get("raw_score", 0.0))), reverse=True)
        return out[: int(limit)]

    def _impacted_containers(self, candidates: List[Dict[str, Any]]) -> List[str]:
        values: List[str] = []
        seen = set()
        for item in candidates:
            meta = item.get("process_meta", {}) or {}
            container_id = str(meta.get("container_id") or "").strip()
            if container_id and container_id not in seen:
                seen.add(container_id)
                values.append(container_id)
        return values

    def _window_id_from_hint(self, window_hint: str | None) -> str:
        if window_hint:
            name = os.path.basename(str(window_hint))
            if name.endswith(".json"):
                return name[:-5]
            return name
        return "window_in_memory"

    def _process_display_name(self, meta: Dict[str, Any]) -> str:
        return str(meta.get("name") or meta.get("pathname") or "unknown")

    def _process_evidence_key(self, node: str, meta: Dict[str, Any]) -> str:
        container_id = str(meta.get("container_id") or "").strip()
        pid = meta.get("pid")
        if container_id and pid is not None:
            return f"{container_id}:{pid}"
        return str(node)

    def _summarize_window_alert(
        self,
        window_id: str,
        window_score: float,
        top_processes: List[Dict[str, Any]],
        impacted_containers: List[str],
        top_rare_paths: List[Dict[str, Any]],
    ) -> str:
        proc_bits = []
        for item in top_processes[:DEFAULT_TOP_EVIDENCE_ITEMS]:
            proc_bits.append(
                f"{item.get('display_name')} pid={item.get('pid')} score={float(item.get('process_score', 0.0)):.3f}"
            )
        path_bits = []
        for rp in top_rare_paths[:DEFAULT_TOP_EVIDENCE_ITEMS]:
            text = str(rp.get("text") or "").strip()
            if text:
                path_bits.append(text[:96])

        parts = [
            f"{window_id} score={float(window_score):.3f}",
            f"containers={len(impacted_containers)}",
        ]
        if proc_bits:
            parts.append("top_processes=" + "; ".join(proc_bits))
        if path_bits:
            parts.append("top_paths=" + "; ".join(path_bits))
        return " | ".join(parts)

    def _normalize_bbk_rarity_score(self, raw_score: float) -> float:
        score = max(float(raw_score or 0.0), 0.0)
        if score <= 0.0:
            return 0.0
        return max(0.0, min(1.0, 1.0 - math.exp(-score * math.log(2.0))))

    def _load_gmae_runtime(self) -> Optional[Dict[str, Any]]:
        if not os.path.exists(KB_PATHS.gmae_baseline_path):
            self.gmae_load_error = f"missing_gmae_baseline:{KB_PATHS.gmae_baseline_path}"
            return None
        try:
            import torch
            from src.common.gmae import build_model

            device = self._resolve_gmae_device(torch)
            payload = torch.load(KB_PATHS.gmae_baseline_path, map_location=device)
            config = dict(payload.get("config") or {})
            if not config:
                raise RuntimeError("missing_gmae_config")
            model = build_model(SimpleNamespace(**config)).to(device)
            state_dict = payload.get("state_dict")
            if not isinstance(state_dict, dict) or not state_dict:
                raise RuntimeError("missing_gmae_state_dict")
            model.load_state_dict(state_dict)
            model.eval()
            process_error_calibration = payload.get("process_error_calibration")
            calibration_file = read_json(KB_PATHS.process_error_calibration_path) if os.path.exists(KB_PATHS.process_error_calibration_path) else {}
            if not process_error_calibration and isinstance(calibration_file, dict) and calibration_file:
                process_error_calibration = calibration_file
            return {
                "torch": torch,
                "device": device,
                "config": config,
                "model": model,
                "baseline_version": int(payload.get("baseline_version") or 1),
                "process_error_calibration": process_error_calibration,
                "window_score_threshold": payload.get("window_score_threshold"),
                "feature_profile": str(payload.get("feature_profile") or config.get("feature_profile") or "legacy"),
                "load_error": "",
            }
        except Exception as exc:
            self.gmae_load_error = f"gmae_load_failed:{type(exc).__name__}: {exc}"
            print(f"Warning: failed to load GMAE baseline, disabling GMAE scoring: {exc}")
            return None

    def _load_logic_graph(self, payload: Dict[str, Any]) -> nx.DiGraph:
        if "links" in payload:
            return nx.node_link_graph(payload, directed=True, edges="links")
        return nx.node_link_graph(payload, directed=True)

    def _resolve_gmae_device(self, torch_module) -> str:
        if not torch_module.cuda.is_available():
            return "cpu"
        try:
            import dgl

            g = dgl.graph((torch_module.tensor([], dtype=torch_module.int64), torch_module.tensor([], dtype=torch_module.int64)), num_nodes=0)
            g = g.to("cuda")
            del g
            return "cuda"
        except Exception:
            return "cpu"

    def _normalize_node_scores(self, raw_scores: Dict[str, float]) -> Dict[str, float]:
        if not raw_scores:
            return {}
        values = [float(v) for v in raw_scores.values()]
        lo = min(values)
        hi = max(values)
        if hi - lo <= 1e-12:
            return {node_id: 0.0 for node_id in raw_scores}
        return {node_id: (float(score) - lo) / (hi - lo) for node_id, score in raw_scores.items()}

    def _apply_process_error_calibration(
        self,
        raw_scores: Dict[str, float],
        calibration: Dict[str, Any] | None,
    ) -> Dict[str, float]:
        if not raw_scores or not isinstance(calibration, dict):
            return {}
        if str(calibration.get("type") or "") != "empirical_cdf":
            return {}

        scores = calibration.get("scores") or []
        count = int(calibration.get("count") or len(scores))
        if count <= 0 or not scores:
            return {}

        count = min(count, len(scores))
        return {
            node_id: float(bisect_right(scores, float(raw_score)) / float(count))
            for node_id, raw_score in raw_scores.items()
        }

    def _legacy_gmae_process_scores(self, adapter, runtime: Dict[str, Any]) -> Dict[str, float]:
        torch = runtime["torch"]
        with torch.no_grad():
            node_errors = runtime["model"].compute_node_reconstruction_errors(adapter.graph)

        raw_scores = {
            adapter.idx_to_node_id[idx]: float(node_errors[idx].detach().cpu().item())
            for idx in range(len(adapter.node_ids))
        }
        normalized = self._normalize_node_scores(raw_scores)
        return {
            adapter.idx_to_node_id[idx]: float(normalized.get(adapter.idx_to_node_id[idx], 0.0))
            for idx in adapter.process_node_indices
        }

    def _gmae_process_scores(self, g: nx.MultiDiGraph) -> Dict[str, float]:
        runtime = self.gmae_runtime
        if runtime is None:
            return {}
        try:
            from src.process.dgl_adapter import window_to_dgl_graph

            adapter = window_to_dgl_graph(
                g,
                node_attr_dim=int(runtime["config"].get("n_dim", 64)),
                edge_attr_dim=int(runtime["config"].get("e_dim", 16)),
                device=runtime["device"],
                feature_profile=str(runtime.get("feature_profile") or runtime["config"].get("feature_profile") or "legacy"),
            )
            if int(adapter.graph.ndata["attr"].shape[1]) != int(runtime["config"].get("n_dim", 64)):
                raise RuntimeError(
                    f"node_feature_dim_mismatch:model={int(runtime['config'].get('n_dim', 64))}:graph={int(adapter.graph.ndata['attr'].shape[1])}"
                )
            if int(adapter.graph.edata["attr"].shape[1]) != int(runtime["config"].get("e_dim", 16)):
                raise RuntimeError(
                    f"edge_feature_dim_mismatch:model={int(runtime['config'].get('e_dim', 16))}:graph={int(adapter.graph.edata['attr'].shape[1])}"
                )
            if int(adapter.graph.num_nodes()) == 0:
                return {}
            if not adapter.process_node_indices:
                return {}

            calibration = runtime.get("process_error_calibration")
            if calibration:
                torch = runtime["torch"]
                with torch.no_grad():
                    node_errors = runtime["model"].compute_node_reconstruction_errors(
                        adapter.graph,
                        node_indices=adapter.process_node_indices,
                    )
                raw_scores = {
                    adapter.idx_to_node_id[idx]: float(node_errors[idx].detach().cpu().item())
                    for idx in adapter.process_node_indices
                }
                calibrated = self._apply_process_error_calibration(raw_scores, calibration)
                if calibrated:
                    return calibrated

            return self._legacy_gmae_process_scores(adapter, runtime)
        except Exception as exc:
            print(f"Warning: GMAE scoring failed, falling back to statistical rarity score: {exc}")
            self.gmae_runtime = None
            return {}

    def score_process_nodes(self, g: nx.MultiDiGraph) -> Dict[str, float]:
        """Return GMAE process-node scores only.

        This method is used by the explicit two-stage pipeline. It must not
        fall back to BBK because BBK is Stage-1 window screening there.
        """

        return self._gmae_process_scores(g)

    def group_suspicious_processes(self, suspicious_list: List[Dict[str, Any]], sim_threshold: float = 0.2) -> List[Dict[str, Any]]:
        sessions: List[Dict[str, Any]] = []

        def features(item: Dict[str, Any]) -> set[str]:
            parts = []
            if item.get("graph_context"):
                parts.append(str(item.get("graph_context")))
            rp = item.get("rare_paths") or []
            for x in rp[:5]:
                if x.get("text"):
                    parts.append(str(x.get("text")))
            ent = self._extract_entities_from_text("\n".join(parts))
            feats = set(ent.get("paths", [])[:60] + ent.get("ips", [])[:30] + ent.get("techniques", [])[:30])
            return feats

        def jacc(a: set[str], b: set[str]) -> float:
            if not a or not b:
                return 0.0
            inter = len(a & b)
            uni = len(a | b)
            return float(inter) / float(uni) if uni else 0.0

        for item in (suspicious_list or []):
            f = features(item)
            best_idx = -1
            best_sim = 0.0
            for i, s in enumerate(sessions):
                sim = jacc(f, s["features"])
                if sim > best_sim:
                    best_sim = sim
                    best_idx = i
            if best_idx >= 0 and best_sim >= float(sim_threshold):
                sessions[best_idx]["processes"].append(item)
                sessions[best_idx]["features"] |= f
            else:
                sessions.append({"processes": [item], "features": set(f)})

        out: List[Dict[str, Any]] = []
        for idx, s in enumerate(sessions, start=1):
            procs = s["processes"]
            procs.sort(key=lambda x: float(x.get("rarity_score", 0.0)), reverse=True)
            out.append(
                {
                    "session_id": idx,
                    "process_count": len(procs),
                    "top_rarity": float(procs[0].get("rarity_score", 0.0)) if procs else 0.0,
                    "features": sorted(list(s["features"]))[:120],
                    "processes": procs,
                }
            )
        out.sort(key=lambda x: (-int(x.get("process_count", 0)), -float(x.get("top_rarity", 0.0))))
        return out

    def _reconstruct_attack_provenance_graph(
        self,
        g: nx.MultiDiGraph,
        process_meta: Dict[str, Any],
        rare_paths: List[Dict[str, Any]],
        max_edges_print: int = 80,
    ) -> tuple[nx.MultiDiGraph, str]:
        seed = process_meta.get("node")
        if seed is not None and seed not in g:
            seed = None
        for n, data in g.nodes(data=True):
            if seed is not None:
                break
            meta = (data or {}).get("meta", {})
            if not str(n).startswith("proc:"):
                continue
            if (
                meta.get("pid") == process_meta.get("pid")
                and str(meta.get("container_id") or "") == str(process_meta.get("container_id") or "")
            ):
                seed = n
                break
        if seed is None:
            for n, data in g.nodes(data=True):
                meta = (data or {}).get("meta", {})
                if meta.get("pid") == process_meta.get("pid") and str(n).startswith("proc:"):
                    seed = n
                    break
        if seed is None:
            seed = str(process_meta.get("node") or f"proc:pid:{process_meta.get('pid')}")

        sg = nx.MultiDiGraph()
        sg.add_node(seed, meta=g.nodes.get(seed, {}).get("meta", {}))

        edge_agg: Dict[tuple[str, str, str], int] = {}
        for rp in (rare_paths or [])[:10]:
            chain = rp.get("chain") or []
            for u, et, v, direction in chain:
                src = u if direction == "out" else v
                dst = v if direction == "out" else u
                if src not in sg:
                    sg.add_node(src, meta=g.nodes.get(src, {}).get("meta", {}))
                if dst not in sg:
                    sg.add_node(dst, meta=g.nodes.get(dst, {}).get("meta", {}))
                cnt = 1
                try:
                    for _k, d in (g.get_edge_data(src, dst) or {}).items():
                        if str(d.get("type")) == str(et):
                            cnt = int(d.get("count", 1))
                            break
                except Exception:
                    pass
                ek = (src, dst, str(et))
                edge_agg[ek] = max(int(cnt), int(edge_agg.get(ek, 0)))

        for (src, dst, et), cnt in edge_agg.items():
            if src not in sg:
                sg.add_node(src, meta=g.nodes.get(src, {}).get("meta", {}))
            if dst not in sg:
                sg.add_node(dst, meta=g.nodes.get(dst, {}).get("meta", {}))
            sg.add_edge(src, dst, type=et, count=int(cnt))

        edges = []
        for u, v, k, d in sg.edges(keys=True, data=True):
            edges.append((u, v, str(d.get("type")), int(d.get("count", 1))))
        edges.sort(key=lambda x: (-x[3], x[2], x[0], x[1]))

        lines: List[str] = []
        lines.append("Attack Provenance Graph (reconstructed from top rare paths):")
        lines.append(f"nodes={sg.number_of_nodes()} edges={sg.number_of_edges()}")
        for u, v, et, cnt in edges[:max_edges_print]:
            u_meta = sg.nodes[u].get("meta", {})
            v_meta = sg.nodes[v].get("meta", {})
            u_name = u_meta.get("pathname") or u_meta.get("name") or u
            v_name = v_meta.get("pathname") or v_meta.get("name") or v
            lines.append(
                f"{self._shorten_entity_label(u_name, 60)} -[{self._abbr_edge_type(et)} x{cnt}]-> {self._shorten_entity_label(v_name, 60)}"
            )
        if len(edges) > max_edges_print:
            lines.append(f"... ({len(edges) - max_edges_print} more edges omitted)")
        return sg, "\n".join(lines)

    def _linearize_context(self, g: nx.MultiDiGraph, seed: str, hops: int = 2, max_edges: int = 60) -> str:
        if seed not in g:
            return ""
        nodes = {seed}
        frontier = {seed}
        for _ in range(hops):
            nxt = set()
            for n in frontier:
                for _, v in g.out_edges(n):
                    nxt.add(v)
                for u, _ in g.in_edges(n):
                    nxt.add(u)
            nxt -= nodes
            nodes |= nxt
            frontier = nxt
            if not frontier:
                break

        edge_lines: List[str] = []
        edges: List[tuple[str, str, str, int]] = []
        for u, v, key, data in g.edges(keys=True, data=True):
            if u in nodes and v in nodes:
                edges.append((u, v, str(data.get("type")), int(data.get("count", 1))))
        def _priority(item: tuple[str, str, str, int]) -> tuple[int, int, str, str]:
            _u, _v, _et, _cnt = item
            et = str(_et)
            w = 0
            if et in {"Execute", "Fork"}:
                w += 5
            if et in {"Send", "Receive"}:
                w += 4
            if et in {"Write"}:
                w += 3
            if et in {"Read", "Mmap"}:
                w += 2
            return (-w, -int(_cnt), et, f"{_u}->{_v}")

        edges.sort(key=_priority)
        kept: List[tuple[str, str, str, int]] = []
        seen_keys = set()
        for u, v, et, cnt in edges:
            k = (u, v, et)
            if k in seen_keys:
                continue
            seen_keys.add(k)
            kept.append((u, v, et, cnt))
            if len(kept) >= max_edges:
                break

        for u, v, et, cnt in kept:
            u_meta = g.nodes[u].get("meta", {})
            v_meta = g.nodes[v].get("meta", {})
            u_name = u_meta.get("pathname") or u_meta.get("name") or u
            v_name = v_meta.get("pathname") or v_meta.get("name") or v
            edge_lines.append(
                f"{self._shorten_entity_label(u_name, 60)} -[{self._abbr_edge_type(et)} x{cnt}]-> {self._shorten_entity_label(v_name, 60)}"
            )
        return "\n".join(edge_lines)

if __name__ == "__main__":
    # 测试
    engine = AnalysisEngine()
    print("AnalysisEngine initialized.")
