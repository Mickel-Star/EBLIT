#!/usr/bin/env python3
from __future__ import annotations

"""Knowledge base builders.

本模块负责三个构建入口：
1. `build_tik`：构建威胁情报向量库。
2. `build_ark`：构建 MITRE 逻辑图。
3. `build_bbk`：构建/更新 BBK，并执行两阶段 GMAE 训练

其中 `build_bbk` 是训练主入口：
- 阶段 1 把 benign 日志切成窗口，更新 BBK/Word2Vec，并落盘窗口 + manifest。
- 阶段 2 基于 manifest 按顺序做离线 GMAE 训练并保存 baseline。
"""

import copy
import json
import logging
import math
import os
import re
import shutil
import tempfile
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable

from src.common.defaults import (
    DEFAULT_BBK_MIN_TRAIN_WINDOWS,
    DEFAULT_BBK_PROFILE_IMBALANCE_RATIO,
    DEFAULT_BBK_TRAIN_WINDOW_SECONDS,
    DEFAULT_DETECT_STRIDE_SECONDS,
    DEFAULT_TIME_BIN_SECONDS,
    DEFAULT_WINDOW_SECONDS,
)
from src.common.io import read_json, write_json
from src.knowledge.kb_paths import KB_PATHS


GMAE_MANIFEST_FILENAME = "gmae_windows_manifest.json"
GMAE_STAGING_PREFIX = "gmae_bbk_staging_"
GMAE_BASELINE_VERSION = 5
DEFAULT_GMAE_EPOCHS = 30
DEFAULT_GMAE_THRESHOLD_POLICY = "p95"
TRANSFER_GMAE_CONTEXT_TAG = "gmae_transfer"


for _quiet_logger_name in ("gensim", "gensim.models.word2vec", "gensim.utils", "transformers"):
    logging.getLogger(_quiet_logger_name).setLevel(logging.ERROR)
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _percentile(sorted_values: list[float], ratio: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    idx = max(0, min(len(sorted_values) - 1, int(math.ceil(float(ratio) * len(sorted_values))) - 1))
    return float(sorted_values[idx])


def _copy_optional_file(src: str, dst: str) -> bool:
    source = str(src or "").strip()
    target = str(dst or "").strip()
    if not source or not target:
        return False
    src_path = Path(source).expanduser()
    if not src_path.exists() or not src_path.is_file():
        return False
    Path(target).expanduser().parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(str(src_path), str(target))
    return True


def _window_records_for_calibration(records: list[dict[str, Any]], fallback: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    usable = [dict(record) for record in records if str(record.get("path") or "").strip()]
    if usable:
        return usable
    return [dict(record) for record in (fallback or []) if str(record.get("path") or "").strip()]


def _build_bbk_calibration_payload(
    *,
    store: Any,
    records: list[dict[str, Any]],
    source_mode: str,
    fallback_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    from src.analysis.bbk_window_scorer import score_bbk_window
    from src.process.window_io import load_window_graph

    usable_records = _window_records_for_calibration(records, fallback_records)
    novelty_samples: list[float] = []
    bbk_scores: list[float] = []
    candidate_counts: list[float] = []
    window_count = 0

    for record in usable_records:
        try:
            graph = load_window_graph(str(record["path"]))
        except Exception:
            continue
        window_count += 1
        for node in graph.nodes:
            if not str(node).startswith("proc:"):
                continue
            meta = dict(graph.nodes[node].get("meta", {}) or {})
            try:
                novelty_samples.append(float(store.novelty_score(node, meta)))
            except Exception:
                novelty_samples.append(1.0)
        try:
            scored = score_bbk_window(graph, store)
            bbk_scores.append(float(scored.get("bbk_score", 0.0) or 0.0))
            candidate_counts.append(float(scored.get("candidate_process_count", 0) or 0))
        except Exception:
            continue

    novelty_samples.sort()
    process_novelty_threshold = _percentile(novelty_samples, 0.95) if novelty_samples else 0.15
    process_novelty_threshold = max(1e-6, float(process_novelty_threshold or 0.15))
    bbk_scores.sort()
    candidate_counts.sort()

    return {
        "schema_version": 2,
        "generated_at": _utc_now_iso(),
        "source_mode": str(source_mode or ""),
        "window_count": int(window_count),
        "record_count": int(len(usable_records)),
        "process_novelty_threshold": float(process_novelty_threshold),
        "process_novelty_p95": float(process_novelty_threshold),
        "process_novelty_count": int(len(novelty_samples)),
        "process_novelty_min": float(novelty_samples[0]) if novelty_samples else 0.0,
        "process_novelty_max": float(novelty_samples[-1]) if novelty_samples else 0.0,
        "process_novelty_mean": float(sum(novelty_samples) / float(len(novelty_samples))) if novelty_samples else 0.0,
        "window_bbk_score_p95": float(_percentile(bbk_scores, 0.95) or 0.0),
        "window_bbk_score_mean": float(sum(bbk_scores) / float(len(bbk_scores))) if bbk_scores else 0.0,
        "window_bbk_score_max": float(bbk_scores[-1]) if bbk_scores else 0.0,
        "candidate_process_count_p95": float(_percentile(candidate_counts, 0.95) or 0.0),
        "candidate_process_count_mean": float(sum(candidate_counts) / float(len(candidate_counts))) if candidate_counts else 0.0,
    }


@dataclass
class RunningStats:
    """用在线方式累计均值/方差，避免保存无限增长的原始 loss 列表。"""

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    min: float | None = None
    max: float | None = None

    def update(self, value: float) -> None:
        x = float(value)
        self.count += 1
        delta = x - self.mean
        self.mean += delta / float(self.count)
        delta2 = x - self.mean
        self.m2 += delta * delta2
        self.min = x if self.min is None else min(self.min, x)
        self.max = x if self.max is None else max(self.max, x)

    def to_dict(self) -> dict[str, Any]:
        if self.count <= 0:
            return {"count": 0, "mean": None, "std": None, "min": None, "max": None}
        return {
            "count": int(self.count),
            "mean": float(self.mean),
            "std": float(math.sqrt(self.m2 / float(self.count))),
            "min": float(self.min) if self.min is not None else None,
            "max": float(self.max) if self.max is not None else None,
        }


def build_tik() -> None:
    KB_PATHS.ensure_layout()

    from src.knowledge.threat_intel_kb_builder import ThreatIntelligenceKnowledgeBuilder

    builder = ThreatIntelligenceKnowledgeBuilder(db_path=KB_PATHS.tik_db_dir)
    builder.build()


def build_bbk(
    log_file: str = "",
    *,
    logs_dir: str = "",
    sampled_train_windows: str = "",
    full_window_index: str = "",
    persist_windows_dir: str = "",
    window_seconds: int = DEFAULT_BBK_TRAIN_WINDOW_SECONDS,
    time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS,
) -> None:
    """构建 BBK，并以 manifest 为桥梁执行两阶段 GMAE 训练。"""

    KB_PATHS.ensure_layout()

    sampled_index_path = _resolve_sampled_train_windows_path(
        log_file=log_file,
        logs_dir=logs_dir,
        sampled_train_windows=sampled_train_windows,
    )
    if sampled_index_path:
        _build_bbk_from_sampled_train_windows(
            sampled_train_windows_path=sampled_index_path,
            full_window_index_path=str(full_window_index or ""),
            logs_dir=str(logs_dir or ""),
            persist_windows_dir=str(persist_windows_dir or ""),
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
        )
        return

    from src.knowledge.benign_behavior_kb import BenignBehaviorKnowledgeBase
    from src.process.log_parser import TraceeLogParser
    from src.process.streaming_reduction import iter_reduced_edges
    from src.process.window_io import dump_window_graph

    sources, source_mode = _resolve_bbk_sources(log_file=log_file, logs_dir=logs_dir)
    parser = TraceeLogParser()

    windows_dir, persist_windows, windows_dir_preexisting = _prepare_staging_dir(persist_windows_dir, cleanup=True)
    manifest_path = os.path.join(windows_dir, GMAE_MANIFEST_FILENAME)
    manifest_records: list[dict[str, Any]] = []
    total_nodes = 0
    total_edges = 0
    window_idx = 0

    store = BenignBehaviorKnowledgeBase(
        db_path=KB_PATHS.bbk_db_path,
        model_path=KB_PATHS.bbk_word2vec_path,
        calibration_path=KB_PATHS.bbk_calibration_path,
        reset=True,
    )

    try:
        print(f"📦 Stage 1/2: streaming benign windows into {windows_dir}")
        for source in sources:
            logs = parser.parse_log_file(str(source["log_file"]))
            source_context = _hydrate_source_runtime_context(source, logs)
            fit_for_bbk = _source_participates_in_bbk_fit(source_context, source_mode=source_mode)
            source_window_idx = 0
            for g, metas in _iter_bbk_windows(
                logs,
                window_seconds=int(window_seconds),
                time_bin_seconds=int(time_bin_seconds),
            ):
                source_window_idx += 1
                window_idx += 1
                window_id = f"window_{window_idx:04d}"
                window_path = os.path.join(windows_dir, f"{window_id}.json")

                dump_window_graph(window_path, g)
                window_start_ns, window_end_ns = _graph_time_range_ns(g)
                resolved_profile = _resolve_window_profile(
                    source_context,
                    window_start_ns=window_start_ns,
                    window_end_ns=window_end_ns,
                    window_sequence=source_window_idx,
                    window_seconds=int(window_seconds),
                )
                record = _build_manifest_record(
                    window_id,
                    window_path,
                    g,
                    source_log_file=str(source["log_file"]),
                    source_run_id=str(source.get("run_id") or ""),
                    source_profile=str(resolved_profile.get("profile_id") or ""),
                    split_role=str(source.get("split_role") or ""),
                )
                manifest_records.append(record)

                if fit_for_bbk:
                    train_graph = _filter_training_graph(g)
                    train_metas = _metas_from_graph(train_graph)
                    store.update_from_edges(iter_reduced_edges(train_graph), train_metas)
                    store.update_word2vec_from_metas(train_metas)

                total_nodes += int(record["node_count"])
                total_edges += int(record["edge_count"])
        calibration_payload = _build_bbk_calibration_payload(
            store=store,
            records=[
                record
                for record in manifest_records
                if str(record.get("split_role") or "").strip().lower() in {"calibration", "train"}
            ],
            fallback_records=manifest_records,
            source_mode=source_mode,
        )
        store.save_calibration(calibration_payload)
    finally:
        store.close()

    manifest_payload = _write_gmae_manifest(
        manifest_path=manifest_path,
        log_file=log_file,
        logs_dir=logs_dir,
        source_mode=source_mode,
        sources=sources,
        windows_dir=windows_dir,
        persist_windows=persist_windows,
        window_seconds=int(window_seconds),
        reduction_config=_bbk_reduction_config_payload(
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
        ),
        records=manifest_records,
    )

    print(
        f"🧠 Stage 2/2: offline GMAE training on {len(manifest_records)} windows "
        f"(manifest={manifest_path})"
    )
    runtime = _init_gmae_runtime()
    training_result = _train_gmae_from_manifest(runtime, manifest_path)

    staging_cleaned = False
    if not persist_windows and not bool(training_result.get("rejected_reason")):
        try:
            shutil.rmtree(windows_dir)
            staging_cleaned = True
        except OSError:
            staging_cleaned = False

    _save_gmae_runtime(
        runtime=runtime,
        manifest_payload=manifest_payload,
        training_result=training_result,
        context={
            "log_file": os.path.abspath(log_file) if str(log_file or "").strip() else "",
            "logs_dir": os.path.abspath(logs_dir) if str(logs_dir or "").strip() else "",
            "source_mode": source_mode,
            "windows_dir": windows_dir,
            "persist_windows": bool(persist_windows),
            "windows_dir_preexisting": bool(windows_dir_preexisting),
            "staging_cleaned": bool(staging_cleaned),
            "window_nodes_sum": int(total_nodes),
            "window_edges_sum": int(total_edges),
            "sampled_train_windows_source": "",
            "full_window_index_source": "",
        },
    )

    if training_result.get("rejected_reason"):
        raise RuntimeError(str(training_result["rejected_reason"]))

    print(
        f"\n✅ BBK 基线库更新完成：window_count={len(manifest_records)}, "
        f"window_nodes_sum={total_nodes}, window_edges_sum={total_edges}"
    )


def build_gmae_transfer(
    *,
    e3_dir: str,
    groundtruth: str,
    local_corpus: str,
    output_dir: str = "",
    e3_limit_windows: int = 0,
    local_limit_windows: int = 0,
    e3_epochs: int = 3,
    local_epochs: int = 3,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    stride_seconds: int = DEFAULT_DETECT_STRIDE_SECONDS,
    time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS,
    dry_run: bool = False,
) -> dict[str, Any]:
    KB_PATHS.ensure_layout()

    e3_root = Path(str(e3_dir or "")).expanduser().resolve()
    if not e3_root.exists() or not e3_root.is_dir():
        raise FileNotFoundError(f"E3 directory not found: {e3_root}")
    groundtruth_path = Path(str(groundtruth or "")).expanduser().resolve()
    if not groundtruth_path.exists() or not groundtruth_path.is_file():
        raise FileNotFoundError(f"E3 groundtruth file not found: {groundtruth_path}")
    local_root = Path(str(local_corpus or "")).expanduser().resolve()
    if not local_root.exists() or not local_root.is_dir():
        raise FileNotFoundError(f"local corpus directory not found: {local_root}")

    transfer_dir, _persist_windows, _preexisting = _prepare_staging_dir(output_dir, cleanup=True)
    transfer_root = Path(transfer_dir)
    e3_windows_dir = transfer_root / "e3_windows"
    local_windows_dir = transfer_root / "local_windows"
    e3_manifest_path = transfer_root / "gmae_e3_manifest.json"
    local_manifest_path = transfer_root / "gmae_local_transfer_manifest.json"

    local_reduction_config = _infer_transfer_local_reduction_config(
        local_root,
        fallback_window_seconds=int(window_seconds),
        fallback_time_bin_seconds=int(time_bin_seconds),
    )
    local_window_seconds = int(local_reduction_config.get("window_seconds") or int(window_seconds))
    local_time_bin_seconds = int(local_reduction_config.get("time_bin_seconds") or int(time_bin_seconds))

    e3_reduction_config = {
        "window_seconds": int(window_seconds),
        "stride_seconds": int(stride_seconds),
        "time_bin_seconds": int(time_bin_seconds),
        "edge_key_mode": "event_time_bin",
    }

    from src.process.e3_cdm_adapter import build_e3_windows
    from src.process.window_io import dump_window_graph

    e3_results, e3_summary = build_e3_windows(
        e3_dir=str(e3_root),
        groundtruth_path=str(groundtruth_path),
        window_seconds=int(window_seconds),
        stride_seconds=int(stride_seconds),
        time_bin_seconds=int(time_bin_seconds),
        max_windows=int(e3_limit_windows),
        emit_partial=False,
    )

    e3_windows_dir.mkdir(parents=True, exist_ok=True)
    e3_records: list[dict[str, Any]] = []
    for idx, item in enumerate(e3_results, start=1):
        graph = _filter_training_graph(item.graph)
        window_id = f"e3_window_{idx:06d}"
        output_path = e3_windows_dir / f"{window_id}.json"
        dump_window_graph(str(output_path), graph)
        e3_records.append(
            _build_manifest_record(
                window_id,
                str(output_path),
                graph,
                source_log_file=str(e3_root),
                source_run_id=item.source_run_id,
                source_profile=item.source_profile,
                split_role=item.split_role,
            )
        )

    e3_manifest = _write_gmae_manifest(
        manifest_path=str(e3_manifest_path),
        log_file="",
        logs_dir=str(e3_root),
        source_mode="e3_cadets_pretrain",
        sources=_e3_manifest_sources(e3_root),
        windows_dir=str(e3_windows_dir),
        persist_windows=True,
        window_seconds=int(window_seconds),
        reduction_config=e3_reduction_config,
        records=e3_records,
    )
    e3_manifest["summary"]["excluded_attack_window_count"] = int(e3_summary.get("excluded_attack_window_count") or 0)
    write_json(str(e3_manifest_path), e3_manifest)

    local_records = _build_transfer_local_records(
        local_root=local_root,
        materialized_dir=local_windows_dir,
        window_seconds=int(local_window_seconds),
        time_bin_seconds=int(local_time_bin_seconds),
        local_limit_windows=int(local_limit_windows),
    )
    local_manifest = _write_gmae_manifest(
        manifest_path=str(local_manifest_path),
        log_file="",
        logs_dir=str(local_root),
        source_mode="tracee_local_transfer",
        sources=_sources_from_manifest_records(local_records),
        windows_dir=str(local_windows_dir),
        persist_windows=True,
        window_seconds=int(local_window_seconds),
        reduction_config=dict(local_reduction_config),
        records=local_records,
    )

    plan = {
        "mode": TRANSFER_GMAE_CONTEXT_TAG,
        "dry_run": bool(dry_run),
        "e3_dir": str(e3_root),
        "groundtruth": str(groundtruth_path),
        "local_corpus": str(local_root),
        "output_dir": str(transfer_root),
        "e3_manifest_path": str(e3_manifest_path),
        "local_manifest_path": str(local_manifest_path),
        "e3_window_count": int(len(e3_records)),
        "local_window_count": int(len(local_records)),
        "e3_reduction_config": dict(e3_reduction_config),
        "local_reduction_config": dict(local_reduction_config),
        "e3_summary": e3_summary,
        "local_summary": local_manifest.get("summary") or {},
        "pretrained_checkpoint_path": KB_PATHS.gmae_e3_pretrained_path,
        "pretrained_meta_path": KB_PATHS.gmae_e3_pretrained_meta_path,
        "final_baseline_path": KB_PATHS.gmae_baseline_path,
        "final_meta_path": KB_PATHS.gmae_baseline_meta_path,
        "process_error_calibration_path": KB_PATHS.process_error_calibration_path,
    }
    if dry_run:
        return plan

    runtime = _init_gmae_runtime()
    runtime["config"] = dict(runtime.get("config") or {})
    runtime["config"]["feature_profile"] = "transfer_v1"

    runtime["epochs"] = max(1, int(e3_epochs))
    pretrain_result = _train_gmae_from_manifest(runtime, str(e3_manifest_path))
    _save_named_gmae_runtime(
        runtime=runtime,
        manifest_payload=e3_manifest,
        training_result=pretrain_result,
        checkpoint_path=KB_PATHS.gmae_e3_pretrained_path,
        meta_path=KB_PATHS.gmae_e3_pretrained_meta_path,
        calibration_path=KB_PATHS.gmae_calibration_path,
        process_error_calibration_path=KB_PATHS.process_error_calibration_path,
        context={
            "stage": "e3_pretrain",
            "mode": TRANSFER_GMAE_CONTEXT_TAG,
            "e3_dir": str(e3_root),
            "groundtruth": str(groundtruth_path),
        },
    )

    state_dict = pretrain_result.get("state_dict")
    if isinstance(state_dict, dict) and state_dict:
        runtime["model"].load_state_dict(state_dict, strict=False)
    runtime["epochs"] = max(1, int(local_epochs))
    finetune_result = _train_gmae_from_manifest(runtime, str(local_manifest_path))
    _save_named_gmae_runtime(
        runtime=runtime,
        manifest_payload=local_manifest,
        training_result=finetune_result,
        checkpoint_path=KB_PATHS.gmae_baseline_path,
        meta_path=KB_PATHS.gmae_baseline_meta_path,
        calibration_path=KB_PATHS.gmae_calibration_path,
        process_error_calibration_path=KB_PATHS.process_error_calibration_path,
        context={
            "stage": "local_adapt",
            "mode": TRANSFER_GMAE_CONTEXT_TAG,
            "e3_pretrained_checkpoint": KB_PATHS.gmae_e3_pretrained_path,
            "local_corpus": str(local_root),
        },
    )

    plan["pretrain_result"] = {
        "saved_baseline": bool(pretrain_result.get("saved_baseline")),
        "best_epoch": pretrain_result.get("best_epoch"),
        "best_metric_value": pretrain_result.get("best_metric_value"),
        "rejected_reason": pretrain_result.get("rejected_reason"),
    }
    plan["finetune_result"] = {
        "saved_baseline": bool(finetune_result.get("saved_baseline")),
        "best_epoch": finetune_result.get("best_epoch"),
        "best_metric_value": finetune_result.get("best_metric_value"),
        "rejected_reason": finetune_result.get("rejected_reason"),
    }
    return plan


def build_ark() -> None:
    KB_PATHS.ensure_layout()

    import networkx as nx

    from src.knowledge.logic_graph_builder import LogicGraphBuilder
    from src.knowledge.stix_loader import MitreStixLoader

    techniques = MitreStixLoader().load_data()
    if not techniques:
        raise RuntimeError("无法加载 STIX 数据")

    graph = LogicGraphBuilder().build_graph(techniques)
    payload = nx.node_link_data(graph, edges="links")
    write_json(KB_PATHS.ark_graph_path, payload)
    print(f"✅ ARK 逻辑图已保存: {KB_PATHS.ark_graph_path}")


def _resolve_sampled_train_windows_path(
    *,
    log_file: str,
    logs_dir: str,
    sampled_train_windows: str,
) -> str:
    explicit = str(sampled_train_windows or "").strip()
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"sampled_train_windows.jsonl not found: {path}")
        return str(path)

    log_file_value = str(log_file or "").strip()
    if log_file_value:
        path = Path(log_file_value).expanduser()
        if path.name == "sampled_train_windows.jsonl":
            resolved = path.resolve()
            if not resolved.exists() or not resolved.is_file():
                raise FileNotFoundError(f"sampled_train_windows.jsonl not found: {resolved}")
            return str(resolved)

    logs_dir_value = str(logs_dir or "").strip()
    if logs_dir_value:
        logs_dir_path = Path(logs_dir_value).expanduser().resolve()
        candidate = logs_dir_path / "sampled_train_windows.jsonl"
        if candidate.exists() and candidate.is_file():
            return str(candidate)
        parent_candidate = logs_dir_path.parent / "sampled_train_windows.jsonl"
        if logs_dir_path.name in {"train", "calibration", "holdout"} and parent_candidate.exists() and parent_candidate.is_file():
            return str(parent_candidate)

    return ""


def _build_bbk_from_sampled_train_windows(
    *,
    sampled_train_windows_path: str,
    full_window_index_path: str,
    logs_dir: str,
    persist_windows_dir: str,
    window_seconds: int,
    time_bin_seconds: int,
) -> None:
    """从 benign manifest v3 的采样清单训练 BBK/GMAE。

    训练窗口只来自 sampled_train_windows.jsonl；full_window_index.jsonl 中的
    calibration/holdout 只进入校准/评估元数据，不参与 BBK 频次统计或 GMAE 参数更新。
    """

    from src.knowledge.benign_behavior_kb import BenignBehaviorKnowledgeBase
    from src.process.streaming_reduction import iter_reduced_edges
    from src.process.window_io import load_window_graph

    sampled_path = Path(sampled_train_windows_path).expanduser().resolve()
    corpus_dir = sampled_path.parent
    logs_dir_value = str(logs_dir or "").strip()
    if logs_dir_value:
        logs_root = Path(logs_dir_value).expanduser().resolve()
        if logs_root.exists() and logs_root.is_dir() and logs_root == sampled_path.parent:
            corpus_dir = logs_root

    full_index_path = _resolve_full_window_index_path(
        corpus_dir=corpus_dir,
        explicit_path=full_window_index_path,
    )
    activity_cache: dict[str, list[dict[str, Any]]] = {}
    trace_window_cache: dict[str, list[tuple[Any, dict[str, Any]]]] = {}
    warnings: list[str] = []

    manifest_dir, persist_manifest, manifest_dir_preexisting = _prepare_staging_dir(persist_windows_dir)
    manifest_path = os.path.join(manifest_dir, GMAE_MANIFEST_FILENAME)
    materialized_windows_dir = os.path.join(manifest_dir, "materialized_windows")
    os.makedirs(materialized_windows_dir, exist_ok=True)

    sampled_rows = _read_jsonl_objects(sampled_path)
    train_records, train_skips = _records_from_window_index_rows(
        sampled_rows,
        corpus_dir=corpus_dir,
        split_filter={"train"},
        require_sampled_train=True,
        activity_cache=activity_cache,
        trace_window_cache=trace_window_cache,
        materialized_windows_dir=materialized_windows_dir,
        window_seconds=int(window_seconds),
        time_bin_seconds=int(time_bin_seconds),
        warnings=warnings,
    )

    calibration_records: list[dict[str, Any]] = []
    holdout_records: list[dict[str, Any]] = []
    if full_index_path:
        full_rows = _read_jsonl_objects(Path(full_index_path))
        eval_records, _eval_skips = _records_from_window_index_rows(
            full_rows,
            corpus_dir=corpus_dir,
            split_filter={"calibration", "holdout"},
            require_sampled_train=False,
            activity_cache=activity_cache,
            trace_window_cache=trace_window_cache,
            materialized_windows_dir=materialized_windows_dir,
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
            warnings=warnings,
        )
        calibration_records = [
            record for record in eval_records if _normalize_split_role(record.get("split_role") or "") == "calibration"
        ]
        holdout_records = [
            record for record in eval_records if _normalize_split_role(record.get("split_role") or "") == "holdout"
        ]
    else:
        warnings.append(f"full_window_index_missing:{corpus_dir / 'full_window_index.jsonl'}")

    if not train_records:
        raise RuntimeError(
            "sampled_train_windows produced no trainable non-empty train windows; "
            f"path={sampled_path}"
        )

    records = [*train_records, *calibration_records, *holdout_records]
    total_nodes = int(sum(int(record.get("node_count") or 0) for record in records))
    total_edges = int(sum(int(record.get("edge_count") or 0) for record in records))

    store = BenignBehaviorKnowledgeBase(
        db_path=KB_PATHS.bbk_db_path,
        model_path=KB_PATHS.bbk_word2vec_path,
        calibration_path=KB_PATHS.bbk_calibration_path,
        reset=True,
    )
    try:
        print(f"📦 Stage 1/2: fitting BBK from sampled train windows ({sampled_path})")
        for record in train_records:
            graph = load_window_graph(str(record["path"]))
            graph = _filter_training_graph(graph)
            metas = _metas_from_graph(graph)
            store.update_from_edges(iter_reduced_edges(graph), metas)
            store.update_word2vec_from_metas(metas)
        calibration_payload = _build_bbk_calibration_payload(
            store=store,
            records=calibration_records,
            fallback_records=train_records,
            source_mode="sampled_train_windows",
        )
        store.save_calibration(calibration_payload)
    finally:
        store.close()

    sources = _sources_from_manifest_records(records)
    manifest_payload = _write_gmae_manifest(
        manifest_path=manifest_path,
        log_file="",
        logs_dir=str(corpus_dir),
        source_mode="sampled_train_windows",
        sources=sources,
        windows_dir=manifest_dir,
        persist_windows=persist_manifest,
        window_seconds=int(window_seconds),
        reduction_config=_bbk_reduction_config_payload(
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
        ),
        records=records,
    )

    print(
        f"🧠 Stage 2/2: offline GMAE training on sampled train windows "
        f"(train={len(train_records)}, manifest={manifest_path})"
    )
    runtime = _init_gmae_runtime()
    training_result = _train_gmae_from_manifest(runtime, manifest_path)

    staging_cleaned = False
    if not persist_manifest and not bool(training_result.get("rejected_reason")):
        try:
            shutil.rmtree(manifest_dir)
            staging_cleaned = True
        except OSError:
            staging_cleaned = False

    _save_gmae_runtime(
        runtime=runtime,
        manifest_payload=manifest_payload,
        training_result=training_result,
        context={
            "log_file": "",
            "logs_dir": str(corpus_dir),
            "source_mode": "sampled_train_windows",
            "windows_dir": manifest_dir,
            "persist_windows": bool(persist_manifest),
            "windows_dir_preexisting": bool(manifest_dir_preexisting),
            "staging_cleaned": bool(staging_cleaned),
            "window_nodes_sum": int(total_nodes),
            "window_edges_sum": int(total_edges),
            "sampled_train_windows_source": str(sampled_path),
            "full_window_index_source": str(full_index_path or ""),
        },
    )

    if training_result.get("rejected_reason"):
        raise RuntimeError(str(training_result["rejected_reason"]))

    print(
        "\n✅ BBK/GMAE sampled-train pipeline complete: "
        f"train={len(train_records)}, skipped_train={dict(train_skips)}, "
        f"warnings={len(set(warnings))}"
    )


def _resolve_full_window_index_path(corpus_dir: Path, explicit_path: str) -> str:
    value = str(explicit_path or "").strip()
    if value:
        path = Path(value).expanduser().resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"full_window_index.jsonl not found: {path}")
        return str(path)

    candidate = corpus_dir / "full_window_index.jsonl"
    if candidate.exists() and candidate.is_file():
        return str(candidate.resolve())
    return ""


def _read_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        for line_no, line in enumerate(fp, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(payload)
    return rows


def _records_from_window_index_rows(
    rows: list[dict[str, Any]],
    *,
    corpus_dir: Path,
    split_filter: set[str],
    require_sampled_train: bool,
    activity_cache: dict[str, list[dict[str, Any]]],
    trace_window_cache: dict[str, list[tuple[Any, dict[str, Any]]]],
    materialized_windows_dir: str,
    window_seconds: int,
    time_bin_seconds: int,
    warnings: list[str],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    from src.process.window_io import load_window_graph

    records: list[dict[str, Any]] = []
    skip_counts = {
        "wrong_split": 0,
        "empty": 0,
        "missing_graph_path": 0,
        "missing_graph_file": 0,
        "load_failed": 0,
    }
    seen_train_keys: set[tuple[str, str]] = set()

    for idx, raw_row in enumerate(rows, start=1):
        row = dict(raw_row)
        activity_row = _load_activity_row_for_window(row, corpus_dir, activity_cache, warnings)
        merged = dict(activity_row)
        merged.update(row)

        split = str(merged.get("split") or "").strip().lower()
        if split not in split_filter:
            skip_counts["wrong_split"] += 1
            continue
        if require_sampled_train and split != "train":
            skip_counts["wrong_split"] += 1
            continue

        activity_level = str(merged.get("activity_level") or "").strip().lower()
        if not activity_level or activity_level == "empty":
            skip_counts["empty"] += 1
            continue

        graph = None
        graph_path = None
        graph_path_value = str(merged.get("window_graph_path") or "").strip()
        if graph_path_value:
            graph_path = _resolve_index_path(graph_path_value, corpus_dir)
            if graph_path is not None and graph_path.exists() and graph_path.is_file():
                try:
                    graph = load_window_graph(str(graph_path))
                except Exception as exc:
                    skip_counts["load_failed"] += 1
                    warnings.append(f"window_graph_load_failed:{split}:{graph_path_value}:{type(exc).__name__}")
                    continue

        if graph is None:
            materialized = _materialize_index_window_graph(
                merged,
                corpus_dir=corpus_dir,
                materialized_windows_dir=materialized_windows_dir,
                window_seconds=int(window_seconds),
                time_bin_seconds=int(time_bin_seconds),
                trace_window_cache=trace_window_cache,
                warnings=warnings,
            )
            if materialized is not None:
                graph_path, graph = materialized

        if graph is None or graph_path is None:
            if graph_path_value:
                skip_counts["missing_graph_file"] += 1
                warnings.append(f"missing_window_graph_file:{split}:{graph_path_value}")
            else:
                skip_counts["missing_graph_path"] += 1
                warnings.append(f"missing_window_graph_path:{split}:{merged.get('run_id')}:{merged.get('window_id') or idx}")
            continue

        node_count = int(graph.number_of_nodes())
        edge_count = int(graph.number_of_edges())
        if node_count <= 0:
            skip_counts["empty"] += 1
            continue

        run_id = str(merged.get("run_id") or graph_path.parent.parent.name or "").strip()
        window_id = str(merged.get("window_id") or graph_path.stem).strip() or graph_path.stem
        if require_sampled_train:
            key = (run_id, window_id)
            if key in seen_train_keys:
                continue
            seen_train_keys.add(key)

        process_node_count = sum(1 for node_id in graph.nodes() if str(node_id).startswith("proc:"))
        records.append(
            {
                "window_id": window_id,
                "path": str(graph_path.resolve()),
                "node_count": int(node_count),
                "edge_count": int(edge_count),
                "process_node_count": int(process_node_count),
                "trainable": bool(node_count > 0),
                "scorable": bool(node_count > 0 and process_node_count > 0),
                "source_log_file": _resolved_optional_index_path(merged.get("trace_log_path"), corpus_dir),
                "source_run_id": run_id,
                "source_profile": _row_source_profile(merged),
                "split_role": _normalize_split_role(split) or split,
            }
        )

    return records, skip_counts


def _materialize_index_window_graph(
    row: dict[str, Any],
    *,
    corpus_dir: Path,
    materialized_windows_dir: str,
    window_seconds: int,
    time_bin_seconds: int,
    trace_window_cache: dict[str, list[tuple[Any, dict[str, Any]]]],
    warnings: list[str],
) -> tuple[Path, Any] | None:
    trace_path = _resolve_index_path(str(row.get("trace_log_path") or ""), corpus_dir)
    if trace_path is None or not trace_path.exists() or not trace_path.is_file():
        warnings.append(f"trace_log_unavailable_for_window:{row.get('split')}:{row.get('run_id')}:{row.get('window_id')}")
        return None

    sequence = _safe_int(row.get("window_sequence"), 0)
    if sequence <= 0:
        sequence = _window_sequence_from_id(row.get("window_id"))
    if sequence <= 0:
        warnings.append(f"window_sequence_unavailable:{row.get('split')}:{row.get('run_id')}:{row.get('window_id')}")
        return None

    cache_key = f"{trace_path.resolve()}|window={int(window_seconds)}|bin={int(time_bin_seconds)}"
    if cache_key not in trace_window_cache:
        trace_window_cache[cache_key] = _build_windows_from_trace_log(
            trace_path,
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
            warnings=warnings,
        )

    windows = trace_window_cache.get(cache_key) or []
    if sequence > len(windows):
        warnings.append(
            "trace_window_sequence_unavailable:"
            f"{row.get('split')}:{row.get('run_id')}:{row.get('window_id')}:"
            f"sequence={sequence}:available={len(windows)}"
        )
        return None

    graph, _metas = windows[sequence - 1]
    if int(graph.number_of_nodes()) <= 0:
        return None

    from src.process.window_io import dump_window_graph

    run_id = _safe_path_fragment(row.get("run_id") or trace_path.parent.name or "run")
    window_id = _safe_path_fragment(row.get("window_id") or f"w{sequence:06d}")
    output_dir = Path(materialized_windows_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{run_id}_{window_id}.json"
    dump_window_graph(str(output_path), graph)
    return output_path.resolve(), graph


def _build_windows_from_trace_log(
    trace_path: Path,
    *,
    window_seconds: int,
    time_bin_seconds: int,
    warnings: list[str],
) -> list[tuple[Any, dict[str, Any]]]:
    try:
        from src.process.log_parser import TraceeLogParser

        logs = TraceeLogParser().parse_log_file(str(trace_path))
        if not logs:
            warnings.append(f"trace_log_parsed_no_events:{trace_path}")
            return []
        return list(
            _iter_bbk_windows(
                logs,
                window_seconds=int(window_seconds),
                time_bin_seconds=int(time_bin_seconds),
            )
        )
    except Exception as exc:
        warnings.append(f"trace_log_window_materialization_failed:{trace_path}:{type(exc).__name__}")
        return []


def _window_sequence_from_id(value: Any) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    match = re.search(r"(?:^|[_-])w(?:indow)?[_-]?0*([0-9]+)$", text, flags=re.IGNORECASE)
    if not match:
        match = re.search(r"0*([0-9]+)$", text)
    if not match:
        return 0
    return _safe_int(match.group(1), 0)


def _safe_path_fragment(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._") or "unknown"


def _load_activity_row_for_window(
    row: dict[str, Any],
    corpus_dir: Path,
    activity_cache: dict[str, list[dict[str, Any]]],
    warnings: list[str],
) -> dict[str, Any]:
    activity_path_value = str(row.get("window_activity_path") or "").strip()
    if not activity_path_value:
        return {}

    activity_path = _resolve_index_path(activity_path_value, corpus_dir)
    if activity_path is None or not activity_path.exists() or not activity_path.is_file():
        warnings.append(f"missing_window_activity_file:{activity_path_value}")
        return {}

    key = str(activity_path.resolve())
    if key not in activity_cache:
        try:
            activity_cache[key] = _read_jsonl_objects(activity_path)
        except Exception as exc:
            warnings.append(f"window_activity_parse_failed:{activity_path_value}:{type(exc).__name__}")
            activity_cache[key] = []

    rows = activity_cache.get(key) or []
    window_id = str(row.get("window_id") or "").strip()
    sequence = _safe_int(row.get("window_sequence"), 0)
    run_id = str(row.get("run_id") or "").strip()
    for activity_row in rows:
        if window_id and str(activity_row.get("window_id") or "").strip() == window_id:
            return dict(activity_row)
    if sequence > 0 and sequence <= len(rows):
        candidate = dict(rows[sequence - 1])
        if not run_id or str(candidate.get("run_id") or run_id).strip() == run_id:
            return candidate
    return {}


def _resolve_index_path(value: str, corpus_dir: Path) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    raw = Path(text).expanduser()
    candidates: list[Path]
    if raw.is_absolute():
        candidates = [raw]
    else:
        candidates = [corpus_dir / raw, Path.cwd() / raw, raw]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return candidates[0].resolve() if candidates else None


def _resolved_optional_index_path(value: Any, corpus_dir: Path) -> str:
    path = _resolve_index_path(str(value or ""), corpus_dir)
    if path is None:
        return ""
    return str(path)


def _row_source_profile(row: dict[str, Any]) -> str:
    for key in ("source_profile", "dominant_profile", "primary_profile"):
        value = str(row.get(key) or "").strip()
        if value:
            return value
    profiles = row.get("dominant_profiles")
    if isinstance(profiles, list):
        for value in profiles:
            text = str(value or "").strip()
            if text:
                return text
    return ""


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return int(default)


def _prepare_staging_dir(persist_dir: str, *, cleanup: bool = False) -> tuple[str, bool, bool]:
    requested_dir = str(persist_dir or "").strip()
    if requested_dir:
        abs_dir = os.path.abspath(requested_dir)
        preexisting = os.path.isdir(abs_dir)
        os.makedirs(abs_dir, exist_ok=True)
        if cleanup:
            _cleanup_generated_window_files(abs_dir)
        return abs_dir, True, preexisting
    processed_dir = os.path.abspath(os.path.join("data", "processed"))
    os.makedirs(processed_dir, exist_ok=True)
    staging_dir = tempfile.mkdtemp(prefix=GMAE_STAGING_PREFIX, dir=processed_dir)
    return staging_dir, False, False


def _sources_from_manifest_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        run_id = str(record.get("source_run_id") or "").strip()
        split_role = _normalize_split_role(record.get("split_role") or "") or "train"
        if not run_id:
            continue
        key = (split_role, run_id)
        if key not in by_key:
            by_key[key] = {
                "log_file": str(record.get("source_log_file") or ""),
                "run_id": run_id,
                "split_role": split_role,
                "source_profile": str(record.get("source_profile") or ""),
                "phases": [],
                "training_pool": split_role == "train",
                "bootstrap_only": False,
            }
    return [by_key[key] for key in sorted(by_key)]


def _resolve_bbk_sources(log_file: str, logs_dir: str) -> tuple[list[dict[str, Any]], str]:
    log_file_value = str(log_file or "").strip()
    logs_dir_value = str(logs_dir or "").strip()
    if bool(log_file_value) == bool(logs_dir_value):
        raise ValueError("build_bbk requires exactly one of log_file or --logs-dir")

    if logs_dir_value:
        return _resolve_bbk_logs_dir_sources(logs_dir_value), "logs_dir"

    source = _build_single_log_source(log_file_value)
    return [source], "single_log"


def _build_single_log_source(log_file: str) -> dict[str, Any]:
    path = Path(log_file).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"benign log file not found: {path}")

    return {
        "log_file": str(path),
        "run_id": path.stem or "single_log",
        "split_role": "train",
        "source_profile": "",
        "phases": [],
        "training_pool": False,
        "bootstrap_only": True,
    }


def _resolve_bbk_logs_dir_sources(logs_dir: str) -> list[dict[str, Any]]:
    root = Path(logs_dir).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"benign corpus directory not found: {root}")

    raw_sources: list[dict[str, Any]] = []
    for run_dir in _iter_bbk_run_dirs(root):
        trace_path = _discover_trace_log(run_dir)
        if trace_path is None:
            continue

        run_meta_path = run_dir / "run_meta.json"
        run_meta = read_json(str(run_meta_path)) if run_meta_path.exists() else {}
        if not isinstance(run_meta, dict):
            run_meta = {}

        training_pool = bool(run_meta.get("training_pool", True))
        if not training_pool:
            continue

        run_id = str(run_meta.get("run_id") or run_dir.name).strip() or run_dir.name
        raw_sources.append(
            {
                "log_file": str(trace_path.resolve()),
                "run_id": run_id,
                "split_role": _normalize_split_role(run_meta.get("split_role") or ""),
                "source_profile": str(run_meta.get("source_profile") or run_meta.get("primary_profile") or "").strip(),
                "phases": _normalize_source_phases(run_meta.get("phases") or []),
                "training_pool": True,
                "bootstrap_only": bool(run_meta.get("bootstrap_only", False)),
            }
        )

    if not raw_sources:
        raise ValueError(f"no benign corpus runs discovered under {root}")

    sources: list[dict[str, Any]] = []
    total = len(raw_sources)
    for idx, source in enumerate(raw_sources):
        enriched = dict(source)
        if not enriched.get("split_role"):
            enriched["split_role"] = _default_split_role_for_run(
                run_id=str(enriched.get("run_id") or ""),
                order_index=idx,
                total_runs=total,
            )
        sources.append(enriched)
    return sources


def _e3_manifest_sources(root: Path) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if not path.is_file():
            continue
        if path.name == "cadets.txt":
            continue
        if not path.name.endswith(".json") and ".json." not in path.name:
            continue
        sources.append(
            {
                "log_file": str(path.resolve()),
                "run_id": path.name,
                "split_role": "train",
                "source_profile": "cadets_e3_benign_filtered",
                "training_pool": True,
                "bootstrap_only": False,
                "phases": [],
            }
        )
    return sources


def _infer_transfer_local_reduction_config(
    local_root: Path,
    *,
    fallback_window_seconds: int,
    fallback_time_bin_seconds: int,
) -> dict[str, Any]:
    for split_role in ("train", "calibration", "holdout"):
        split_dir = local_root / split_role
        if not split_dir.exists() or not split_dir.is_dir():
            continue
        for run_dir in sorted([item for item in split_dir.iterdir() if item.is_dir()], key=lambda item: item.name):
            windows_dir = run_dir / "windows"
            if not windows_dir.exists() or not windows_dir.is_dir():
                continue
            for path in sorted(windows_dir.glob("window_*.json")):
                try:
                    payload = read_json(str(path))
                except Exception:
                    continue
                if not isinstance(payload, dict):
                    continue
                metadata = dict(payload.get("metadata") or {})
                reduction_config = dict(metadata.get("sliding_window_config") or {})
                reduction_config.update(
                    {
                        key: value
                        for key, value in dict(metadata.get("reduction_config") or {}).items()
                        if value not in (None, "")
                    }
                )
                if not reduction_config:
                    continue
                return {
                    "window_seconds": _safe_int(
                        reduction_config.get("window_seconds"),
                        int(fallback_window_seconds),
                    ),
                    "stride_seconds": _safe_int(
                        reduction_config.get("stride_seconds"),
                        int(fallback_window_seconds),
                    ),
                    "time_bin_seconds": _safe_int(
                        reduction_config.get("time_bin_seconds"),
                        int(fallback_time_bin_seconds),
                    ),
                    "edge_key_mode": str(reduction_config.get("edge_key_mode") or "event_time_bin"),
                }
    return {
        "window_seconds": int(fallback_window_seconds),
        "stride_seconds": int(fallback_window_seconds),
        "time_bin_seconds": int(fallback_time_bin_seconds),
        "edge_key_mode": "event_time_bin",
    }


def _build_transfer_local_records(
    *,
    local_root: Path,
    materialized_dir: Path,
    window_seconds: int,
    time_bin_seconds: int,
    local_limit_windows: int,
) -> list[dict[str, Any]]:
    from src.process.window_io import load_window_graph, dump_window_graph

    materialized_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    limit = int(local_limit_windows)

    for split_role in ("train", "calibration", "holdout"):
        split_count = 0
        split_dir = local_root / split_role
        if not split_dir.exists() or not split_dir.is_dir():
            continue
        for run_dir in sorted([item for item in split_dir.iterdir() if item.is_dir()], key=lambda item: item.name):
            run_meta_path = run_dir / "run_meta.json"
            run_meta = read_json(str(run_meta_path)) if run_meta_path.exists() else {}
            if not isinstance(run_meta, dict):
                run_meta = {}
            run_id = str(run_meta.get("run_id") or run_dir.name).strip() or run_dir.name
            source_profile = str(run_meta.get("source_profile") or run_meta.get("primary_profile") or "").strip()
            trace_path = _discover_trace_log(run_dir)
            windows_dir = run_dir / "windows"
            window_paths = sorted(windows_dir.glob("window_*.json")) if windows_dir.exists() and windows_dir.is_dir() else []
            if window_paths:
                graph_items = [
                    (
                        path.stem,
                        str(path),
                        _filter_training_graph(load_window_graph(str(path))),
                    )
                    for path in window_paths
                ]
            else:
                if trace_path is None:
                    continue
                graph_items = []
                for idx, (graph, _metas) in enumerate(
                    _build_windows_from_trace_log(
                        trace_path,
                        window_seconds=int(window_seconds),
                        time_bin_seconds=int(time_bin_seconds),
                        warnings=[],
                    ),
                    start=1,
                ):
                    graph_items.append(
                        (
                            f"window_{idx:04d}",
                            f"{run_id}_window_{idx:04d}.json",
                            _filter_training_graph(graph),
                        )
                    )

            for window_id, source_name, graph in graph_items:
                output_path = materialized_dir / f"{run_id}_{Path(source_name).name}"
                dump_window_graph(str(output_path), graph)
                records.append(
                    _build_manifest_record(
                        window_id,
                        str(output_path),
                        graph,
                        source_log_file=str(trace_path.resolve()) if trace_path is not None else "",
                        source_run_id=run_id,
                        source_profile=source_profile,
                        split_role=split_role,
                    )
                )
                split_count += 1
                if limit > 0 and split_count >= limit:
                    break
            if limit > 0 and split_count >= limit:
                break
    return records


def _iter_bbk_run_dirs(root: Path) -> list[Path]:
    """Return direct run dirs and one-level split/run dirs, without duplicates."""

    candidates: list[Path] = []
    seen: set[Path] = set()
    split_names = {"train", "calibration", "holdout", "smoke"}
    for path in sorted([item for item in root.iterdir() if item.is_dir()], key=lambda item: item.as_posix()):
        children = []
        if path.name in split_names:
            children = sorted([child for child in path.iterdir() if child.is_dir()], key=lambda item: item.as_posix())
        scan = children if children else [path]
        for candidate in scan:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            candidates.append(candidate)
    return candidates


def _discover_trace_log(run_dir: Path) -> Path | None:
    preferred = run_dir / "trace.log"
    if preferred.exists() and preferred.is_file():
        return preferred

    log_candidates = sorted(
        [
            path
            for path in run_dir.iterdir()
            if path.is_file() and path.suffix.lower() in {".log", ".json", ".jsonl"}
        ],
        key=lambda item: item.name,
    )
    if len(log_candidates) == 1:
        return log_candidates[0]
    if not log_candidates:
        return None
    raise ValueError(f"multiple trace log candidates found under {run_dir}: {[item.name for item in log_candidates]}")


def _normalize_source_phases(raw_phases: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    phases: list[dict[str, Any]] = []
    cursor = 0.0
    for idx, raw in enumerate(raw_phases or []):
        if not isinstance(raw, dict):
            continue
        duration_seconds = float(raw.get("duration_seconds") or raw.get("seconds") or 0.0)
        if duration_seconds <= 0:
            continue

        start_offset = raw.get("start_offset_seconds")
        end_offset = raw.get("end_offset_seconds")
        if start_offset is None:
            start_offset = cursor
        start_value = max(float(start_offset), 0.0)
        end_value = float(end_offset) if end_offset is not None else start_value + duration_seconds
        if end_value <= start_value:
            end_value = start_value + duration_seconds

        profile_id = str(raw.get("profile_id") or raw.get("source_profile") or "").strip()
        phase_id = str(raw.get("phase_id") or f"phase_{idx + 1:02d}").strip() or f"phase_{idx + 1:02d}"
        phases.append(
            {
                "phase_id": phase_id,
                "profile_id": profile_id,
                "start_offset_seconds": float(start_value),
                "end_offset_seconds": float(end_value),
                "duration_seconds": float(end_value - start_value),
            }
        )
        cursor = end_value
    return phases


def _default_split_role_for_run(run_id: str, order_index: int, total_runs: int) -> str:
    normalized = str(run_id or "").strip().lower()
    fixed = {
        "run_a": "train",
        "run_b": "train",
        "run_c": "calibration",
        "run_d": "holdout",
    }
    if normalized in fixed:
        return fixed[normalized]

    if total_runs <= 1:
        return "train"
    if total_runs == 2:
        return "train" if order_index == 0 else "calibration"
    if total_runs == 3:
        return "calibration" if order_index == 2 else "train"
    if order_index < total_runs - 2:
        return "train"
    if order_index == total_runs - 2:
        return "calibration"
    return "holdout"


def _normalize_split_role(value: Any) -> str:
    role = str(value or "").strip().lower()
    if not role:
        return ""
    if role not in {"train", "calibration", "holdout"}:
        raise ValueError(f"unsupported benign corpus split_role: {role}")
    return role


def _hydrate_source_runtime_context(source: dict[str, Any], logs: list[dict[str, Any]]) -> dict[str, Any]:
    hydrated = dict(source)
    start_ns = _first_log_timestamp_ns(logs)
    if start_ns is not None:
        hydrated["log_start_ns"] = int(start_ns)
    return hydrated


def _first_log_timestamp_ns(logs: Iterable[dict[str, Any]]) -> int | None:
    for log in logs or []:
        raw = log.get("timestamp")
        try:
            return int(float(raw) * 1_000_000_000)
        except Exception:
            continue
    return None


def _source_participates_in_bbk_fit(source: dict[str, Any], source_mode: str) -> bool:
    if str(source_mode or "") != "logs_dir":
        return True
    return (_normalize_split_role(source.get("split_role") or "") or "train") == "train"


def _graph_time_range_ns(g) -> tuple[int, int]:
    start_ns = None
    end_ns = None
    for _src, _dst, _key, data in g.edges(keys=True, data=True):
        first_ts = data.get("first_ts")
        last_ts = data.get("last_ts")
        try:
            first_value = int(first_ts)
            start_ns = first_value if start_ns is None else min(start_ns, first_value)
        except Exception:
            pass
        try:
            last_value = int(last_ts)
            end_ns = last_value if end_ns is None else max(end_ns, last_value)
        except Exception:
            pass
    if start_ns is None or end_ns is None:
        return 0, 0
    return int(start_ns), int(end_ns)


def _resolve_window_profile(
    source: dict[str, Any],
    *,
    window_start_ns: int,
    window_end_ns: int,
    window_sequence: int,
    window_seconds: int,
) -> dict[str, Any]:
    phases = list(source.get("phases") or [])
    static_profile = str(source.get("source_profile") or "").strip()
    if not phases:
        return {"profile_id": static_profile, "phase_id": ""}

    midpoint_offset_seconds = None
    log_start_ns = source.get("log_start_ns")
    if log_start_ns is not None and (window_start_ns > 0 or window_end_ns > 0):
        midpoint_ns = float(int(window_start_ns or 0) + int(window_end_ns or window_start_ns or 0)) / 2.0
        midpoint_offset_seconds = max((midpoint_ns - float(log_start_ns)) / 1_000_000_000.0, 0.0)

    if midpoint_offset_seconds is not None:
        resolved = _phase_for_offset_seconds(phases, midpoint_offset_seconds)
        if resolved:
            return resolved

    fallback_offset_seconds = max((float(window_sequence) - 0.5) * float(window_seconds), 0.0)
    resolved = _phase_for_offset_seconds(phases, fallback_offset_seconds)
    if resolved:
        return resolved

    tail = phases[-1]
    return {
        "profile_id": str(tail.get("profile_id") or static_profile),
        "phase_id": str(tail.get("phase_id") or ""),
    }


def _phase_for_offset_seconds(phases: list[dict[str, Any]], offset_seconds: float) -> dict[str, Any] | None:
    for phase in phases:
        start_offset = float(phase.get("start_offset_seconds") or 0.0)
        end_offset = float(phase.get("end_offset_seconds") or start_offset)
        if start_offset <= float(offset_seconds) < end_offset:
            return {
                "profile_id": str(phase.get("profile_id") or ""),
                "phase_id": str(phase.get("phase_id") or ""),
            }
    if phases and float(offset_seconds) >= float(phases[-1].get("start_offset_seconds") or 0.0):
        last = phases[-1]
        return {
            "profile_id": str(last.get("profile_id") or ""),
            "phase_id": str(last.get("phase_id") or ""),
        }
    return None


def _init_gmae_runtime() -> dict[str, Any]:
    """初始化一次 build_bbk 运行期共享的 GMAE 上下文。"""

    seed = _env_int("DRSEC_GMAE_SEED", 1337)
    epochs = max(1, _env_int("DRSEC_GMAE_EPOCHS", DEFAULT_GMAE_EPOCHS))
    config: dict[str, Any] = {}
    device = "cpu"

    try:
        import torch

        from src.common.gmae import build_model
        from src.process.dgl_adapter import DEFAULT_EDGE_ATTR_DIM, DEFAULT_NODE_ATTR_DIM

        config = {
            "n_dim": int(os.environ.get("DRSEC_GMAE_NODE_DIM", DEFAULT_NODE_ATTR_DIM)),
            "e_dim": int(os.environ.get("DRSEC_GMAE_EDGE_DIM", DEFAULT_EDGE_ATTR_DIM)),
            "num_hidden": int(os.environ.get("DRSEC_GMAE_HIDDEN_DIM", 64)),
            "num_layers": int(os.environ.get("DRSEC_GMAE_LAYERS", 2)),
            "n_heads": int(os.environ.get("DRSEC_GMAE_HEADS", 4)),
            "mask_rate": float(os.environ.get("DRSEC_GMAE_MASK_RATE", 0.5)),
            "negative_slope": float(os.environ.get("DRSEC_GMAE_NEGATIVE_SLOPE", 0.2)),
            "alpha_l": float(os.environ.get("DRSEC_GMAE_ALPHA", 2.0)),
            "feat_drop": float(os.environ.get("DRSEC_GMAE_FEAT_DROP", 0.1)),
            "activation": os.environ.get("DRSEC_GMAE_ACTIVATION", "prelu"),
            "residual": True,
            "norm": os.environ.get("DRSEC_GMAE_NORM", "BatchNorm"),
            "feature_profile": os.environ.get("DRSEC_GMAE_FEATURE_PROFILE", "legacy"),
        }

        _seed_torch(torch, seed)
        # 这里统一探测 device，避免后续每个窗口都重复做环境判断。
        device = _resolve_gmae_device(torch)
        model = build_model(SimpleNamespace(**config)).to(device)
        optimizer = torch.optim.Adam(
            model.parameters(),
            lr=float(os.environ.get("DRSEC_GMAE_LR", 1e-3)),
            weight_decay=float(os.environ.get("DRSEC_GMAE_WEIGHT_DECAY", 1e-5)),
        )

        return {
            "torch": torch,
            "config": config,
            "device": device,
            "model": model,
            "optimizer": optimizer,
            "seed": int(seed),
            "epochs": int(epochs),
            "disabled_reason": None,
        }
    except Exception as exc:
        print(f"Warning: GMAE runtime unavailable, skipping GNN baseline training: {exc}")
        return {
            "config": config,
            "device": device,
            "seed": int(seed),
            "epochs": int(epochs),
            "disabled_reason": str(exc),
        }


def _iter_bbk_windows(
    logs: Iterable[dict[str, Any]],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS,
):
    """按 streaming reduction 逻辑把日志切成训练窗口。"""

    from src.process.provenance_model import ProvenanceEventMapper
    from src.process.streaming_reduction import StreamingReducer, StreamingReductionConfig

    reducer = StreamingReducer(
        mapper=ProvenanceEventMapper(),
        config=StreamingReductionConfig(
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
        ),
    )
    yield from reducer.ingest_logs(logs)


def _filter_training_graph(g):
    """Remove placeholder connected-socket nodes from BBK/GMAE training input."""

    unknown_nodes = [
        node_id
        for node_id, node_data in g.nodes(data=True)
        if _is_unknown_connected_socket_node(node_id, (node_data or {}).get("meta") or {})
    ]
    if not unknown_nodes:
        return g

    filtered = g.copy()
    filtered.remove_nodes_from(unknown_nodes)
    graph_filter = dict(filtered.graph.get("training_filter") or {})
    graph_filter["removed_unknown_connected_socket_nodes"] = int(len(unknown_nodes))
    graph_filter["policy"] = "drop_unknown_connected_socket_nodes_and_incident_edges"
    filtered.graph["training_filter"] = graph_filter
    return filtered


def _metas_from_graph(g) -> dict[str, dict[str, Any]]:
    return {
        str(node_id): dict((node_data or {}).get("meta") or {})
        for node_id, node_data in g.nodes(data=True)
    }


def _is_unknown_connected_socket_node(node_id: Any, meta: dict[str, Any]) -> bool:
    node_text = str(node_id or "")
    if node_text == "net:unknown_connected_socket" or node_text.startswith("net:unknown_connected_socket:"):
        return True
    if bool(meta.get("is_unspec_net")):
        return True
    for key in ("uuid", "name", "dst_ip"):
        if str(meta.get(key) or "") == "unknown_connected_socket":
            return True
    return False


def _bbk_reduction_config_payload(window_seconds: int, time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS) -> dict[str, Any]:
    from src.process.streaming_reduction import StreamingReductionConfig

    return StreamingReductionConfig(
        window_seconds=int(window_seconds),
        time_bin_seconds=int(time_bin_seconds),
    ).to_dict()


def _resolve_gmae_device(torch_module) -> str:
    if not torch_module.cuda.is_available():
        return "cpu"
    try:
        import dgl

        graph = dgl.graph(
            (
                torch_module.tensor([], dtype=torch_module.int64),
                torch_module.tensor([], dtype=torch_module.int64),
            ),
            num_nodes=0,
        )
        graph = graph.to("cuda")
        del graph
        return "cuda"
    except Exception:
        return "cpu"


def _train_gmae_from_manifest(runtime: dict[str, Any], manifest_path: str) -> dict[str, Any]:
    """按 manifest 顺序训练 GMAE，并选择 train loss 最低的 checkpoint。"""

    manifest_payload = read_json(manifest_path)
    records = list(manifest_payload.get("records") or [])
    manifest_summary = dict(manifest_payload.get("summary") or _summarize_manifest_records(records))
    epochs = int(runtime.get("epochs") or 0)
    split = _split_gmae_manifest(
        records,
        source_mode=str(manifest_payload.get("source_mode") or ""),
    )
    split_summary = dict(split["summary"])
    quality = _evaluate_training_quality(manifest_payload, split_summary)
    metric_name = "train_mean_total_loss"

    rejected_reason: str | None = None
    if quality["errors"] or runtime.get("disabled_reason"):
        rejected_reason = "; ".join(str(item) for item in quality["errors"]) if quality["errors"] else None

    training_counters = {
        "trained_updates": 0,
        "skipped_empty_windows": 0,
        "skipped_nonfinite_windows": 0,
        "failed_windows": 0,
    }
    aggregate_losses = _new_loss_trackers()
    epoch_metric_summary: list[dict[str, Any]] = []
    best_state_dict: dict[str, Any] | None = None
    best_epoch: int | None = None
    best_metric_value: float | None = None
    epochs_completed = 0

    if not rejected_reason:
        train_records = list(split["train_records"])
        train_window_count = max(len(train_records), 1)
        for epoch in range(1, epochs + 1):
            epochs_completed = epoch
            epoch_counters = {
                "trained_updates": 0,
                "skipped_empty_windows": 0,
                "skipped_nonfinite_windows": 0,
                "failed_windows": 0,
            }
            epoch_losses = _new_loss_trackers()

            for record in train_records:
                outcome = _train_gmae_on_window(runtime, record, train_window_count=train_window_count)
                if outcome["skipped"]:
                    _count_gmae_skip(training_counters, epoch_counters, str(outcome.get("skip_kind") or "failed"))
                    continue

                losses = dict(outcome["losses"])
                training_counters["trained_updates"] += 1
                epoch_counters["trained_updates"] += 1
                _update_loss_trackers(aggregate_losses, losses)
                _update_loss_trackers(epoch_losses, losses)

            train_metric_value = float(epoch_losses["total_loss"].mean) if epoch_losses["total_loss"].count > 0 else None
            is_best_checkpoint = False
            if train_metric_value is not None and math.isfinite(train_metric_value):
                if best_metric_value is None or train_metric_value < float(best_metric_value):
                    best_metric_value = float(train_metric_value)
                    best_epoch = int(epoch)
                    best_state_dict = _clone_state_dict_to_cpu(runtime["model"].state_dict())
                    is_best_checkpoint = True

            epoch_metric_summary.append(
                {
                    "epoch": int(epoch),
                    "trained_updates": int(epoch_counters["trained_updates"]),
                    "skipped_empty_windows": int(epoch_counters["skipped_empty_windows"]),
                    "skipped_nonfinite_windows": int(epoch_counters["skipped_nonfinite_windows"]),
                    "failed_windows": int(epoch_counters["failed_windows"]),
                    "train_total_loss": epoch_losses["total_loss"].to_dict(),
                    "train_node_recon_loss": epoch_losses["node_recon_loss"].to_dict(),
                    "train_structure_loss": epoch_losses["structure_loss"].to_dict(),
                    "checkpoint_metric_name": metric_name if train_metric_value is not None else None,
                    "checkpoint_metric_value": train_metric_value,
                    "is_best_checkpoint": bool(is_best_checkpoint),
                }
            )
            if train_metric_value is None:
                print(f"GMAE epoch {epoch}/{epochs}: train_loss=nan updates={epoch_counters['trained_updates']}")
            else:
                print(
                    f"GMAE epoch {epoch}/{epochs}: "
                    f"train_loss={train_metric_value:.6f} updates={epoch_counters['trained_updates']}"
                )

    training_summary = {
        "trained_updates": int(training_counters["trained_updates"]),
        "skipped_empty_windows": int(training_counters["skipped_empty_windows"]),
        "skipped_nonfinite_windows": int(training_counters["skipped_nonfinite_windows"]),
        "failed_windows": int(training_counters["failed_windows"]),
        "total_loss": aggregate_losses["total_loss"].to_dict(),
        "node_recon_loss": aggregate_losses["node_recon_loss"].to_dict(),
        "structure_loss": aggregate_losses["structure_loss"].to_dict(),
    }

    process_error_calibration = {}
    calibration_payload = {}
    if not rejected_reason and best_state_dict and training_counters["trained_updates"] > 0:
        process_error_calibration, calibration_payload = _calibrate_gmae_from_split(
            runtime=runtime,
            state_dict=best_state_dict,
            calibration_records=list(split.get("calibration_records") or []),
            reduction_config=dict(manifest_payload.get("reduction_config") or {}),
            split_summary=dict(split_summary),
        )

    return {
        "saved_baseline": bool(best_state_dict is not None and training_counters["trained_updates"] > 0),
        "disabled_reason": runtime.get("disabled_reason"),
        "manifest_summary": manifest_summary,
        "split_summary": split_summary,
        "training_summary": training_summary,
        "epoch_metric_summary": epoch_metric_summary,
        "selected_checkpoint_metric": metric_name,
        "best_epoch": best_epoch,
        "best_metric_value": best_metric_value,
        "final_epoch": epochs,
        "epochs_completed": epochs_completed,
        "state_dict": best_state_dict,
        "process_error_calibration": process_error_calibration,
        "calibration_payload": calibration_payload,
        "quality_gate_errors": list(quality["errors"]),
        "rejected_reason": rejected_reason,
        "imbalance_warning": quality["imbalance_warning"],
        "training_tier": quality["training_tier"],
    }


def _calibrate_gmae_from_split(
    *,
    runtime: dict[str, Any],
    state_dict: dict[str, Any],
    calibration_records: list[dict[str, Any]],
    reduction_config: dict[str, Any],
    split_summary: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not calibration_records:
        return {}, {
            "status": "not_available",
            "reason": "no_calibration_windows",
            "threshold_policy": DEFAULT_GMAE_THRESHOLD_POLICY,
            "split_info": {"split_summary": split_summary},
        }

    try:
        torch = runtime["torch"]
        from src.common.gmae import build_model
        from src.process.dgl_adapter import window_to_dgl_graph
        from src.process.window_io import load_window_graph
    except Exception as exc:
        return {}, {
            "status": "not_available",
            "reason": f"calibration_runtime_unavailable:{type(exc).__name__}: {exc}",
            "threshold_policy": DEFAULT_GMAE_THRESHOLD_POLICY,
            "split_info": {"split_summary": split_summary},
        }

    model = build_model(SimpleNamespace(**runtime["config"])).to(runtime["device"])
    model.load_state_dict(state_dict)
    model.eval()

    node_dim = int(runtime["config"].get("n_dim", 64))
    edge_dim = int(runtime["config"].get("e_dim", 16))
    process_scores: list[float] = []
    window_scores: list[float] = []
    per_window_rows: list[dict[str, Any]] = []

    for record in calibration_records:
        try:
            graph = load_window_graph(str(record["path"]))
            graph = _filter_training_graph(graph)
            adapter = window_to_dgl_graph(
                graph,
                node_attr_dim=node_dim,
                edge_attr_dim=edge_dim,
                device=runtime["device"],
                feature_profile=str(runtime["config"].get("feature_profile") or "legacy"),
            )
            if int(adapter.graph.num_nodes()) <= 0 or not adapter.process_node_indices:
                continue
            with torch.no_grad():
                node_errors = model.compute_node_reconstruction_errors(
                    adapter.graph,
                    node_indices=adapter.process_node_indices,
                )
            current_scores = [
                float(node_errors[idx].detach().cpu().item())
                for idx in adapter.process_node_indices
            ]
            if not current_scores:
                continue
            current_scores.sort()
            process_scores.extend(current_scores)
            window_score = float(max(current_scores))
            window_scores.append(window_score)
            per_window_rows.append(
                {
                    "window_id": str(record.get("window_id") or ""),
                    "path": str(record.get("path") or ""),
                    "process_node_count": int(len(current_scores)),
                    "window_max_process_error": window_score,
                    "window_mean_process_error": float(sum(current_scores) / float(len(current_scores))),
                }
            )
        except Exception:
            continue

    process_scores = sorted(float(item) for item in process_scores if math.isfinite(float(item)))
    window_scores = sorted(float(item) for item in window_scores if math.isfinite(float(item)))
    if not process_scores:
        return {}, {
            "status": "not_available",
            "reason": "calibration_collected_no_process_errors",
            "threshold_policy": DEFAULT_GMAE_THRESHOLD_POLICY,
            "split_info": {"split_summary": split_summary},
        }

    process_mean = float(sum(process_scores) / float(len(process_scores)))
    process_var = float(sum((score - process_mean) ** 2 for score in process_scores) / float(len(process_scores)))
    process_std = float(math.sqrt(process_var))
    process_p95 = _percentile(process_scores, 0.95)
    process_p99 = _percentile(process_scores, 0.99)
    mean_plus_3std = float(process_mean + 3.0 * process_std)
    threshold_policy = str(os.environ.get("DRSEC_GMAE_THRESHOLD_POLICY") or DEFAULT_GMAE_THRESHOLD_POLICY).strip().lower()
    threshold_candidates = {
        "p95": process_p95,
        "p99": process_p99,
        "mean+3std": mean_plus_3std,
    }
    process_threshold = float(threshold_candidates.get(threshold_policy) or process_p95 or process_scores[-1])
    window_threshold = float(_percentile(window_scores, 0.95) or process_threshold)

    process_error_calibration = {
        "type": "empirical_cdf",
        "policy": threshold_policy,
        "scores": process_scores,
        "count": int(len(process_scores)),
        "process_score_threshold": float(process_threshold),
        "window_score_threshold": float(window_threshold),
    }
    calibration_payload = {
        "status": "ok",
        "threshold_policy": threshold_policy,
        "process_score_threshold": float(process_threshold),
        "window_score_threshold": float(window_threshold),
        "process_error_distribution": {
            "count": int(len(process_scores)),
            "min": float(process_scores[0]),
            "max": float(process_scores[-1]),
            "mean": float(process_mean),
            "std": float(process_std),
            "p95": float(process_p95 or process_threshold),
            "p99": float(process_p99 or process_threshold),
            "mean_plus_3std": float(mean_plus_3std),
        },
        "window_error_distribution": {
            "count": int(len(window_scores)),
            "min": float(window_scores[0]) if window_scores else None,
            "max": float(window_scores[-1]) if window_scores else None,
            "p95": float(_percentile(window_scores, 0.95) or process_threshold) if window_scores else None,
        },
        "reduction_config": dict(reduction_config or {}),
        "split_info": {
            "split_summary": split_summary,
            "calibration_window_count": int(len(calibration_records)),
        },
        "window_samples": per_window_rows,
    }
    return process_error_calibration, calibration_payload


def _train_gmae_on_window(
    runtime: dict[str, Any],
    record: dict[str, Any],
    *,
    train_window_count: int,
) -> dict[str, Any]:
    """对单个窗口执行一次 GMAE 参数更新。"""

    from src.process.dgl_adapter import window_to_dgl_graph
    from src.process.window_io import load_window_graph

    if not bool(record.get("trainable")):
        return {"skipped": True, "skip_kind": "empty", "reason": "empty_graph", "losses": None}

    torch = runtime["torch"]
    model = runtime["model"]
    optimizer = runtime["optimizer"]

    try:
        graph = load_window_graph(str(record["path"]))
        graph = _filter_training_graph(graph)
        if int(graph.number_of_nodes()) <= 0:
            return {"skipped": True, "skip_kind": "empty", "reason": "empty_graph", "losses": None}

        adapter = window_to_dgl_graph(
            graph,
            node_attr_dim=int(runtime["config"]["n_dim"]),
            edge_attr_dim=int(runtime["config"]["e_dim"]),
            device=runtime["device"],
            feature_profile=str(runtime["config"].get("feature_profile") or "legacy"),
        )
        dgl_graph = adapter.graph
        if int(dgl_graph.num_nodes()) <= 0:
            return {"skipped": True, "skip_kind": "empty", "reason": "empty_graph", "losses": None}

        model.train()
        optimizer.zero_grad(set_to_none=True)
        components = model.compute_loss_components(dgl_graph)

        total_loss = components["total_loss"]
        node_recon_loss = components["node_recon_loss"]
        structure_loss = components["structure_loss"]
        if not (
            _is_finite_tensor(torch, total_loss)
            and _is_finite_tensor(torch, node_recon_loss)
            and _is_finite_tensor(torch, structure_loss)
        ):
            optimizer.zero_grad(set_to_none=True)
            return {
                "skipped": True,
                "skip_kind": "nonfinite",
                "reason": "nonfinite_loss",
                "losses": {
                    "total_loss": _tensor_to_float(total_loss),
                    "node_recon_loss": _tensor_to_float(node_recon_loss),
                    "structure_loss": _tensor_to_float(structure_loss),
                },
            }

        (total_loss / max(int(train_window_count), 1)).backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
        optimizer.step()
        return {
            "skipped": False,
            "skip_kind": None,
            "reason": "",
            "losses": {
                "total_loss": _tensor_to_float(total_loss),
                "node_recon_loss": _tensor_to_float(node_recon_loss),
                "structure_loss": _tensor_to_float(structure_loss),
            },
        }
    except Exception as exc:
        try:
            optimizer.zero_grad(set_to_none=True)
        except Exception:
            pass
        return {
            "skipped": True,
            "skip_kind": "failed",
            "reason": _short_reason(str(exc)),
            "losses": None,
        }


def _save_gmae_runtime(
    runtime: dict[str, Any],
    manifest_payload: dict[str, Any],
    training_result: dict[str, Any],
    context: dict[str, Any],
) -> None:
    _save_named_gmae_runtime(
        runtime=runtime,
        manifest_payload=manifest_payload,
        training_result=training_result,
        checkpoint_path=KB_PATHS.gmae_baseline_path,
        meta_path=KB_PATHS.gmae_baseline_meta_path,
        calibration_path=KB_PATHS.gmae_calibration_path,
        process_error_calibration_path=KB_PATHS.process_error_calibration_path,
        context=context,
    )


def _save_named_gmae_runtime(
    *,
    runtime: dict[str, Any],
    manifest_payload: dict[str, Any],
    training_result: dict[str, Any],
    checkpoint_path: str,
    meta_path: str,
    calibration_path: str,
    process_error_calibration_path: str,
    context: dict[str, Any],
) -> None:
    """Save a checkpoint plus JSON sidecars describing training and calibration."""

    split_summary = training_result.get("split_summary") or {}
    process_error_calibration = dict(training_result.get("process_error_calibration") or {})
    calibration_payload = dict(training_result.get("calibration_payload") or {})
    reduction_config = dict(manifest_payload.get("reduction_config") or {})
    split_info = {
        "split_summary": split_summary,
        "source_run_ids": list(split_summary.get("source_run_ids") or []),
        "training_source_run_ids": list(split_summary.get("training_source_run_ids") or []),
        "holdout_run_ids": list(split_summary.get("holdout_run_ids") or []),
    }
    final_loss = ((training_result.get("training_summary") or {}).get("total_loss") or {}).get("mean")
    process_threshold = float(process_error_calibration.get("process_score_threshold") or 0.0)
    threshold_policy = str(process_error_calibration.get("policy") or calibration_payload.get("threshold_policy") or DEFAULT_GMAE_THRESHOLD_POLICY)
    meta_payload = {
        "model_type": "GMAE",
        "created_at": _utc_now_iso(),
        "baseline_version": GMAE_BASELINE_VERSION,
        "seed": int(runtime.get("seed") or 0),
        "window_seconds": int(reduction_config.get("window_seconds") or manifest_payload.get("window_seconds") or DEFAULT_WINDOW_SECONDS),
        "stride_seconds": int(reduction_config.get("stride_seconds") or DEFAULT_DETECT_STRIDE_SECONDS),
        "window_mode": "sliding" if reduction_config.get("stride_seconds") else "fixed",
        "train_window_count": int(split_summary.get("train_window_count") or 0),
        "calibration_window_count": int(split_summary.get("calibration_window_count") or 0),
        "node_feature_dim": int(runtime.get("config", {}).get("n_dim") or 0),
        "edge_feature_dim": int(runtime.get("config", {}).get("e_dim") or 0),
        "feature_profile": str(runtime.get("config", {}).get("feature_profile") or "legacy"),
        "hidden_dim": int(runtime.get("config", {}).get("num_hidden") or 0),
        "epochs": int(runtime.get("epochs") or 0),
        "final_loss": float(final_loss) if final_loss is not None else None,
        "threshold_policy": threshold_policy,
        "process_score_threshold": float(process_threshold),
        "split_info": split_info,
        "epochs_requested": int(runtime.get("epochs") or 0),
        "epochs_completed": int(training_result.get("epochs_completed") or 0),
        "best_epoch": training_result.get("best_epoch"),
        "best_metric_value": training_result.get("best_metric_value"),
        "selected_checkpoint_metric": training_result.get("selected_checkpoint_metric"),
        "saved_baseline": bool(training_result.get("saved_baseline")),
        "training_tier": training_result.get("training_tier"),
        "rejected_reason": training_result.get("rejected_reason"),
        "imbalance_warning": training_result.get("imbalance_warning"),
        "quality_gate_errors": list(training_result.get("quality_gate_errors") or []),
        "training_summary": training_result.get("training_summary") or {},
        "epoch_metric_summary": list(training_result.get("epoch_metric_summary") or []),
        "manifest_summary": training_result.get("manifest_summary") or manifest_payload.get("summary") or {},
        "split_summary": split_summary,
        "calibration_summary": calibration_payload,
        "context": context,
        "reduction_config": reduction_config,
    }
    write_json(meta_path, meta_payload)
    write_json(calibration_path, calibration_payload)
    write_json(process_error_calibration_path, process_error_calibration)

    skip_reason = (
        runtime.get("disabled_reason")
        or training_result.get("rejected_reason")
        or (None if training_result.get("saved_baseline") else "no_successful_checkpoint")
    )
    if skip_reason:
        print(f"Warning: GMAE baseline was not saved: {skip_reason}")
        return

    state_dict = training_result.get("state_dict")
    if not isinstance(state_dict, dict) or not state_dict:
        print("Warning: GMAE baseline was not saved because no checkpoint was selected.")
        return

    torch = runtime["torch"]
    payload = {
        "baseline_version": GMAE_BASELINE_VERSION,
        "state_dict": state_dict,
        "config": runtime["config"],
        "device": runtime["device"],
        "seed": int(runtime["seed"]),
        "epochs_completed": int(training_result.get("epochs_completed") or 0),
        "best_epoch": training_result.get("best_epoch"),
        "selected_checkpoint_metric": training_result.get("selected_checkpoint_metric"),
        "reduction_config": reduction_config,
        "train_window_count": int(split_summary.get("train_window_count") or 0),
        "source_run_ids": list(split_summary.get("source_run_ids") or []),
        "holdout_run_ids": list(split_summary.get("holdout_run_ids") or []),
        "process_error_calibration": process_error_calibration,
        "window_score_threshold": calibration_payload.get("window_score_threshold"),
        "node_feature_dim": int(runtime["config"].get("n_dim") or 0),
        "edge_feature_dim": int(runtime["config"].get("e_dim") or 0),
        "feature_profile": str(runtime["config"].get("feature_profile") or "legacy"),
    }

    torch.save(payload, checkpoint_path)
    print(f"? GMAE baseline saved: {checkpoint_path}")
    print(f"? GMAE training metadata saved: {meta_path}")
    if context.get("sampled_train_windows_source"):
        _copy_optional_file(str(context.get("sampled_train_windows_source") or ""), KB_PATHS.sampled_train_windows_snapshot_path)
    if context.get("full_window_index_source"):
        _copy_optional_file(str(context.get("full_window_index_source") or ""), KB_PATHS.full_window_index_snapshot_path)


def _cleanup_generated_window_files(directory: str) -> None:
    try:
        entries = os.listdir(directory)
    except OSError:
        return

    generated_names = {GMAE_MANIFEST_FILENAME}
    for name in entries:
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        if name in generated_names or (name.startswith("window_") and name.endswith(".json")):
            try:
                os.remove(path)
            except OSError:
                continue


def _write_gmae_manifest(
    manifest_path: str,
    log_file: str,
    logs_dir: str,
    source_mode: str,
    sources: list[dict[str, Any]],
    windows_dir: str,
    persist_windows: bool,
    window_seconds: int,
    reduction_config: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    """把阶段 1 产出的窗口索引写成 manifest，供离线训练阶段消费"""

    payload = {
        "manifest_version": 2,
        "source_mode": str(source_mode or ""),
        "log_file": os.path.abspath(log_file) if str(log_file or "").strip() else "",
        "logs_dir": os.path.abspath(logs_dir) if str(logs_dir or "").strip() else "",
        "windows_dir": os.path.abspath(windows_dir),
        "persist_windows": bool(persist_windows),
        "window_seconds": int(window_seconds),
        "reduction_config": dict(reduction_config or {}),
        "source_count": int(len(sources)),
        "sources": [_serialize_manifest_source(source) for source in sources],
        "record_count": int(len(records)),
        "summary": _summarize_manifest_records(records),
        "records": records,
    }
    write_json(manifest_path, payload)
    payload["manifest_path"] = os.path.abspath(manifest_path)
    return payload


def _serialize_manifest_source(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "log_file": os.path.abspath(str(source.get("log_file") or "")) if str(source.get("log_file") or "").strip() else "",
        "run_id": str(source.get("run_id") or ""),
        "split_role": _normalize_split_role(source.get("split_role") or ""),
        "source_profile": str(source.get("source_profile") or ""),
        "training_pool": bool(source.get("training_pool", True)),
        "bootstrap_only": bool(source.get("bootstrap_only", False)),
        "phases": list(source.get("phases") or []),
    }


def _build_manifest_record(
    window_id: str,
    window_path: str,
    g,
    *,
    source_log_file: str = "",
    source_run_id: str = "",
    source_profile: str = "",
    split_role: str = "",
) -> dict[str, Any]:
    node_count = int(g.number_of_nodes())
    edge_count = int(g.number_of_edges())
    process_node_count = sum(1 for node_id in g.nodes() if str(node_id).startswith("proc:"))
    return {
        "window_id": window_id,
        "path": os.path.abspath(window_path),
        "node_count": node_count,
        "edge_count": edge_count,
        "process_node_count": int(process_node_count),
        "trainable": bool(node_count > 0),
        "scorable": bool(node_count > 0 and process_node_count > 0),
        "source_log_file": os.path.abspath(source_log_file) if str(source_log_file or "").strip() else "",
        "source_run_id": str(source_run_id or ""),
        "source_profile": str(source_profile or ""),
        "split_role": _normalize_split_role(split_role or ""),
    }


def _summarize_manifest_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    trainable_records = [record for record in records if bool(record.get("trainable"))]
    scorable_records = [record for record in records if bool(record.get("scorable"))]
    source_run_ids = sorted(
        {
            str(record.get("source_run_id") or "").strip()
            for record in records
            if str(record.get("source_run_id") or "").strip()
        }
    )
    profile_counter = Counter(
        _profile_label(record.get("source_profile"))
        for record in records
        if bool(record.get("trainable"))
    )
    split_role_counter = Counter(
        _normalize_split_role(record.get("split_role") or "") or "train"
        for record in records
    )
    return {
        "window_count": int(len(records)),
        "trainable_window_count": int(len(trainable_records)),
        "scorable_window_count": int(len(scorable_records)),
        "empty_window_count": int(sum(1 for record in records if not bool(record.get("trainable")))),
        "node_count_sum": int(sum(int(record.get("node_count") or 0) for record in records)),
        "edge_count_sum": int(sum(int(record.get("edge_count") or 0) for record in records)),
        "source_run_ids": source_run_ids,
        "profile_window_distribution": dict(sorted(profile_counter.items())),
        "split_role_window_distribution": dict(sorted(split_role_counter.items())),
    }


def _split_gmae_manifest(
    records: list[dict[str, Any]],
    source_mode: str = "",
) -> dict[str, Any]:
    """按 manifest 角色取训练窗口；不随机切分，也不做 calibration 采样。"""

    role_records: dict[str, list[dict[str, Any]]] = {"train": [], "calibration": [], "holdout": []}
    for record in records:
        role = _normalize_split_role(record.get("split_role") or "") or "train"
        role_records.setdefault(role, []).append(record)

    train_records = [record for record in role_records["train"] if bool(record.get("trainable"))]
    empty_records = [record for record in role_records["train"] if not bool(record.get("trainable"))]
    calibration_records = [record for record in role_records["calibration"] if bool(record.get("scorable"))]
    holdout_records = [record for record in role_records["holdout"] if bool(record.get("trainable"))]
    scorable_records = [record for record in records if bool(record.get("scorable"))]

    train_run_ids = _unique_source_run_ids(role_records["train"])
    calibration_run_ids = _unique_source_run_ids(role_records["calibration"])
    holdout_run_ids = _unique_source_run_ids(role_records["holdout"])
    training_source_run_ids = sorted(set(train_run_ids) | set(calibration_run_ids))
    source_run_ids = sorted(set(training_source_run_ids) | set(holdout_run_ids))
    split_role_counter = Counter(
        _normalize_split_role(record.get("split_role") or "") or "train"
        for record in records
    )

    summary = {
        "split_strategy": "manifest_order",
        "source_mode": str(source_mode or ""),
        "window_count": int(len(records)),
        "trainable_window_count": int(sum(1 for record in records if bool(record.get("trainable")))),
        "scorable_window_count": int(len(scorable_records)),
        "train_window_count": int(len(train_records)),
        "calibration_window_count": int(len(calibration_records)),
        "holdout_window_count": int(len(holdout_records)),
        "empty_window_count": int(len(empty_records)),
        "source_run_ids": source_run_ids,
        "training_source_run_ids": training_source_run_ids,
        "holdout_run_ids": holdout_run_ids,
        "profile_window_distribution": _profile_window_distribution(train_records),
        "split_role_window_distribution": dict(sorted(split_role_counter.items())),
    }
    return {
        "train_records": train_records,
        "calibration_records": calibration_records,
        "empty_records": empty_records,
        "holdout_records": holdout_records,
        "summary": summary,
    }


def _unique_source_run_ids(records: Iterable[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(record.get("source_run_id") or "").strip()
            for record in records
            if str(record.get("source_run_id") or "").strip()
        }
    )


def _profile_label(value: Any) -> str:
    text = str(value or "").strip()
    return text if text else "unknown"


def _profile_window_distribution(records: Iterable[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(_profile_label(record.get("source_profile")) for record in records if bool(record.get("trainable", True)))
    return dict(sorted(counter.items()))


def _evaluate_training_quality(
    manifest_payload: dict[str, Any],
    split_summary: dict[str, Any],
) -> dict[str, Any]:
    source_mode = str(manifest_payload.get("source_mode") or "")
    split_strategy = str(split_summary.get("split_strategy") or "")
    formal_source_modes = {"logs_dir", "sampled_train_windows"}
    training_tier = "formal" if source_mode in formal_source_modes and split_strategy == "manifest_order" else "bootstrap"
    errors: list[str] = []

    if training_tier == "formal":
        train_window_count = int(split_summary.get("train_window_count") or 0)
        if train_window_count < DEFAULT_BBK_MIN_TRAIN_WINDOWS:
            errors.append(
                f"trainable benign windows below threshold: {train_window_count} < {DEFAULT_BBK_MIN_TRAIN_WINDOWS}"
            )

    imbalance_warning = _build_profile_imbalance_warning(
        dict(split_summary.get("profile_window_distribution") or {}),
        total_windows=int(split_summary.get("train_window_count") or 0),
    )
    return {
        "training_tier": training_tier,
        "errors": errors,
        "imbalance_warning": imbalance_warning,
    }


def _build_profile_imbalance_warning(
    profile_window_distribution: dict[str, int],
    *,
    total_windows: int,
) -> dict[str, Any] | None:
    if total_windows <= 0 or not profile_window_distribution:
        return None

    offenders = []
    for profile_id, count in sorted(profile_window_distribution.items()):
        ratio = float(count) / float(total_windows)
        if ratio > float(DEFAULT_BBK_PROFILE_IMBALANCE_RATIO):
            offenders.append(
                {
                    "source_profile": str(profile_id),
                    "window_count": int(count),
                    "ratio": float(ratio),
                }
            )

    if not offenders:
        return None
    return {
        "threshold_ratio": float(DEFAULT_BBK_PROFILE_IMBALANCE_RATIO),
        "train_window_count": int(total_windows),
        "offenders": offenders,
    }


def _new_loss_trackers() -> dict[str, RunningStats]:
    return {
        "total_loss": RunningStats(),
        "node_recon_loss": RunningStats(),
        "structure_loss": RunningStats(),
    }


def _update_loss_trackers(trackers: dict[str, RunningStats], losses: dict[str, float]) -> None:
    trackers["total_loss"].update(float(losses["total_loss"]))
    trackers["node_recon_loss"].update(float(losses["node_recon_loss"]))
    trackers["structure_loss"].update(float(losses["structure_loss"]))


def _count_gmae_skip(
    global_counters: dict[str, int],
    epoch_counters: dict[str, int],
    skip_kind: str,
) -> None:
    if skip_kind == "empty":
        global_counters["skipped_empty_windows"] += 1
        epoch_counters["skipped_empty_windows"] += 1
        return
    if skip_kind == "nonfinite":
        global_counters["skipped_nonfinite_windows"] += 1
        epoch_counters["skipped_nonfinite_windows"] += 1
        return
    global_counters["failed_windows"] += 1
    epoch_counters["failed_windows"] += 1


def _clone_state_dict_to_cpu(state_dict: dict[str, Any]) -> dict[str, Any]:
    """冻结当前 checkpoint，避免后续训练继续原地修改同一组张量。"""

    cloned: dict[str, Any] = {}
    for key, value in state_dict.items():
        if hasattr(value, "detach"):
            cloned[key] = value.detach().cpu().clone()
        else:
            cloned[key] = copy.deepcopy(value)
    return cloned


def _seed_torch(torch_module, seed: int) -> None:
    torch_module.manual_seed(int(seed))
    if torch_module.cuda.is_available():
        torch_module.cuda.manual_seed_all(int(seed))
        if hasattr(torch_module.backends, "cudnn"):
            torch_module.backends.cudnn.deterministic = True
            torch_module.backends.cudnn.benchmark = False


def _is_finite_tensor(torch_module, value) -> bool:
    try:
        return bool(torch_module.isfinite(value.detach()).all().item())
    except Exception:
        return False


def _tensor_to_float(value) -> float | None:
    try:
        return float(value.detach().cpu().item())
    except Exception:
        return None


def _short_reason(reason: str, limit: int = 120) -> str:
    text = " ".join(str(reason or "").split())
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)] + "..."


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return int(default)
    try:
        return int(raw)
    except ValueError:
        return int(default)
