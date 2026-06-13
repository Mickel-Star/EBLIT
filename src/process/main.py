#!/usr/bin/env python3
"""
基于Tracee的溯源入侵检测系统主脚本

该脚本仅保留论文主链路：
1) BBK 基线构建（Streaming Reduction + 频次/支持度）
2) TIK 构建（MITRE 容器相关技术 + ASG paths + Doc2Vec）
3) 检测与调查（稀有路径 + TIK 检索 + 逻辑链重构 + LLM 报告）
"""

import argparse
import json
import logging
import os
import sys
import signal

from src.common.defaults import (
    DEFAULT_ALERT_THRESHOLD,
    DEFAULT_BBK_TRAIN_WINDOW_SECONDS,
    DEFAULT_DETECT_STRIDE_SECONDS,
    DEFAULT_TIME_BIN_SECONDS,
    DEFAULT_TOP_EVIDENCE_ITEMS,
    DEFAULT_WINDOW_SECONDS,
)
from src.common.io import write_json, write_jsonl

# 禁用 ChromaDB 的遥测功能以防止网络超时
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_TELEMETRY_IMPL"] = "ct_none"

os.makedirs("logs", exist_ok=True)

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join("logs", "drsec.log")),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

def setup_directories() -> None:
    """设置必要的目录结构"""
    directories = [
        'data/raw',
        'data/processed',
        'data/kb',
        'data/kb/vector_db',
        'logs'
    ]
    
    for dir_path in directories:
        os.makedirs(dir_path, exist_ok=True)
        logger.info(f"已创建目录: {dir_path}")


def _short_container_id(container_id: str) -> str:
    value = str(container_id or "").strip()
    return value[:12] if value else "unknown"


def _print_window_alert_summary(alert, max_processes: int = DEFAULT_TOP_EVIDENCE_ITEMS, prefix: str = "") -> None:
    window_file = alert.window_file or f"{alert.window_id}.json"
    print(
        f"{prefix}window={alert.window_id} file={window_file} "
        f"score={float(alert.window_score):.3f} threshold={float(alert.threshold):.3f} "
        f"suspicious_processes={int(alert.suspicious_process_count)}"
    )
    if alert.impacted_containers:
        containers = ", ".join([_short_container_id(item) for item in alert.impacted_containers[:DEFAULT_TOP_EVIDENCE_ITEMS]])
        print(f"{prefix}containers={containers}")
    if alert.top_processes:
        print(f"{prefix}top_processes:")
        for item in alert.top_processes[: int(max_processes)]:
            print(
                f"{prefix}- pid={item.get('pid')} container={_short_container_id(item.get('container_id') or '')} "
                f"name={item.get('display_name') or 'unknown'} score={float(item.get('process_score', 0.0)):.3f}"
            )
    if alert.top_rare_paths:
        print(f"{prefix}top_rare_paths:")
        for rp in alert.top_rare_paths[:DEFAULT_TOP_EVIDENCE_ITEMS]:
            print(f"{prefix}- score={float(rp.get('score', 0.0)):.3f} path={str(rp.get('text') or '')[:160]}")


def _add_window_args(parser: argparse.ArgumentParser, *, include_mode: bool = True) -> None:
    if include_mode:
        parser.add_argument('--window-mode', choices=['sliding', 'fixed'], default='sliding', help='窗口模式：sliding 为默认主流程，fixed 仅用于 baseline/兼容')
    parser.add_argument('--window-seconds', type=int, default=DEFAULT_WINDOW_SECONDS, help='窗口长度（秒，默认 1800）')
    parser.add_argument('--stride-seconds', type=int, default=DEFAULT_DETECT_STRIDE_SECONDS, help='滑动窗口步长（秒，默认 600；fixed 模式忽略）')


def _add_two_stage_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--two-stage', action='store_true', default=False, help='启用 BBK 窗口级预筛选 -> GMAE 节点级定位')
    parser.add_argument('--bbk-trigger-threshold', type=float, default=DEFAULT_ALERT_THRESHOLD, help='BBK Stage-1 触发 GMAE 的窗口分数阈值')
    parser.add_argument('--top-k', type=int, default=DEFAULT_TOP_EVIDENCE_ITEMS, help='GMAE Stage-2 输出的 Top-k 异常进程节点数')
    parser.add_argument('--disable-gmae', action='store_true', default=False, help='只运行 BBK Stage-1，不调用 GMAE')
    parser.add_argument('--force-gmae-all-windows', action='store_true', default=False, help='GMAE-only baseline：对所有窗口调用 GMAE')


def _validate_window_args(args) -> None:
    if hasattr(args, "window_seconds") and int(args.window_seconds) <= 0:
        raise SystemExit("--window-seconds must be > 0")
    if hasattr(args, "stride_seconds") and int(args.stride_seconds) <= 0:
        raise SystemExit("--stride-seconds must be > 0")
    if getattr(args, "window_mode", "sliding") == "sliding" and int(getattr(args, "stride_seconds", DEFAULT_DETECT_STRIDE_SECONDS)) > int(getattr(args, "window_seconds", DEFAULT_WINDOW_SECONDS)):
        raise SystemExit("--stride-seconds must be <= --window-seconds when --window-mode=sliding")
    if hasattr(args, "top_k") and int(args.top_k) < 0:
        raise SystemExit("--top-k must be >= 0")


def _two_stage_config_from_args(args):
    from src.process.analysis_engine import TwoStageDetectionConfig

    return TwoStageDetectionConfig(
        bbk_trigger_threshold=float(args.bbk_trigger_threshold),
        top_k=int(args.top_k),
        disable_gmae=bool(args.disable_gmae),
        force_gmae_all_windows=bool(args.force_gmae_all_windows),
        window_mode=str(getattr(args, "window_mode", "sliding")),
        window_seconds=int(getattr(args, "window_seconds", DEFAULT_WINDOW_SECONDS)),
        stride_seconds=int(getattr(args, "stride_seconds", DEFAULT_DETECT_STRIDE_SECONDS)),
    )


def _print_two_stage_result(result: dict, prefix: str = "") -> None:
    print(
        f"{prefix}window={result.get('window_id')} mode={result.get('window_mode')} "
        f"range={result.get('window_start')}..{result.get('window_end')} "
        f"nodes={int(result.get('node_count') or 0)} edges={int(result.get('edge_count') or 0)} "
        f"bbk_score={float(result.get('bbk_score') or 0.0):.3f} "
        f"threshold={float(result.get('bbk_trigger_threshold') or 0.0):.3f} "
        f"bbk_triggered={bool(result.get('bbk_triggered'))} "
        f"gmae_triggered={bool(result.get('gmae_triggered'))}"
    )
    reason = result.get("gmae_reason_if_skipped") or result.get("bbk_reason")
    if reason:
        print(f"{prefix}reason={reason}")
    top_processes = list(result.get("top_processes") or [])
    if top_processes:
        print(f"{prefix}top_processes:")
        for item in top_processes:
            print(
                f"{prefix}- pid={item.get('pid')} container={_short_container_id(item.get('container_id') or '')} "
                f"name={item.get('display_name') or 'unknown'} score={float(item.get('process_score') or 0.0):.3f}"
            )
    top_rare_paths = list(result.get("top_rare_paths") or [])
    if top_rare_paths:
        print(f"{prefix}top_rare_paths:")
        for item in top_rare_paths[:DEFAULT_TOP_EVIDENCE_ITEMS]:
            print(f"{prefix}- score={float(item.get('score') or 0.0):.3f} path={str(item.get('text') or '')[:160]}")


def _write_two_stage_outputs(output_dir: str, results: list[dict], summary: dict) -> None:
    os.makedirs(output_dir, exist_ok=True)
    per_window_dir = os.path.join(output_dir, "two_stage_windows")
    os.makedirs(per_window_dir, exist_ok=True)
    write_jsonl(os.path.join(output_dir, "two_stage_window_results.jsonl"), results)
    write_json(os.path.join(output_dir, "two_stage_summary.json"), summary)
    for item in results:
        window_id = str(item.get("window_id") or "window_unknown")
        write_json(os.path.join(per_window_dir, f"{window_id}.json"), item)

def main() -> None:
    """主函数"""
    parser = argparse.ArgumentParser(description='DRSEC：基于溯源图与知识库的容器异常检测')
    
    # 子命令
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # analyze 命令
    analyze_parser = subparsers.add_parser('analyze', help='分析Tracee日志中的可疑行为')
    analyze_parser.add_argument('log_file', help='Tracee日志文件路径')
    analyze_parser.add_argument('--threshold', type=float, default=DEFAULT_ALERT_THRESHOLD, help='窗口告警阈值（窗口分数，0-1）')
    _add_window_args(analyze_parser)
    analyze_parser.add_argument('--time-bin-seconds', type=int, default=DEFAULT_TIME_BIN_SECONDS, help='边时间分桶长度（秒）')
    analyze_parser.add_argument('--debug-dump-dir', default='data/processed/debug', help='调试信息输出目录')
    analyze_parser.add_argument('--print-attack-graph', action='store_true', default=True, help='打印攻击溯源图重构结果')
    analyze_parser.add_argument('--print-llm-context', action='store_true', default=True, help='打印输入给LLM的上下文（截断展示）')
    analyze_parser.add_argument('--print-process-details', action='store_true', default=False, help='打印窗口内的进程证据明细')
    analyze_parser.add_argument('--max-attack-graph-edges', type=int, default=80, help='攻击溯源图最多打印多少条边')
    analyze_parser.add_argument('--max-prompt-chars', type=int, default=2000, help='LLM上下文最多打印多少字符（其余写入文件）')
    analyze_parser.add_argument('--persist-windows-dir', default='data/processed/windows', help='持久化窗口图的输出目录')
    _add_two_stage_args(analyze_parser)

    # build_tik 命令
    build_tik_parser = subparsers.add_parser('build_tik', help='构建 TIK（Threat Intelligence Knowledge）向量库')

    # build_bbk 命令
    build_bbk_parser = subparsers.add_parser('build_bbk', help='构建/更新 BBK（Benign Behavior Knowledge）基线库')
    build_bbk_parser.add_argument('log_file', nargs='?', default='', help='可选：单个良性Tracee日志文件路径（兼容 bootstrap 模式）')
    build_bbk_parser.add_argument(
        '--logs-dir',
        default='',
        help='推荐：benign corpus 根目录；若存在 sampled_train_windows.jsonl，则按采样清单训练',
    )
    build_bbk_parser.add_argument(
        '--sampled-train-windows',
        default='',
        help='显式指定 sampled_train_windows.jsonl；训练只消费其中 split=train 且非 empty 的窗口',
    )
    build_bbk_parser.add_argument(
        '--full-window-index',
        default='',
        help='可选：full_window_index.jsonl，用于读取 calibration/holdout 窗口；默认使用 sampled 文件同目录下的文件',
    )
    build_bbk_parser.add_argument('--window-seconds', type=int, default=DEFAULT_BBK_TRAIN_WINDOW_SECONDS, help='训练窗口长度（秒，默认 30s）')
    build_bbk_parser.add_argument('--time-bin-seconds', type=int, default=DEFAULT_TIME_BIN_SECONDS, help='边时间分桶长度（秒）')
    build_bbk_parser.add_argument('--persist-windows-dir', default='', help='可选：持久化窗口图/训练 manifest 的输出目录')

    build_gmae_transfer_parser = subparsers.add_parser('build_gmae_transfer', help='CADETS E3 预训练 + 本地 Tracee 适配 GMAE')
    build_gmae_transfer_parser.add_argument('--e3-dir', required=True, help='DARPA E3 CADETS 数据目录')
    build_gmae_transfer_parser.add_argument('--groundtruth', required=True, help='恶意 UUID groundtruth 文件路径')
    build_gmae_transfer_parser.add_argument('--local-corpus', required=True, help='本地 Tracee benign corpus 根目录')
    build_gmae_transfer_parser.add_argument('--output-dir', default='data/processed/gmae_transfer', help='迁移训练中间产物输出目录')
    build_gmae_transfer_parser.add_argument('--e3-limit-windows', type=int, default=0, help='仅处理前 N 个 E3 窗口（0 表示不限）')
    build_gmae_transfer_parser.add_argument('--local-limit-windows', type=int, default=0, help='仅处理前 N 个本地窗口（0 表示不限）')
    build_gmae_transfer_parser.add_argument('--e3-epochs', type=int, default=3, help='E3 预训练 epoch 数')
    build_gmae_transfer_parser.add_argument('--local-epochs', type=int, default=3, help='本地微调 epoch 数')
    build_gmae_transfer_parser.add_argument('--window-seconds', type=int, default=DEFAULT_WINDOW_SECONDS, help='迁移训练窗口长度（秒）')
    build_gmae_transfer_parser.add_argument('--stride-seconds', type=int, default=DEFAULT_DETECT_STRIDE_SECONDS, help='迁移训练滑动步长（秒）')
    build_gmae_transfer_parser.add_argument('--time-bin-seconds', type=int, default=DEFAULT_TIME_BIN_SECONDS, help='迁移训练边时间分桶长度（秒）')
    build_gmae_transfer_parser.add_argument('--dry-run', action='store_true', default=False, help='只生成计划和 manifest，不执行训练')

    build_ark_parser = subparsers.add_parser('build_ark', help='构建 ARK（Attack Representation Knowledge）逻辑图')

    replay_parser = subparsers.add_parser('replay', help='从已持久化的窗口图回放并执行检测')
    replay_parser.add_argument('windows_dir', help='窗口图目录（window_*.json）')
    replay_parser.add_argument('--threshold', type=float, default=DEFAULT_ALERT_THRESHOLD, help='窗口告警阈值（窗口分数，0-1）')
    _add_window_args(replay_parser)
    replay_parser.add_argument('--debug-dump-dir', default='data/processed/debug', help='调试信息输出目录')
    replay_parser.add_argument('--print-process-details', action='store_true', default=False, help='打印窗口内的进程证据明细')
    replay_parser.add_argument('--max-attack-graph-edges', type=int, default=80, help='攻击溯源图最多打印多少条边')
    replay_parser.add_argument('--max-prompt-chars', type=int, default=2000, help='LLM上下文最多打印多少字符（其余写入文件）')
    _add_two_stage_args(replay_parser)

    realtime_parser = subparsers.add_parser('realtime', help='实时监控：增量读取 Tracee 输出并窗口检测')
    realtime_parser.add_argument('log_file', help='Tracee 输出文件路径（持续增长）')
    realtime_parser.add_argument('--threshold', type=float, default=DEFAULT_ALERT_THRESHOLD, help='窗口告警阈值（窗口分数，0-1）')
    _add_window_args(realtime_parser)
    realtime_parser.add_argument('--time-bin-seconds', type=int, default=DEFAULT_TIME_BIN_SECONDS, help='边时间分桶长度（秒）')
    realtime_parser.add_argument('--emit-partial-window', action='store_true', default=False, help='在输入暂时没有新行时输出当前未完成窗口')
    realtime_parser.add_argument('--poll-interval', type=float, default=0.2, help='轮询间隔（秒）')
    realtime_parser.add_argument('--start-at-end', action='store_true', default=True, help='从文件末尾开始追踪（默认）')
    realtime_parser.add_argument('--start-from-begin', action='store_true', default=False, help='从文件开头回放并实时追踪')
    realtime_parser.add_argument('--max-alerts-per-window', type=int, default=1, help='兼容参数：V1 固定每个窗口最多输出 1 条窗口告警')
    realtime_parser.add_argument('--max-process-evidence', type=int, default=DEFAULT_TOP_EVIDENCE_ITEMS, help='每条窗口告警最多打印多少个 top processes')
    realtime_parser.add_argument('--no-llm', action='store_true', default=True, help='默认不调用LLM，仅输出告警与稀有路径')
    realtime_parser.add_argument('--with-llm', action='store_true', default=False, help='启用LLM生成报告（可能较慢）')
    realtime_parser.add_argument('--debug-dump-dir', default='data/processed/realtime_debug', help='调试信息输出目录')
    realtime_parser.add_argument('--persist-windows-dir', default='data/processed/realtime_windows', help='持久化窗口图的输出目录')
    realtime_parser.add_argument('--max-attack-graph-edges', type=int, default=80, help='攻击溯源图最多打印多少条边')
    realtime_parser.add_argument('--max-windows', type=int, default=0, help='可选：最多处理多少个窗口后退出（0表示不限制）')
    _add_two_stage_args(realtime_parser)
    
    # setup 命令
    setup_parser = subparsers.add_parser('setup', help='设置必要的目录结构')
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return
    _validate_window_args(args)
    
    logger.info(f"执行命令: {args.command}")
    
    if args.command == 'setup':
        setup_directories()
        logger.info("目录结构设置完成")

    elif args.command == 'analyze':
        from src.analysis.report_generator import AnalysisEngine
        
        engine = AnalysisEngine()
        print(f"\n🔍 正在分析日志文件: {args.log_file}")
        print(f"   阈值: {args.threshold}")
        print(f"   窗口: mode={args.window_mode} window={int(args.window_seconds)}s stride={int(args.stride_seconds)}s")

        if bool(args.two_stage):
            from src.process.analysis_engine import detect_two_stage_window, summarize_two_stage_results
            from src.process.log_parser import TraceeLogParser
            from src.process.streaming_reduction import iter_window_graphs
            from src.process.window_io import dump_window_graph

            logs = TraceeLogParser().parse_log_file(args.log_file)
            results = []
            if args.persist_windows_dir:
                os.makedirs(args.persist_windows_dir, exist_ok=True)
            for idx, (g, _metas) in enumerate(
                iter_window_graphs(
                    logs,
                    window_mode=str(args.window_mode),
                    window_seconds=int(args.window_seconds),
                    stride_seconds=int(args.stride_seconds),
                    time_bin_seconds=int(args.time_bin_seconds),
                    mapper=engine.provenance_mapper,
                    emit_partial=True,
                ),
                start=1,
            ):
                window_id = f"window_{idx:04d}"
                if args.persist_windows_dir:
                    dump_window_graph(os.path.join(args.persist_windows_dir, f"{window_id}.json"), g)
                result = detect_two_stage_window(
                    g,
                    {"window_id": window_id},
                    engine.benign_kb,
                    None if bool(args.disable_gmae) else engine,
                    _two_stage_config_from_args(args),
                )
                results.append(result)
                _print_two_stage_result(result)
            summary = summarize_two_stage_results(
                results,
                top_k=int(args.top_k),
                window_seconds=int(args.window_seconds),
                stride_seconds=int(args.stride_seconds),
                window_mode=str(args.window_mode),
            )
            _write_two_stage_outputs(args.debug_dump_dir, results, summary)
            print(json.dumps({"two_stage_results": results}, ensure_ascii=False, indent=2))
            print(json.dumps({"two_stage_summary": summary}, ensure_ascii=False, indent=2))
            return
        
        alerts = engine.detect_window_alerts(
            args.log_file,
            args.threshold,
            persist_windows_dir=(args.persist_windows_dir or None),
            window_mode=str(args.window_mode),
            window_seconds=int(args.window_seconds),
            stride_seconds=int(args.stride_seconds),
            time_bin_seconds=int(args.time_bin_seconds),
        )
        
        if not alerts:
            print("\n✅ 未发现窗口告警（基于当前阈值）")
            return

        print(f"\n⚠️ 发现 {len(alerts)} 个窗口告警:")
        for i, alert in enumerate(alerts, start=1):
            print(
                f"\n--- 窗口告警 #{i} "
                f"(window={alert.window_id}, score={float(alert.window_score):.3f}, file={alert.window_file or 'n/a'}) ---"
            )
            _print_window_alert_summary(alert, max_processes=int(DEFAULT_TOP_EVIDENCE_ITEMS))
            if bool(args.print_process_details):
                for proc in alert.top_processes[:DEFAULT_TOP_EVIDENCE_ITEMS]:
                    graph_context = str(proc.get("graph_context") or "").strip()
                    if graph_context:
                        print("\nGraph Context:")
                        print(graph_context)

            print("\n🤖 正在生成窗口级分析报告...")
            report, debug = engine.analyze_window_alert(
                alert,
                dump_dir=args.debug_dump_dir,
                return_debug=True,
                max_attack_graph_edges_print=int(args.max_attack_graph_edges),
            )

            if args.print_attack_graph and debug.get("attack_provenance_graph_edges"):
                print("\n" + "-" * 50)
                print(debug["attack_provenance_graph_edges"])
                print("-" * 50)

            prompt_for_print = debug.get("llm_stage3_prompt") or debug.get("prompt")
            if args.print_llm_context and prompt_for_print:
                p = str(prompt_for_print)
                head = p[: int(args.max_prompt_chars)]
                print("\n" + "-" * 50)
                print("LLM Prompt (truncated):")
                print(head)
                if len(p) > int(args.max_prompt_chars):
                    print(f"... (truncated, full prompt saved under {args.debug_dump_dir})")
                print("-" * 50)
            
            print("\n" + "="*50)
            print("分析报告")
            print("="*50)
            print(report)
            print("="*50)

    elif args.command == 'build_tik':
        from src.knowledge.kb_builders import build_tik
        build_tik()
        print("\n✅ TIK 知识库构建完成（tik_knowledge）")

    elif args.command == 'build_bbk':
        from src.knowledge.kb_builders import build_bbk
        build_bbk(
            args.log_file,
            logs_dir=str(args.logs_dir or ""),
            sampled_train_windows=str(args.sampled_train_windows or ""),
            full_window_index=str(args.full_window_index or ""),
            persist_windows_dir=str(args.persist_windows_dir or ""),
            window_seconds=int(args.window_seconds),
            time_bin_seconds=int(args.time_bin_seconds),
        )

    elif args.command == 'build_gmae_transfer':
        from src.knowledge.kb_builders import build_gmae_transfer

        summary = build_gmae_transfer(
            e3_dir=str(args.e3_dir),
            groundtruth=str(args.groundtruth),
            local_corpus=str(args.local_corpus),
            output_dir=str(args.output_dir or ""),
            e3_limit_windows=int(args.e3_limit_windows),
            local_limit_windows=int(args.local_limit_windows),
            e3_epochs=int(args.e3_epochs),
            local_epochs=int(args.local_epochs),
            window_seconds=int(args.window_seconds),
            stride_seconds=int(args.stride_seconds),
            time_bin_seconds=int(args.time_bin_seconds),
            dry_run=bool(args.dry_run),
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))

    elif args.command == 'build_ark':
        from src.knowledge.kb_builders import build_ark
        build_ark()

    elif args.command == 'replay':
        from src.analysis.report_generator import AnalysisEngine
        engine = AnalysisEngine()
        if bool(args.two_stage):
            from src.process.analysis_engine import detect_two_stage_window, summarize_two_stage_results
            from src.process.window_io import load_window_graph

            paths = [
                os.path.join(args.windows_dir, name)
                for name in os.listdir(args.windows_dir)
                if name.startswith("window_") and name.endswith(".json")
            ]
            paths.sort()
            results = []
            for path in paths:
                g = load_window_graph(path)
                result = detect_two_stage_window(
                    g,
                    {"window_id": os.path.basename(path)[:-5]},
                    engine.benign_kb,
                    None if bool(args.disable_gmae) else engine,
                    _two_stage_config_from_args(args),
                )
                results.append(result)
                _print_two_stage_result(result)
            summary = summarize_two_stage_results(
                results,
                top_k=int(args.top_k),
                window_seconds=int(args.window_seconds),
                stride_seconds=int(args.stride_seconds),
                window_mode=str(args.window_mode),
            )
            _write_two_stage_outputs(args.debug_dump_dir, results, summary)
            print(json.dumps({"two_stage_results": results}, ensure_ascii=False, indent=2))
            print(json.dumps({"two_stage_summary": summary}, ensure_ascii=False, indent=2))
            return

        alerts = engine.detect_window_alerts_from_windows(args.windows_dir, args.threshold)
        if not alerts:
            print("\n✅ 未发现窗口告警（基于当前阈值）")
            return
        print(f"\n⚠️ 发现 {len(alerts)} 个窗口告警:")
        for i, alert in enumerate(alerts, start=1):
            print(
                f"\n--- 窗口告警 #{i} "
                f"(window={alert.window_id}, score={float(alert.window_score):.3f}, file={alert.window_file or 'n/a'}) ---"
            )
            _print_window_alert_summary(alert, max_processes=int(DEFAULT_TOP_EVIDENCE_ITEMS))
            if bool(args.print_process_details):
                for proc in alert.top_processes[:DEFAULT_TOP_EVIDENCE_ITEMS]:
                    graph_context = str(proc.get("graph_context") or "").strip()
                    if graph_context:
                        print("\nGraph Context:")
                        print(graph_context)
            print("\n🤖 正在生成窗口级分析报告...")
            report, debug = engine.analyze_window_alert(
                alert,
                dump_dir=args.debug_dump_dir,
                return_debug=True,
                max_attack_graph_edges_print=int(args.max_attack_graph_edges),
            )
            prompt_for_print = debug.get("llm_stage3_prompt") or debug.get("prompt")
            if prompt_for_print:
                p = str(prompt_for_print)
                head = p[: int(args.max_prompt_chars)]
                print("\n" + "-" * 50)
                print("LLM Prompt (truncated):")
                print(head)
                if len(p) > int(args.max_prompt_chars):
                    print(f"... (truncated, full prompt saved under {args.debug_dump_dir})")
                print("-" * 50)
            print("\n" + "="*50)
            print("分析报告")
            print("="*50)
            print(report)
            print("="*50)

    elif args.command == 'realtime':
        from src.analysis.report_generator import AnalysisEngine
        from src.process.analysis_engine import summarize_two_stage_results
        from src.process.realtime_monitor import RealtimeConfig, iter_realtime_windows
        from src.process.window_io import dump_window_graph

        engine = AnalysisEngine()
        os.makedirs(args.debug_dump_dir, exist_ok=True)
        os.makedirs(args.persist_windows_dir, exist_ok=True)
        start_at_end = True
        if bool(args.start_from_begin):
            start_at_end = False
        if bool(args.with_llm):
            args.no_llm = False

        cfg = RealtimeConfig(
            window_mode=str(args.window_mode),
            window_seconds=int(args.window_seconds),
            stride_seconds=int(args.stride_seconds),
            time_bin_seconds=int(args.time_bin_seconds),
            poll_interval_seconds=float(args.poll_interval),
            start_at_end=bool(start_at_end),
            emit_partial=bool(args.emit_partial_window),
        )

        window_idx = 0
        two_stage_results = []
        overlap_seconds = 0
        if str(cfg.window_mode).lower() == "sliding":
            overlap_seconds = max(0, int(cfg.window_seconds) - int(cfg.stride_seconds))
        print(
            f"🔎 Realtime monitoring: file={args.log_file} "
            f"window_mode={cfg.window_mode} window_seconds={cfg.window_seconds}s "
            f"stride_seconds={cfg.stride_seconds}s time_bin_seconds={cfg.time_bin_seconds}s "
            f"overlap_seconds={overlap_seconds}s threshold={float(args.threshold)}"
        )
        if str(cfg.window_mode).lower() == "fixed":
            print("   fixed mode ignores stride_seconds and uses non-overlapping legacy windows")
        for g, metas in iter_realtime_windows(args.log_file, cfg):
            window_idx += 1
            win_name = f"window_{window_idx:04d}.json"
            win_path = os.path.join(args.persist_windows_dir, win_name)
            dump_window_graph(win_path, g)

            if bool(args.two_stage):
                from src.process.analysis_engine import detect_two_stage_window

                result = detect_two_stage_window(
                    g,
                    {"window_id": win_name[:-5]},
                    engine.benign_kb,
                    None if bool(args.disable_gmae) else engine,
                    _two_stage_config_from_args(args),
                )
                two_stage_results.append(result)
                _print_two_stage_result(result, prefix=f"[window#{window_idx}] ")
                if int(args.max_windows) > 0 and window_idx >= int(args.max_windows):
                    summary = summarize_two_stage_results(
                        two_stage_results,
                        top_k=int(args.top_k),
                        window_seconds=int(args.window_seconds),
                        stride_seconds=int(args.stride_seconds),
                        window_mode=str(args.window_mode),
                    )
                    _write_two_stage_outputs(args.debug_dump_dir, two_stage_results, summary)
                    break
                continue

            alerts = engine.detect_window_alerts_in_window(g, float(args.threshold), window_hint=win_name)
            if not alerts:
                print(f"[window#{window_idx}] ✅ no window alerts")
                if int(args.max_windows) > 0 and window_idx >= int(args.max_windows):
                    break
                continue

            alert = alerts[0]
            print(
                f"[window#{window_idx}] ⚠️ window_alert score={float(alert.window_score):.3f} "
                f"saved={win_name} suspicious_processes={int(alert.suspicious_process_count)}"
            )
            _print_window_alert_summary(
                alert,
                max_processes=int(args.max_process_evidence),
                prefix="  ",
            )

            if bool(args.no_llm):
                if int(args.max_windows) > 0 and window_idx >= int(args.max_windows):
                    break
                continue

            print(f"\n🤖 report window={alert.window_id} score={float(alert.window_score):.3f} ...")
            report, _debug = engine.analyze_window_alert(
                alert,
                dump_dir=args.debug_dump_dir,
                return_debug=True,
                max_attack_graph_edges_print=int(args.max_attack_graph_edges),
            )
            print(report)
            if int(args.max_windows) > 0 and window_idx >= int(args.max_windows):
                break
        if bool(args.two_stage):
            summary = summarize_two_stage_results(
                two_stage_results,
                top_k=int(args.top_k),
                window_seconds=int(args.window_seconds),
                stride_seconds=int(args.stride_seconds),
                window_mode=str(args.window_mode),
            )
            _write_two_stage_outputs(args.debug_dump_dir, two_stage_results, summary)

if __name__ == "__main__":
    main()
