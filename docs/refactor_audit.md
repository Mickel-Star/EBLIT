# EBLIT 目标新方案重构审计

审计日期：2026-05-08  
审计范围：本轮指定文件和与窗口质量直接相关的现有 benign corpus 索引。未修改 Python 源码、配置、脚本或数据文件。

## 1. 当前项目结构图

```text
EBLIT / DRSEC_v2
├── AGENTS.md
├── README.md                         # 当前不存在
├── src/
│   ├── common/
│   │   ├── defaults.py               # 全局阈值、窗口、Top-k、训练图质量默认值
│   │   └── gmae.py                   # DGL/Torch GMAE 模型、训练 loss、节点重构误差
│   ├── process/
│   │   ├── main.py                   # CLI: setup/analyze/build_bbk/build_tik/build_ark/replay/realtime
│   │   ├── log_parser.py             # Tracee JSON/JSONL 日志解析
│   │   ├── provenance_model.py       # Tracee 事件到溯源边映射、BBK 稀有路径搜索
│   │   ├── streaming_reduction.py    # legacy 固定窗口 reducer + 已新增但未接入主流程的 sliding reducer
│   │   ├── realtime_monitor.py       # tail Tracee 输出并用 fixed reducer 生成实时窗口
│   │   └── dgl_adapter.py            # NetworkX 窗口图转 DGL 图，供 GMAE 使用
│   ├── knowledge/
│   │   ├── benign_behavior_kb.py     # BBK SQLite 边频次/节点度/节点元数据和 support()
│   │   └── kb_builders.py            # TIK/ARK/BBK 构建、GMAE manifest 和离线 GMAE 训练
│   └── analysis/
│       └── report_generator.py       # 当前窗口告警、进程候选、GMAE 打分、BBK 稀有路径、LLM 报告核心
├── scripts/
│   ├── collect_benign_corpus.py      # benign corpus v3 采集与 dry-run 分布校验
│   ├── run_benchmark_matrix.py       # Docker/Tracee attack benchmark 采集、窗口物化、评估
│   └── eval_mix_accuracy.py          # process/window/role/scenario 多层级指标评估
├── tests/
│   └── test_sliding_window_reduction.py
├── config/ configs/                  # benchmark 与 benign corpus 配置
├── deploy/                           # Docker demo 与 vulnerable app
└── data/                             # 运行态 trace、窗口、KB、模型、corpus、benchmark
```

## 2. 文件职责

| 文件 | 当前职责和关键实现 |
|---|---|
| `AGENTS.md` | 定义研究、沟通、编码、测试和安全约束。项目结构说明在第 65-66 行，常用命令在第 68-76 行，测试建议在第 81-82 行。注意该文件仍称“没有 dedicated tests 目录”，但当前工作区已经有 `tests/test_sliding_window_reduction.py`。 |
| `README.md` | 当前仓库根目录未发现 `README.md` 或 `README*`。 |
| `src/common/defaults.py` | 当前全局默认值已改为目标倾向：`DEFAULT_WINDOW_SECONDS=1800`、`DEFAULT_DETECT_STRIDE_SECONDS=600`、`DEFAULT_TIME_BIN_SECONDS=30`、`DEFAULT_BBK_TRAIN_WINDOW_SECONDS=1800`、`DEFAULT_BBK_MIN/MAX_TRAIN_WINDOWS=10/20`、训练图质量阈值 500/1000/20/5。问题是后续主流程未全部消费这些默认值，质量阈值也未被 `kb_builders.py` 使用。 |
| `src/process/main.py` | CLI 总入口。`analyze` 和 `realtime` 的窗口长度默认来自 `DEFAULT_WINDOW_SECONDS`，`build_bbk` 默认来自 `DEFAULT_BBK_TRAIN_WINDOW_SECONDS`。执行路径仍是 `AnalysisEngine.detect_window_alerts()`、`detect_window_alerts_from_windows()`、`detect_window_alerts_in_window()`；`realtime` 通过 `iter_realtime_windows()` 生成窗口。`build_bbk` 的 help 文案仍写“默认 30s”，与当前常量 1800 不一致。 |
| `src/process/log_parser.py` | `TraceeLogParser` 只解析 Tracee JSON/JSONL；table 输出会被拒绝，因为 COMM/IMAGE 等固定宽度字段会截断且 syscall 参数类型信息不完整。 |
| `src/process/provenance_model.py` | `ProvenanceEventMapper` 将 Tracee 事件标准化为 `ProvenanceEdge`，`event_semantics` 定义 Read/Write/Send/Receive/Execute/Fork 等语义和方向；维护 fd 到 file/net 的短期映射。`RarePathSelector.select_with_chains()` 从进程节点做 k-hop 扩展，用 BBK `support_fn` 计算路径 rarity。 |
| `src/process/streaming_reduction.py` | 同时存在两套窗口构建：`StreamingReducer` 是 legacy 固定事件时间窗口，`ingest_edge()` 在 `timestamp - window_start >= window_ns` 时 flush 并以当前事件重置新窗口；`SlidingWindowConfig/SlidingWindowReducer` 已实现 1800 秒窗口、600 秒 stride 的重叠窗口逻辑，并给图写入 `sliding_window_config`、`window_start/end`、`event_count`、`complete`。 |
| `src/process/realtime_monitor.py` | `TraceeTail` tail 增长日志；`iter_realtime_windows()` 解析新增行后仍使用 `StreamingReducer` 和 `StreamingReductionConfig`，因此实时主路径仍是固定窗口，不是 sliding reducer。 |
| `src/process/dgl_adapter.py` | GMAE 适配层。`window_to_dgl_graph()` 将 NetworkX `MultiDiGraph` 转为 DGL graph，生成 `ndata["attr"]`、`edata["attr"]`、`ndata["is_process"]`，并返回 process node index 映射。模块顶层导入 `torch`，可选导入 `dgl`。 |
| `src/knowledge/benign_behavior_kb.py` | `BenignBehaviorKnowledgeBase` 管理 BBK SQLite 表：`edge_freq`、`node_degree`、`node_meta`。`update_from_edges()` 累加边频次和节点出入度；`update_word2vec_from_metas()` 训练/更新 Word2Vec；`support(src,dst,type)` 返回 `edge_freq/out_freq`，未知边返回 `1e-9`。 |
| `src/knowledge/kb_builders.py` | `build_tik()` 和 `build_ark()` 构建 TIK/ARK。`build_bbk()` 是 BBK+GMAE 训练入口：阶段 1 物化窗口并更新 BBK，阶段 2 写 GMAE manifest 并训练 baseline。`_build_bbk_from_sampled_train_windows()` 只用 sampled train 窗口更新 BBK/GMAE，calibration/holdout 进入 manifest。`_iter_bbk_windows()` 仍使用 `StreamingReducer`。`_evaluate_training_quality()` 当前只检查 trainable window 数量是否低于 10 和 profile imbalance warning。 |
| `src/analysis/report_generator.py` | 当前检测核心。`AnalysisEngine.__init__()` 加载 BBK 和 GMAE runtime。`detect_window_alerts*()` 生成窗口告警。`_process_candidates_from_graph()` 对每个进程节点先调用 `_gmae_process_scores()`，再计算 BBK rare paths；如果 GMAE 可用，`process_score` 来自 GMAE，否则才用 BBK rarity。`_build_window_alert()` 用最高进程分数作为 `window_score`。`analyze_window_alert()` 对一条窗口告警生成单份报告。 |
| `src/common/gmae.py` | DGL/Torch GMAE 实现。`build_model()` 构建 `GMAEModel`；`GAT/GATConv` 做带边特征的多头注意力；`GMAEModel.compute_loss_components()` 训练 masked node reconstruction + structure loss；`compute_node_reconstruction_errors()` 对指定节点或所有节点逐批 mask 并计算重构误差。训练时 `encoding_mask_noise()` 优先 mask process nodes。 |
| `scripts/collect_benign_corpus.py` | benign corpus v3 采集器。`expected_distribution()` 基于 `duration_seconds / window_seconds` 估算窗口数；`validate_distribution()` 校验 min_train/min_calibration/min_holdout/min_profile 和 profile imbalance；`collect_run()` 启动 Tracee 并写 `run_meta.json`；`write_corpus_manifest()` 写推荐 build_bbk 命令。它不构建图，也不计算图质量。 |
| `scripts/run_benchmark_matrix.py` | attack benchmark 编排。`materialize_windows()` 解析 trace 并用 `StreamingReducer` 固定窗口落盘；`benchmark_plan_summary()` 用固定窗口长度估计 expected windows；`execute_run()` 采集 trace、物化窗口、调用 `evaluate_single_run()`；CLI 默认 `--window-seconds 30 --time-bin-seconds 2` 仍硬编码，没有使用 `defaults.py`。 |
| `scripts/eval_mix_accuracy.py` | replay/benchmark 评估。`build_run_samples()` 每个窗口同时调用 `detect_window_alerts_in_window(threshold=0)` 和 `detect_suspicious_processes_in_window(threshold=0)`，因此评估仍触发 GMAE/BBK 混合路径。`_stage_label_for_window()` 根据窗口序号和 `window_seconds` 推断 `[0,w),[w,2w)`，没有读取图内真实 `window_start/window_end`。`evaluate_dataset()` 输出 process/window/role/scenario 指标和 TTD。 |

## 3. 当前检测流程

```text
Tracee JSON/JSONL
  -> TraceeLogParser
  -> ProvenanceEventMapper
  -> StreamingReducer fixed/tumbling windows
  -> AnalysisEngine.detect_window_alerts_in_window()
  -> _process_candidates_from_graph()
       -> _gmae_process_scores() if baseline exists
            -> window_to_dgl_graph()
            -> GMAEModel.compute_node_reconstruction_errors()
       -> RarePathSelector.select_with_chains(..., BBK.support)
       -> process_score = GMAE score if available, otherwise BBK rarity score
  -> _build_window_alert()
       -> window_score = highest process_score
       -> top_processes/top_rare_paths evidence
  -> analyze_window_alert()
       -> one report for the window alert, led by top process
       -> optional TIK/ARK/case memory enrichment
       -> LLM or Mock report
```

结论：当前主检测不是独立窗口级 gate。窗口告警阈值实际作用在窗口内最高进程分数上；当 GMAE baseline 存在时，窗口告警直接受 GMAE 节点重构误差控制。

## 4. 目标新方案流程

```text
离线：
良性 Tracee 日志
  -> 日志解析与事件标准化
  -> 长时间窗口溯源图构建
  -> 图质量筛选，仅保留 10-20 个高质量训练图
       node_count > 500
       edge_count > 1000
       process_node_count > 20
       edge_type_count >= 5
  -> 构建 BBK
  -> 训练 GMAE
  -> 良性校准集确定窗口级告警阈值和节点级异常阈值

在线：
Tracee 实时事件流
  -> 日志解析与事件标准化
  -> 维护最近 30min 事件缓存
  -> 每 10min 生成一次 30min sliding window graph
  -> BBK + 窗口统计特征做窗口级预筛选
  -> 正常窗口：不调用 GMAE，不调用 LLM
  -> 异常窗口：生成窗口级告警
       -> GMAE 只做进程节点级异常定位
       -> Top-k process nodes，默认 k=3
       -> 提取稀有路径、局部子图、威胁知识
       -> LLM 生成节点级证据约束报告
```

## 5. 明确问题回答

| 问题 | 当前结论 |
|---|---|
| 当前窗口构建是固定窗口还是滑动窗口？ | 主流程仍是固定事件时间窗口。`StreamingReducer.ingest_edge()` 是 tumbling window；`analyze`、`build_bbk`、`realtime`、benchmark、eval 都主要调用它。`SlidingWindowReducer` 已存在且有测试，但未接入 CLI/实时/训练/评估主路径。 |
| 当前默认窗口长度是多少？ | 核心常量当前是 1800 秒：`DEFAULT_WINDOW_SECONDS=1800`、`DEFAULT_BBK_TRAIN_WINDOW_SECONDS=1800`。但现有 `config/benign_corpus.default.json` 是 30 秒，`scripts/run_benchmark_matrix.py` CLI 默认仍是 30 秒，已有 `data/kb/gmae_baseline.meta.json` 的 `reduction_config.window_seconds` 也是 30。 |
| 当前是否支持 30min 窗口 + 10min 步长 + 20min 重叠？ | 工具层部分支持：`SlidingWindowConfig` 默认 1800/600，测试验证相邻窗口重叠 1200 秒。主流程不支持：`realtime_monitor.py` 和 `AnalysisEngine.detect_window_alerts()` 没有 stride 参数，也没有使用 `SlidingWindowReducer`。 |
| 当前训练窗口筛选是否考虑图质量指标？ | 不完整。`_records_from_window_index_rows()` 和 `_build_manifest_record()` 会记录 `node_count/edge_count/process_node_count`，但 `trainable` 只要求 `node_count > 0`；没有 `edge_type_count` 字段，也没有 `node_count > 500`、`edge_count > 1000`、`process_node_count > 20`、`edge_type_count >= 5` 的 gate。 |
| 当前是否支持只筛选 10-20 个高质量训练窗口？ | 不支持。`defaults.py` 有 10/20 常量，但 `DEFAULT_BBK_MAX_TRAIN_WINDOWS` 未被 `kb_builders.py` 使用；`_evaluate_training_quality()` 只检查 formal train 窗口数不少于 10，不限制最多 20，也不按质量排序筛选。现有 sampled train 文件有 313 行，当前 baseline meta 里 train window count 为 292。 |
| 当前 GMAE 是否在窗口级检测中被直接调用？ | 是。`detect_window_alerts_in_window()` 调 `_process_candidates_from_graph()`，该函数第一行调用 `_gmae_process_scores()`；`_build_window_alert()` 又用最高 `process_score` 作为 `window_score`。 |
| 当前窗口级检测和节点级定位是否使用不同原理？ | 否。窗口级告警是 top process score 触发，节点候选也是同一套 `_process_candidates_from_graph()`；有 GMAE 时二者都由 GMAE 节点重构误差主导，无 GMAE 时二者都由 BBK rare path fallback 主导。 |
| 当前 BBK 在检测流程中承担什么职责？ | BBK 存储良性边频次和节点度；检测时提供 `support()` 给 `RarePathSelector` 计算稀有路径，生成 evidence 和 BBK comparison；GMAE 不可用时，BBK rare path score 还会作为进程/窗口分数 fallback。 |
| 当前是否已有独立 BBK 窗口级异常预筛选逻辑？ | 没有。当前没有 `rare_edge_ratio`、`rare_edge_intensity`、`novel_entity_ratio`、`sensitive_behavior_score`、`graph_structure_deviation` 等窗口级统计 gate。 |
| 当前 LLM 报告生成是窗口级、进程级还是混合形式？ | 混合形式。主 CLI 对每个 `WindowAlert` 生成一份窗口报告，但 `analyze_window_alert()` 以 top process 作为 lead target，并聚合 top processes 与 top rare paths。`analyze_suspicious_process()` 仍是进程级接口。 |
| 当前是否支持只对 Top-k 异常进程节点调用 LLM？ | 不支持目标语义。当前 `DEFAULT_TOP_EVIDENCE_ITEMS=3` 控制报告里聚合多少 evidence；`DEFAULT_TOPK_NODE_REPORTS=3` 存在但未被主报告路径使用。系统默认每个窗口告警生成单份报告，而不是对 Top-k 节点分别生成节点级报告。 |
| 当前有哪些测试或脚本可以用于回归验证？ | `tests/test_sliding_window_reduction.py` 验证 sliding reducer 和 legacy fixed reducer 保持分离；`python -m src.process.main --help/setup/analyze/replay/realtime/build_bbk`；`scripts/collect_benign_corpus.py --dry-run`；`scripts/run_benchmark_matrix.py --dry-run`；`scripts/eval_mix_accuracy.py`；有 Docker/Tracee 时可跑 `run_realtime_demo.sh --no-llm` 或 benchmark smoke。 |

## 6. 现有数据质量观察

只读检查 `data/benign_corpus_v3/sampled_train_windows.jsonl`：

- rows = 313。
- `node_count`: min 0, max 4, avg 3.86。
- `edge_count`: min 0, max 138, avg 82.70。
- `process_node_count`: 字段缺失 313/313。
- `edge_type_count`: 字段缺失 313/313。
- 满足 `node_count > 500 && edge_count > 1000 && process_node_count > 20 && edge_type_count >= 5` 的窗口数为 0。

只读检查 `data/benign_corpus_v3/full_window_index.jsonl`：

- rows = 481，其中 train 314、calibration 67、holdout 100。
- `node_count`: min 0, max 4, avg 3.78。
- `edge_count`: min 0, max 207, avg 84.49。
- `unique_process_count`: min 0, max 2, avg 1.89。
- `process_node_count` 和 `edge_type_count` 缺失。
- 满足目标四项质量阈值的窗口数为 0。

只读检查当前 `data/kb/gmae_baseline.meta.json`：

- `saved_baseline=True`，`training_tier=formal`，`quality_gate_errors=[]`。
- `reduction_config.window_seconds=30`、`time_bin_seconds=2`。
- `process_error_calibration=None`。

这说明现有数据和当前 baseline 仍是短窗口稀疏训练产物，不能作为目标方案的高质量长窗口训练证据。

## 7. 差异清单

### A. 窗口构建层差异

当前实现：

- `StreamingReducer` 是主流程固定窗口，窗口起点由第一条事件锚定，flush 后以下一条事件开始新窗口。
- `SlidingWindowReducer` 已实现 30min/10min 重叠窗口，但只被 `tests/test_sliding_window_reduction.py` 覆盖，没有接入 `main.py`、`realtime_monitor.py`、`kb_builders.py`、benchmark 或 eval。
- `RealtimeConfig` 没有 `stride_seconds`，`iter_realtime_windows()` 仍实例化 `StreamingReducer`。

目标要求：

- 在线检测必须维护最近 30min 事件缓存，每 10min 生成一次新 30min sliding window，overlap 20min。
- legacy fixed window 可以保留，但新模式必须成为目标在线路径或通过参数明确启用。

差距：

- 有滑动窗口基础设施，但不是主路径。
- CLI、实时监控、训练、评估缺少 `stride_seconds` 与 `sliding/legacy` 模式边界。
- eval 的 `_stage_label_for_window()` 仍用窗口序号推断固定窗口边界，不能准确评估 sliding graph 的真实时间范围。

建议修改文件：

- `src/process/realtime_monitor.py`: 增加 `stride_seconds` 和 sliding mode，使用 `SlidingWindowReducer`。
- `src/process/main.py`: 增加 `--stride-seconds`、`--window-mode {sliding,legacy}`，实时输出显示窗口真实 start/end。
- `src/analysis/report_generator.py`: `detect_window_alerts()` 支持 sliding reducer 或保留 legacy 参数。
- `src/knowledge/kb_builders.py`: 训练窗口构建明确支持 long fixed 或 sliding，避免与 legacy 30 秒混用。
- `scripts/run_benchmark_matrix.py`、`scripts/eval_mix_accuracy.py`: benchmark 物化与标签评估支持 sliding window graph metadata。

### B. 训练窗口筛选层差异

当前实现：

- `defaults.py` 已声明训练图质量阈值和 10/20 个窗口目标。
- `kb_builders.py` 未导入 `DEFAULT_BBK_MAX_TRAIN_WINDOWS` 和四个 `DEFAULT_MIN_TRAIN_*` 常量。
- `_records_from_window_index_rows()` 只跳过 empty 和 `node_count <= 0`；`_build_manifest_record()` 只把 `trainable` 定义为 `node_count > 0`。
- `edge_type_count` 不计算、不入 manifest、不参与质量判断。
- `_evaluate_training_quality()` 只检查 formal train 窗口数不低于 10 和 profile imbalance warning。

目标要求：

- 保留 10-20 个高质量训练图。
- 单图尽量满足 `node_count > 500`、`edge_count > 1000`、`process_node_count > 20`、`edge_type_count >= 5`。
- 不复制窗口凑数；达不到阈值时如实报告原因。

差距：

- 当前训练会接受大量稀疏图。
- 没有质量排序、筛选上限、拒绝原因统计。
- 现有 sampled/full index 数据明显不满足目标质量阈值。

建议修改文件：

- `src/knowledge/kb_builders.py`: 增加 `edge_type_count` 计算；实现 `_score_train_window_quality()`、`_filter_high_quality_train_records()`；把 rejected reasons 写入 manifest/meta。
- `src/common/defaults.py`: 保留现有质量默认值，并增加是否严格执行、是否允许 relaxed fallback 的开关。
- `src/process/window_activity_builder.py` 或 `src/process/benign_manifest_builder.py`: 若继续依赖 index，需在 index 中生成 `process_node_count/edge_type_count`。
- `scripts/collect_benign_corpus.py`: dry-run 增加长窗口预期数量提示，避免 30 秒 config 与 1800 秒训练默认冲突。

### C. 窗口级检测层差异

当前实现：

- `detect_window_alerts_in_window()` 直接调用 `_process_candidates_from_graph()`。
- `_process_candidates_from_graph()` 总是先尝试 `_gmae_process_scores()`。
- `_build_window_alert()` 使用 top process score 作为 `window_score`。
- 没有独立窗口统计特征，也没有 BBK-only window gate。

目标要求：

- 窗口级检测不能使用 GMAE、DGL、torch 或节点重构误差。
- 窗口级检测应使用 BBK 和窗口统计特征，如 rare edge ratio/intensity、novel entity ratio、sensitive behavior score、graph structure deviation。

差距：

- 当前窗口级检测违反“不得调用 GMAE/DGL/torch”的约束。
- 当前窗口分数与节点分数混用，无法解释为独立窗口级异常预筛选。
- LLM/GMAE 虽不直接参与最终报告前的自然语言判定，但 GMAE 已参与窗口阈值判定。

建议修改文件：

- `src/analysis/report_generator.py`: 新增 `score_window_with_bbk_gate(g)` 或独立 `WindowGateScorer`；让 `detect_window_alerts_in_window()` 先执行 BBK/stat window gate。
- `src/knowledge/benign_behavior_kb.py`: 可能增加查询接口以支持实体新颖度、边类型频次、节点度分布。
- `src/common/defaults.py`: 增加窗口 gate 特征权重和阈值默认值。

### D. 节点级定位层差异

当前实现：

- `_process_candidates_from_graph()` 同时负责窗口告警前候选生成和节点分数。
- 有 GMAE 时 `score_source="gmae"`；无 GMAE 时 fallback 到 `score_source="bbk"`。
- BBK rare path score 被写入候选 evidence，但 `rarity_score` 字段在 GMAE 模式下等于 GMAE score，命名存在混淆。

目标要求：

- GMAE 只在 BBK window gate 触发告警之后做进程节点级定位。
- GMAE 节点分数和 BBK 解释分数不能混用。
- 默认 Top-k 进程节点 k=3。

差距：

- 节点定位没有独立的“告警后”入口。
- `process_score`、`rarity_score`、`top_path_score` 的语义不清晰，容易把 GMAE 分数和 BBK 稀有度混为一类。
- `DEFAULT_TOPK_NODE_REPORTS` 已存在但未用于节点定位/报告流程。

建议修改文件：

- `src/analysis/report_generator.py`: 拆出 `_localize_process_nodes_with_gmae_after_gate()`，输出 `gmae_node_score`；BBK rare path 只输出 `bbk_path_rarity`。
- `src/process/dgl_adapter.py`: 保留为 GMAE 定位适配层，不应被 window gate 代码路径导入。
- `src/common/gmae.py`: 大概率无需大改；可确认 `compute_node_reconstruction_errors(node_indices=...)` 满足 Top-k 定位效率。

### E. LLM 报告生成层差异

当前实现：

- `analyze_window_alert()` 每条窗口告警生成单份报告，以 top process 为 lead target，合并最多 3 个 top process 的 graph context。
- `_generate_report_staged()` stage3 明确要求 LLM “Provide a verdict (Malicious/Benign/Unknown)”。
- Mock fallback 也生成 incident report，但不会改变阈值判断。

目标要求：

- LLM 不参与异常判定，只对 Top-k 异常进程节点生成证据约束报告。
- 报告应强调证据、稀有路径、局部子图、威胁知识，不承担最终分类裁决。

差距：

- LLM 确实在告警后调用，但报告 prompt 包含 verdict，职责边界不够清楚。
- 当前是窗口级单报告 + top process lead，不是 Top-k 节点级报告。

建议修改文件：

- `src/analysis/report_generator.py`: 增加 `analyze_topk_process_nodes(alert, k=DEFAULT_TOPK_NODE_REPORTS)`；调整 prompt，去掉 verdict，改为“已触发告警后的证据约束分析、置信度和处置建议”。
- `src/process/main.py`: CLI 输出区分 window alert summary 和 node report 列表；`--no-llm/--with-llm` 继续保留。

### F. CLI / 实时检测流程差异

当前实现：

- `analyze/realtime/build_bbk` 已从 `defaults.py` 拿到 1800 秒默认值。
- `realtime` 没有 stride 参数，仍由 `iter_realtime_windows()` 产生 fixed windows。
- `--max-alerts-per-window` 是兼容参数，固定每窗口最多一条窗口告警。
- `--no-llm` 默认 True，`--with-llm` 才生成报告，这符合降低在线成本的方向。

目标要求：

- 在线窗口机制是真正 sliding window：1800/600/1200。
- 正常窗口不调用 GMAE/LLM，异常窗口才触发 GMAE 和 LLM。
- 保留旧流程 legacy mode 或兼容参数。

差距：

- 缺少 `--stride-seconds` 和 `--mode`。
- 正常窗口当前如果 GMAE baseline 可用，仍会在判定前调用 GMAE；不是“正常窗口不调用 GMAE”。
- `build_bbk` help 文案与默认值不一致。

建议修改文件：

- `src/process/main.py`: 增加 `--stride-seconds`、`--legacy-window-mode` 或 `--window-mode`；修正 build_bbk help 文案；输出 score source。
- `src/process/realtime_monitor.py`: 改为 sliding reducer；保留 fixed reducer legacy path。
- `run_realtime.sh`、`run_realtime_demo.sh`: 如脚本显式传窗口参数，需同步默认值和模式。

### G. 实验与评估脚本差异

当前实现：

- `scripts/run_benchmark_matrix.py` 使用固定窗口物化，默认 30/2 硬编码。
- `_window_overlap_count()` 和 `expected_windows` 按 non-overlap fixed window 估算。
- `scripts/eval_mix_accuracy.py` 用窗口序号推断窗口时间，评估时调用当前混合检测路径，阈值 sweep 明确警告不能用于 formal calibration。
- `tests/test_sliding_window_reduction.py` 已验证 sliding reducer，但不是完整检测回归。

目标要求：

- benchmark 和 eval 应能处理 1800/600 sliding windows。
- 应分别评估 window gate、node localization、LLM 报告覆盖，不用 attack_dev 调阈值替代 benign calibration。

差距：

- benchmark 默认值和物化逻辑仍是旧 30 秒 fixed。
- eval 没有读取 graph metadata 中的真实 `window_start/end`，不能准确评估 sliding overlap。
- 缺少窗口 gate 不导入 GMAE 的回归测试。

建议修改文件：

- `scripts/run_benchmark_matrix.py`: 默认值改从 `src.common.defaults` 读取；支持 sliding materialization；expected window count 使用 stride。
- `scripts/eval_mix_accuracy.py`: 优先读取图内 `window_start/window_end`，再 fallback 到序号；指标中记录 `window_score_source`、`node_score_source`。
- `tests/test_sliding_window_reduction.py`: 保留现有测试，新增集成级测试覆盖 `AnalysisEngine` 的 gate/localization 调用顺序。

## 8. 后续重构建议

1. 先做最小闭环：只改实时/分析主路径，不动 GMAE 模型结构。新增 BBK-only `WindowGateScorer`，让 `detect_window_alerts_in_window()` 先输出 window score。
2. 将 `_process_candidates_from_graph()` 拆成两个函数：legacy 兼容路径和 `localize_processes_after_window_alert()`。后者只在 window gate 告警后调用 GMAE。
3. 为 `WindowAlert` 增加显式字段：`window_score_source`、`window_features`、`localization_score_source`、`topk_process_nodes`，避免 `rarity_score` 与 GMAE score 混用。
4. 将 `SlidingWindowReducer` 接入 `realtime_monitor.py`，并通过 `--window-mode legacy|sliding` 保留旧 fixed window 行为。
5. 在 `kb_builders.py` 增加训练图质量筛选和拒绝报告。默认筛选 10-20 个高质量窗口；如果没有足够图，直接写明各指标最大值和失败原因。
6. 重建 benign corpus 或至少重建窗口图时，使用 1800 秒窗口，避免继续用现有 30 秒稀疏索引训练。
7. LLM prompt 改为“证据约束解释”，不要让 LLM 输出 Malicious/Benign 判定。LLM 可以输出 uncertainty，但不应反向影响告警。
8. 评估分三层：window gate FPR/recall/TTD，GMAE node localization Top-k hit rate，LLM report evidence coverage。阈值校准只用 benign calibration。

## 9. 预计需要修改的文件列表

| 文件 | 预计修改点 |
|---|---|
| `src/common/defaults.py` | 保留当前 1800/600/10-20/质量阈值；新增 window gate 特征权重、relaxed fallback 开关、score source 名称常量。 |
| `src/process/streaming_reduction.py` | `SlidingWindowReducer` 基础可保留；可能补充迟到事件处理、最大缓存保护、真实窗口边界元数据一致性。 |
| `src/process/realtime_monitor.py` | 接入 `SlidingWindowReducer`；`RealtimeConfig` 增加 `stride_seconds/window_mode/emit_partial`。 |
| `src/process/main.py` | CLI 增加 stride/mode/top-k 参数；修正 help 文案；实时路径按 gate -> GMAE -> LLM 执行；保留 legacy mode。 |
| `src/analysis/report_generator.py` | 最大改动点：拆分 window gate、GMAE localization、BBK rare path explanation、Top-k node LLM report；移除 LLM verdict 语义。 |
| `src/knowledge/benign_behavior_kb.py` | 增加窗口统计所需查询能力，如边类型支持度、节点/实体新颖度、敏感路径支持度。 |
| `src/knowledge/kb_builders.py` | 长窗口训练、图质量字段、10-20 窗口筛选、calibration score/threshold 元数据、失败原因报告。 |
| `src/process/dgl_adapter.py` | 保持 GMAE-only 调用边界；不应被 window gate 导入。 |
| `src/common/gmae.py` | 主要保持；如需效率优化，可利用 `node_indices` 只对 process nodes 计算。 |
| `scripts/collect_benign_corpus.py` | dry-run 与 manifest 中同步长窗口目标和质量预期；避免 30 秒 config 与代码默认冲突。 |
| `scripts/run_benchmark_matrix.py` | 默认值统一到 `defaults.py`；支持 sliding materialize 和 stride-based expected windows。 |
| `scripts/eval_mix_accuracy.py` | 使用图内真实窗口时间；分开评估 window gate 与 node localization。 |
| `tests/test_sliding_window_reduction.py` | 保留；补充 AnalysisEngine gate/localization 顺序测试。 |

## 10. 风险点说明

- 当前 `src/common/defaults.py` 和 `src/process/streaming_reduction.py` 已是工作区 modified 状态，审计按当前文件内容判断；这些改动是否已被用户确认需要另行管理。
- 现有 `data/kb/gmae_baseline.meta.json` 来自 30 秒稀疏窗口，不能代表 1800 秒目标训练结果。
- `DEFAULT_TIME_BIN_SECONDS` 当前为 30，但 benchmark 仍默认 2；不同路径生成的图特征会不可比。
- `SlidingWindowReducer` 假设事件时间非递减。真实 Tracee tail 若存在乱序或 flush 延迟，需要策略，否则 30min cache 可能漏算或重复。
- 30min sliding window 会显著增大图规模和内存；需要在 reducer 中设置缓存上限、窗口物化策略和 GMAE 推理批大小。
- BBK window gate 的特征权重和阈值需要 benign calibration 支持；不能用 attack benchmark sweep 代替正式阈值校准。
- 如果按目标质量阈值严格执行，现有 benign corpus 没有可用训练窗口；需要先重新采集或重新物化长窗口，而不是复制短窗口凑数。
- LLM 报告 prompt 若继续要求 verdict，容易被误读为检测判定。应在接口和文案上明确 LLM 只解释已触发告警的证据。

## 11. 最小回归验证建议

不修改源码时可执行的只读/低风险入口：

```bash
.venv/bin/python -m src.process.main --help
.venv/bin/python scripts/collect_benign_corpus.py --help
.venv/bin/python scripts/run_benchmark_matrix.py --help
.venv/bin/python scripts/eval_mix_accuracy.py --help
.venv/bin/python -m unittest tests.test_sliding_window_reduction
```

有可用窗口数据时：

```bash
.venv/bin/python -m src.process.main replay data/processed/realtime_windows --threshold 0.5
.venv/bin/python scripts/eval_mix_accuracy.py --windows-dir data/processed/realtime_windows
.venv/bin/python scripts/run_benchmark_matrix.py --mode smoke --dry-run
.venv/bin/python scripts/collect_benign_corpus.py --config config/benign_corpus.default.json --dry-run
```

Docker/Tracee 环境可用时再运行 `run_realtime_demo.sh --no-llm` 或 benchmark smoke。
