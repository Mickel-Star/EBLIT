# Repository Guidelines
## Role
You are a research-oriented coding and analysis partner for my project.

## Communication style
Be objective, rigorous, and critical.
Do not flatter, overpraise, or agree too quickly.
Maintain a sober, evidence-seeking tone when discussing ideas; do not present speculative claims as established facts.
When discussing ideas, explicitly state:
what is promising,
what is weak or risky,
what evidence is missing,
what the cheapest useful validation is.

## Research workflow
For any research idea, separate:
hypothesis,
relation to prior work,
likely novelty versus recombination,
implementation difficulty,
evaluation plan.
When exploring an idea, actively connect it to both:
frontier papers or recent research directions,
relevant open-source repositories or concrete implementations.
Do not rely only on internal model knowledge for research discussions when external evidence is important.
When using papers or repositories, distinguish:
what the paper/repo claims,
what is actually implemented,
what remains unclear.

## Architecture explanation style
Explain systems in input-to-output order.
Map paper ideas to repository files whenever possible.
When explaining code, start from first principles and explain it in a logical, step-by-step order.
Prefer explaining code in execution order: what the inputs are, how state changes, what each block is doing, and what outputs or side effects are produced.
Make code explanations structured and easy to follow, with clear causal links rather than isolated local descriptions.

## Coding workflow
Before writing substantial code, first propose a minimal implementation plan.
Prefer the smallest runnable slice first.
Keep changes localized unless a broader refactor is explicitly requested.
After coding, re-check correctness by:
reviewing logic,
checking interfaces,
running the smallest meaningful validation,
reporting remaining uncertainty.

## Tool usage
Use external tools such as GitHub or paper/document access when external evidence is needed.
If MCP-backed tools are unavailable or insufficient, fall back to web search or other available external search tools rather than relying purely on memory.
When discussing ideas, related work, or external implementations, proactively search for relevant evidence when it is likely to improve accuracy or sharpen criticism.
Use subagents only for clearly separable tasks.
Avoid spawning subagents for casual brainstorming or small edits.
For complex tasks, it is acceptable to spawn a small number of subagents when doing so materially improves parallel exploration, implementation, or verification.
Prefer keeping subagent responsibilities narrow and non-overlapping, and integrate their outputs critically rather than trusting them by default.
When discussing related work, prefer MCP-backed paper/document tools over unsupported guesses.
When discussing open-source implementations, prefer MCP-backed repository/GitHub tools and local workspace evidence.
Distinguish clearly between evidence from papers, evidence from repositories, and personal inference.

## Language preference
Communicate with the user in Chinese by default.
It is fine to use English for code, code comments, config keys, commit messages, tool calls, and agent-to-agent communication when that is more efficient or standard.
When explaining technical ideas to the user, prefer clear Chinese first, but preserve important technical terms in English when needed for precision.

## Project Structure & Module Organization
`src/process/` contains the main CLI, Tracee log parsing, streaming reduction, realtime monitoring, and window persistence. `src/analysis/` holds suspicious-process scoring and LLM report generation. `src/knowledge/` builds the BBK, TIK, and ARK stores plus MITRE/STIX loaders. Shared helpers live in `src/common/`. Use `deploy/` for the Docker demo stack and vulnerable app. Treat `data/` as runtime state for raw traces, generated windows, debug dumps, vector stores, and models; avoid committing regenerated artifacts unless they are fixtures. Helper scripts live in `scripts/`.

## Build, Test, and Development Commands
Use a local virtual environment: `python -m venv .venv && .venv/bin/pip install -r requirements.txt`.

- `.venv/bin/python -m src.process.main setup` creates expected `data/` and `logs/` directories.
- `.venv/bin/python -m src.process.main build_bbk data/raw/benign_tracee.log` refreshes the benign baseline.
- `.venv/bin/python -m src.process.main build_tik` and `.venv/bin/python -m src.process.main build_ark` rebuild knowledge stores.
- `./run_realtime.sh --with-llm` runs live monitoring; `./run_realtime_demo.sh --no-llm` runs the Docker demo without LLM calls.
- `.venv/bin/python scripts/eval_mix_accuracy.py --windows-dir data/processed/realtime_windows` evaluates replay output.
- `./scripts/cleanup_generated_artifacts.sh` removes generated realtime/debug artifacts.

## Coding Style & Naming Conventions
Follow the existing Python style: 4-space indentation, type hints where practical, and focused functions. Keep naming consistent with the codebase: `snake_case` for modules, functions, and variables; `PascalCase` for classes; `UPPER_SNAKE_CASE` for constants. Add new logic under the existing domain packages instead of extra top-level scripts. There is no formatter or linter config in this repo, so match surrounding style and run `python -m compileall src scripts` before submitting.

## Testing Guidelines
There is no dedicated `tests/` directory or coverage gate yet. Every change should include a syntax check plus one path-specific smoke test such as `build_bbk`, `replay`, or `./run_realtime_demo.sh`. If you touch evaluation logic, rerun `scripts/eval_mix_accuracy.py` and capture the command used.

## Commit & Pull Request Guidelines
This workspace snapshot does not include `.git`, so local history cannot be used to infer a commit convention. Until one is documented, use short imperative commits such as `fix: tighten realtime threshold parsing`. Pull requests should explain which pipeline stage changed, list validation commands, link related issues, and include screenshots or log excerpts when detection output or demo behavior changes.

## Security & Configuration Tips
Do not commit secrets or local overrides. Put provider settings in `config/config.local.json` or environment variables such as `DEEPSEEK_API_KEY`, `MISTRAL_API_KEY`, and `PROXY_PORT`. Keep large generated assets in ignored paths like `data/kb/`, `data/models/`, and raw trace logs unless the update is explicitly required.

---

## Project Overview（项目整体定位）

EBLIT 是一个**面向容器场景的、基于溯源图（Provenance Graph）与多知识库驱动的两阶段入侵检测 + LLM 调查系统**。核心思路：

1. 用 Tracee（eBPF）抓取容器内 syscall 流；
2. 切成滑动窗口，构建窗口级溯源图；
3. 在 BBK（良性基线）+ TIK（威胁情报向量库）+ ARK（MITRE 攻击逻辑图）支撑下，先做 **BBK 窗口级稀有性粗筛**，再对可疑窗口跑 **GMAE 节点级重构误差细筛**（两阶段检测）；
4. 对命中窗口做 **攻击图重构 + 攻击链可达性推理 + 三段式受约束 LLM Prompt**，最终输出可读事故报告。

代码组织按 "采集 → 处理 → 知识 → 检测 → 报告" 五段流水线切分。

---

## Module Responsibilities（模块职责）

### `src/process/` — 采集与处理层
- `log_parser.py`：`TraceeLogParser`，只接受 JSON/JSONL 格式，自动拒绝 Tracee table 输出；智能识别 ns/μs/ms/s 时间戳。
- `provenance_model.py`：`ProvenanceEventMapper` 把单事件转 `ProvenanceEdge`。维护 `_fd_files / _fd_nets / _fd_local_sockets` 三类作用域状态机；`fork/vfork/clone` 写新 proc 节点；区分 forward / backward 边。
- `streaming_reduction.py`：暴露 `SlidingWindowReducer`（主链）与 `StreamingReducer`（fixed 桶），按 `(edge_type, event_name, bin_idx)` 合并边；`iter_window_graphs` 是统一入口。
- `realtime_monitor.py`：`TraceeTail` 增量 tail + 喂入 reducer；持久化到 `data/processed/realtime_windows/window_*.json`。
- `analysis_engine.py`：`detect_two_stage_window` 主入口，串联 BBK 粗筛与 GMAE 细筛。
- `dgl_adapter.py`：把 `nx.MultiDiGraph` 转 DGL 异构图 + 节点/边特征；`feature_profile=transfer_v1` 用于 E3 迁移训练。
- `e3_cdm_adapter.py`：把 DARPA E3 CADETS CDM 18 适配为统一 `ProvenanceEdge`，按 groundtruth 剔除恶意 UUID。
- `vector_db.py / vectorizer.py`：ChromaDB + Word2Vec/Doc2Vec，离线时退化为 SHA256 哈希向量。
- `window_io.py`：窗口图落盘/读盘（JSON 格式 `{metadata, nodes, edges}`）。
- `benign_manifest_builder.py / benign_workload_driver.py / window_activity_builder.py`：良性语料采集编排与窗口活动度评估。
- `main.py`：CLI 入口（`analyze / build_bbk / build_tik / build_ark / replay / realtime / build_gmae_transfer` 等子命令）。

### `src/knowledge/` — 知识库层
- `benign_behavior_kb.py`：`BenignBehaviorKnowledgeBase`（SQLite + gensim）。三张表：`edge_freq / node_degree / node_meta`。`support(src, dst, type) = total_freq / max(out_freq(src), 1)`，钳到 `[1e-9, 1.0]`，是稀有性打分核心。
- `stix_loader.py`：下载/缓存 `enterprise-attack.json`，筛 `x_mitre_platforms` 含 "container" 的 `attack-pattern`。
- `asg_transformer.py`：把 MITRE 技术描述按工具/对象词表拆成 `(Adversary uses Tool targets Object)` 三元组路径，喂给 Doc2Vec。
- `threat_intel_kb_builder.py`：`build` 后把每条 ASG path 用 Doc2Vec 编码，写入 ChromaDB collection `tik_knowledge`。
- `logic_graph_builder.py`：把容器相关 MITRE 技术按 `tactic_order` 建完全跨层逻辑图，序列化到 `ark_logic_graph.json`。
- `kb_builders.py`：三大知识库 + GMAE 训练编排主入口。`build_bbk` 两阶段：Stage 1 累边频/Word2Vec；Stage 2 训 GMAE（含质量门 + calibration）。`build_gmae_transfer` 先 E3 预训练再本地微调。
- `kb_paths.py`：所有知识库产物路径统一管理 + 自动迁移。

### `src/analysis/` — 分析与报告层
- `bbk_window_scorer.py`：`score_bbk_window` 算 BBK 分数。`raw_score = -log2(support)`，归一化为 `_normalize_rarity = 1 - exp(-raw_score * ln2)` 钳到 `[0,1]`；`bbk_score = 0.5 * rare_edge_ratio + 0.5 * top_rare_mean`。
- `llm_client.py`：OpenAI 兼容客户端，自动选 DeepSeek / Mistral / Ollama / Mock。`get_llm_client` 是统一工厂。
- `report_generator.py`：`AnalysisEngine` 串联攻击图重构、TIK 检索、攻击链重构、三段式 LLM Prompt（Stage1 IOC 抽取 → Stage2 TTP 映射 → Stage3 综合报告），最后 `_validate_report` 回扫过滤未在 `AllowedEntities / AllowedTechniques` 中的实体，避免幻觉。

### `src/common/` — 公共工具
- `defaults.py`：全局默认参数（阈值、窗口长度、时间桶等）。
- `io.py`：JSON / JSONL / YAML / 路径工具。
- `text.py`：标识符分词器（`tokenize_identifier`）。
- `gmae.py`：`GATConv + GMAEModel`，编码器多层带边特征 GAT（多头拼接 + 残差 + BatchNorm + PReLU）；解码器重建节点特征 + 边结构；损失 `SCE(node_recon) + BCE(structure_recon)`，仅掩码 `is_process=True` 的节点。
- `benchmarking.py`：场景清单 / 标签校验 / 指标工具。

### `scripts/` — 编排脚本
- `collect_formal_benign_corpus_v3.sh` + `run_benign_corpus_v3_tracee.sh`：良性语料采集编排。
- `collect_rich_benign_corpus.py / collect_formal_rich_benign_corpus_v4.py`：富化语料采集。
- `check_benign_corpus_v3.py`：语料校验。
- `validate_provenance_windows.py`：窗口图结构校验。
- `eval_mix_accuracy.py`：离线评估（多 run × 多窗口 × 多种检测模式），输出 TP/FP/FN/TN。
- `eval_benign_holdout.py`：holdout 集（run_d）误报率评估。
- `run_benchmark_matrix.py`：以 `config/benchmark_scenarios.{atomic,full}.json` 编排 run × repeat × profile × mode 矩阵。
- `benign_profiles/vuln_app.py`：攻击/良性负载的应用。

---

## Data Chain（数据链，按执行顺序）

### 阶段 A — 数据采集
- **Tracee 容器 eBPF**：`run_realtime*.sh` 启 `aquasec/tracee:0.24.1` 抓 syscalls（execve/openat/read/write/connect/accept/sendto/recvfrom/fork/clone/vfork/mmap/security_socket_* 等），落 `data/raw/realtime_tracee.log`。**注意：text 表格式会被 `log_parser` 拒收**。
- **DARPA E3 CADETS**：`e3_cdm_adapter.iter_cadets_events` 把 CDM 18 JSON-Lines 转 `ProvenanceEdge`，按 groundtruth 剔除恶意 UUID。流式进 reducer，不落盘原始。
- **本地 benign 语料**：`collect_formal_benign_corpus_v3.sh` 编排采集 + window activity + manifest；落 `data/benign_corpus_v3/{run_a,b,c,d}/{trace.log, window_activity.jsonl, run_meta.json, request_events.jsonl}`。
- **Corpus 清单**：`benign_manifest_builder` 写 `sampled_train_windows.jsonl`（训练采样）与 `full_window_index.jsonl`（含 calibration/holdout）。
- **固定 split**：`run_a/b → train`、`run_c → calibration`、`run_d → holdout`（见 `kb_builders._default_split_role_for_run`）。

### 阶段 B — 日志解析 → 溯源边
1. `TraceeLogParser`：`detect_trace_log_format` 拒绝 table 格式；`_json_timestamp_seconds` 智能识别 ns/μs/ms/s。
2. `ProvenanceEventMapper`：
   - 维护 `_fd_files / _fd_nets / _fd_local_sockets` 三类作用域状态机；
   - 纯状态事件（socket/bind/listen/getpeername/getsockname）只更新缓存，不产边；
   - `openat` 用 `ret` 写文件 fd；`connect/accept` 用 `ret` 写网络 fd；
   - 区分 forward（proc→obj：Write/Execute/Fork/Send）与 backward（obj→proc：Read/Receive/Mmap）；`fork/vfork/clone` 把 child_pid 写成新 proc 节点。
3. 节点 ID 规则：
   - 进程：`proc:container:<container_id前12位>:pid:<pid>`
   - 文件：`file:<path>|inode:<inode>`
   - 网络：`net:<proto>:<src_ip>:<src_port>-><dst_ip>:<dst_port>`

### 阶段 C — 流式归约 → 窗口图
- `SlidingWindowReducer` 为主链；`StreamingReducer`（fixed 桶）保留作 baseline。
- 归约时同类边按 `(edge_type, event_name, bin_idx)` 合并，累加 count/last_ts/segments。
- 元数据写入：`reduction_config + sliding_window_config + window_start/end_ns + window_mode`。
- `iter_window_graphs(logs, mode, window_seconds, stride_seconds, time_bin_seconds, mapper, emit_partial)` 是上层统一入口。
- 持久化：`dump_window_graph / load_window_graph`（JSON）。

### 阶段 D — 实时流
- `iter_realtime_windows(file_path, cfg)`：`TraceeTail`（`start_at_end`）按 `poll_interval_seconds` 轮询；新行 → `SlidingWindowReducer.ingest_log`。
- 无新行时按 `emit_partial` 决定是否 yield 当前未完成窗口（实时模式默认不 emit）。
- 落盘：`data/processed/realtime_windows/window_NNNN.json`；调试转储 `data/processed/realtime_debug/`。

### 阶段 E — 知识库构建
- **BBK**：SQLite `data/kb/bbk.sqlite` + gensim `data/models/bbk_word2vec.model`；边频次 + 节点度 + 节点元数据；训练时过滤 `is_unspec_net` 节点；`update_word2vec_from_metas` 多 epoch 扩 vocab。
- **TIK**：STIX → 容器相关 technique → `ASGTransformer` → Doc2Vec 编码 → ChromaDB `tik_knowledge` collection。
- **ARK**：`LogicGraphBuilder.build_graph` 按 `tactic_order` 建完全跨层逻辑图，序列化为 `data/kb/ark_logic_graph.json`。
- **GMAE 训练编排（`kb_builders.py`，最重）**：
  1. Stage 1：消费 `sampled_train_windows.jsonl`（仅 `split=train && activity≠empty`），或从 `--logs-dir` 启动 tracee → windowing → manifest；`update_from_edges` 累 BBK。
  2. Stage 2：`build_gmae_transfer` 可先 E3 预训练再 local 微调；`_train_gmae_from_manifest` 按 epoch 选 `train_mean_total_loss` 最小的 checkpoint；`_calibrate_gmae_from_split` 用 calibration 集算 process_error 阈值（默认 p95）。
  3. 落盘：`gmae_baseline.pt + gmae_baseline_meta.json + gmae_calibration.json + process_error_calibration.json`。
  4. Staging 目录（`data/processed/gmae_bbk_staging_*`）训练通过后清理。
- **质量门**（来自 `defaults.py`）：最小窗口数 / profile 平衡比 / 最低节点/边/proc/边类型数；不达标会在 `build_bbk` 末尾抛 `RuntimeError`。

### 阶段 F — 两阶段检测
1. **BBK 粗筛**（`score_bbk_window`）：
   - 遍历所有边调 `bbk.support(src, dst, type)`；`raw_score = -log2(support)`；
   - 归一化 `_normalize_rarity = 1 - exp(-raw_score * ln2)` 钳到 `[0,1]`；
   - `rare_edge_ratio = count(support ≤ 1e-3) / total_edges`；
   - `bbk_score = 0.5 * rare_edge_ratio + 0.5 * top_rare_mean`（**默认阈值 0.5**）。
2. **GMAE 细筛**（**仅**在 bbk_score ≥ 阈值时触发，`--force-gmae-all-windows` 可强制）：
   - DGL 图构建：`process/dgl_adapter.window_to_dgl_graph`，节点/边特征用 `_node_feature / _edge_feature`（前缀 one-hot + 7 维结构化统计 + 哈希 token embedding）。
   - GMAE 推理：取**进程节点**的 `SCE` 误差作为 `process_score`。
3. **进程候选 → 窗口告警**（`_process_candidates_from_graph + _build_window_alert`）：
   - 对每个 proc 节点取 GMAE `process_score`；fallback 时取 BBK 稀有路径 top-1 score；
   - `RarePathSelector.select_with_chains` 做 k1 跳 BFS + k2 返回的稀有路径回溯；稀有度 = `-Σ log2(support(each_edge))`；
   - 阈值过滤排序后取 top-3 进 `WindowAlert`。

### 阶段 G — LLM 报告
- `_ensure_enrichment` 懒加载：LLM 客户端、Word2Vec/Doc2Vec、ChromaDB（`tik_knowledge` + `case_memory`）、ARK 逻辑图。
- **三段式 prompt**（每个进程候选一次）：
  1. **Stage1（IOC 抽取）**：只输出 Evidence 中**字面出现**的 IOC。
  2. **Stage2（TTP 映射）**：只映射到 `AllowedTechniques`（从 TIK 抽 TechniqueID + `reconstruct_attack_chain(detected_tech_ids)` 给 attack_chain），输出 Stage / TechniqueID / Confidence / EvidenceSnippet 表。
  3. **Stage3（综合报告）**：塞入 BBK 上下文、稀有路径、证据图、相似历史 cases、IOC、Stage2 映射，**约束**只能引用 `AllowedEntities` 和 `AllowedTechniques`。
- **回扫校验**：`_validate_report` 把报告里出现的、未在 `allowed_paths/ips/tech` 中的实体追加到 `Unverified Mentions`，避免幻觉。
- 调试产物落 `data/processed/<realtime_debug|debug>/pid_<pid>_<name>_{prompt,prompt_stage1,prompt_stage2,attack_graph,report.md,debug.json}`。

### 阶段 H — 回放与评估
- `replay`：从 `data/processed/realtime_windows/window_*.json` 重建窗口，调 `AnalysisEngine.detect_window_alerts_from_windows` 或 `detect_two_stage_window`，可与 LLM 重报。
- `eval_mix_accuracy.py`：按容器 ID + 时间窗与 `run_meta.json` 标签做 TP/FP/FN/TN；支持两阶段 + V1 GMAE + BBK-only 多模式对照。
- `run_benchmark_matrix.py`：以 `config/benchmark_scenarios.{atomic,full}.json` 编排多对多实验。
- `eval_benign_holdout.py`：单独跑 holdout 集算误报。

---

## Key Defaults（关键默认参数）

| 参数 | 值 | 含义 |
|---|---|---|
| `DEFAULT_ALERT_THRESHOLD` | 0.5 | BBK 窗口分数触发 GMAE 的阈值 |
| `DEFAULT_WINDOW_SECONDS` | 1800 | 检测窗口长度（30 分钟） |
| `DEFAULT_DETECT_STRIDE_SECONDS` | 600 | 滑动步长（重叠 1200s） |
| `DEFAULT_TIME_BIN_SECONDS` | 30 | 边归约时间桶 |
| `DEFAULT_TOP_EVIDENCE_ITEMS` | 3 | Top-K 进程/稀有路径展示 |
| `DEFAULT_BBK_TRAIN_WINDOW_SECONDS` | 1800 | BBK 训练窗口长度 |
| `DEFAULT_BBK_MIN_TRAIN_WINDOWS / MAX` | 10 / 20 | 训练窗口数质量门 |
| `DEFAULT_BBK_PROFILE_IMBALANCE_RATIO` | 0.4 | 多 profile 平衡门 |
| `DEFAULT_MIN_TRAIN_*` | 500 nodes / 1000 edges / 20 proc / 5 edge types | 训练样本最低质量门 |
| `DEFAULT_GMAE_EPOCHS` | 30 | build_bbk 阶段 GMAE 默认 epoch |
| `DEFAULT_GMAE_THRESHOLD_POLICY` | "p95" | 校准取 p95 |

---

## Test Coverage（测试覆盖范围）

无独立 `tests/` 目录约定或覆盖率门禁；现有 `tests/` 是 `unittest` 单元测试，覆盖核心流水线：

- `test_log_parser_json_only.py`：`TraceeLogParser` 接受 JSON、拒绝 text。
- `test_provenance_model.py`：clone/fork 等边类型转换正确。
- `test_sliding_window_reduction.py` + `test_realtime_monitor_windows.py`：滑动/实时窗口边界、metadata 完整、IO 往返、partial 行为。
- `test_bbk_window_scorer.py` + `test_two_stage_detection.py`：BBK 打分上下界、两阶段阈值/fallback 路径、summary reduction ratio。
- `test_e3_cdm_adapter.py` + `test_build_gmae_transfer_dry_run.py`：DARPA E3 适配、transfer dry-run 计划。
- `test_eval_mix_accuracy_sliding.py` + `test_benchmark_scenario_manifest.py` + `test_run_benchmark_matrix_dry_run.py`：评估与场景清单的 dry-run 行为。

> 改 KB 训练逻辑时务必跑一次 `build_bbk` + `eval_mix_accuracy` 验证；改检测逻辑时跑一次 `replay` + `eval_mix_accuracy`。

---

## End-to-End Minimal Runnable Slice（端到端最小可运行切片）

```bash
# 1. 准备
.venv/bin/python -m src.process.main setup

# 2. 三类知识库（顺序无关，可并行）
.venv/bin/python -m src.process.main build_tik
.venv/bin/python -m src.process.main build_ark
.venv/bin/python -m src.process.main build_bbk data/raw/benign_tracee.log

# 3. 离线分析
.venv/bin/python -m src.process.main analyze data/raw/eval.log --two-stage

# 4. 实时监控
./run_realtime.sh --with-llm            # 单容器
./run_realtime_demo.sh --no-llm          # 整链 docker compose 编排

# 5. 评估
.venv/bin/python scripts/eval_mix_accuracy.py --windows-dir data/processed/realtime_windows
```

---

## Known Design Trade-offs & Risks（已知设计取舍与风险）

1. **Stage1 攻击图全窗口子图入 prompt**：窗口较大时极易超长；当前只走 `max_attack_graph_edges_print` 控制打印，但 prompt 仍可能因边数过多而 OOM/truncate。**建议**：对长边数子图先做 sub-sampling 或边重要度截断。
2. **`--with-llm` 默认开**，生产建议走 `--no-llm` + 离线 batch 报告；`MockLLMClient` 是兜底，任何时候不会因 LLM 失败而中断检测。
3. **BBK SQLite 是单文件**；`update_from_edges` 每次 commit 一次。**建议**：增大学习集时改用更高效的存储或批量 import。
4. **`build_bbk` 在没有 `sampled_train_windows.jsonl` 时的两种模式判定不同**：
   - `logs_dir` 模式只取 `split_role=train`；
   - 单文件模式视为 bootstrap 全部进 BBK（`bootstrap_only=True`）。
5. **GMAE 训练质量门很严**（`DEFAULT_MIN_TRAIN_*`）；`build_bbk` reject 时仍会 `_save_gmae_runtime` 写空 baseline 覆盖既有文件，**可能造成数据丢失**。**建议**：reject 路径上跳过写盘。
6. **`realtime_monitor.iter_realtime_windows` 默认 `start_at_end=True`**：从文件尾开始追；`run_realtime_demo.sh` 显式传 `--start-from-begin` 以便 demo 时复现历史。
7. **DARPA E3 适配只支持 12 类事件**（见 `e3_cdm_adapter.SUPPORTED_EVENT_TYPES`），覆盖了大多数 BBK 训练所需 syscall 类型。
8. **测试均为单元测试**，缺少端到端跑通（`scripts/eval_mix_accuracy.py` 的运行结果作为最终 smoke test）。
9. **路径迁移逻辑在 `kb_paths.py`**：旧版产物目录会按版本号自动迁移；新增/修改产物路径时务必更新 `kb_paths.py` 与 `kb_builders.py` 的对应映射，否则旧数据会被孤立。
10. **ARK 是完全跨层逻辑图**：任意战术 N 的技术 → 任意战术 N+1 的技术，规模较大时攻击链重构的搜索空间需关注；`reconstruct_attack_chain` 已有 heuristic，但未做形式化复杂度分析。

---

## One-line Summary（一句话总结）

> EBLIT = **Tracee 抓 syscall → 单事件规整为溯源边 → 滑动窗口图 → BBK 频次支持度粗筛 → GMAE 节点级重构误差细筛 → 攻击图 + TIK 检索 + ARK 攻击链重构 → 三段式受约束 LLM 报告**，其中 BBK / TIK / ARK 与 GMAE baseline 在 `kb_builders.py` 集中编排，产物路径在 `kb_paths.py` 统一管理。
