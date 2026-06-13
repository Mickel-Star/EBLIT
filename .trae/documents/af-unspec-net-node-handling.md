# AF_UNSPEC / addrlen=0 网络节点处理方案

## 问题分析

Tracee 采集的日志中，`connect`/`accept`/`sendto`/`recvfrom` 等网络事件可能携带 `AF_UNSPEC` 地址或 `addrlen=0`。当前处理链路：

1. `_normalize_addr()` 将 `AF_UNSPEC` 静默返回 `""`
2. `_addr_arg()` 返回空，`remote_raw` 为空
3. `_resolve_net_object()` 缓存未命中时，调用 `_net_from_addr()`，`dst_ip` fallback 为 `"unknown"`
4. 生成 `net:tcp:pid:12345->unknown:0` 这样的低信息量节点
5. 该节点**未被缓存**（`dst_ip in {"", "unknown"}` 不写 `_fd_nets`），但**已进入溯源图**
6. 下游 BBK/GMAE/RarePathSelector 均无过滤，导致：
   - BBK `support()` 返回 `1e-9`，路径被误判为极度稀有
   - GMAE 训练中 `net:...unknown...` 节点参与消息传递，影响嵌入质量
   - `window_activity_builder` 统计 `unique_net_count` 包含这些无意义节点

## 实施步骤

### Step 1: `provenance_model.py` — 溯源层改造

**1a. 新增 AF_UNSPEC/addrlen=0 计数器**

在 `ProvenanceEventMapper.__init__` 中新增：
```python
self.af_unspec_count: int = 0
self.addrlen_zero_count: int = 0
```

**1b. 修改 `_normalize_addr()` — 识别 AF_UNSPEC 并标记**

当前逻辑：`AF_UNSPEC` 返回 `""`，与 `None` 等价，下游无法区分。

改为：返回一个特殊哨兵值 `"<AF_UNSPEC>"`，让 `_addr_arg()` 和 `_resolve_net_object()` 能区分"无地址"和"AF_UNSPEC 地址"。

同时在 `_normalize_addr()` 中检测 `addrlen=0`（当 value 是 dict 且含 `addrlen` 键且值为 0 时），返回 `"<ADDRLEN_ZERO>"`。

**1c. 修改 `_addr_arg()` — 透传哨兵值**

当前逻辑：`normalized` 为空时返回 `""`。

改为：`normalized` 为 `"<AF_UNSPEC>"` 或 `"<ADDRLEN_ZERO>"` 时，**仍然返回原始 value**（让 `_resolve_net_object` 能感知），同时在 mapper 上递增对应计数器。

**1d. 修改 `_resolve_net_object()` — 核心逻辑变更**

当前逻辑：
```python
if not remote_raw and fd_key is not None:
    cached = self._fd_nets.get(fd_key)
    if cached:
        return str(cached["node"]), dict(cached["meta"])

node, meta = self._net_from_addr(remote_raw, local_raw, args, pid)
if fd_key is not None and meta.get("dst_ip") not in {"", "unknown"}:
    self._fd_nets[fd_key] = {"node": node, "meta": meta}
return node, meta
```

改为：
```python
is_unspec = self._is_unspec_addr(remote_raw) or self._is_addrlen_zero(args)

# fd peer cache 命中 → 返回具体 net node（不变）
if (not remote_raw or is_unspec) and fd_key is not None:
    cached = self._fd_nets.get(fd_key)
    if cached:
        return str(cached["node"]), dict(cached["meta"])

# cache 未命中 + AF_UNSPEC/addrlen=0 → 生成 net:unknown_connected_socket
if is_unspec and (fd_key is None or fd_key not in self._fd_nets):
    node, meta = self._make_unknown_connected_socket(event, args, container_scope, pid)
    return node, meta

# 正常有地址 → 原有逻辑不变
node, meta = self._net_from_addr(remote_raw, local_raw, args, pid)
if fd_key is not None and meta.get("dst_ip") not in {"", "unknown"}:
    self._fd_nets[fd_key] = {"node": node, "meta": meta}
return node, meta
```

**1e. 新增 `_make_unknown_connected_socket()` 方法**

生成节点 ID：`net:unknown_connected_socket:{proto}:{container_scope}:pid:{pid}:fd:{fd}`

- 如果有 fd：`net:unknown_connected_socket:tcp:abc123:pid:12345:fd:7`
- 如果无 fd：`net:unknown_connected_socket:tcp:abc123:pid:12345`

meta 中包含：
```python
{
    "uuid": "...",
    "src_ip": "pid",
    "dst_ip": "unknown_connected_socket",
    "name": "unknown_connected_socket",
    "is_unspec_net": True,   # 关键标记
}
```

**1f. 新增 `_is_unspec_addr()` 和 `_is_addrlen_zero()` 辅助方法**

```python
def _is_unspec_addr(self, value: Any) -> bool:
    if isinstance(value, dict):
        family = str(value.get("sa_family") or "").upper()
        return family == "AF_UNSPEC"
    return False

def _is_addrlen_zero(self, args: Dict[str, Any]) -> bool:
    addrlen = args.get("addrlen")
    if addrlen is not None:
        try:
            return int(addrlen) == 0
        except (ValueError, TypeError):
            pass
    return False
```

**1g. 修改 `_normalize_addr()` — 不再返回哨兵**

保持 `_normalize_addr()` 原有行为（AF_UNSPEC 返回 `""`），因为判断逻辑移到 `_resolve_net_object()` 中用原始 value 判断，不依赖 `_normalize_addr` 的返回值来区分。这样改动最小，不影响其他调用者。

### Step 2: `dgl_adapter.py` — GMAE 训练降权

**2a. 节点特征中增加 `is_unspec_net` 标记**

在 `_node_feature()` 的 stats 列表中新增一项：
```python
1.0 if meta.get("is_unspec_net") else 0.0,
```

这样 GMAE 模型能学到 `net:unknown_connected_socket` 节点的特殊性。

**2b. 可选：在 `window_to_dgl_graph()` 中过滤 `net:unknown_connected_socket` 节点**

提供 `filter_unspec_net: bool = True` 参数。当启用时：
- 移除所有 `is_unspec_net=True` 的 net 节点
- 移除与之相连的边
- 保留 proc→proc 的间接关系（如果两端都是进程节点）

默认 `True`，因为这些节点对 GMAE 训练无正面贡献，反而引入噪声。

### Step 3: `benign_behavior_kb.py` — BBK 训练过滤

**3a. `update_from_edges()` 中跳过 `is_unspec_net` 节点**

在写入 `edge_freq`、`node_degree`、`node_meta` 时，检查边两端的 meta 是否包含 `is_unspec_net=True`。如果是，跳过该边的频次更新。

这样 BBK 的 `support()` 不会因为 `unknown_connected_socket` 节点而返回 `1e-9`。

### Step 4: `streaming_reduction.py` — 窗口元数据传播

**4a. 确认 `is_unspec_net` 标记在归约过程中保留**

当前 `StreamingReducer` 在合并边时，meta 来自 `ProvenanceEdge.src_meta` / `dst_meta`，通过 `g.nodes[node_id]["meta"]` 存储。需要确认 `is_unspec_net` 标记在窗口图中正确传播。

检查 `ingest_edge()` 方法中 meta 的合并逻辑，确保 `is_unspec_net` 不会被覆盖。

### Step 5: `window_activity_builder.py` — 统计修正

**5a. `unique_net_count` 排除 `is_unspec_net` 节点**

在统计 `unique_net_count` 时，排除 `meta.get("is_unspec_net")` 为 True 的节点。

### Step 6: `report_generator.py` — 检测路径过滤

**6a. `RarePathSelector.select_with_chains()` 中跳过 `net:unknown_connected_socket` 节点**

在 BFS 扩展时，如果邻居节点是 `net:unknown_connected_socket`（通过 `is_unspec_net` meta 判断），跳过该邻居，不将其加入 frontier。

这避免了稀有路径经过无信息量的网络节点而被误判为极度稀有。

### Step 7: 验证

- 语法检查：`python -m compileall src`
- 单元测试：确认 AF_UNSPEC 事件生成 `net:unknown_connected_socket` 节点
- 集成测试：`build_bbk` 流程中确认 `is_unspec_net` 节点不进入 BBK
- 回归测试：`run_realtime_demo.sh --no-llm` 确认端到端流程正常

## 文件修改清单

| 文件 | 修改内容 |
|------|----------|
| `src/process/provenance_model.py` | 新增计数器、`_is_unspec_addr()`、`_is_addrlen_zero()`、`_make_unknown_connected_socket()`，修改 `_resolve_net_object()` |
| `src/process/dgl_adapter.py` | `_node_feature()` 增加 `is_unspec_net` 特征，`window_to_dgl_graph()` 增加 `filter_unspec_net` 过滤 |
| `src/knowledge/benign_behavior_kb.py` | `update_from_edges()` 跳过 `is_unspec_net` 边 |
| `src/process/window_activity_builder.py` | `unique_net_count` 排除 `is_unspec_net` |
| `src/analysis/report_generator.py` | `RarePathSelector` 或 `_process_candidates_from_graph` 中跳过 `is_unspec_net` 节点 |

## 设计决策说明

1. **保留边但标记节点**：AF_UNSPEC 事件仍然生成溯源边（proc→net:unknown_connected_socket），保留"进程确实发起了网络操作"这一信息，但明确标记目标不可解析。
2. **fd peer cache 命中时恢复具体节点**：如果同一 fd 先后有 connect（有地址）和 sendto（AF_UNSPEC），cache 命中时返回 connect 时缓存的具体 net node，这是正确行为。
3. **BBK 完全排除而非降权**：对 BBK 来说，`unknown_connected_socket` 节点的频次统计没有意义，排除比降权更干净。
4. **GMAE 默认过滤而非降权**：在图神经网络中，少量噪声节点通过消息传递会影响所有邻居的嵌入，过滤比降权更安全。
5. **RarePathSelector 跳过而非降权**：稀有路径经过 `unknown_connected_socket` 节点时，`support()` 必然极低，降权仍会产生高分数误报，跳过更合理。
