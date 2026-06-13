# 修复 Tracee 0.24.1 日志解析兼容性 Spec

## Why
Tracee 0.24.1 的 JSON 输出格式将 `containerImage` 和 `containerName` 从顶层字段移入嵌套的 `container` 对象中，导致现有解析器丢失容器镜像和容器名称信息，直接影响下游溯源图节点元数据及 GNN 节点特征向量化质量。同时，0.24.1 新增了 `threadEntityId` / `processEntityId` / `parentEntityId` 稳定实体标识，当前解析器完全忽略，浪费了可提升节点标识稳定性的信息。

## What Changes
- **修复** `log_parser.py` 的 `_parse_json_line` 方法：在顶层 key 查找失败后，回退到 `container` 嵌套对象提取 `id`、`image`、`name`
- **增强** `log_parser.py` 的 `_parse_json_line` 方法：提取 `threadEntityId`、`processEntityId`、`parentEntityId` 三个新字段到 `structured_data`
- **增强** `provenance_model.py` 的 `parse_log_event` 方法：将 `process_entity_id` 写入 `proc_meta`，供下游可选使用

## Impact
- Affected code: `src/process/log_parser.py`、`src/process/provenance_model.py`
- 下游自动受益模块：`src/process/dgl_adapter.py`（节点特征恢复 `container_image` token）、`src/process/window_activity_builder.py`（trace 解析统计不受影响）
- 无破坏性变更：所有改动均为新增回退逻辑或新增字段，不改变现有字段名和语义

## ADDED Requirements

### Requirement: 嵌套 container 对象字段回退提取
系统 SHALL 在解析 Tracee JSON 行时，对 `container_id`、`container_image`、`container_name` 三个字段执行两级查找：先查顶层 key（`containerId`、`containerImage`、`containerName`），若未找到则回退到 `container` 嵌套对象（`id`、`image`、`name`）。

#### Scenario: 顶层字段存在（旧格式兼容）
- **WHEN** Tracee JSON 行包含顶层 `containerImage` 字段
- **THEN** 使用顶层值，不回退

#### Scenario: 顶层字段缺失但嵌套对象存在（0.24.1 格式）
- **WHEN** Tracee JSON 行顶层无 `containerImage`，但 `container.image` 存在
- **THEN** 从 `container.image` 提取值写入 `structured_data["container_image"]`

#### Scenario: 两级均无值
- **WHEN** 顶层和嵌套对象均无对应字段
- **THEN** 不设置该 key（与当前行为一致）

### Requirement: 提取 Tracee Entity ID 字段
系统 SHALL 在解析 Tracee JSON 行时，提取 `threadEntityId`、`processEntityId`、`parentEntityId` 三个字段到 `structured_data`，键名分别为 `thread_entity_id`、`process_entity_id`、`parent_entity_id`，值类型为 int。

#### Scenario: Entity ID 字段存在
- **WHEN** Tracee JSON 行包含 `processEntityId: 1884311065`
- **THEN** `structured_data["process_entity_id"]` 为 `1884311065`

#### Scenario: Entity ID 字段缺失（旧格式）
- **WHEN** Tracee JSON 行不包含 `processEntityId`
- **THEN** `structured_data` 不包含 `process_entity_id` 键

### Requirement: 溯源图节点元数据包含 process_entity_id
系统 SHALL 在 `ProvenanceEventMapper.parse_log_event` 构建进程节点元数据时，将 `process_entity_id` 写入 `proc_meta` 和 fork 子进程的 `obj_meta`。

#### Scenario: process_entity_id 存在时写入 proc_meta
- **WHEN** 解析后的 log 字典包含 `process_entity_id`
- **THEN** `proc_meta["process_entity_id"]` 为对应值

#### Scenario: process_entity_id 不存在时无影响
- **WHEN** 解析后的 log 字典不包含 `process_entity_id`
- **THEN** `proc_meta` 不包含该键（与当前行为一致）
