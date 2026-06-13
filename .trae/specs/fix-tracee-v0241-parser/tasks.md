# Tasks

- [x] Task 1: 修复 `log_parser.py` 嵌套 container 对象字段回退提取
  - [x] 1.1: 在 `_parse_json_line` 方法中，顶层 key 查找循环之后，增加对 `container` 嵌套对象的回退提取逻辑（`id`→`container_id`、`image`→`container_image`、`name`→`container_name`），仅在对应 key 尚未设置或为空时回退
- [x] Task 2: 增强 `log_parser.py` 提取 Entity ID 字段
  - [x] 2.1: 在 `_parse_json_line` 方法中，提取 `threadEntityId`、`processEntityId`、`parentEntityId` 到 `structured_data`，键名为 `thread_entity_id`、`process_entity_id`、`parent_entity_id`
- [x] Task 3: 增强 `provenance_model.py` 将 process_entity_id 写入节点元数据
  - [x] 3.1: 在 `parse_log_event` 的 `proc_meta` 构建中，有条件地写入 `process_entity_id`
  - [x] 3.2: 在 fork/clone 分支的 `obj_meta` 构建中，有条件地写入 `process_entity_id`（子进程的 entity_id 从 `parentEntityId` 推断）
- [x] Task 4: 验证修改正确性
  - [x] 4.1: 用 `python -m compileall src/process/log_parser.py src/process/provenance_model.py` 确认语法正确
  - [x] 4.2: 用实际 trace.log 第一条记录做 smoke test，验证 `container_image`、`container_name`、`process_entity_id` 被正确提取

# Task Dependencies
- Task 2 依赖 Task 1（同一文件，顺序修改避免冲突）
- Task 3 依赖 Task 2（消费 Task 2 新增的字段）
- Task 4 依赖 Task 1、2、3 全部完成
