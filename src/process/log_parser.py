#!/usr/bin/env python3
"""
Tracee JSON/JSONL log parser.

Training and preprocessing expect one Tracee JSON object per non-empty line.
Text/table output is intentionally rejected because it truncates fields such as
COMM and IMAGE and loses type information for syscall arguments.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def detect_trace_log_format(file_path: str | os.PathLike[str]) -> Dict[str, Any]:
    """Detect the on-disk Tracee trace format used by a trace.log file."""
    path = Path(file_path)
    result: Dict[str, Any] = {
        "actual_trace_format": "missing",
        "trace_log_exists": path.exists(),
        "trace_log_size_bytes": path.stat().st_size if path.exists() else 0,
        "nonempty_lines": 0,
        "json_object_lines": 0,
        "json_array_lines": 0,
        "json_parse_error_lines": 0,
        "non_json_lines": 0,
        "parse_error_examples": [],
    }
    if not path.exists():
        return result
    if path.stat().st_size <= 0:
        result["actual_trace_format"] = "empty"
        return result

    first_nonempty = ""
    whole_text_parts: List[str] | None = [] if path.stat().st_size <= 1_000_000 else None
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            if whole_text_parts is not None:
                whole_text_parts.append(line)
            stripped = line.strip()
            if not stripped:
                continue
            if not first_nonempty:
                first_nonempty = stripped
            result["nonempty_lines"] = int(result["nonempty_lines"]) + 1
            if not stripped.startswith(("{", "[")):
                result["non_json_lines"] = int(result["non_json_lines"]) + 1
                if len(result["parse_error_examples"]) < 5:
                    result["parse_error_examples"].append(stripped[:160])
                continue
            try:
                payload = json.loads(stripped)
            except Exception:
                result["json_parse_error_lines"] = int(result["json_parse_error_lines"]) + 1
                if len(result["parse_error_examples"]) < 5:
                    result["parse_error_examples"].append(stripped[:160])
                continue
            if isinstance(payload, dict):
                result["json_object_lines"] = int(result["json_object_lines"]) + 1
            elif isinstance(payload, list):
                result["json_array_lines"] = int(result["json_array_lines"]) + 1

    nonempty = int(result["nonempty_lines"])
    object_lines = int(result["json_object_lines"])
    array_lines = int(result["json_array_lines"])
    non_json = int(result["non_json_lines"])
    parse_errors = int(result["json_parse_error_lines"])

    if nonempty <= 0:
        result["actual_trace_format"] = "empty"
    elif object_lines == nonempty:
        result["actual_trace_format"] = "jsonl"
    elif array_lines == 1 and nonempty == 1:
        result["actual_trace_format"] = "json_array"
    elif non_json == nonempty:
        result["actual_trace_format"] = "table"
    else:
        whole_text = "".join(whole_text_parts).strip() if whole_text_parts is not None else ""
        if whole_text:
            try:
                payload = json.loads(whole_text)
            except Exception:
                payload = None
            if isinstance(payload, dict):
                result["actual_trace_format"] = "json"
            elif isinstance(payload, list):
                result["actual_trace_format"] = "json_array"
            elif object_lines or array_lines:
                result["actual_trace_format"] = "mixed"
            elif parse_errors:
                result["actual_trace_format"] = "invalid_json"
            else:
                result["actual_trace_format"] = "mixed"
        else:
            result["actual_trace_format"] = "empty"
    if first_nonempty:
        result["first_nonempty_prefix"] = first_nonempty[:80]
    return result


class TraceeLogParser:
    """Parse Tracee JSON/JSONL events into the internal log schema."""

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        raw = str(line or "").strip()
        if not raw:
            return None
        if not raw.startswith("{"):
            return None
        try:
            payload = json.loads(raw)
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        return self._parse_json_line(payload)

    def _parse_json_line(self, json_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            if not json_log.get("eventName"):
                return None

            timestamp = self._json_timestamp_seconds(json_log.get("timestamp", 0))
            process_id = int(json_log.get("processId") or 0)
            thread_id = int(json_log.get("threadId") or process_id)
            host_process_id = int(json_log.get("hostProcessId") or process_id)
            host_thread_id = int(json_log.get("hostThreadId") or thread_id)

            structured_data: Dict[str, Any] = {
                "timestamp": timestamp,
                "uid": json_log.get("userId", 0),
                "comm": json_log.get("processName", "unknown"),
                "pid": host_process_id,
                "tid": host_thread_id,
                "ret": json_log.get("returnValue", 0),
                "event": json_log.get("eventName", "unknown"),
                "args": {},
                "container_pid": process_id,
                "container_tid": thread_id,
            }

            for source_key, target_key in (
                ("containerId", "container_id"),
                ("containerImage", "container_image"),
                ("containerName", "container_name"),
                ("podName", "pod_name"),
                ("podNamespace", "pod_namespace"),
                ("podUID", "pod_uid"),
            ):
                value = json_log.get(source_key)
                if value not in (None, ""):
                    structured_data[target_key] = value

            container_obj = json_log.get("container")
            if isinstance(container_obj, dict):
                if not structured_data.get("container_id"):
                    v = container_obj.get("id") or container_obj.get("containerId")
                    if v not in (None, ""):
                        structured_data["container_id"] = v
                if not structured_data.get("container_image"):
                    v = container_obj.get("image") or container_obj.get("containerImage")
                    if v not in (None, ""):
                        structured_data["container_image"] = v
                if not structured_data.get("container_name"):
                    v = container_obj.get("name") or container_obj.get("containerName")
                    if v not in (None, ""):
                        structured_data["container_name"] = v

            for entity_key, entity_target in (
                ("threadEntityId", "thread_entity_id"),
                ("processEntityId", "process_entity_id"),
                ("parentEntityId", "parent_entity_id"),
            ):
                entity_val = json_log.get(entity_key)
                if entity_val is not None:
                    try:
                        structured_data[entity_target] = int(entity_val)
                    except (ValueError, TypeError):
                        pass

            args = json_log.get("args")
            if isinstance(args, list):  # 如果json数据是列表格式，分别提取key和value
                for arg in args:
                    if not isinstance(arg, dict):
                        continue
                    key = arg.get("name")
                    if key:
                        structured_data["args"][str(key)] = arg.get("value")
            elif isinstance(args, dict):  # 如果json数据是字典格式，直接更新
                structured_data["args"].update(args)

            k8s = json_log.get("kubernetes")
            if isinstance(k8s, dict):
                if k8s.get("podName"):
                    structured_data["pod_name"] = k8s.get("podName")
                if k8s.get("containerId"):
                    structured_data["container_id"] = k8s.get("containerId")

            return structured_data
        except Exception:
            return None

    def _json_timestamp_seconds(self, value: Any) -> float:
        try:
            numeric = float(value)
        except Exception:
            return 0.0
        if numeric > 1e17:
            return numeric / 1e9
        if numeric > 1e14:
            return numeric / 1e6
        if numeric > 1e11:
            return numeric / 1e3
        return numeric

    def parse_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        structured_logs: List[Dict[str, Any]] = []

        if not os.path.exists(file_path):
            print(f"Error: Log file not found at {file_path}")
            return []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
            for line in fp:
                parsed = self.parse_line(line)
                if parsed:
                    structured_logs.append(parsed)

        return structured_logs

    def parse_log_file_with_stats(self, file_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        stats: Dict[str, Any] = {
            "trace_log_exists": os.path.exists(file_path),
            "trace_log_size_bytes": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            "trace_lines_total": 0,
            "trace_lines_parsed": 0,
            "trace_lines_failed": 0,
            "trace_lines_non_json": 0,
            "parse_error_examples": [],
        }
        structured_logs: List[Dict[str, Any]] = []
        if not os.path.exists(file_path):
            return structured_logs, stats

        with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
            for line in fp:
                raw = line.rstrip("\n")
                if not raw.strip():
                    continue
                stats["trace_lines_total"] = int(stats["trace_lines_total"]) + 1
                if not raw.lstrip().startswith("{"):
                    stats["trace_lines_non_json"] = int(stats["trace_lines_non_json"]) + 1
                parsed = self.parse_line(raw)
                if parsed is None:
                    stats["trace_lines_failed"] = int(stats["trace_lines_failed"]) + 1
                    if len(stats["parse_error_examples"]) < 5:
                        stats["parse_error_examples"].append(raw[:160])
                    continue
                stats["trace_lines_parsed"] = int(stats["trace_lines_parsed"]) + 1
                structured_logs.append(parsed)

        return structured_logs, stats


if __name__ == "__main__":
    parser = TraceeLogParser()
    test_file = "../../data/raw/tracee.log"
    if os.path.exists(test_file):
        logs = parser.parse_log_file(test_file)
        print(f"解析了 {len(logs)} 条日志记录")
        if logs:
            print("\n第一条记录:")
            for key, value in logs[0].items():
                print(f"  {key}: {value}")
    else:
        print(f"Test file not found: {test_file}")
