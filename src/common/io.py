from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ACTIVITY_LEVELS = ("empty", "idle", "low_activity", "active", "burst")


def _as_path(p: str | Path) -> Path:
    return p if isinstance(p, Path) else Path(p)


def ensure_dir(path: str) -> None:
    if not path:
        return
    os.makedirs(path, exist_ok=True)


def ensure_parent_dir(file_path: str) -> None:
    d = os.path.dirname(os.path.abspath(file_path))
    if d:
        os.makedirs(d, exist_ok=True)


def write_text(file_path: str, content: str) -> None:
    ensure_parent_dir(file_path)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)


def read_json(file_path: str | Path) -> Any:
    p = _as_path(file_path)
    if not p.exists() or p.stat().st_size <= 0:
        return {} if isinstance(file_path, (Path, str)) else None
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload


def write_json(file_path: str | Path, payload: Any) -> None:
    p = _as_path(file_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    p = _as_path(path)
    rows: list[dict[str, Any]] = []
    if not p.exists() or p.stat().st_size <= 0:
        return rows
    with p.open("r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def read_jsonl_strict(path: str | Path) -> list[dict[str, Any]]:
    p = _as_path(path)
    rows: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8", errors="ignore") as fp:
        for line_no, line in enumerate(fp, start=1):
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError(f"{p}:{line_no}: expected JSON object")
            rows.append(payload)
    return rows


def write_jsonl(path: str | Path, rows: list[dict[str, Any]]) -> None:
    p = _as_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fp:
        for row in rows:
            fp.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def load_mapping(path: str | Path, warnings: list[str] | None = None) -> dict[str, Any]:
    p = _as_path(path)
    if not p.exists() or p.stat().st_size <= 0:
        return {}
    text = p.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        pass
    try:
        import yaml
        payload = yaml.safe_load(text)
        return payload if isinstance(payload, dict) else {}
    except Exception as exc:
        if warnings is not None:
            warnings.append(f"config_parse_failed:{p}:{type(exc).__name__}")
        return {}


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return int(default)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def safe_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def relpath(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return os.path.relpath(str(path), str(root))


def utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def activity_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(str(row.get("activity_level") or "empty") for row in records)
    return {level: int(counter.get(level, 0)) for level in ACTIVITY_LEVELS}
