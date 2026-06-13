#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = ROOT_DIR / "configs" / "benign_corpus_v3.yaml"
DEFAULT_ITEM_IDS = ["sku-001", "sku-002", "sku-003"]
DEFAULT_SEARCH_TERMS = ["sku", "alice", "bob", "container", "threat", "provenance", "audit"]
PROTECTED_NORMAL_ACTIONS = {
    "session_read",
    "catalog",
    "search",
    "item_detail",
    "order_checkout",
    "order_status",
    "order_read",
    "logout",
}
ADMIN_ACTIONS = {"admin_audit", "admin_inspection", "report_status", "logout"}


@dataclass(frozen=True)
class EndpointSpec:
    name: str
    method: str
    path: str
    real: bool = True
    driver_level: bool = False
    fallback_for: str = ""
    fallback_reason: str = ""
    note: str = ""


@dataclass(frozen=True)
class HttpResult:
    status_code: int
    success: bool
    latency_ms: float
    body: dict[str, Any]
    error: str | None
    url: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_config(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            return payload
    except json.JSONDecodeError:
        pass

    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None
    if yaml is not None:
        payload = yaml.safe_load(text)
        if isinstance(payload, dict):
            return payload
        raise ValueError(f"config must be a mapping: {path}")

    payload = parse_simple_yaml(text)
    if not isinstance(payload, dict):
        raise ValueError(f"config must be a mapping: {path}")
    return payload


def parse_simple_yaml(text: str) -> dict[str, Any]:
    """Small YAML subset parser for this repo's dependency-free config files."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = strip_yaml_comment(raw_line).rstrip()
        if not line.strip():
            continue
        if line.lstrip(" ") != line and "\t" in raw_line[: len(raw_line) - len(raw_line.lstrip())]:
            raise ValueError(f"tabs are not supported in config indentation at line {line_no}")
        indent = len(line) - len(line.lstrip(" "))
        content = line.strip()
        if content.startswith("- "):
            raise ValueError(f"list entries are not supported by fallback YAML parser at line {line_no}")
        if ":" not in content:
            raise ValueError(f"expected key: value at line {line_no}")
        key, raw_value = content.split(":", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"empty key at line {line_no}")
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise ValueError(f"invalid indentation at line {line_no}")
        parent = stack[-1][1]
        raw_value = raw_value.strip()
        if raw_value == "":
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = parse_scalar(raw_value)
    return root


def strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if ch == "#" and not in_single and not in_double:
            return line[:idx]
    return line


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "None", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(part.strip()) for part in inner.split(",")]
    try:
        if "." not in value:
            return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def normalize_duration(value: float) -> int | float:
    rounded = round(float(value), 6)
    if abs(rounded - int(rounded)) < 1e-6:
        return int(rounded)
    return rounded


def stable_seed(base_seed: int, actor_idx: int, vu_idx: int) -> int:
    return (int(base_seed) + int(actor_idx) * 100_003 + int(vu_idx) * 9_973) % (2**32)


def normalize_endpoints(raw: dict[str, Any]) -> dict[str, EndpointSpec]:
    endpoints: dict[str, EndpointSpec] = {}
    for name, value in sorted(raw.items()):
        if isinstance(value, str):
            endpoints[str(name)] = EndpointSpec(name=str(name), method="GET", path=value)
            continue
        if not isinstance(value, dict):
            raise ValueError(f"endpoint {name} must be a path string or mapping")
        endpoints[str(name)] = EndpointSpec(
            name=str(name),
            method=str(value.get("method") or "GET").upper(),
            path=str(value.get("path") or ""),
            real=as_bool(value.get("real"), True),
            driver_level=as_bool(value.get("driver_level"), False),
            fallback_for=str(value.get("fallback_for") or ""),
            fallback_reason=str(value.get("fallback_reason") or ""),
            note=str(value.get("note") or ""),
        )
    return endpoints


def endpoint_metadata(endpoints: dict[str, EndpointSpec]) -> list[dict[str, Any]]:
    return [
        {
            "name": spec.name,
            "method": spec.method,
            "path": spec.path,
            "real": bool(spec.real),
            "driver_level": bool(spec.driver_level),
            "fallback_for": spec.fallback_for,
            "fallback_reason": spec.fallback_reason,
            "note": spec.note,
        }
        for spec in sorted(endpoints.values(), key=lambda item: item.name)
    ]


def fallback_endpoint_summary(endpoints: dict[str, EndpointSpec]) -> tuple[list[str], list[dict[str, str]]]:
    missing = []
    fallbacks = []
    for spec in sorted(endpoints.values(), key=lambda item: item.name):
        if spec.real:
            continue
        missing_name = spec.fallback_for or spec.name
        missing.append(missing_name)
        fallbacks.append(
            {
                "endpoint": spec.name,
                "path": spec.path,
                "fallback_for": missing_name,
                "reason": spec.fallback_reason,
                "driver_level": str(bool(spec.driver_level)).lower(),
            }
        )
    return missing, fallbacks


class RunRecorder:
    def __init__(self, output_dir: Path, summary_seed: dict[str, Any]) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = output_dir / "driver.log"
        self.events_path = output_dir / "request_events.jsonl"
        self.summary_path = output_dir / "workload_summary.json"
        self._lock = threading.Lock()
        self._log_fp = self.log_path.open("w", encoding="utf-8")
        self._events_fp = self.events_path.open("w", encoding="utf-8")
        self.summary: dict[str, Any] = {
            "total_requests": 0,
            "success_count": 0,
            "failure_count": 0,
            "retry_count": 0,
            "per_actor_request_count": {},
            "per_profile_request_count": {},
            "per_action_request_count": {},
            "missing_endpoints": list(summary_seed.get("missing_endpoints") or []),
            "fallback_endpoints": list(summary_seed.get("fallback_endpoints") or []),
            "state_machine_violations_prevented": 0,
            "driver_level_action_count": 0,
            "duration_seconds": int(summary_seed.get("duration_seconds") or 0),
        }

    def close(self) -> None:
        with self._lock:
            self._log_fp.flush()
            self._events_fp.flush()
            self._log_fp.close()
            self._events_fp.close()

    def log(self, message: str, **fields: Any) -> None:
        payload = " ".join(f"{key}={json.dumps(value, ensure_ascii=False)}" for key, value in sorted(fields.items()))
        line = f"{utc_now()} {message}"
        if payload:
            line += " " + payload
        with self._lock:
            self._log_fp.write(line + "\n")
            self._log_fp.flush()

    def record_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._events_fp.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            self._events_fp.flush()
            self.summary["total_requests"] = int(self.summary.get("total_requests", 0)) + 1
            if bool(event.get("success")):
                self.summary["success_count"] = int(self.summary.get("success_count", 0)) + 1
            else:
                self.summary["failure_count"] = int(self.summary.get("failure_count", 0)) + 1
            if bool(event.get("retry")):
                self.summary["retry_count"] = int(self.summary.get("retry_count", 0)) + 1
            if str(event.get("method") or "").upper() == "DRIVER":
                self.summary["driver_level_action_count"] = int(self.summary.get("driver_level_action_count", 0)) + 1
            self._increment("per_actor_request_count", str(event.get("actor") or "unknown"))
            self._increment("per_profile_request_count", str(event.get("profile") or "unknown"))
            self._increment("per_action_request_count", str(event.get("action") or "unknown"))

    def _increment(self, bucket_name: str, key: str) -> None:
        bucket = self.summary.setdefault(bucket_name, {})
        bucket[key] = int(bucket.get(key, 0)) + 1

    def record_prevented_violation(self, *, actor: str, vu_id: str, action: str, state: str, reason: str) -> None:
        with self._lock:
            self.summary["state_machine_violations_prevented"] = (
                int(self.summary.get("state_machine_violations_prevented", 0)) + 1
            )
        self.log(
            "skipped_action_due_to_invalid_state",
            actor=actor,
            vu_id=vu_id,
            action=action,
            state=state,
            reason=reason,
        )

    def write_summary(self) -> None:
        with self._lock:
            payload = dict(self.summary)
        self.summary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


class HttpClient:
    def __init__(self, base_url: str, timeout_seconds: float) -> None:
        self.base_url = str(base_url).rstrip("/")
        self.timeout_seconds = float(timeout_seconds)
        host = urllib.parse.urlparse(self.base_url).hostname or ""
        if should_bypass_proxy(host):
            self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        else:
            self.opener = urllib.request.build_opener()

    def request(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        token: str = "",
    ) -> HttpResult:
        url = self.build_url(path, query)
        headers = {"Accept": "application/json"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        started = time.perf_counter()
        req = urllib.request.Request(url, data=body, headers=headers, method=str(method).upper())
        try:
            with self.opener.open(req, timeout=self.timeout_seconds) as resp:
                raw = resp.read().decode("utf-8", "ignore")
                status = int(getattr(resp, "status", 0) or 0)
                return HttpResult(
                    status_code=status,
                    success=200 <= status < 400,
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    body=parse_response_body(raw),
                    error=None,
                    url=url,
                )
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "ignore")
            status = int(getattr(exc, "code", 0) or 0)
            return HttpResult(
                status_code=status,
                success=False,
                latency_ms=(time.perf_counter() - started) * 1000.0,
                body=parse_response_body(raw),
                error=f"http_error:{status}",
                url=url,
            )
        except Exception as exc:
            return HttpResult(
                status_code=0,
                success=False,
                latency_ms=(time.perf_counter() - started) * 1000.0,
                body={},
                error=f"{type(exc).__name__}: {exc}",
                url=url,
            )

    def build_url(self, path: str, query: dict[str, Any] | None = None) -> str:
        clean_path = str(path or "")
        if clean_path and not clean_path.startswith("/"):
            clean_path = "/" + clean_path
        url = self.base_url + clean_path
        if query:
            clean_query = {str(key): value for key, value in query.items() if value is not None}
            if clean_query:
                url += "?" + urllib.parse.urlencode(clean_query)
        return url


def should_bypass_proxy(host: str) -> bool:
    if host == "localhost" or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


def parse_response_body(raw: str) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except Exception:
        return {"raw": raw[:4096]}


class VirtualUser:
    def __init__(
        self,
        *,
        config: dict[str, Any],
        actor: str,
        actor_config: dict[str, Any],
        actor_idx: int,
        vu_idx: int,
        endpoints: dict[str, EndpointSpec],
        recorder: RunRecorder,
        client: HttpClient,
        deadline: float,
    ) -> None:
        self.config = config
        self.actor = actor
        self.actor_config = actor_config
        self.actor_idx = int(actor_idx)
        self.vu_idx = int(vu_idx)
        self.vu_id = f"{actor}_{vu_idx}"
        self.endpoints = endpoints
        self.recorder = recorder
        self.client = client
        self.deadline = float(deadline)
        self.seed = stable_seed(as_int(config.get("random_seed"), 0), actor_idx, vu_idx)
        self.rng = random.Random(self.seed)
        self.state = "anonymous"
        self.token = ""
        self.username = str((config.get("auth") or {}).get("user_username") or "alice")
        self.admin_username = str((config.get("auth") or {}).get("admin_username") or "bob")
        self.password = str((config.get("auth") or {}).get("password") or "password")
        self.selected_item = ""
        self.order_id = 0
        self.last_action = ""

    def run(self) -> None:
        self.recorder.log("virtual_user_start", actor=self.actor, vu_id=self.vu_id, seed=self.seed)
        self.sleep_with_deadline(self.initial_stagger_seconds())
        try:
            while time.monotonic() < self.deadline:
                action = self.choose_action()
                self.perform_action(action)
                self.sleep_with_deadline(self.next_delay_seconds())
        except BaseException as exc:
            self.recorder.log("virtual_user_error", actor=self.actor, vu_id=self.vu_id, error=f"{type(exc).__name__}: {exc}")
        finally:
            self.recorder.log("virtual_user_end", actor=self.actor, vu_id=self.vu_id, state=self.state)

    def initial_stagger_seconds(self) -> float:
        jitter = as_float(self.actor_config.get("start_jitter_seconds"), 0.0)
        remaining = max(self.deadline - time.monotonic(), 0.0)
        cap = min(max(jitter, 0.0), max(remaining * 0.2, 0.0))
        return self.rng.uniform(0.0, cap) if cap > 0 else 0.0

    def next_delay_seconds(self) -> float:
        virtual_users = max(as_int(self.actor_config.get("virtual_users"), 1), 1)
        actor_rate_per_min = max(as_float(self.actor_config.get("arrival_rate_per_min"), 1.0), 0.0)
        per_vu_rate_per_sec = (actor_rate_per_min / float(virtual_users)) / 60.0
        if per_vu_rate_per_sec > 0:
            arrival_delay = self.rng.expovariate(per_vu_rate_per_sec)
        else:
            arrival_delay = 30.0
        think_delay = self.sample_think_time()
        return max(0.05, max(arrival_delay, think_delay))

    def sample_think_time(self) -> float:
        cfg = dict(self.actor_config.get("think_time") or {})
        dist = str(cfg.get("distribution") or "uniform").lower()
        min_seconds = as_float(cfg.get("min_seconds"), 0.5)
        max_seconds = as_float(cfg.get("max_seconds"), 5.0)
        if max_seconds < min_seconds:
            max_seconds = min_seconds
        if dist == "lognormal":
            value = self.rng.lognormvariate(as_float(cfg.get("mu"), 1.0), as_float(cfg.get("sigma"), 0.4))
        else:
            value = self.rng.uniform(min_seconds, max_seconds)
        return min(max(value, min_seconds), max_seconds)

    def sleep_with_deadline(self, seconds: float) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(max(float(seconds), 0.0), remaining))

    def choose_action(self) -> str:
        if self.actor == "foreground_user":
            return self.choose_foreground_action()
        if self.actor == "readonly_user":
            return self.choose_readonly_action()
        if self.actor == "admin_user":
            return self.choose_admin_action()
        if self.actor == "burst_retry_user":
            return self.choose_burst_retry_action()
        if self.actor == "background_worker":
            return self.rng.choices(
                ["health_check", "cache_warmup", "report_export", "periodic_sync", "legal_backup_read", "metrics_push"],
                weights=[0.18, 0.20, 0.22, 0.18, 0.12, 0.10],
                k=1,
            )[0]
        if self.actor == "health_checker":
            return self.rng.choices(["health_check", "static_read", "readiness_check"], weights=[0.65, 0.20, 0.15], k=1)[0]
        return "health_check"

    def choose_foreground_action(self) -> str:
        if self.state == "anonymous":
            return "login"
        if self.state == "login_success":
            return self.rng.choices(["session_read", "catalog", "search", "logout"], weights=[0.18, 0.42, 0.30, 0.10], k=1)[0]
        if self.state == "browsing":
            return self.rng.choices(["item_detail", "catalog", "search", "logout"], weights=[0.48, 0.22, 0.22, 0.08], k=1)[0]
        if self.state == "item_selected":
            return self.rng.choices(["order_checkout", "catalog", "search", "item_detail", "logout"], weights=[0.42, 0.16, 0.18, 0.14, 0.10], k=1)[0]
        if self.state == "order_created":
            return self.rng.choices(["order_status", "session_read", "logout"], weights=[0.70, 0.18, 0.12], k=1)[0]
        if self.state == "order_checked":
            return self.rng.choices(["catalog", "search", "order_status", "logout"], weights=[0.34, 0.28, 0.18, 0.20], k=1)[0]
        return "login"

    def choose_readonly_action(self) -> str:
        if self.state == "anonymous":
            return "login"
        if self.state == "login_success":
            return self.rng.choices(["catalog", "search", "order_read", "logout"], weights=[0.40, 0.34, 0.16, 0.10], k=1)[0]
        if self.state in {"browsing", "item_selected"}:
            return self.rng.choices(["item_detail", "catalog", "search", "order_read", "logout"], weights=[0.24, 0.24, 0.26, 0.16, 0.10], k=1)[0]
        return "login"

    def choose_admin_action(self) -> str:
        if self.state != "admin_login_success":
            return "admin_login"
        return self.rng.choices(["admin_audit", "admin_inspection", "report_status", "logout"], weights=[0.44, 0.24, 0.22, 0.10], k=1)[0]

    def choose_burst_retry_action(self) -> str:
        if self.state == "anonymous":
            return "login"
        if self.state == "login_success":
            return self.rng.choices(
                ["catalog", "search", "order_checkout", "order_status", "session_read", "logout"],
                weights=[0.20, 0.20, 0.25, 0.15, 0.10, 0.10],
                k=1,
            )[0]
        if self.state == "browsing":
            return self.rng.choices(
                ["item_detail", "order_checkout", "catalog", "search", "logout"],
                weights=[0.25, 0.30, 0.15, 0.15, 0.15],
                k=1,
            )[0]
        if self.state == "item_selected":
            return self.rng.choices(
                ["order_checkout", "catalog", "search", "item_detail", "logout"],
                weights=[0.45, 0.15, 0.15, 0.15, 0.10],
                k=1,
            )[0]
        if self.state == "order_created":
            return self.rng.choices(
                ["order_status", "catalog", "search", "logout"],
                weights=[0.40, 0.25, 0.20, 0.15],
                k=1,
            )[0]
        if self.state == "order_checked":
            return self.rng.choices(
                ["catalog", "search", "order_checkout", "logout"],
                weights=[0.25, 0.25, 0.30, 0.20],
                k=1,
            )[0]
        return "login"

    def perform_action(self, action: str, *, retry: bool = False) -> None:
        if not self.ensure_preconditions(action):
            return
        if action == "login":
            self.do_login(retry=retry)
        elif action == "admin_login":
            self.do_admin_login(retry=retry)
        elif action == "logout":
            self.do_logout(retry=retry)
        elif action == "session_read":
            self.do_simple_get("auth_read_session", "session_read", "session_read", token=self.token, retry=retry)
        elif action == "catalog":
            self.do_catalog(retry=retry)
        elif action == "search":
            self.do_search(retry=retry)
        elif action == "item_detail":
            self.do_item_detail(retry=retry)
        elif action == "order_checkout":
            self.do_order_checkout(retry=retry)
        elif action == "order_status":
            self.do_order_status(retry=retry)
        elif action == "order_read":
            self.do_simple_get("catalog_browse_search", "order_read", "order_read", token=self.token, retry=retry)
        elif action == "admin_audit":
            self.do_admin_audit(retry=retry)
        elif action == "admin_inspection":
            self.do_admin_inspection(retry=retry)
        elif action == "report_status":
            self.do_report_status(retry=retry)
        elif action == "health_check":
            self.do_simple_get("health_idle_poll", "health_check", "health", retry=retry)
        elif action == "static_read":
            self.do_simple_get("health_idle_poll", "static_read", "static", retry=retry)
        elif action == "readiness_check":
            self.do_simple_get("health_idle_poll", "readiness_check", "readiness", retry=retry)
        elif action == "cache_warmup":
            self.do_simple_get("background_worker", "cache_warmup", "cache_warmup", retry=retry)
        elif action == "report_export":
            self.do_report_export("report_export_batch", "report_export", "report_export", retry=retry)
        elif action == "periodic_sync":
            self.do_periodic_sync(retry=retry)
        elif action == "legal_backup_read":
            self.do_report_export("background_worker", "legal_backup_read", "legal_backup_read", retry=retry)
        elif action == "metrics_push":
            self.do_driver_level("background_worker", "metrics_push", "metrics_push", retry=retry)
        else:
            self.recorder.log("unknown_action_skipped", actor=self.actor, vu_id=self.vu_id, action=action)

    def ensure_preconditions(self, action: str) -> bool:
        if action == "logout" and self.state == "anonymous":
            self.recorder.record_prevented_violation(
                actor=self.actor,
                vu_id=self.vu_id,
                action=action,
                state=self.state,
                reason="logout requires an active session",
            )
            return False
        if self.actor == "admin_user" and action in ADMIN_ACTIONS and action != "logout" and self.state != "admin_login_success":
            self.recorder.record_prevented_violation(
                actor=self.actor,
                vu_id=self.vu_id,
                action=action,
                state=self.state,
                reason="admin action requires admin_login_success",
            )
            self.perform_action("admin_login", retry=True)
            return False
        if self.actor == "readonly_user" and action == "order_checkout":
            self.recorder.record_prevented_violation(
                actor=self.actor,
                vu_id=self.vu_id,
                action=action,
                state=self.state,
                reason="readonly_user is not allowed to execute order checkout",
            )
            return False
        if self.actor in {"foreground_user", "readonly_user", "burst_retry_user"} and action in PROTECTED_NORMAL_ACTIONS and self.state == "anonymous":
            self.recorder.record_prevented_violation(
                actor=self.actor,
                vu_id=self.vu_id,
                action=action,
                state=self.state,
                reason="protected action requires login_success",
            )
            self.perform_action("login", retry=True)
            return False
        if action == "item_detail" and self.state not in {"browsing", "item_selected", "order_created", "order_checked"}:
            self.recorder.record_prevented_violation(
                actor=self.actor,
                vu_id=self.vu_id,
                action=action,
                state=self.state,
                reason="item_detail requires catalog browse or search first",
            )
            self.perform_action("catalog", retry=True)
            return False
        if action == "order_checkout" and self.state != "item_selected":
            self.recorder.record_prevented_violation(
                actor=self.actor,
                vu_id=self.vu_id,
                action=action,
                state=self.state,
                reason="order_checkout requires item_selected",
            )
            if self.state == "browsing":
                self.perform_action("item_detail", retry=True)
            elif self.state == "login_success":
                self.perform_action("catalog", retry=True)
            else:
                self.perform_action("login", retry=True)
            return False
        if action == "order_status" and (self.state not in {"order_created", "order_checked"} or self.order_id <= 0):
            self.recorder.record_prevented_violation(
                actor=self.actor,
                vu_id=self.vu_id,
                action=action,
                state=self.state,
                reason="order_status requires order_created",
            )
            self.perform_action("order_checkout", retry=True)
            return False
        return True

    def do_login(self, *, retry: bool = False) -> None:
        state_before = self.state
        result = self.request_endpoint(
            "login",
            payload={"username": self.username, "password": self.password},
            token="",
        )
        if result.success and result.body.get("token"):
            self.token = str(result.body.get("token") or "")
            self.transition("login_success")
            self.recorder.log("login_success", actor=self.actor, vu_id=self.vu_id, username=self.username)
        else:
            self.token = ""
            self.transition("anonymous")
            self.recorder.log("login_failure", actor=self.actor, vu_id=self.vu_id, status_code=result.status_code, error=result.error)
        self.emit_event("auth_read_session", "login", "login", state_before, result, retry=retry)

    def do_admin_login(self, *, retry: bool = False) -> None:
        state_before = self.state
        result = self.request_endpoint(
            "admin_login",
            payload={"username": self.admin_username, "password": self.password},
            token="",
        )
        if result.success and result.body.get("token"):
            self.token = str(result.body.get("token") or "")
            self.transition("admin_login_success")
            self.recorder.log("login_success", actor=self.actor, vu_id=self.vu_id, username=self.admin_username, role="admin")
        else:
            self.token = ""
            self.transition("anonymous")
            self.recorder.log("login_failure", actor=self.actor, vu_id=self.vu_id, status_code=result.status_code, error=result.error)
        self.emit_event("admin_readonly_audit", "admin_login", "admin_login", state_before, result, retry=retry)

    def do_logout(self, *, retry: bool = False) -> None:
        state_before = self.state
        endpoint_name = "logout"
        result = self.request_endpoint(endpoint_name, token=self.token)
        self.token = ""
        self.transition("anonymous")
        self.recorder.log("state_transition", actor=self.actor, vu_id=self.vu_id, action="logout", before=state_before, after=self.state)
        profile = "admin_readonly_audit" if self.actor == "admin_user" else "auth_read_session"
        self.emit_event(profile, "logout", endpoint_name, state_before, result, retry=retry)

    def do_simple_get(self, profile: str, action: str, endpoint_name: str, *, token: str = "", retry: bool = False) -> None:
        state_before = self.state
        result = self.request_endpoint(endpoint_name, token=token)
        self.handle_unauthorized(action, result)
        self.emit_event(profile, action, endpoint_name, state_before, result, retry=retry)

    def do_catalog(self, *, retry: bool = False) -> None:
        state_before = self.state
        result = self.request_endpoint("catalog", token=self.token)
        if result.success:
            self.selected_item = self.pick_item_from_body(result.body)
            self.transition("browsing")
        self.handle_unauthorized("catalog", result)
        self.emit_event("catalog_browse_search", "catalog", "catalog", state_before, result, retry=retry)

    def do_search(self, *, retry: bool = False) -> None:
        state_before = self.state
        term = self.rng.choice(DEFAULT_SEARCH_TERMS)
        result = self.request_endpoint("search", query={"q": term}, token=self.token)
        if result.success:
            self.transition("browsing")
        self.handle_unauthorized("search", result)
        self.emit_event("catalog_browse_search", "search", "search", state_before, result, retry=retry)

    def do_item_detail(self, *, retry: bool = False) -> None:
        state_before = self.state
        if not self.selected_item:
            self.selected_item = self.rng.choice(DEFAULT_ITEM_IDS)
        result = self.request_endpoint("item_detail", token=self.token)
        if result.success:
            self.selected_item = self.pick_item_from_body(result.body) or self.selected_item
            self.transition("item_selected")
        self.handle_unauthorized("item_detail", result)
        self.emit_event("catalog_browse_search", "item_detail", "item_detail", state_before, result, retry=retry)

    def do_order_checkout(self, *, retry: bool = False) -> None:
        state_before = self.state
        item = self.selected_item or self.rng.choice(DEFAULT_ITEM_IDS)
        payload = {"customer": self.username, "item": item, "quantity": self.rng.randint(1, 3)}
        result = self.request_endpoint("order_checkout", payload=payload, token=self.token)
        if result.success:
            self.order_id = as_int(result.body.get("order_id"), 0)
            if self.order_id > 0:
                self.transition("order_created")
        self.handle_unauthorized("order_checkout", result)
        self.emit_event("order_write_checkout", "order_checkout", "order_checkout", state_before, result, retry=retry)

    def do_order_status(self, *, retry: bool = False) -> None:
        state_before = self.state
        result = self.request_endpoint("order_status", path_values={"order_id": self.order_id}, token=self.token)
        if result.success:
            self.transition("order_checked")
        self.handle_unauthorized("order_status", result)
        self.emit_event("order_write_checkout", "order_status", "order_status", state_before, result, retry=retry)

    def do_admin_audit(self, *, retry: bool = False) -> None:
        state_before = self.state
        result = self.request_endpoint("admin_audit", query={"limit": self.rng.choice([5, 10, 20, 35])}, token=self.token)
        self.handle_unauthorized("admin_audit", result)
        self.emit_event("admin_readonly_audit", "admin_audit", "admin_audit", state_before, result, retry=retry)

    def do_admin_inspection(self, *, retry: bool = False) -> None:
        state_before = self.state
        result = self.request_endpoint("admin_inspection", query={"q": self.rng.choice(["alice", "bob", "sku"])}, token=self.token)
        self.handle_unauthorized("admin_inspection", result)
        self.emit_event("admin_readonly_audit", "admin_inspection", "admin_inspection", state_before, result, retry=retry)

    def do_report_status(self, *, retry: bool = False) -> None:
        state_before = self.state
        result = self.request_endpoint("report_status", query={"q": self.rng.choice(["alice", "bob", "sku"]), "limit": 5}, token=self.token)
        self.handle_unauthorized("report_status", result)
        self.emit_event("admin_readonly_audit", "report_status", "report_status", state_before, result, retry=retry)

    def do_report_export(self, profile: str, action: str, endpoint_name: str, *, retry: bool = False) -> None:
        state_before = self.state
        result = self.request_endpoint(
            endpoint_name,
            query={"q": self.rng.choice(DEFAULT_SEARCH_TERMS), "limit": self.rng.choice([5, 10, 25, 50])},
        )
        self.emit_event(profile, action, endpoint_name, state_before, result, retry=retry)

    def do_periodic_sync(self, *, retry: bool = False) -> None:
        state_before = self.state
        result = self.request_endpoint("periodic_sync", query={"q": self.rng.choice(["sku", "audit", "provenance"])})
        self.emit_event("background_worker", "periodic_sync", "periodic_sync", state_before, result, retry=retry)

    def do_driver_level(self, profile: str, action: str, endpoint_name: str, *, retry: bool = False) -> None:
        state_before = self.state
        spec = self.endpoints[endpoint_name]
        event = self.base_event(profile, action, endpoint_name, state_before, retry=retry)
        event.update(
            {
                "state_after": self.state,
                "method": "DRIVER",
                "url": "",
                "status_code": 0,
                "success": True,
                "latency_ms": 0.0,
                "error": None,
                "fallback_for": spec.fallback_for,
                "endpoint_real": bool(spec.real),
            }
        )
        self.recorder.log("driver_level_action", actor=self.actor, vu_id=self.vu_id, action=action, fallback_for=spec.fallback_for)
        self.recorder.record_event(event)

    def request_endpoint(
        self,
        endpoint_name: str,
        *,
        query: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        token: str = "",
        path_values: dict[str, Any] | None = None,
    ) -> HttpResult:
        spec = self.endpoints.get(endpoint_name)
        if spec is None:
            return HttpResult(
                status_code=0,
                success=False,
                latency_ms=0.0,
                body={},
                error=f"missing endpoint config: {endpoint_name}",
                url="",
            )
        path = spec.path
        for key, value in dict(path_values or {}).items():
            path = path.replace("{" + str(key) + "}", urllib.parse.quote(str(value)))
        result = self.client.request(method=spec.method, path=path, query=query, payload=payload, token=token)
        if result.error and not result.error.startswith("http_error"):
            self.recorder.log("connection_error", actor=self.actor, vu_id=self.vu_id, endpoint=endpoint_name, error=result.error)
        if result.status_code >= 500:
            self.recorder.log("unexpected_server_error", actor=self.actor, vu_id=self.vu_id, endpoint=endpoint_name, status_code=result.status_code)
        return result

    def emit_event(
        self,
        profile: str,
        action: str,
        endpoint_name: str,
        state_before: str,
        result: HttpResult,
        *,
        retry: bool = False,
    ) -> None:
        spec = self.endpoints.get(endpoint_name)
        event = self.base_event(profile, action, endpoint_name, state_before, retry=retry)
        event.update(
            {
                "state_after": self.state,
                "method": spec.method if spec else "",
                "url": result.url,
                "status_code": int(result.status_code),
                "success": bool(result.success),
                "latency_ms": round(float(result.latency_ms), 3),
                "error": result.error,
                "endpoint_real": bool(spec.real) if spec else False,
                "fallback_for": spec.fallback_for if spec else "",
            }
        )
        self.recorder.record_event(event)

    def base_event(self, profile: str, action: str, endpoint_name: str, state_before: str, *, retry: bool) -> dict[str, Any]:
        return {
            "ts": utc_now(),
            "run_id": str(self.config.get("run_id") or "run_smoke"),
            "actor": self.actor,
            "vu_id": self.vu_id,
            "profile": profile,
            "action": action,
            "endpoint": endpoint_name,
            "state_before": state_before,
            "state_after": self.state,
            "method": "",
            "url": "",
            "status_code": 0,
            "success": False,
            "latency_ms": 0.0,
            "retry": bool(retry),
            "error": None,
        }

    def transition(self, new_state: str) -> None:
        old_state = self.state
        self.state = str(new_state)
        if old_state != self.state:
            self.recorder.log("state_transition", actor=self.actor, vu_id=self.vu_id, before=old_state, after=self.state)

    def handle_unauthorized(self, action: str, result: HttpResult) -> None:
        if result.status_code not in {401, 403}:
            return
        self.recorder.log("authz_failure_relogin", actor=self.actor, vu_id=self.vu_id, action=action, status_code=result.status_code)
        self.token = ""
        self.transition("anonymous")
        if self.actor == "admin_user":
            self.perform_action("admin_login", retry=True)
        elif self.actor in {"foreground_user", "readonly_user", "burst_retry_user"}:
            self.perform_action("login", retry=True)

    def pick_item_from_body(self, body: dict[str, Any]) -> str:
        items = body.get("items")
        if isinstance(items, list) and items:
            item = self.rng.choice(items)
            if isinstance(item, dict) and item.get("id"):
                return str(item.get("id"))
        return self.rng.choice(DEFAULT_ITEM_IDS)


def write_run_meta(config: dict[str, Any], endpoints: dict[str, EndpointSpec], output_dir: Path) -> None:
    missing, fallbacks = fallback_endpoint_summary(endpoints)
    auth = dict(config.get("auth") or {})
    raw_phases = list(config.get("phases") or [])
    phases: list[dict[str, Any]] = []
    phase_role_schedule: list[dict[str, Any]] = []
    phase_cursor = 0.0
    for idx, raw_phase in enumerate(raw_phases, start=1):
        if not isinstance(raw_phase, dict):
            continue
        duration = as_float(raw_phase.get("duration_seconds"), 0.0)
        if duration <= 0:
            continue
        start_offset = as_float(raw_phase.get("start_offset_seconds"), phase_cursor)
        end_offset = as_float(raw_phase.get("end_offset_seconds"), start_offset + duration)
        if end_offset <= start_offset:
            end_offset = start_offset + duration
        phase_id = str(raw_phase.get("phase_id") or raw_phase.get("name") or f"phase_{idx:02d}")
        profile_id = str(raw_phase.get("profile_id") or raw_phase.get("profile") or raw_phase.get("name") or phase_id)
        phase_payload = {
            "phase_id": phase_id,
            "profile_id": profile_id,
            "name": str(raw_phase.get("name") or phase_id),
            "start_offset_seconds": float(start_offset),
            "end_offset_seconds": float(end_offset),
            "duration_seconds": normalize_duration(end_offset - start_offset),
        }
        phases.append(phase_payload)
        phase_actors = _resolve_phase_actors(dict(config.get("actors") or {}), raw_phase.get("actors"))
        for actor_name, actor_cfg in phase_actors.items():
            if not isinstance(actor_cfg, dict) or not as_bool(actor_cfg.get("enabled"), True):
                continue
            phase_role_schedule.append(
                {
                    "phase_id": phase_id,
                    "profile_id": profile_id,
                    "driver_role": str(actor_name),
                    "role_profile_id": profile_id,
                    "start_offset_seconds": float(start_offset),
                    "end_offset_seconds": float(end_offset),
                    "duration_seconds": normalize_duration(end_offset - start_offset),
                }
            )
        phase_cursor = end_offset
    actors = []
    for name, actor_cfg in dict(config.get("actors") or {}).items():
        if not isinstance(actor_cfg, dict):
            continue
        actors.append(
            {
                "actor": str(name),
                "enabled": as_bool(actor_cfg.get("enabled"), True),
                "virtual_users": as_int(actor_cfg.get("virtual_users"), 1),
                "arrival_rate_per_min": as_float(actor_cfg.get("arrival_rate_per_min"), 1.0),
                "think_time": dict(actor_cfg.get("think_time") or {}),
            }
        )
    payload = {
        "dataset": str(config.get("dataset") or "benign_corpus_v3"),
        "run_id": str(config.get("run_id") or "run_smoke"),
        "split": str(config.get("split") or "smoke"),
        "phase": str(config.get("phase") or "first_stage_multi_actor_driver_mvp"),
        "duration_seconds": as_int(config.get("duration_seconds"), 300),
        "random_seed": as_int(config.get("random_seed"), 0),
        "workload_model": str(config.get("workload_model") or "multi_actor_arrival_rate"),
        "output_dir": str(output_dir),
        "window_seconds": as_int(config.get("window_seconds"), 30),
        "time_bin_seconds": as_int(config.get("time_bin_seconds"), 2),
        "base_url": str(config.get("base_url") or ""),
        "collection": dict(config.get("collection") or {}),
        "actors": actors,
        "phases": phases,
        "phase_role_schedule": phase_role_schedule,
        "auth_model": {
            "real_session_cookie": as_bool(auth.get("real_session_cookie"), False),
            "bearer_token_session": as_bool(auth.get("bearer_token_session"), True),
            "driver_state_machine": as_bool(auth.get("driver_state_machine"), True),
            "admin_driver_level_state_machine": False,
            "admin_login_endpoint": "real /api/login with bob admin user",
        },
        "rate_model": {
            "arrival_rate_per_min_scope": "actor_total_divided_across_virtual_users",
            "arrival_distribution": "exponential_interarrival_with_configured_random_think_time_floor",
        },
        "endpoint_map": endpoint_metadata(endpoints),
        "missing_endpoints": missing,
        "fallback_endpoints": fallbacks,
        "output_files": {
            "run_meta": str(output_dir / "run_meta.json"),
            "driver_log": str(output_dir / "driver.log"),
            "request_events": str(output_dir / "request_events.jsonl"),
            "workload_summary": str(output_dir / "workload_summary.json"),
        },
        "notes": [
            "The workload driver records benign request events; Tracee, window activity, and manifest artifacts are produced by orchestration scripts.",
            "The vulnerable demo app uses bearer tokens in Authorization headers, not real session cookies.",
            "background_worker uses public/read-only endpoints and driver-level simulation for metrics_push; no service token is configured.",
            "The driver does not call /ping or benchmark attack paths.",
        ],
    }
    (output_dir / "run_meta.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _resolve_phase_actors(base_actors: dict[str, Any], phase_actors: dict[str, Any] | None) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    for name, cfg in base_actors.items():
        resolved[str(name)] = dict(cfg or {})
    if phase_actors:
        for name, override in phase_actors.items():
            key = str(name)
            if key not in resolved:
                resolved[key] = dict(override or {})
            elif isinstance(override, dict):
                merged = dict(resolved[key] or {})
                merged.update(override)
                resolved[key] = merged
            else:
                resolved[key] = override
    return resolved


def run_driver(config: dict[str, Any]) -> dict[str, Any]:
    endpoints = normalize_endpoints(dict(config.get("endpoints") or {}))
    missing, fallbacks = fallback_endpoint_summary(endpoints)
    output_dir = ROOT_DIR / str(config.get("output_dir") or "data/benign_corpus_v3/smoke/run_smoke")
    if Path(str(config.get("output_dir") or "")).is_absolute():
        output_dir = Path(str(config.get("output_dir")))
    output_dir.mkdir(parents=True, exist_ok=True)
    write_run_meta(config, endpoints, output_dir)

    recorder = RunRecorder(
        output_dir,
        {
            "missing_endpoints": missing,
            "fallback_endpoints": fallbacks,
            "duration_seconds": as_int(config.get("duration_seconds"), 300),
        },
    )
    client = HttpClient(str(config.get("base_url") or "http://127.0.0.1:5000"), as_float(config.get("request_timeout_seconds"), 5.0))
    duration_seconds = max(as_float(config.get("duration_seconds"), 300.0), 0.0)
    recorder.log(
        "run_start",
        run_id=str(config.get("run_id") or "run_smoke"),
        base_url=str(config.get("base_url") or ""),
        duration_seconds=duration_seconds,
    )

    base_actors = dict(config.get("actors") or {})
    phases = list(config.get("phases") or [])
    if not phases:
        phases = [{"phase_id": "default", "duration_seconds": duration_seconds, "actors": None}]

    run_start = time.monotonic()
    try:
        for phase in phases:
            phase_id = str(phase.get("phase_id") or phase.get("name") or "default")
            phase_duration = max(as_float(phase.get("duration_seconds"), 0.0), 0.0)
            if phase_duration <= 0:
                continue
            phase_actors_override = phase.get("actors")
            phase_actors = _resolve_phase_actors(base_actors, phase_actors_override)
            phase_deadline = min(time.monotonic() + phase_duration, run_start + duration_seconds)
            if phase_deadline <= time.monotonic():
                continue

            recorder.log(
                "phase_start",
                phase_id=phase_id,
                duration_seconds=phase_duration,
                actors=list(phase_actors.keys()),
            )

            threads_by_actor: dict[str, list[threading.Thread]] = {}
            actor_idx = 0
            for actor, actor_cfg_raw in phase_actors.items():
                actor_cfg = dict(actor_cfg_raw or {})
                if not as_bool(actor_cfg.get("enabled"), True):
                    continue
                actor_idx += 1
                virtual_users = max(as_int(actor_cfg.get("virtual_users"), 1), 1)
                recorder.log(
                    "actor_start",
                    actor=actor,
                    phase_id=phase_id,
                    virtual_users=virtual_users,
                    arrival_rate_per_min=as_float(actor_cfg.get("arrival_rate_per_min"), 1.0),
                )
                threads = []
                for vu_idx in range(virtual_users):
                    vu = VirtualUser(
                        config=config,
                        actor=str(actor),
                        actor_config=actor_cfg,
                        actor_idx=actor_idx,
                        vu_idx=vu_idx,
                        endpoints=endpoints,
                        recorder=recorder,
                        client=client,
                        deadline=phase_deadline,
                    )
                    thread = threading.Thread(target=vu.run, name=vu.vu_id, daemon=True)
                    thread.start()
                    threads.append(thread)
                threads_by_actor[str(actor)] = threads

            for actor, threads in threads_by_actor.items():
                for thread in threads:
                    thread.join()
                recorder.log("actor_end", actor=actor, phase_id=phase_id, virtual_users=len(threads))

            recorder.log("phase_end", phase_id=phase_id)

        elapsed = max(duration_seconds - max((run_start + duration_seconds) - time.monotonic(), 0.0), 0.0)
        recorder.summary["elapsed_seconds"] = round(float(elapsed), 3)
        recorder.log("run_end", elapsed_seconds=round(float(elapsed), 3), summary=recorder.summary)
    finally:
        recorder.write_summary()
        recorder.close()
    return recorder.summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-actor benign workload driver MVP.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--duration-seconds", type=float, default=None, help="override config duration for local validation")
    parser.add_argument("--base-url", default="", help="override config base_url")
    parser.add_argument("--output-dir", default="", help="override config output_dir")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = ROOT_DIR / config_path
    config = load_config(config_path)
    if args.duration_seconds is not None:
        config["duration_seconds"] = float(args.duration_seconds)
    if args.base_url:
        config["base_url"] = str(args.base_url)
    if args.output_dir:
        config["output_dir"] = str(args.output_dir)
    run_driver(config)


if __name__ == "__main__":
    main()
