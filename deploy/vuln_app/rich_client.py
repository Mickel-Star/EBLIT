#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import os
import random
import shlex
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode


DEFAULT_ITEMS = ["sku-001", "sku-002", "sku-003"]
DEFAULT_TERMS = ["sku", "alice", "bob", "audit", "provenance", "container"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_component(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value or "unknown"))
    return cleaned[:96] or "unknown"


class EventWriter:
    def __init__(self, output_dir: Path, run_id: str, role: str) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        shard = output_dir / f"request_events_{safe_component(role)}_{uuid.uuid4().hex[:8]}.jsonl"
        self.path = shard
        self.fp = shard.open("a", encoding="utf-8")

    def write(self, event: dict[str, Any]) -> None:
        self.fp.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        self.fp.flush()

    def close(self) -> None:
        self.fp.close()


class RichClient:
    def __init__(
        self,
        *,
        run_id: str,
        role: str,
        base_url: str,
        metrics_url: str,
        output_dir: Path,
        duration_seconds: float,
        interval_seconds: float,
        worker_mode: str,
        seed: int,
    ) -> None:
        self.run_id = run_id
        self.role = role
        self.base_url = base_url.rstrip("/")
        self.metrics_url = metrics_url.rstrip("/")
        self.duration_seconds = float(duration_seconds)
        self.interval_seconds = float(interval_seconds)
        self.worker_mode = worker_mode
        self.rng = random.Random(seed)
        self.writer = EventWriter(output_dir, run_id, role)
        self.token = ""
        self.order_id = 0
        self.selected_item = self.rng.choice(DEFAULT_ITEMS)

    def close(self) -> None:
        self.writer.close()

    def run(self) -> None:
        if self.worker_mode == "jobs":
            self.run_job_worker()
            return

        deadline = time.time() + self.duration_seconds
        for action in self.initial_actions():
            self.perform(action)
        while time.time() < deadline:
            self.perform(self.next_action())
            time.sleep(max(self.interval_seconds * self.rng.uniform(0.5, 1.5), 0.05))

    def initial_actions(self) -> list[str]:
        if self.role == "foreground_user":
            return ["login", "catalog", "item_detail", "order_checkout", "order_status", "session_read", "order_read", "logout"]
        if self.role == "readonly_user":
            return ["login", "catalog", "search", "item_detail", "order_read", "session_read", "logout"]
        if self.role == "admin_user":
            return ["admin_login", "admin_audit", "admin_inspection", "report_status", "logout"]
        if self.role == "background_worker":
            return ["cache_warmup", "report_export", "periodic_sync", "legal_backup_read", "metrics_push"]
        if self.role == "health_checker":
            return ["health_check", "readiness_check", "static_read"]
        if self.role == "burst_retry_user":
            return ["login", "catalog", "search", "item_detail", "order_checkout", "order_status", "report_export", "logout"]
        return ["health_check"]

    def next_action(self) -> str:
        actions = self.initial_actions()
        if self.role == "burst_retry_user":
            return self.rng.choice(actions + ["search", "catalog", "metrics_push"])
        return self.rng.choice(actions)

    def perform(self, action: str) -> None:
        if action in {"login", "admin_login"}:
            username = "bob" if action == "admin_login" else "alice"
            self.login(action, username)
        elif action == "logout":
            self.request(action, "POST", "/api/logout", token=self.token)
            self.token = ""
        elif action == "session_read":
            self.request(action, "GET", "/api/me", token=self.token)
        elif action == "order_read":
            self.request(action, "GET", "/api/me/orders", token=self.token)
        elif action == "catalog":
            self.request(action, "GET", "/api/items", token=self.token)
        elif action == "search":
            self.request(action, "GET", "/api/search", query={"q": self.rng.choice(DEFAULT_TERMS)}, token=self.token)
        elif action == "item_detail":
            self.selected_item = self.rng.choice(DEFAULT_ITEMS)
            self.request(action, "GET", f"/api/items/{quote(self.selected_item)}", token=self.token)
        elif action == "order_checkout":
            result = self.request(
                action,
                "POST",
                "/api/order",
                payload={"customer": "alice", "item": self.selected_item, "quantity": self.rng.randint(1, 3)},
                token=self.token,
            )
            try:
                self.order_id = int((result.get("body") or {}).get("order_id") or self.order_id)
            except Exception:
                pass
        elif action == "order_status":
            if self.order_id <= 0:
                self.perform("order_checkout")
            self.request(action, "GET", f"/api/order/{self.order_id}", token=self.token)
        elif action == "admin_audit":
            self.request(action, "GET", "/api/admin/audit", query={"limit": self.rng.choice([5, 10, 20])}, token=self.token)
        elif action == "admin_inspection":
            self.request(action, "GET", "/api/search", query={"q": self.rng.choice(["alice", "bob", "sku"])}, token=self.token)
        elif action == "report_status":
            self.request(action, "GET", "/api/report/export", query={"q": "sku", "limit": 5}, token=self.token)
        elif action == "health_check":
            self.request(action, "GET", "/health")
        elif action == "readiness_check":
            self.request(action, "GET", "/ready")
        elif action == "static_read":
            self.request(action, "GET", "/")
        elif action == "cache_warmup":
            self.request(action, "POST", "/api/cache/warmup", payload={"category": self.rng.choice(["catalog", "orders", "reports"])})
        elif action == "report_export":
            self.request(action, "GET", "/api/report/export", query={"q": self.rng.choice(DEFAULT_TERMS), "limit": self.rng.choice([10, 25, 50])})
        elif action == "periodic_sync":
            self.request(action, "GET", "/api/search", query={"q": self.rng.choice(["audit", "provenance", "container"])})
        elif action == "legal_backup_read":
            self.request(action, "GET", "/api/report/export", query={"q": "alice", "limit": 50})
        elif action == "metrics_push":
            self.metrics_push()

    def login(self, action: str, username: str) -> None:
        result = self.request(action, "POST", "/api/login", payload={"username": username, "password": "password"})
        token = (result.get("body") or {}).get("token")
        if token:
            self.token = str(token)

    def request(
        self,
        action: str,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        token: str = "",
        shell: bool = False,
    ) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        url = self.base_url + path
        if query:
            url += "?" + urlencode(query)
        headers = [
            "Accept: application/json",
            f"X-DRSEC-Run-ID: {self.run_id}",
            f"X-DRSEC-Actor: {self.role}",
            f"X-DRSEC-Action: {action}",
            f"X-DRSEC-Request-ID: {request_id}",
        ]
        if payload is not None:
            headers.append("Content-Type: application/json")
        if token:
            headers.append(f"Authorization: Bearer {token}")

        cmd = ["curl", "-sS", "-m", "10", "-X", method.upper()]
        for header in headers:
            cmd.extend(["-H", header])
        if payload is not None:
            cmd.extend(["-d", json.dumps(payload, separators=(",", ":"))])
        cmd.extend(["-w", "\n%{http_code}", url])

        started = time.perf_counter()
        if shell:
            shell_cmd = " ".join(shlex.quote(part) for part in cmd)
            proc = subprocess.run(["sh", "-lc", shell_cmd], text=True, capture_output=True)
        else:
            proc = subprocess.run(cmd, text=True, capture_output=True)
        latency_ms = (time.perf_counter() - started) * 1000.0
        body_text, status_code = self.split_curl_output(proc.stdout)
        body = parse_json_body(body_text)
        event = {
            "ts": utc_now(),
            "run_id": self.run_id,
            "actor": self.role,
            "action": action,
            "request_id": request_id,
            "method": method.upper(),
            "url": url,
            "status_code": status_code,
            "success": proc.returncode == 0 and 200 <= status_code < 400,
            "latency_ms": round(latency_ms, 3),
            "error": proc.stderr.strip()[:500] if proc.returncode else "",
            "container_client": True,
        }
        self.writer.write(event)
        return {"event": event, "body": body}

    def split_curl_output(self, output: str) -> tuple[str, int]:
        text = output or ""
        if "\n" not in text:
            return text, 0
        body, status_text = text.rsplit("\n", 1)
        try:
            status_code = int(status_text.strip())
        except Exception:
            status_code = 0
        return body, status_code

    def metrics_push(self) -> None:
        if not self.metrics_url:
            return
        request_id = uuid.uuid4().hex
        payload = {
            "run_id": self.run_id,
            "actor": self.role,
            "action": "metrics_push",
            "request_id": request_id,
            "value": self.rng.random(),
            "ts": utc_now(),
        }
        cmd = [
            "curl",
            "-sS",
            "-m",
            "10",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            f"X-DRSEC-Run-ID: {self.run_id}",
            "-H",
            f"X-DRSEC-Actor: {self.role}",
            "-H",
            "X-DRSEC-Action: metrics_push",
            "-H",
            f"X-DRSEC-Request-ID: {request_id}",
            "-d",
            json.dumps(payload, separators=(",", ":")),
            "-w",
            "\n%{http_code}",
            self.metrics_url,
        ]
        started = time.perf_counter()
        proc = subprocess.run(cmd, text=True, capture_output=True)
        latency_ms = (time.perf_counter() - started) * 1000.0
        _body, status_code = self.split_curl_output(proc.stdout)
        self.writer.write(
            {
                "ts": utc_now(),
                "run_id": self.run_id,
                "actor": self.role,
                "action": "metrics_push",
                "request_id": request_id,
                "method": "POST",
                "url": self.metrics_url,
                "status_code": status_code,
                "success": proc.returncode == 0 and 200 <= status_code < 400,
                "latency_ms": round(latency_ms, 3),
                "error": proc.stderr.strip()[:500] if proc.returncode else "",
                "container_client": True,
            }
        )

    def run_job_worker(self) -> None:
        deadline = time.time() + self.duration_seconds
        rich_dir = Path(os.environ.get("DRSEC_RICH_DATA_DIR", "/app/data/rich"))
        while time.time() < deadline:
            pattern = rich_dir / "runs" / safe_component(self.run_id) / "jobs" / "pending" / "*" / "*" / "*.json"
            for job_path in sorted(glob.glob(str(pattern)))[:20]:
                self.process_job(Path(job_path))
            time.sleep(max(self.interval_seconds, 0.5))

    def process_job(self, job_path: Path) -> None:
        request_id = uuid.uuid4().hex
        try:
            job = json.loads(job_path.read_text(encoding="utf-8"))
        except Exception:
            job = {"source": str(job_path)}
        done_dir = job_path.parents[3] / "done" / safe_component(self.role) / "worker_job"
        done_dir.mkdir(parents=True, exist_ok=True)
        out_path = done_dir / f"{job_path.stem}_{request_id}.json"
        out_path.write_text(json.dumps({"job": job, "processed_at": utc_now(), "worker": self.role}, sort_keys=True), encoding="utf-8")
        self.writer.write(
            {
                "ts": utc_now(),
                "run_id": self.run_id,
                "actor": self.role,
                "action": "worker_job",
                "request_id": request_id,
                "method": "FILE",
                "url": str(job_path),
                "status_code": 0,
                "success": True,
                "latency_ms": 0.0,
                "error": "",
                "output_path": str(out_path),
                "container_client": True,
            }
        )


def parse_json_body(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except Exception:
        return {"raw": raw[:1000]} if raw else {}


def main() -> None:
    parser = argparse.ArgumentParser(description="Container-side rich benign workload client.")
    parser.add_argument("--role", default=os.environ.get("DRSEC_RICH_ROLE", "foreground_user"))
    parser.add_argument("--run-id", default=os.environ.get("DRSEC_RICH_RUN_ID", "run_rich"))
    parser.add_argument("--base-url", default=os.environ.get("DRSEC_RICH_BASE_URL", "http://api-rich:5000"))
    parser.add_argument("--metrics-url", default=os.environ.get("DRSEC_RICH_METRICS_URL", "http://metrics-sink-rich:9100/metrics"))
    parser.add_argument("--output-dir", default=os.environ.get("DRSEC_RICH_OUTPUT_DIR", "/out"))
    parser.add_argument("--duration-seconds", type=float, default=float(os.environ.get("DRSEC_RICH_DURATION_SECONDS", "1800")))
    parser.add_argument("--interval-seconds", type=float, default=float(os.environ.get("DRSEC_RICH_INTERVAL_SECONDS", "0.4")))
    parser.add_argument("--worker-mode", default=os.environ.get("DRSEC_RICH_WORKER_MODE", ""))
    parser.add_argument("--seed", type=int, default=int(os.environ.get("DRSEC_RICH_SEED", "20260501")))
    args = parser.parse_args()

    client = RichClient(
        run_id=str(args.run_id),
        role=str(args.role),
        base_url=str(args.base_url),
        metrics_url=str(args.metrics_url),
        output_dir=Path(args.output_dir),
        duration_seconds=float(args.duration_seconds),
        interval_seconds=float(args.interval_seconds),
        worker_mode=str(args.worker_mode),
        seed=int(args.seed),
    )
    try:
        client.run()
    finally:
        client.close()


if __name__ == "__main__":
    main()
