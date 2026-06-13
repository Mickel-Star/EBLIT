#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.common.benchmarking import load_scenario_manifest, role_label
from src.common.defaults import DEFAULT_DETECT_STRIDE_SECONDS, DEFAULT_TIME_BIN_SECONDS, DEFAULT_WINDOW_SECONDS
from src.common.io import write_json
from src.process.log_parser import TraceeLogParser
from src.process.streaming_reduction import (
    SlidingWindowConfig,
    SlidingWindowReducer,
    StreamingReducer,
    StreamingReductionConfig,
)
from src.process.window_io import dump_window_graph


DEFAULT_SCENARIO_SET = "config/benchmark_scenarios.atomic.json"
DEFAULT_OUTPUT_ROOT = "data/benchmarks_atomic"
DEFAULT_COMPOSE_FILE = "deploy/docker-compose.yml"
DEFAULT_NETWORK = "drsec-net"
DEFAULT_DRIVER_IMAGE = "curlimages/curl:8.6.0"
DEFAULT_TRACEE_IMAGE = "aquasec/tracee:0.24.1"
DEFAULT_TRACEE_EVENTS = (
    "sched_process_exec",
    "execve",
    "openat",
    "read",
    "write",
    "close",
    "connect",
    "accept",
    "accept4",
    "sendto",
    "recvfrom",
    "fork",
    "clone",
    "vfork",
    "mmap",
    "security_socket_connect",
    "security_socket_accept",
)


@dataclass(frozen=True)
class BenchmarkRun:
    scenario: dict[str, Any]
    variant: dict[str, Any]
    repeat_id: int
    run_dir: Path
    duration_seconds: int
    warmup_seconds: int
    attack_seconds: int
    cooldown_seconds: int
    invoke_interval_seconds: int

    @property
    def scenario_id(self) -> str:
        return str(self.scenario.get("id") or "unknown")

    @property
    def variant_id(self) -> str:
        return str(self.variant.get("variant_id") or "variant")

    @property
    def command_template_id(self) -> str:
        return str(self.variant.get("command_template_id") or f"{self.scenario_id}.{self.variant_id}")

    @property
    def command(self) -> str:
        return str(self.variant.get("command") or "")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_component(value: Any) -> str:
    text = str(value or "unknown")
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)
    return cleaned[:96] or "unknown"


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


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT_DIR / path


def resolve_scenario_set(value: str) -> str:
    raw = str(value or "").strip() or DEFAULT_SCENARIO_SET
    candidate = Path(raw)
    if candidate.is_absolute() and candidate.exists():
        return str(candidate)
    repo_candidate = ROOT_DIR / raw
    if repo_candidate.exists():
        return str(repo_candidate)
    return raw


def detect_compose_cmd() -> list[str]:
    if shutil.which("docker") and subprocess.run(
        ["docker", "compose", "version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose") and subprocess.run(
        ["docker-compose", "version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0:
        return ["docker-compose"]
    raise RuntimeError("Docker Compose is unavailable: neither 'docker compose' nor 'docker-compose' works")


def compose_base() -> list[str]:
    compose_file = resolve_path(DEFAULT_COMPOSE_FILE)
    cmd = detect_compose_cmd()
    if cmd == ["docker", "compose"]:
        return cmd + ["-f", str(compose_file), "--profile", "attack"]
    return cmd + ["-f", str(compose_file)]


def run_checked(cmd: list[str], *, log_path: Path | None = None, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    if log_path is None:
        return subprocess.run(cmd, cwd=str(ROOT_DIR), text=True, check=True, timeout=timeout)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fp:
        fp.write("$ " + " ".join(cmd) + "\n")
        fp.flush()
        return subprocess.run(cmd, cwd=str(ROOT_DIR), text=True, stdout=fp, stderr=fp, check=True, timeout=timeout)


def run_capture(cmd: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(ROOT_DIR),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def ensure_docker_available() -> None:
    if not shutil.which("docker"):
        raise RuntimeError("Docker is unavailable: 'docker' was not found on PATH")
    probe = run_capture(["docker", "ps"], timeout=15)
    if probe.returncode != 0:
        detail = (probe.stderr or probe.stdout or "").strip()
        raise RuntimeError(f"Docker daemon is not usable. docker ps failed: {detail}")
    detect_compose_cmd()


def wait_ready(url: str, timeout_seconds: float = 90.0) -> None:
    deadline = time.time() + float(timeout_seconds)
    last_error = ""
    while time.time() < deadline:
        try:
            req = Request(url, headers={"X-DRSEC-Run-ID": "benchmark_readiness", "X-DRSEC-Actor": "orchestrator"})
            with urlopen(req, timeout=5) as resp:
                if 200 <= int(resp.status) < 400:
                    return
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(1.0)
    raise RuntimeError(f"readiness check failed for {url}: {last_error}")


def inspect_container_id(name: str) -> str:
    proc = run_capture(["docker", "inspect", "-f", "{{.Id}}", name], timeout=10)
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip().splitlines()[0] if proc.stdout.strip() else ""


def inspect_container_name(name: str) -> str:
    proc = run_capture(["docker", "inspect", "-f", "{{.Name}}", name], timeout=10)
    if proc.returncode != 0:
        return name
    value = (proc.stdout or "").strip().splitlines()[0] if proc.stdout.strip() else name
    return value.lstrip("/")


def drain_stderr_to_log(stream: Any, runtime_log: Path, max_bytes: int = 10_000_000) -> None:
    written = 0
    truncated = False
    with runtime_log.open("ab") as fp:
        while True:
            chunk = stream.readline()
            if not chunk:
                break
            if written < max_bytes:
                remaining = max_bytes - written
                part = chunk[:remaining]
                fp.write(part)
                written += len(part)
            elif not truncated:
                fp.write(f"\n[tracee stderr truncated after {max_bytes} bytes]\n".encode("utf-8"))
                truncated = True
            fp.flush()


def start_tracee(run: BenchmarkRun, trace_path: Path, runtime_log: Path) -> tuple[subprocess.Popen[Any], Any, threading.Thread | None, str, list[str]]:
    tracee_name = safe_component(f"tracee_atomic_{run.scenario_id}_{run.variant_id}_r{run.repeat_id}")
    subprocess.run(["docker", "rm", "-f", tracee_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    trace_fp = trace_path.open("w", encoding="utf-8", errors="ignore")
    events = ",".join(DEFAULT_TRACEE_EVENTS)
    cmd = [
        "docker",
        "run",
        "--name",
        tracee_name,
        "--rm",
        "-i",
        "--privileged",
        "--pid=host",
        "--cgroupns=host",
        "--network=host",
        "-v",
        "/lib/modules:/lib/modules:ro",
        "-v",
        "/usr/src:/usr/src:ro",
        "-v",
        "/etc/os-release:/etc/os-release-host:ro",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        "/sys/fs/cgroup:/sys/fs/cgroup:ro",
        DEFAULT_TRACEE_IMAGE,
        "--containers",
        "enrich=true",
        "--containers",
        "sockets.docker=/var/run/docker.sock",
        "--containers",
        "cgroupfs.path=/sys/fs/cgroup",
        "--containers",
        "cgroupfs.force=true",
        "--scope",
        "container",
        "--scope",
        "comm!=tracee",
        "--events",
        events,
        "--output",
        "json",
        "--output",
        "option:parse-arguments-fds",
    ]
    with runtime_log.open("a", encoding="utf-8") as fp:
        fp.write("tracee command: " + " ".join(cmd) + "\n")
    proc = subprocess.Popen(cmd, cwd=str(ROOT_DIR), stdout=trace_fp, stderr=subprocess.PIPE)
    stderr_thread = None
    if proc.stderr is not None:
        stderr_thread = threading.Thread(target=drain_stderr_to_log, args=(proc.stderr, runtime_log), daemon=True)
        stderr_thread.start()
    time.sleep(4.0)
    if proc.poll() is not None:
        trace_fp.close()
        if stderr_thread is not None:
            stderr_thread.join(timeout=5)
        raise RuntimeError(f"Tracee exited during startup with code {proc.returncode}; see {runtime_log}")
    return proc, trace_fp, stderr_thread, tracee_name, cmd


def stop_tracee(proc: subprocess.Popen[Any] | None, trace_fp: Any, stderr_thread: threading.Thread | None, tracee_name: str, runtime_log: Path) -> None:
    time.sleep(5.0)
    subprocess.run(["docker", "rm", "-f", tracee_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if proc is not None:
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
    if trace_fp is not None:
        trace_fp.close()
    if stderr_thread is not None:
        stderr_thread.join(timeout=5)
    with runtime_log.open("a", encoding="utf-8") as fp:
        fp.write(f"tracee stopped: {tracee_name}\n")


def profile_for(scenario: dict[str, Any], profile_name: str) -> dict[str, Any]:
    profile = scenario.get(f"{profile_name}_profile")
    if isinstance(profile, dict):
        return dict(profile)
    return {
        "duration_seconds": scenario.get("duration_seconds"),
        "warmup_seconds": scenario.get("warmup_seconds"),
        "attack_seconds": scenario.get("attack_seconds"),
        "cooldown_seconds": scenario.get("cooldown_seconds"),
    }


def invoke_interval_for(profile: dict[str, Any], attack_seconds: int) -> int:
    pacing = profile.get("attack_pacing") if isinstance(profile.get("attack_pacing"), dict) else {}
    interval = as_int(pacing.get("recommended_reinvoke_every_seconds"), 0)
    if interval <= 0:
        return max(int(attack_seconds), 1)
    return max(interval, 1)


def build_plan(args: argparse.Namespace) -> dict[str, Any]:
    manifest = load_scenario_manifest(str(ROOT_DIR), resolve_scenario_set(args.scenario_set))
    output_root = resolve_path(args.output_root)
    repeats = max(int(args.repeats), 1)
    runs: list[BenchmarkRun] = []
    for scenario in manifest.get("scenarios", []) or []:
        profile = profile_for(scenario, str(args.profile))
        warmup = as_int(profile.get("warmup_seconds"), as_int(scenario.get("warmup_seconds"), 0))
        attack = as_int(profile.get("attack_seconds"), as_int(scenario.get("attack_seconds"), 0))
        cooldown = as_int(profile.get("cooldown_seconds"), as_int(scenario.get("cooldown_seconds"), 0))
        duration = as_int(profile.get("duration_seconds"), warmup + attack + cooldown)
        if duration <= 0:
            duration = warmup + attack + cooldown
        if duration <= 0 or attack <= 0:
            raise ValueError(f"{scenario.get('id')}: profile {args.profile} must define positive duration and attack_seconds")
        for variant in scenario.get("command_variants", []) or []:
            if not str(variant.get("command") or "").strip():
                raise ValueError(f"{scenario.get('id')}: variant {variant.get('variant_id')} has no command")
            for repeat_id in range(1, repeats + 1):
                scenario_id = safe_component(scenario.get("id"))
                variant_id = safe_component(variant.get("variant_id"))
                run_dir = output_root / scenario_id / variant_id / f"repeat_{repeat_id}"
                runs.append(
                    BenchmarkRun(
                        scenario=scenario,
                        variant=variant,
                        repeat_id=repeat_id,
                        run_dir=run_dir,
                        duration_seconds=duration,
                        warmup_seconds=warmup,
                        attack_seconds=attack,
                        cooldown_seconds=cooldown,
                        invoke_interval_seconds=invoke_interval_for(profile, attack),
                    )
                )
    return {
        "scenario_set": manifest.get("scenario_set"),
        "manifest_path": manifest.get("manifest_path"),
        "profile": str(args.profile),
        "repeats": repeats,
        "output_root": str(output_root),
        "window_mode": str(args.window_mode),
        "window_seconds": int(args.window_seconds),
        "stride_seconds": int(args.stride_seconds),
        "time_bin_seconds": int(args.time_bin_seconds),
        "run_count": len(runs),
        "runs": runs,
    }


def serializable_plan(plan: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for run in plan["runs"]:
        rows.append(
            {
                "scenario_id": run.scenario_id,
                "variant_id": run.variant_id,
                "command_template_id": run.command_template_id,
                "repeat_id": run.repeat_id,
                "run_dir": str(run.run_dir),
                "duration_seconds": run.duration_seconds,
                "warmup_seconds": run.warmup_seconds,
                "attack_seconds": run.attack_seconds,
                "cooldown_seconds": run.cooldown_seconds,
                "invoke_interval_seconds": run.invoke_interval_seconds,
                "target_service": str(run.scenario.get("target_service") or ""),
                "benchmark_split": str(run.scenario.get("benchmark_split") or ""),
            }
        )
    return {k: v for k, v in plan.items() if k != "runs"} | {"runs": rows}


def clean_run_dir(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    for name in ["tracee.log", "run_meta.json", "labels.json", "driver.log", "runtime.log", "window_manifest.json"]:
        path = run_dir / name
        if path.exists():
            path.unlink()
    windows_dir = run_dir / "windows"
    if windows_dir.exists():
        for path in windows_dir.glob("window_*.json"):
            path.unlink()
    else:
        windows_dir.mkdir(parents=True, exist_ok=True)


def start_compose(runtime_log: Path) -> None:
    base = compose_base()
    run_checked(base + ["down"], log_path=runtime_log)
    run_checked(base + ["up", "-d", "--build", "vuln-app", "vuln-app-dsock", "c2-listener"], log_path=runtime_log)
    wait_ready("http://127.0.0.1:5000/ready", timeout_seconds=90)
    wait_ready("http://127.0.0.1:5001/ready", timeout_seconds=90)


def stop_compose(runtime_log: Path) -> None:
    try:
        run_checked(compose_base() + ["down"], log_path=runtime_log)
    except Exception as exc:
        with runtime_log.open("a", encoding="utf-8") as fp:
            fp.write(f"compose down failed: {type(exc).__name__}: {exc}\n")


def create_driver_container(run: BenchmarkRun, invocation_id: int, runtime_log: Path) -> tuple[str, str]:
    driver_cfg = ((run.scenario.get("container_roles") or {}).get("driver_container") or {}) if isinstance(run.scenario.get("container_roles"), dict) else {}
    image = str(driver_cfg.get("image") or DEFAULT_DRIVER_IMAGE)
    name = safe_component(f"drsec-bench-{run.scenario_id}-{run.variant_id}-r{run.repeat_id}-i{invocation_id}")
    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    cmd = ["docker", "create", "--name", name, "--network", DEFAULT_NETWORK, image, "sh", "-lc", run.command]
    run_checked(cmd, log_path=runtime_log)
    container_id = inspect_container_id(name)
    if not container_id:
        raise RuntimeError(f"failed to inspect attacker container id for {name}")
    return name, container_id


def run_driver_container(name: str, run_dir: Path, timeout_seconds: float) -> int:
    driver_log = run_dir / "driver.log"
    with driver_log.open("a", encoding="utf-8") as fp:
        fp.write(f"$ docker start -a {name}\n")
        fp.flush()
        proc = subprocess.run(
            ["docker", "start", "-a", name],
            cwd=str(ROOT_DIR),
            text=True,
            stdout=fp,
            stderr=fp,
            check=False,
            timeout=timeout_seconds,
        )
    return int(proc.returncode)


def remove_driver_container(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def run_attack_stage(run: BenchmarkRun, run_start: float, runtime_log: Path) -> list[dict[str, Any]]:
    invocations: list[dict[str, Any]] = []
    attack_end_at = run_start + float(run.warmup_seconds + run.attack_seconds)
    next_invoke_at = time.monotonic()
    invocation_id = 1
    while time.monotonic() < attack_end_at:
        sleep_for = max(0.0, next_invoke_at - time.monotonic())
        if sleep_for > 0:
            time.sleep(min(sleep_for, max(attack_end_at - time.monotonic(), 0.0)))
        if time.monotonic() >= attack_end_at:
            break
        name = ""
        container_id = ""
        start_offset = time.monotonic() - run_start
        try:
            name, container_id = create_driver_container(run, invocation_id, runtime_log)
            remaining = max(attack_end_at - time.monotonic(), 1.0)
            exit_code = run_driver_container(name, run.run_dir, timeout_seconds=remaining + 60.0)
            end_offset = time.monotonic() - run_start
            invocations.append(
                {
                    "invocation_id": invocation_id,
                    "container_name": name,
                    "container_id": container_id,
                    "start_offset_seconds": float(start_offset),
                    "end_offset_seconds": float(end_offset),
                    "exit_code": int(exit_code),
                }
            )
            if exit_code != 0:
                raise RuntimeError(f"driver command failed for {run.scenario_id}/{run.variant_id} with exit code {exit_code}; see {run.run_dir / 'driver.log'}")
        finally:
            if name:
                remove_driver_container(name)
        invocation_id += 1
        if run.invoke_interval_seconds >= run.attack_seconds:
            break
        next_invoke_at = min(next_invoke_at + float(run.invoke_interval_seconds), attack_end_at)
    remaining_attack = attack_end_at - time.monotonic()
    if remaining_attack > 0:
        time.sleep(remaining_attack)
    return invocations


def labels_payload(run: BenchmarkRun, attacker_invocations: list[dict[str, Any]]) -> dict[str, Any]:
    scenario = run.scenario
    positive_roles = list(scenario.get("positive_roles") or [])
    negative_roles = list(scenario.get("negative_roles") or [])
    containers: list[dict[str, Any]] = []

    role_names = {
        "target": "drsec-target",
        "target_dsock": "drsec-target-dsock",
        "c2": "drsec-c2",
    }
    for role, name in role_names.items():
        cid = inspect_container_id(name)
        if not cid:
            continue
        containers.append(
            {
                "role": role,
                "container_id": cid,
                "container_name": inspect_container_name(name),
                "label": role_label(role, positive_roles, negative_roles),
            }
        )

    seen_attackers: set[str] = set()
    for invocation in attacker_invocations:
        cid = str(invocation.get("container_id") or "")
        if not cid or cid in seen_attackers:
            continue
        seen_attackers.add(cid)
        containers.append(
            {
                "role": str(scenario.get("driver_role") or "attacker"),
                "container_id": cid,
                "container_name": str(invocation.get("container_name") or ""),
                "label": role_label(str(scenario.get("driver_role") or "attacker"), positive_roles, negative_roles),
            }
        )

    return {
        "schema_version": 1,
        "scenario_id": run.scenario_id,
        "kind": str(scenario.get("kind") or "attack"),
        "positive_roles": positive_roles,
        "negative_roles": negative_roles,
        "containers": containers,
    }


def materialize_windows(
    trace_path: Path,
    windows_dir: Path,
    *,
    window_mode: str,
    window_seconds: int,
    stride_seconds: int,
    time_bin_seconds: int,
) -> dict[str, Any]:
    windows_dir.mkdir(parents=True, exist_ok=True)
    for stale in windows_dir.glob("window_*.json"):
        stale.unlink()

    logs, parse_stats = TraceeLogParser().parse_log_file_with_stats(str(trace_path))
    window_rows: list[dict[str, Any]] = []
    if window_mode == "sliding":
        reducer = SlidingWindowReducer(
            config=SlidingWindowConfig(
                window_seconds=int(window_seconds),
                stride_seconds=int(stride_seconds),
                time_bin_seconds=int(time_bin_seconds),
            )
        )
        for idx, result in enumerate(reducer.ingest_logs(logs, emit_partial=True), start=1):
            path = windows_dir / f"window_{idx:06d}.json"
            dump_window_graph(str(path), result.graph)
            window_rows.append(
                {
                    "file": path.name,
                    "node_count": int(result.graph.number_of_nodes()),
                    "edge_count": int(result.graph.number_of_edges()),
                    "event_count": int(result.event_count),
                    "complete": bool(result.complete),
                    "window_start": float(result.window_start),
                    "window_end": float(result.window_end),
                }
            )
    else:
        reducer = StreamingReducer(
            config=StreamingReductionConfig(
                window_seconds=int(window_seconds),
                time_bin_seconds=int(time_bin_seconds),
            )
        )
        for idx, (graph, _metas) in enumerate(reducer.ingest_logs(logs), start=1):
            path = windows_dir / f"window_{idx:06d}.json"
            dump_window_graph(str(path), graph)
            window_rows.append(
                {
                    "file": path.name,
                    "node_count": int(graph.number_of_nodes()),
                    "edge_count": int(graph.number_of_edges()),
                    "event_count": None,
                    "complete": None,
                }
            )

    write_json(
        str(windows_dir.parent / "window_manifest.json"),
        {
            "trace_path": str(trace_path),
            "windows_dir": str(windows_dir),
            "window_mode": window_mode,
            "window_seconds": int(window_seconds),
            "stride_seconds": int(stride_seconds),
            "time_bin_seconds": int(time_bin_seconds),
            "window_count": len(window_rows),
            "windows": window_rows,
            "trace_stats": parse_stats,
        },
    )
    return {"trace_stats": parse_stats, "window_count": len(window_rows), "windows": window_rows}


def run_single(run: BenchmarkRun, args: argparse.Namespace) -> None:
    clean_run_dir(run.run_dir)
    runtime_log = run.run_dir / "runtime.log"
    trace_path = run.run_dir / "tracee.log"
    windows_dir = run.run_dir / "windows"

    tracee_proc = None
    tracee_fp = None
    tracee_thread = None
    tracee_name = ""
    tracee_cmd: list[str] = []
    attacker_invocations: list[dict[str, Any]] = []
    run_start = time.monotonic()
    run_start_ts = utc_now()
    error = ""
    try:
        start_compose(runtime_log)
        tracee_proc, tracee_fp, tracee_thread, tracee_name, tracee_cmd = start_tracee(run, trace_path, runtime_log)
        if run.warmup_seconds > 0:
            time.sleep(float(run.warmup_seconds))
        attacker_invocations = run_attack_stage(run, run_start, runtime_log)
        if run.cooldown_seconds > 0:
            time.sleep(float(run.cooldown_seconds))
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        if tracee_name:
            stop_tracee(tracee_proc, tracee_fp, tracee_thread, tracee_name, runtime_log)
        label_payload = labels_payload(run, attacker_invocations)
        write_json(str(run.run_dir / "labels.json"), label_payload)
        target_container_id = inspect_container_id("drsec-target")
        target_dsock_container_id = inspect_container_id("drsec-target-dsock")
        c2_container_id = inspect_container_id("drsec-c2")
        stop_compose(runtime_log)
        stage_boundaries = {
            "warmup_start": 0.0,
            "warmup_end": float(run.warmup_seconds),
            "attack_start": float(run.warmup_seconds),
            "attack_end": float(run.warmup_seconds + run.attack_seconds),
            "cooldown_start": float(run.warmup_seconds + run.attack_seconds),
            "cooldown_end": float(run.warmup_seconds + run.attack_seconds + run.cooldown_seconds),
        }
        run_meta = {
            "schema_version": 1,
            "run_id": str(run.run_dir.relative_to(resolve_path(args.output_root))),
            "scenario_id": run.scenario_id,
            "family_id": str(run.scenario.get("family_id") or run.scenario_id),
            "scenario_type": str(run.scenario.get("scenario_type") or ""),
            "benchmark_split": str(run.scenario.get("benchmark_split") or ""),
            "kind": str(run.scenario.get("kind") or "attack"),
            "variant_id": run.variant_id,
            "command_template_id": run.command_template_id,
            "repeat_id": int(run.repeat_id),
            "profile": str(args.profile),
            "target_service": str(run.scenario.get("target_service") or ""),
            "driver_role": str(run.scenario.get("driver_role") or "attacker"),
            "command": run.command,
            "duration_seconds": int(run.duration_seconds),
            "warmup_seconds": int(run.warmup_seconds),
            "attack_seconds": int(run.attack_seconds),
            "cooldown_seconds": int(run.cooldown_seconds),
            "attack_start": float(stage_boundaries["attack_start"]),
            "attack_end": float(stage_boundaries["attack_end"]),
            "stage_boundaries": stage_boundaries,
            "window_mode": str(args.window_mode),
            "window_seconds": int(args.window_seconds),
            "stride_seconds": int(args.stride_seconds),
            "time_bin_seconds": int(args.time_bin_seconds),
            "two_stage": bool(getattr(args, "two_stage", False)),
            "bbk_trigger_threshold": float(getattr(args, "bbk_trigger_threshold", 0.5)),
            "top_k": int(getattr(args, "top_k", 3)),
            "disable_gmae": bool(getattr(args, "disable_gmae", False)),
            "force_gmae_all_windows": bool(getattr(args, "force_gmae_all_windows", False)),
            "trace_path": str(trace_path),
            "trace_out": str(trace_path),
            "windows_dir": str(windows_dir),
            "labels_path": str(run.run_dir / "labels.json"),
            "run_dir": str(run.run_dir),
            "run_start_ts": run_start_ts,
            "run_end_ts": utc_now(),
            "tracee_command": tracee_cmd,
            "attacker_invocations": attacker_invocations,
            "attacker_container_id": str((attacker_invocations[0] or {}).get("container_id") if attacker_invocations else ""),
            "attacker_container_ids": [str(item.get("container_id") or "") for item in attacker_invocations if item.get("container_id")],
            "target_container_id": target_container_id,
            "target_dsock_container_id": target_dsock_container_id,
            "c2_container_id": c2_container_id,
            "error": error,
        }
        if trace_path.exists():
            try:
                window_summary = materialize_windows(
                    trace_path,
                    windows_dir,
                    window_mode=str(args.window_mode),
                    window_seconds=int(args.window_seconds),
                    stride_seconds=int(args.stride_seconds),
                    time_bin_seconds=int(args.time_bin_seconds),
                )
                run_meta.update(window_summary)
            except Exception as exc:
                run_meta["window_materialization_error"] = f"{type(exc).__name__}: {exc}"
                if not error:
                    error = run_meta["window_materialization_error"]
        write_json(str(run.run_dir / "run_meta.json"), run_meta)


def run_matrix(plan: dict[str, Any], args: argparse.Namespace) -> None:
    ensure_docker_available()
    failures: list[dict[str, Any]] = []
    for idx, run in enumerate(plan["runs"], start=1):
        print(f"[{idx}/{len(plan['runs'])}] {run.scenario_id}/{run.variant_id}/repeat_{run.repeat_id}", flush=True)
        try:
            run_single(run, args)
        except Exception as exc:
            failures.append(
                {
                    "scenario_id": run.scenario_id,
                    "variant_id": run.variant_id,
                    "repeat_id": run.repeat_id,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            print(f"ERROR: {run.scenario_id}/{run.variant_id}/repeat_{run.repeat_id}: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            break
    if failures:
        raise SystemExit(json.dumps({"status": "failed", "failures": failures}, ensure_ascii=False, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run EBLIT first-layer atomic benchmark matrix.")
    parser.add_argument("--scenario-set", default=DEFAULT_SCENARIO_SET)
    parser.add_argument("--profile", choices=("smoke", "formal"), default="smoke")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--window-mode", choices=("fixed", "sliding"), default="sliding")
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--stride-seconds", type=int, default=DEFAULT_DETECT_STRIDE_SECONDS)
    parser.add_argument("--time-bin-seconds", type=int, default=DEFAULT_TIME_BIN_SECONDS)
    parser.add_argument("--two-stage", action="store_true", default=False)
    parser.add_argument("--bbk-trigger-threshold", type=float, default=0.5)
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--disable-gmae", action="store_true", default=False)
    parser.add_argument("--force-gmae-all-windows", action="store_true", default=False)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-docker-run", action="store_true")
    args = parser.parse_args()

    if int(args.repeats) <= 0:
        raise SystemExit("--repeats must be > 0")
    if int(args.window_seconds) <= 0:
        raise SystemExit("--window-seconds must be > 0")
    if int(args.stride_seconds) <= 0:
        raise SystemExit("--stride-seconds must be > 0")
    if str(args.window_mode) == "sliding" and int(args.stride_seconds) > int(args.window_seconds):
        raise SystemExit("--stride-seconds must be <= --window-seconds when --window-mode=sliding")
    if int(args.time_bin_seconds) <= 0:
        raise SystemExit("--time-bin-seconds must be > 0")

    plan = build_plan(args)
    if args.dry_run or args.no_docker_run:
        payload = serializable_plan(plan)
        payload["dry_run"] = bool(args.dry_run)
        payload["no_docker_run"] = bool(args.no_docker_run)
        payload["note"] = "No Docker containers or Tracee processes were started."
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    run_matrix(plan, args)
    print(json.dumps({"status": "success", "run_count": int(plan["run_count"]), "output_root": plan["output_root"]}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
