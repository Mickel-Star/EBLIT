#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.process.benign_workload_driver import load_config
from src.process.log_parser import TraceeLogParser
from src.process.streaming_reduction import StreamingReductionConfig, StreamingReducer
from src.process.window_io import dump_window_graph


DEFAULT_CONFIG = ROOT_DIR / "configs" / "benign_corpus_v4_rich.yaml"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_component(value: str) -> str:
    text = str(value or "unknown")
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)
    return cleaned[:96] or "unknown"


def as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def configured_windows_dir(config: dict[str, Any], run_dir: Path) -> Path:
    configured_name = str(config.get("windows_dir_name") or "").strip()
    return run_dir / configured_name if configured_name else run_dir / f"windows_{as_int(config.get('window_seconds'), 1800)}s"


def chmod_and_retry(function: Any, path: str, excinfo: BaseException) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        function(path)
    except Exception:
        raise excinfo


def rmtree_generated(path: Path) -> None:
    shutil.rmtree(path, onexc=chmod_and_retry)


def unlink_generated(path: Path) -> None:
    try:
        path.unlink()
    except PermissionError:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        path.unlink()


def clean_previous_run_outputs(config: dict[str, Any], run_dir: Path) -> None:
    for dirname in ["client_events"]:
        path = run_dir / dirname
        if path.exists():
            rmtree_generated(path)
    windows_dir = configured_windows_dir(config, run_dir)
    if windows_dir.exists():
        rmtree_generated(windows_dir)
    for filename in [
        "trace.log",
        "tracee_runtime.log",
        "request_events.jsonl",
        "container_inventory.json",
        "run_meta.json",
        "collection_summary.json",
        "effective_config.json",
    ]:
        path = run_dir / filename
        if path.exists():
            unlink_generated(path)


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT_DIR / path


def load_rich_config(path: Path) -> dict[str, Any]:
    config_path = path if path.is_absolute() else ROOT_DIR / path
    return load_config(config_path)


def detect_compose_cmd() -> list[str]:
    if shutil.which("docker") and subprocess.run(["docker", "compose", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose") and subprocess.run(["docker-compose", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        return ["docker-compose"]
    raise RuntimeError("neither 'docker compose' nor 'docker-compose' is available")


def compose_base(config: dict[str, Any]) -> list[str]:
    compose_file = resolve_path(str(config.get("compose_file") or "deploy/docker-compose.yml"))
    cmd = detect_compose_cmd()
    if cmd == ["docker", "compose"]:
        return cmd + ["-f", str(compose_file), "--profile", str(config.get("compose_profile") or "benign-rich")]
    return cmd + ["-f", str(compose_file)]


def wait_ready(url: str, timeout_seconds: float) -> None:
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        try:
            req = Request(url, headers={"X-DRSEC-Run-ID": "readiness", "X-DRSEC-Actor": "collector", "X-DRSEC-Action": "ready"})
            with urlopen(req, timeout=5) as resp:
                if 200 <= int(resp.status) < 400:
                    return
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(1.0)
    raise RuntimeError(f"readiness check failed for {url}: {last_error}")


def run_checked(cmd: list[str], *, env: dict[str, str] | None = None, log_path: Path | None = None) -> None:
    if log_path is None:
        subprocess.run(cmd, cwd=str(ROOT_DIR), env=env, check=True)
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fp:
        fp.write("$ " + " ".join(cmd) + "\n")
        fp.flush()
        subprocess.run(cmd, cwd=str(ROOT_DIR), env=env, stdout=fp, stderr=fp, check=True)


def drain_stderr_to_log(stream: Any, runtime_log: Path, max_bytes: int) -> None:
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


def start_tracee(config: dict[str, Any], run_dir: Path, runtime_log: Path) -> tuple[subprocess.Popen[Any], Any, threading.Thread | None, str]:
    tracee_name = f"tracee_rich_{safe_component(str(config.get('run_id') or 'run_rich'))}"
    subprocess.run(["docker", "rm", "-f", tracee_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    trace_log_fp = (run_dir / "trace.log").open("w", encoding="utf-8", errors="ignore")
    events = ",".join(str(item) for item in list(config.get("tracee_events") or []))
    if not events:
        events = "sched_process_exec,execve,openat,read,write,close,connect,accept,sendto,recvfrom,fork,clone,vfork,mmap,security_socket_connect,security_socket_accept"
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
        str(config.get("tracee_image") or "aquasec/tracee:0.24.1"),
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
    proc = subprocess.Popen(cmd, cwd=str(ROOT_DIR), stdout=trace_log_fp, stderr=subprocess.PIPE)
    stderr_thread = None
    if proc.stderr is not None:
        stderr_thread = threading.Thread(
            target=drain_stderr_to_log,
            args=(proc.stderr, runtime_log, as_int(config.get("tracee_runtime_stderr_max_bytes"), 10_000_000)),
            daemon=True,
        )
        stderr_thread.start()
    time.sleep(as_float(config.get("tracee_settle_seconds"), 4.0))
    return proc, trace_log_fp, stderr_thread, tracee_name


def stop_tracee(proc: subprocess.Popen[Any] | None, trace_log_fp: Any, stderr_thread: threading.Thread | None, tracee_name: str, flush_seconds: float, runtime_log: Path) -> None:
    time.sleep(max(flush_seconds, 0.0))
    subprocess.run(["docker", "rm", "-f", tracee_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if proc is not None:
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
    if trace_log_fp is not None:
        trace_log_fp.close()
    if stderr_thread is not None:
        stderr_thread.join(timeout=5)
    with runtime_log.open("a", encoding="utf-8") as fp:
        fp.write(f"tracee stopped: {tracee_name}\n")


def launch_clients(config: dict[str, Any], run_dir: Path, runtime_log: Path) -> list[subprocess.Popen[Any]]:
    client_events_dir = run_dir / "client_events"
    client_events_dir.mkdir(parents=True, exist_ok=True)
    procs: list[subprocess.Popen[Any]] = []
    actors = list(config.get("actors") or [])
    network = str(config.get("docker_network") or "drsec-net")
    image = str(config.get("client_image") or "deploy-vuln-app:latest")
    duration = str(as_int(config.get("duration_seconds"), 1800))
    interval = str(as_float(config.get("client_interval_seconds"), 0.35))
    runtime_log_fp = runtime_log.open("a", encoding="utf-8")
    for actor in actors:
        role = str(actor.get("role") or "")
        replicas = max(as_int(actor.get("replicas"), 1), 1)
        for idx in range(replicas):
            name = f"drsec-rich-{safe_component(str(config.get('run_id') or 'run'))}-{safe_component(role)}-{idx}"
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cmd = [
                "docker",
                "run",
                "--rm",
                "--name",
                name,
                "--label",
                "drsec.rich=1",
                "--label",
                f"drsec.run_id={config.get('run_id')}",
                "--network",
                network,
                "-e",
                f"DRSEC_RICH_RUN_ID={config.get('run_id')}",
                "-e",
                f"DRSEC_RICH_ROLE={role}",
                "-e",
                f"DRSEC_RICH_BASE_URL={config.get('client_base_url')}",
                "-e",
                f"DRSEC_RICH_METRICS_URL={config.get('metrics_url')}",
                "-e",
                "DRSEC_RICH_OUTPUT_DIR=/out",
                "-e",
                f"DRSEC_RICH_DURATION_SECONDS={duration}",
                "-e",
                f"DRSEC_RICH_INTERVAL_SECONDS={interval}",
                "-e",
                f"DRSEC_RICH_SEED={20260501 + idx}",
                "-v",
                f"{client_events_dir}:/out",
                image,
                "python",
                "/app/rich_client.py",
                "--role",
                role,
            ]
            runtime_log_fp.write("client command: " + " ".join(cmd) + "\n")
            runtime_log_fp.flush()
            procs.append(subprocess.Popen(cmd, cwd=str(ROOT_DIR), stdout=runtime_log_fp, stderr=runtime_log_fp))
    runtime_log_fp.close()
    return procs


def wait_clients(procs: list[subprocess.Popen[Any]], timeout_seconds: float) -> list[int]:
    deadline = time.time() + timeout_seconds
    exit_codes: list[int] = []
    for proc in procs:
        remaining = max(deadline - time.time(), 1.0)
        try:
            exit_codes.append(int(proc.wait(timeout=remaining)))
        except subprocess.TimeoutExpired:
            proc.kill()
            exit_codes.append(-9)
    return exit_codes


def merge_request_events(run_dir: Path, service_data: Path | None = None) -> int:
    output_path = run_dir / "request_events.jsonl"
    sources = sorted((run_dir / "client_events").glob("*.jsonl"))
    worker_data = service_data if service_data is not None else run_dir / "service_data"
    sources.extend(sorted(worker_data.glob("rich_worker_events/*.jsonl")))
    count = 0
    with output_path.open("w", encoding="utf-8") as out:
        for source in sources:
            for line in source.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                out.write(line.rstrip("\n") + "\n")
                count += 1
    return count


def collect_container_inventory(run_dir: Path, run_id: str) -> None:
    names = [
        "drsec-api-rich",
        "drsec-worker-rich",
        "drsec-metrics-sink-rich",
    ]
    try:
        ps = subprocess.run(
            ["docker", "ps", "-a", "--filter", "label=drsec.rich=1", "--format", "{{.Names}}"],
            text=True,
            capture_output=True,
            check=False,
        )
        names.extend([line.strip() for line in ps.stdout.splitlines() if line.strip()])
        payload = []
        for name in sorted(set(names)):
            inspect = subprocess.run(["docker", "inspect", name], text=True, capture_output=True, check=False)
            if inspect.returncode == 0:
                payload.extend(json.loads(inspect.stdout))
        write_json(run_dir / "container_inventory.json", {"run_id": run_id, "containers": payload})
    except Exception as exc:
        write_json(run_dir / "container_inventory.json", {"run_id": run_id, "error": f"{type(exc).__name__}: {exc}", "containers": []})


def materialize_windows(config: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    trace_path = run_dir / "trace.log"
    windows_dir = configured_windows_dir(config, run_dir)
    windows_dir.mkdir(parents=True, exist_ok=True)
    for stale_window in windows_dir.glob("window_*.json"):
        stale_window.unlink()
    parser = TraceeLogParser()
    logs, parse_stats = parser.parse_log_file_with_stats(str(trace_path))
    reducer = StreamingReducer(
        config=StreamingReductionConfig(
            window_seconds=as_int(config.get("window_seconds"), 1800),
            time_bin_seconds=as_int(config.get("time_bin_seconds"), 30),
        )
    )
    count = 0
    window_stats = []
    for count, (graph, _metas) in enumerate(reducer.ingest_logs(logs), start=1):
        path = windows_dir / f"window_{count:04d}.json"
        dump_window_graph(str(path), graph)
        window_stats.append(
            {
                "file": path.name,
                "node_count": graph.number_of_nodes(),
                "edge_count": graph.number_of_edges(),
            }
        )
    return {
        "windows_dir": str(windows_dir),
        "window_count": count,
        "trace_stats": parse_stats,
        "window_stats": window_stats,
    }


def dry_run_plan(config: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    return {
        "dry_run": True,
        "run_id": config.get("run_id"),
        "split": config.get("split"),
        "run_dir": str(run_dir),
        "compose_services": ["api-rich", "worker-rich", "metrics-sink-rich"],
        "tracee_output": ["json", "option:parse-arguments-fds"],
        "actors": config.get("actors"),
        "window_seconds": config.get("window_seconds"),
        "time_bin_seconds": config.get("time_bin_seconds"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect rich benign Tracee corpus with container-side actors.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--run-id", default="")
    parser.add_argument("--split", default="")
    parser.add_argument("--duration-seconds", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    config_path = resolve_path(args.config)
    config = load_rich_config(config_path)
    if args.run_id:
        config["run_id"] = args.run_id
    if args.split:
        config["split"] = args.split
    if args.duration_seconds is not None:
        config["duration_seconds"] = int(args.duration_seconds)

    run_id = safe_component(str(config.get("run_id") or "run_rich"))
    split = safe_component(str(config.get("split") or "train"))
    corpus_dir = resolve_path(str(config.get("corpus_dir") or "data/benign_corpus_v4"))
    run_dir = corpus_dir / split / run_id
    collection_token = safe_component(utc_now().replace(":", "").replace(".", "_"))
    service_data = run_dir / f"service_data_{collection_token}"
    metrics_data = run_dir / f"metrics_data_{collection_token}"
    runtime_log = run_dir / "tracee_runtime.log"

    if args.dry_run:
        print(json.dumps(dry_run_plan(config, run_dir), ensure_ascii=False, indent=2, sort_keys=True))
        return

    run_dir.mkdir(parents=True, exist_ok=True)
    clean_previous_run_outputs(config, run_dir)
    service_data.mkdir(parents=True, exist_ok=True)
    metrics_data.mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "effective_config.json", config)

    env = os.environ.copy()
    env["DRSEC_RICH_APP_DATA"] = str(service_data)
    env["DRSEC_RICH_METRICS_DATA"] = str(metrics_data)
    env["DRSEC_RICH_RUN_ID"] = run_id
    env["DRSEC_RICH_DURATION_SECONDS"] = str(as_int(config.get("duration_seconds"), 1800))
    env["DRSEC_RICH_HOST_PORT"] = str(as_int(config.get("rich_host_port"), 5002))
    env["COMPOSE_PROFILES"] = str(config.get("compose_profile") or "benign-rich")

    summary: dict[str, Any] = {
        "run_id": run_id,
        "split": split,
        "split_role": split,
        "source_profile": str(config.get("source_profile") or ""),
        "training_pool": split == "train",
        "bootstrap_only": False,
        "start_ts": utc_now(),
        "config_path": str(config_path),
        "run_dir": str(run_dir),
        "service_data_dir": str(service_data),
        "metrics_data_dir": str(metrics_data),
        "errors": [],
    }
    tracee_proc = None
    trace_log_fp = None
    tracee_stderr_thread = None
    tracee_name = ""
    failed = False
    try:
        base = compose_base(config)
        run_checked(base + ["up", "-d", "--build", "api-rich", "worker-rich", "metrics-sink-rich"], env=env, log_path=runtime_log)
        wait_ready(str(config.get("host_ready_url") or "http://127.0.0.1:5002/ready"), as_float(config.get("readiness_timeout_seconds"), 90.0))
        tracee_proc, trace_log_fp, tracee_stderr_thread, tracee_name = start_tracee(config, run_dir, runtime_log)
        clients = launch_clients(config, run_dir, runtime_log)
        summary["client_exit_codes"] = wait_clients(clients, as_float(config.get("duration_seconds"), 1800.0) + 90.0)
    except Exception as exc:
        failed = True
        summary["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        if tracee_name:
            stop_tracee(tracee_proc, trace_log_fp, tracee_stderr_thread, tracee_name, as_float(config.get("tracee_flush_seconds"), 5.0), runtime_log)
        try:
            collect_container_inventory(run_dir, run_id)
        finally:
            try:
                base = compose_base(config)
                run_checked(base + ["stop", "api-rich", "worker-rich", "metrics-sink-rich"], env=env, log_path=runtime_log)
            except Exception as exc:
                summary["errors"].append(f"compose_stop_failed:{type(exc).__name__}: {exc}")

    summary["request_event_count"] = merge_request_events(run_dir, service_data)
    summary.update(materialize_windows(config, run_dir))
    summary["end_ts"] = utc_now()
    write_json(run_dir / "run_meta.json", summary)
    write_json(run_dir / "collection_summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    if failed or summary["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
