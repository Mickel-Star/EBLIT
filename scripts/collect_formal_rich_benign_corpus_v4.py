#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.process.benign_workload_driver import load_config


DEFAULT_CONFIG = ROOT_DIR / "configs" / "benign_corpus_v4_rich_formal.yaml"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_component(value: Any) -> str:
    text = str(value or "unknown")
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)
    return cleaned[:96] or "unknown"


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT_DIR / path


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


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


def selected_run_ids(config: dict[str, Any], runs_arg: str) -> list[str]:
    runs = dict(config.get("runs") or {})
    if runs_arg.strip():
        selected = [item.strip() for item in runs_arg.split(",") if item.strip()]
    elif runs:
        selected = list(runs.keys())
    else:
        selected = [str(config.get("run_id") or "run_rich")]
    unknown = [run_id for run_id in selected if runs and run_id not in runs]
    if unknown:
        raise ValueError(f"unknown run id(s): {', '.join(unknown)}")
    return selected


def scaled_duration(value: Any, scale: float) -> int:
    return max(1, int(round(as_float(value, 1.0) * float(scale))))


def corpus_dir_for(config: dict[str, Any], override: str, rehearsal: bool) -> Path:
    if override.strip():
        return resolve_path(override)
    base = str(config.get("rehearsal_corpus_dir") or "").strip()
    if rehearsal and base:
        return resolve_path(base)
    corpus_dir = resolve_path(str(config.get("corpus_dir") or "data/benign_corpus_v4_rich_formal"))
    if rehearsal:
        return corpus_dir.parent / f"{corpus_dir.name}_rehearsal"
    return corpus_dir


def effective_run_config(
    *,
    config: dict[str, Any],
    run_id: str,
    corpus_dir: Path,
    duration_scale: float,
) -> dict[str, Any]:
    runs = dict(config.get("runs") or {})
    raw_run = dict(runs.get(run_id) or {})
    payload = {key: value for key, value in config.items() if key != "runs"}
    payload.update(raw_run)
    payload["run_id"] = run_id
    payload["split"] = str(raw_run.get("split") or payload.get("split") or "train")
    payload["split_role"] = str(payload["split"])
    payload["source_profile"] = str(raw_run.get("source_profile") or payload.get("source_profile") or run_id)
    payload["duration_seconds"] = scaled_duration(raw_run.get("duration_seconds", payload.get("duration_seconds", 300)), duration_scale)
    payload["source_duration_seconds"] = as_int(raw_run.get("duration_seconds", payload.get("duration_seconds")), payload["duration_seconds"])
    payload["duration_scale"] = float(duration_scale)
    payload["corpus_dir"] = str(corpus_dir)
    payload["training_pool"] = str(payload["split"]) == "train"
    payload["bootstrap_only"] = False
    return payload


def run_command(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=str(ROOT_DIR), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return int(proc.returncode), proc.stdout


def build_plan(config: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    scale = as_float(args.duration_scale, 1.0)
    if bool(args.rehearsal) and scale == 1.0:
        scale = 0.1
    corpus_dir = corpus_dir_for(config, str(args.corpus_dir or ""), bool(args.rehearsal))
    plan = []
    for run_id in selected_run_ids(config, str(args.runs or "")):
        run_cfg = effective_run_config(config=config, run_id=run_id, corpus_dir=corpus_dir, duration_scale=scale)
        split = safe_component(run_cfg.get("split") or "train")
        run_dir = corpus_dir / split / safe_component(run_id)
        plan.append(
            {
                "run_id": run_id,
                "split": split,
                "duration_seconds": int(run_cfg["duration_seconds"]),
                "run_dir": str(run_dir),
                "config": run_cfg,
            }
        )
    return plan


def validate_run(run_cfg_path: Path, run_dir: Path, run_cfg: dict[str, Any]) -> tuple[int, str]:
    windows_name = str(run_cfg.get("windows_dir_name") or "").strip()
    if windows_name:
        windows_dir = run_dir / windows_name
    else:
        windows_dir = run_dir / f"windows_{as_int(run_cfg.get('window_seconds'), 1800)}s"
    cmd = [
        sys.executable,
        "scripts/validate_provenance_windows.py",
        "--windows-dir",
        str(windows_dir),
        "--request-events",
        str(run_dir / "request_events.jsonl"),
        "--config",
        str(run_cfg_path),
    ]
    return run_command(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect formal rich benign corpus v4 runs.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--corpus-dir", default="")
    parser.add_argument("--runs", default="", help="Comma-separated run IDs.")
    parser.add_argument("--duration-scale", type=float, default=1.0)
    parser.add_argument("--rehearsal", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-validate", action="store_true")
    parser.add_argument("--continue-on-error", action="store_true")
    args = parser.parse_args()

    config_path = resolve_path(args.config)
    config = load_config(config_path)
    plan = build_plan(config, args)
    if args.dry_run:
        print(json.dumps({"config": str(config_path), "plan": plan}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    report = {
        "dataset": str(config.get("dataset") or "benign_corpus_v4_rich_formal"),
        "created_at": utc_now(),
        "config_path": str(config_path),
        "rehearsal": bool(args.rehearsal),
        "duration_scale": as_float(args.duration_scale, 1.0),
        "runs": {},
        "errors": [],
    }
    failed = False
    corpus_dir = Path(plan[0]["run_dir"]).parents[1] if plan else corpus_dir_for(config, str(args.corpus_dir or ""), bool(args.rehearsal))
    for item in plan:
        run_id = str(item["run_id"])
        run_dir = Path(str(item["run_dir"]))
        run_cfg = dict(item["config"])
        run_cfg_path = run_dir / "collector_input_config.json"
        write_json(run_cfg_path, run_cfg)
        print(f"==> collecting {run_id} split={item['split']} duration={item['duration_seconds']}s dir={run_dir}")
        exit_code, output = run_command([sys.executable, "scripts/collect_rich_benign_corpus.py", "--config", str(run_cfg_path)])
        run_report: dict[str, Any] = {
            "split": item["split"],
            "duration_seconds": item["duration_seconds"],
            "run_dir": str(run_dir),
            "collection_exit_code": exit_code,
            "collection_output_tail": output[-4000:],
            "validation_exit_code": None,
            "validation_output_tail": "",
            "status": "success" if exit_code == 0 else "failed",
        }
        if exit_code != 0:
            failed = True
            report["errors"].append(f"{run_id}:collection_failed:{exit_code}")
        elif not bool(args.no_validate):
            validation_exit, validation_output = validate_run(run_cfg_path, run_dir, run_cfg)
            run_report["validation_exit_code"] = validation_exit
            run_report["validation_output_tail"] = validation_output[-4000:]
            if validation_exit != 0:
                failed = True
                run_report["status"] = "failed"
                report["errors"].append(f"{run_id}:validation_failed:{validation_exit}")
        report["runs"][run_id] = run_report
        write_json(corpus_dir / "formal_rich_collection_report.json", report)
        if run_report["status"] != "success" and not bool(args.continue_on_error):
            break

    report["completed_at"] = utc_now()
    write_json(corpus_dir / "formal_rich_collection_report.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
