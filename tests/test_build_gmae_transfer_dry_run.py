import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def write_jsonl(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def parse_json_payload(stdout: str) -> dict:
    text = str(stdout or "").strip()
    start = text.find("{")
    if start < 0:
        raise AssertionError(f"no JSON payload in stdout: {text}")
    return json.loads(text[start:])


def simple_window_payload() -> dict:
    return {
        "metadata": {
            "window_mode": "sliding",
            "window_start": 0.0,
            "window_end": 1800.0,
            "sliding_window_config": {
                "window_seconds": 1800,
                "stride_seconds": 600,
                "time_bin_seconds": 30,
                "edge_key_mode": "event_time_bin",
            },
            "reduction_config": {
                "window_seconds": 1800,
                "time_bin_seconds": 30,
                "edge_key_mode": "event_time_bin",
            },
        },
        "nodes": [
            {"id": "proc:cadets:test", "meta": {"pid": 1, "name": "proc"}},
            {"id": "file:/tmp/example", "meta": {"pathname": "/tmp/example"}},
        ],
        "edges": [
            {
                "src": "proc:cadets:test",
                "dst": "file:/tmp/example",
                "type": "Write",
                "event_name": "openat",
                "event_names": ["openat"],
                "bin_idx": 1,
                "count": 1,
                "first_ts": 0,
                "last_ts": 0,
                "segments": [{"bin": 1, "count": 1}],
            }
        ],
    }


class BuildGMAETransferDryRunTest(unittest.TestCase):
    def test_dry_run_outputs_transfer_plan_and_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            e3_dir = root / "e3"
            e3_dir.mkdir()
            gt_path = e3_dir / "cadets.txt"
            gt_path.write_text("", encoding="utf-8")
            write_jsonl(
                e3_dir / "ta1-cadets-e3-official.json",
                [
                    {"datum": {"com.bbn.tc.schema.avro.cdm18.Subject": {"uuid": "SUBJECT-1", "cid": 1, "hostId": "HOST", "properties": {"map": {"exec": "proc"}}}}},
                    {"datum": {"com.bbn.tc.schema.avro.cdm18.FileObject": {"uuid": "FILE-1", "type": "FILE_OBJECT_FILE", "baseObject": {"properties": {"map": {}}}}}},
                    {
                        "datum": {
                            "com.bbn.tc.schema.avro.cdm18.Event": {
                                "uuid": "EVENT-1",
                                "type": "EVENT_READ",
                                "subject": {"com.bbn.tc.schema.avro.cdm18.UUID": "SUBJECT-1"},
                                "predicateObject": {"com.bbn.tc.schema.avro.cdm18.UUID": "FILE-1"},
                                "predicateObjectPath": {"string": "/tmp/demo"},
                                "timestampNanos": 100,
                                "name": {"string": "aue_read"},
                                "properties": {"map": {"exec": "proc"}},
                            }
                        }
                    },
                    {
                        "datum": {
                            "com.bbn.tc.schema.avro.cdm18.Event": {
                                "uuid": "EVENT-2",
                                "type": "EVENT_READ",
                                "subject": {"com.bbn.tc.schema.avro.cdm18.UUID": "SUBJECT-1"},
                                "predicateObject": {"com.bbn.tc.schema.avro.cdm18.UUID": "FILE-1"},
                                "predicateObjectPath": {"string": "/tmp/demo"},
                                "timestampNanos": 1_900_000_000_000,
                                "name": {"string": "aue_read"},
                                "properties": {"map": {"exec": "proc"}},
                            }
                        }
                    },
                ],
            )

            local_corpus = root / "benign_corpus_v3"
            for split, run in (("train", "run_a"), ("calibration", "run_c"), ("holdout", "run_d")):
                run_dir = local_corpus / split / run
                windows_dir = run_dir / "windows"
                windows_dir.mkdir(parents=True)
                write_json(windows_dir / "window_0001.json", simple_window_payload())
                write_json(
                    run_dir / "run_meta.json",
                    {
                        "run_id": run,
                        "split_role": split,
                        "source_profile": f"profile_{run}",
                    },
                )
                (run_dir / "trace.log").write_text("", encoding="utf-8")

            output_dir = root / "transfer_output"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.process.main",
                    "build_gmae_transfer",
                    "--e3-dir",
                    str(e3_dir),
                    "--groundtruth",
                    str(gt_path),
                    "--local-corpus",
                    str(local_corpus),
                    "--output-dir",
                    str(output_dir),
                    "--dry-run",
                ],
                cwd=str(REPO_ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(0, proc.returncode, proc.stderr)
            payload = parse_json_payload(proc.stdout)
            self.assertTrue(payload["dry_run"])
            self.assertEqual("gmae_transfer", payload["mode"])
            self.assertEqual(1, payload["e3_window_count"])
            self.assertEqual(3, payload["local_window_count"])
            self.assertEqual(1800, payload["e3_reduction_config"]["window_seconds"])
            self.assertEqual(30, payload["e3_reduction_config"]["time_bin_seconds"])
            self.assertEqual(1800, payload["local_reduction_config"]["window_seconds"])
            self.assertEqual(600, payload["local_reduction_config"]["stride_seconds"])
            self.assertEqual(30, payload["local_reduction_config"]["time_bin_seconds"])
            self.assertTrue(Path(payload["e3_manifest_path"]).exists())
            self.assertTrue(Path(payload["local_manifest_path"]).exists())

    def test_local_limit_applies_per_split_not_globally(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            e3_dir = root / "e3"
            e3_dir.mkdir()
            gt_path = e3_dir / "cadets.txt"
            gt_path.write_text("", encoding="utf-8")
            write_jsonl(
                e3_dir / "ta1-cadets-e3-official.json",
                [
                    {"datum": {"com.bbn.tc.schema.avro.cdm18.Subject": {"uuid": "SUBJECT-1", "cid": 1, "hostId": "HOST", "properties": {"map": {"exec": "proc"}}}}},
                    {"datum": {"com.bbn.tc.schema.avro.cdm18.FileObject": {"uuid": "FILE-1", "type": "FILE_OBJECT_FILE", "baseObject": {"properties": {"map": {}}}}}},
                    {
                        "datum": {
                            "com.bbn.tc.schema.avro.cdm18.Event": {
                                "uuid": "EVENT-1",
                                "type": "EVENT_READ",
                                "subject": {"com.bbn.tc.schema.avro.cdm18.UUID": "SUBJECT-1"},
                                "predicateObject": {"com.bbn.tc.schema.avro.cdm18.UUID": "FILE-1"},
                                "predicateObjectPath": {"string": "/tmp/demo"},
                                "timestampNanos": 100,
                                "name": {"string": "aue_read"},
                                "properties": {"map": {"exec": "proc"}},
                            }
                        }
                    },
                    {
                        "datum": {
                            "com.bbn.tc.schema.avro.cdm18.Event": {
                                "uuid": "EVENT-2",
                                "type": "EVENT_READ",
                                "subject": {"com.bbn.tc.schema.avro.cdm18.UUID": "SUBJECT-1"},
                                "predicateObject": {"com.bbn.tc.schema.avro.cdm18.UUID": "FILE-1"},
                                "predicateObjectPath": {"string": "/tmp/demo"},
                                "timestampNanos": 1_900_000_000_000,
                                "name": {"string": "aue_read"},
                                "properties": {"map": {"exec": "proc"}},
                            }
                        }
                    },
                ],
            )

            local_corpus = root / "benign_corpus_v3"
            for split, run in (("train", "run_a"), ("calibration", "run_c"), ("holdout", "run_d")):
                run_dir = local_corpus / split / run
                windows_dir = run_dir / "windows"
                windows_dir.mkdir(parents=True)
                write_json(windows_dir / "window_0001.json", simple_window_payload())
                write_json(windows_dir / "window_0002.json", simple_window_payload())
                write_json(
                    run_dir / "run_meta.json",
                    {
                        "run_id": run,
                        "split_role": split,
                        "source_profile": f"profile_{run}",
                    },
                )
                (run_dir / "trace.log").write_text("", encoding="utf-8")

            output_dir = root / "transfer_output"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.process.main",
                    "build_gmae_transfer",
                    "--e3-dir",
                    str(e3_dir),
                    "--groundtruth",
                    str(gt_path),
                    "--local-corpus",
                    str(local_corpus),
                    "--output-dir",
                    str(output_dir),
                    "--local-limit-windows",
                    "1",
                    "--dry-run",
                ],
                cwd=str(REPO_ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(0, proc.returncode, proc.stderr)
            payload = parse_json_payload(proc.stdout)
            self.assertEqual(3, payload["local_window_count"])
            distribution = payload["local_summary"]["split_role_window_distribution"]
            self.assertEqual({"calibration": 1, "holdout": 1, "train": 1}, distribution)


if __name__ == "__main__":
    unittest.main()
