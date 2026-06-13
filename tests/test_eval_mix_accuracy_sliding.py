import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import networkx as nx

from scripts.eval_mix_accuracy import (
    RunArtifacts,
    _stage_label_for_window,
    evaluate_single_run,
)
from src.process.window_io import dump_window_graph


ATTACKER_ID = "attackerabcdef123456"


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def make_window_graph(*, start=None, end=None, mode="sliding"):
    g = nx.MultiDiGraph()
    if start is not None and end is not None:
        g.graph.update(
            {
                "window_start": float(start),
                "window_end": float(end),
                "window_start_ns": int(float(start) * 1_000_000_000),
                "window_end_ns": int(float(end) * 1_000_000_000),
                "window_mode": mode,
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
                "event_count": 1,
                "complete": True,
            }
        )
    g.add_node(
        "proc:container:attackerabc:pid:123",
        meta={
            "pid": 123,
            "name": "sleep",
            "pathname": "/bin/sleep",
            "container_id": ATTACKER_ID,
        },
    )
    g.add_node("file:/etc/passwd", meta={"pathname": "/etc/passwd", "name": "/etc/passwd"})
    g.add_edge(
        "proc:container:attackerabc:pid:123",
        "file:/etc/passwd",
        type="Read",
        event_name="openat",
        event_names=["openat"],
        bin_idx=1,
        count=1,
        first_ts=0,
        last_ts=0,
        segments=[{"bin": 1, "count": 1}],
    )
    return g


class FakeEngine:
    def __init__(self, candidates):
        self.candidates = list(candidates)

    def detect_window_alerts_in_window(self, graph, threshold=0.0, window_hint=None):
        if not self.candidates:
            return []
        return [SimpleNamespace(window_score=max(float(item.get("process_score", 0.0)) for item in self.candidates))]

    def detect_suspicious_processes_in_window(self, graph, threshold=0.0, window_hint=None):
        return list(self.candidates)


def candidate(pid, name, score, evidence_text):
    return {
        "pid": pid,
        "node": f"proc:container:attackerabc:pid:{pid}",
        "process_score": score,
        "rarity_score": score,
        "process_meta": {
            "pid": pid,
            "name": name,
            "pathname": f"/bin/{name}",
            "container_id": ATTACKER_ID,
        },
        "display_name": name,
        "rare_paths": [{"text": evidence_text, "keywords": [name], "chain": []}],
        "graph_context": evidence_text,
        "evidence_key": f"{ATTACKER_ID}:{pid}",
    }


class EvalMixAccuracySlidingTest(unittest.TestCase):
    def _write_common_run_files(self, run_dir: Path, expected_evidence=None):
        windows_dir = run_dir / "windows"
        windows_dir.mkdir(parents=True)
        dump_window_graph(str(windows_dir / "window_0001.json"), make_window_graph(start=0, end=1800))
        run_meta = {
            "scenario_id": "synthetic_attack",
            "family_id": "synthetic_attack",
            "kind": "attack",
            "repeat_id": 1,
            "window_mode": "sliding",
            "window_seconds": 1800,
            "stride_seconds": 600,
            "attack_start": 600,
            "attack_end": 900,
            "stage_boundaries": {
                "warmup_start": 0,
                "warmup_end": 600,
                "attack_start": 600,
                "attack_end": 900,
                "cooldown_start": 900,
                "cooldown_end": 1200,
            },
        }
        if expected_evidence is not None:
            run_meta["expected_evidence"] = expected_evidence
        write_json(run_dir / "run_meta.json", run_meta)
        write_json(
            run_dir / "labels.json",
            {
                "schema_version": 1,
                "scenario_id": "synthetic_attack",
                "kind": "attack",
                "positive_roles": ["attacker"],
                "negative_roles": ["benign"],
                "containers": [
                    {
                        "role": "attacker",
                        "container_id": ATTACKER_ID,
                        "container_name": "attacker",
                        "label": "positive",
                    }
                ],
            },
        )
        return windows_dir, run_dir / "labels.json", run_dir / "run_meta.json"

    def test_sliding_metadata_drives_overlap_and_topk_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "repeat_1"
            windows_dir, labels_path, run_meta_path = self._write_common_run_files(
                run_dir,
                expected_evidence={
                    "process_patterns": ["curl"],
                    "file_patterns": ["/etc/passwd"],
                    "net_patterns": [],
                    "edge_types": [],
                },
            )
            engine = FakeEngine(
                [
                    candidate(123, "sleep", 0.9, "sleep touches /tmp/benign"),
                    candidate(124, "curl", 0.8, "curl reads /etc/passwd via Read edge"),
                ]
            )

            summary = evaluate_single_run(
                windows_dir,
                labels_path=labels_path,
                run_meta_path=run_meta_path,
                threshold=0.5,
                engine=engine,
            )

        sample = summary["window_samples"][0]
        self.assertEqual(0.0, sample["window_start_offset_seconds"])
        self.assertEqual(1800.0, sample["window_end_offset_seconds"])
        self.assertEqual(1800.0, sample["window_seconds"])
        self.assertEqual(600.0, sample["stride_seconds"])
        self.assertEqual(1200.0, sample["overlap_seconds"])
        self.assertEqual("sliding", sample["window_mode"])
        self.assertEqual(300.0, sample["attack_overlap_seconds"])
        self.assertAlmostEqual(300.0 / 1800.0, sample["attack_overlap_ratio"])
        self.assertFalse(sample["top1_evidence_hit"])
        self.assertTrue(sample["top3_evidence_hit"])
        self.assertTrue(sample["top5_evidence_hit"])
        self.assertEqual("available", summary["topk_localization"]["status"])
        self.assertEqual(0.0, summary["topk_localization"]["top1_hit_rate"])
        self.assertEqual(1.0, summary["topk_localization"]["top3_hit_rate"])
        self.assertIn("false_positive_rate", summary["by_scenario"]["synthetic_attack"]["window_level"])

    def test_absolute_window_metadata_converts_with_run_start_time(self):
        base = 1_800_000_000.0
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "repeat_1"
            windows_dir = run_dir / "windows"
            windows_dir.mkdir(parents=True)
            window_path = windows_dir / "window_0001.json"
            dump_window_graph(str(window_path), make_window_graph(start=base, end=base + 1800))
            run = RunArtifacts(
                run_id="repeat_1",
                run_dir=run_dir,
                windows_dir=windows_dir,
                scenario_id="absolute",
                repeat_id=1,
                kind="attack",
                labels_path=None,
                run_meta_path=None,
            )
            info = _stage_label_for_window(
                run,
                {
                    "kind": "attack",
                    "window_mode": "sliding",
                    "window_seconds": 1800,
                    "stride_seconds": 600,
                    "run_start_time": base,
                    "attack_start": 600,
                    "attack_end": 900,
                },
                window_path,
            )

        self.assertEqual(0.0, info["window_start_offset_seconds"])
        self.assertEqual(1800.0, info["window_end_offset_seconds"])
        self.assertEqual([], info["time_base_warnings"])
        self.assertEqual(300.0, info["attack_overlap_seconds"])

    def test_old_fixed_window_without_metadata_falls_back_to_sequence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "repeat_1"
            windows_dir = run_dir / "windows"
            windows_dir.mkdir(parents=True)
            legacy_path = windows_dir / "window_0002.json"
            write_json(
                legacy_path,
                {
                    "metadata": {
                        "reduction_config": {
                            "window_seconds": 30,
                            "time_bin_seconds": 30,
                            "edge_key_mode": "event_time_bin",
                        }
                    },
                    "nodes": [],
                    "edges": [],
                },
            )
            run = RunArtifacts(
                run_id="repeat_1",
                run_dir=run_dir,
                windows_dir=windows_dir,
                scenario_id="legacy",
                repeat_id=1,
                kind="attack",
                labels_path=None,
                run_meta_path=None,
            )
            info = _stage_label_for_window(
                run,
                {"kind": "attack", "window_seconds": 30, "attack_start": 40, "attack_end": 100},
                legacy_path,
            )

        self.assertEqual("sequence_fallback", info["window_time_source"])
        self.assertEqual(30.0, info["window_start_offset_seconds"])
        self.assertEqual(60.0, info["window_end_offset_seconds"])
        self.assertEqual(20.0, info["attack_overlap_seconds"])
        self.assertAlmostEqual(20.0 / 30.0, info["attack_overlap_ratio"])

    def test_missing_expected_evidence_outputs_not_available(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "repeat_1"
            windows_dir, labels_path, run_meta_path = self._write_common_run_files(run_dir, expected_evidence=None)
            engine = FakeEngine([candidate(123, "sleep", 0.9, "sleep reads /tmp/benign")])

            summary = evaluate_single_run(
                windows_dir,
                labels_path=labels_path,
                run_meta_path=run_meta_path,
                threshold=0.5,
                engine=engine,
            )

        sample = summary["window_samples"][0]
        self.assertEqual("not_available", sample["topk_evidence_status"])
        self.assertEqual("not_available", sample["top1_evidence_hit"])
        self.assertEqual("not_available", summary["topk_localization"]["status"])


if __name__ == "__main__":
    unittest.main()
