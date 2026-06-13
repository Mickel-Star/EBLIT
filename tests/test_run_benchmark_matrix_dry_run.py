import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class RunBenchmarkMatrixDryRunTest(unittest.TestCase):
    def test_dry_run_outputs_atomic_plan_without_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_root = Path(tmpdir) / "benchmarks_atomic"
            proc = subprocess.run(
                [
                    sys.executable,
                    "scripts/run_benchmark_matrix.py",
                    "--dry-run",
                    "--scenario-set",
                    "config/benchmark_scenarios.atomic.json",
                    "--profile",
                    "smoke",
                    "--repeats",
                    "1",
                    "--output-root",
                    str(output_root),
                ],
                cwd=str(REPO_ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(0, proc.returncode, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertTrue(payload["dry_run"])
            self.assertEqual("atomic_v1", payload["scenario_set"])
            self.assertEqual("smoke", payload["profile"])
            self.assertEqual("sliding", payload["window_mode"])
            self.assertEqual(27, payload["run_count"])
            self.assertEqual(27, len(payload["runs"]))
            self.assertEqual(9, len({row["scenario_id"] for row in payload["runs"]}))
            self.assertEqual(3, len([row for row in payload["runs"] if row["scenario_id"] == "db_exfil_c2"]))
            self.assertFalse(output_root.exists())


if __name__ == "__main__":
    unittest.main()
