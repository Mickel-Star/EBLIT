import unittest
from pathlib import Path

from src.common.benchmarking import load_scenario_manifest


REPO_ROOT = Path(__file__).resolve().parents[1]


class BenchmarkScenarioManifestTest(unittest.TestCase):
    def test_atomic_scenario_manifest_loads_with_extended_metadata(self) -> None:
        manifest = load_scenario_manifest(str(REPO_ROOT), "atomic")

        self.assertEqual("atomic_v1", manifest["scenario_set"])
        self.assertTrue(manifest["manifest_path"].endswith("benchmark_scenarios.atomic.json"))
        scenarios = manifest["scenarios"]
        self.assertEqual(9, len(scenarios))

        required = {
            "recon_probe",
            "secret_read",
            "db_dump_local",
            "db_exfil_c2",
            "drop_and_exec",
            "path_hijack_exec",
            "docker_sock_abuse",
            "long_lived_beacon",
            "resource_abuse",
        }
        self.assertEqual(required, {scenario["id"] for scenario in scenarios})

        for scenario in scenarios:
            self.assertEqual("atomic", scenario["scenario_type"])
            self.assertTrue(scenario["attck"]["tactic"])
            self.assertTrue(scenario["attck"]["technique_id"])
            self.assertTrue(scenario["attck"]["technique_name"])

            evidence = scenario["expected_evidence"]
            self.assertIsInstance(evidence["process_patterns"], list)
            self.assertTrue(evidence["process_patterns"])
            self.assertIsInstance(evidence["file_patterns"], list)
            self.assertIsInstance(evidence["net_patterns"], list)
            self.assertIsInstance(evidence["edge_types"], list)
            self.assertTrue(evidence["edge_types"])

            safety = scenario["safety"]
            self.assertIs(safety["lab_only"], True)
            self.assertIs(safety["real_malware"], False)
            self.assertIs(safety["host_destructive_actions"], False)

            self.assertEqual(210, scenario["smoke_profile"]["duration_seconds"])
            self.assertGreaterEqual(scenario["formal_profile"]["window_seconds"], 1800)
            self.assertGreaterEqual(
                scenario["formal_profile"]["duration_seconds"],
                scenario["formal_profile"]["window_seconds"],
            )

            variants = scenario["command_variants"]
            self.assertEqual(3, len(variants))
            for variant in variants:
                self.assertTrue(variant["variant_id"])
                self.assertTrue(variant["description"])
                self.assertTrue(variant["command"])
                self.assertIn("expected_artifacts", variant)

        db_exfil = next(s for s in scenarios if s["id"] == "db_exfil_c2")
        db_commands = "\n".join(v["command"] for v in db_exfil["command_variants"])
        self.assertIn("/upload", db_commands)
        self.assertNotIn("socket.socket", db_commands)

        beacon = next(s for s in scenarios if s["id"] == "long_lived_beacon")
        beacon_commands = "\n".join(v["command"] for v in beacon["command_variants"])
        self.assertIn("/beacon", beacon_commands)
        self.assertNotIn("socket.socket", beacon_commands)


if __name__ == "__main__":
    unittest.main()
