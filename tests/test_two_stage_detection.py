import unittest

import networkx as nx

from src.process.analysis_engine import TwoStageDetectionConfig, detect_two_stage_window, summarize_two_stage_results


class FakeBBK:
    def __init__(self, support_map, *, seen=None, novelty_threshold=0.2):
        self.support_map = dict(support_map)
        self.seen = set(seen or [])
        self.novelty_threshold = float(novelty_threshold)

    def canonical_signature(self, node, meta=None):
        meta = meta or {}
        if str(node).startswith("proc:"):
            return f"proc:path:{meta.get('pathname') or meta.get('name') or node}"
        if str(node).startswith("file:"):
            return f"file:path:{meta.get('pathname') or node}"
        if str(node).startswith("net:"):
            return f"net:name:{meta.get('name') or node}"
        return None

    def has_signature(self, signature, entity_type=None):
        return str(signature) in self.seen

    def novelty_score(self, node, meta=None):
        signature = self.canonical_signature(node, meta)
        return 0.0 if signature in self.seen else 1.0

    def get_process_novelty_threshold(self, default=0.15):
        return self.novelty_threshold

    def support(self, src, dst, edge_type, src_meta=None, dst_meta=None):
        return float(self.support_map.get((src, dst, edge_type), 1e-9))


class FakeGMAE:
    def __init__(self, scores, *, threshold=0.95, threshold_source="default", warning=""):
        self.gmae_runtime = {
            "loaded": True,
            "process_error_calibration": {
                "type": "empirical_cdf",
                "policy": "p95",
                "scores": [0.1, 0.4, 0.95, 0.99],
                "count": 4,
                "process_score_threshold": 0.95,
            },
        }
        self.scores = dict(scores)
        self.threshold = float(threshold)
        self.threshold_source = str(threshold_source)
        self.warning = str(warning)
        self.calls = 0

    def score_process_nodes(self, graph):
        self.calls += 1
        ranked = sorted(self.scores.items(), key=lambda item: item[1], reverse=True)
        node_results = []
        for rank, (node_id, score) in enumerate(ranked, start=1):
            meta = dict(graph.nodes[node_id].get("meta", {}) or {})
            node_results.append(
                {
                    "node_id": str(node_id),
                    "node_type": "process",
                    "display_name": str(meta.get("name") or meta.get("pathname") or "unknown"),
                    "gmae_score": float(score),
                    "gmae_raw_error": float(score),
                    "gmae_threshold": float(self.threshold),
                    "is_anomalous": bool(float(score) >= float(self.threshold)),
                    "rank": int(rank),
                    "evidence": {
                        "pid": meta.get("pid"),
                        "container_id": str(meta.get("container_id") or ""),
                    },
                }
            )
        return {
            "node_results": node_results,
            "scores": dict(self.scores),
            "threshold": float(self.threshold),
            "threshold_source": self.threshold_source,
            "supported_node_types": ["process"],
            "warning": self.warning,
        }


def make_graph():
    g = nx.MultiDiGraph()
    g.graph.update(
        {
            "window_start": 0.0,
            "window_end": 1800.0,
            "window_mode": "sliding",
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
        }
    )
    proc = "proc:container:abc:pid:123"
    file_node = "file:/etc/passwd"
    net_node = "net:10.0.0.1:443"
    g.add_node(proc, meta={"pid": 123, "name": "curl", "pathname": "/usr/bin/curl", "container_id": "abcdef123456"})
    g.add_node(file_node, meta={"pathname": "/etc/passwd"})
    g.add_node(net_node, meta={"dst_ip": "10.0.0.1", "dst_port": 443})
    g.add_edge(proc, file_node, type="Write", event_name="openat", count=1, first_ts=0, last_ts=0, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=0)
    g.add_edge(proc, net_node, type="Send", event_name="connect", count=1, first_ts=0, last_ts=0, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=0)
    return g, proc, file_node, net_node


class TwoStageDetectionTest(unittest.TestCase):
    def test_bbk_below_threshold_skips_gmae(self):
        g, proc, file_node, net_node = make_graph()
        bbk = FakeBBK(
            {
                (proc, file_node, "Write"): 0.8,
                (proc, net_node, "Send"): 0.9,
            },
            seen={"proc:path:/usr/bin/curl"},
        )
        gmae = FakeGMAE({proc: 0.95})
        result = detect_two_stage_window(g, {"window_id": "window_0001"}, bbk, gmae, TwoStageDetectionConfig(bbk_trigger_threshold=0.95, top_k=3))
        self.assertFalse(result["bbk_triggered"])
        self.assertFalse(result["gmae_triggered"])
        self.assertFalse(result["gmae_ran"])
        self.assertEqual("bbk_score_below_trigger_threshold", result["gmae_reason_if_skipped"])
        self.assertEqual(0, gmae.calls)
        self.assertEqual(0, result["candidate_process_count"])
        self.assertEqual([], result["anomalous_nodes"])
        self.assertEqual("two_stage", result["pipeline_mode"])

    def test_force_gmae_all_windows_does_not_fake_bbk_trigger(self):
        g, proc, file_node, net_node = make_graph()
        bbk = FakeBBK(
            {
                (proc, file_node, "Write"): 0.8,
                (proc, net_node, "Send"): 0.9,
            },
            seen={"proc:path:/usr/bin/curl"},
        )
        gmae = FakeGMAE({proc: 0.88, file_node: 0.99})
        result = detect_two_stage_window(
            g,
            {"window_id": "window_0001"},
            bbk,
            gmae,
            TwoStageDetectionConfig(bbk_trigger_threshold=0.95, top_k=5, force_gmae_all_windows=True),
        )
        self.assertFalse(result["bbk_triggered"])
        self.assertTrue(result["gmae_triggered"])
        self.assertTrue(result["gmae_ran"])
        self.assertEqual("gmae_forced", result["stage"])
        self.assertEqual(1, len(result["top_processes"]))
        self.assertTrue(all(str(item["node"]).startswith("proc:") for item in result["top_processes"]))
        self.assertEqual(1, result["top_processes"][0]["rank"])
        self.assertIn("gmae_score", result["top_processes"][0])
        self.assertIn("supporting_rare_paths", result["top_processes"][0])
        self.assertTrue(result["anomalous_nodes"])
        self.assertEqual(0.95, result["gmae_node_threshold"])
        self.assertEqual(["process"], result["supported_node_types"])

    def test_disable_gmae_keeps_bbk_only(self):
        g, proc, file_node, net_node = make_graph()
        bbk = FakeBBK(
            {
                (proc, file_node, "Write"): 1e-9,
                (proc, net_node, "Send"): 1e-9,
            },
        )
        gmae = FakeGMAE({proc: 0.91})
        result = detect_two_stage_window(
            g,
            {"window_id": "window_0001"},
            bbk,
            gmae,
            TwoStageDetectionConfig(bbk_trigger_threshold=0.1, top_k=3, disable_gmae=True),
        )
        self.assertTrue(result["bbk_triggered"])
        self.assertFalse(result["gmae_triggered"])
        self.assertFalse(result["gmae_ran"])
        self.assertEqual("gmae_disabled", result["gmae_reason_if_skipped"])
        self.assertEqual([], result["top_processes"])
        self.assertEqual([], result["anomalous_nodes"])

    def test_missing_gmae_reports_reason(self):
        g, proc, file_node, net_node = make_graph()
        bbk = FakeBBK(
            {
                (proc, file_node, "Write"): 1e-9,
                (proc, net_node, "Send"): 1e-9,
            },
        )
        result = detect_two_stage_window(
            g,
            {"window_id": "window_0001"},
            bbk,
            None,
            TwoStageDetectionConfig(bbk_trigger_threshold=0.1, top_k=3),
        )
        self.assertTrue(result["bbk_triggered"])
        self.assertFalse(result["gmae_available"])
        self.assertEqual("gmae_unavailable", result["gmae_reason_if_skipped"])
        self.assertEqual([], result["anomalous_nodes"])

    def test_anomalous_nodes_are_thresholded_not_topk_only(self):
        g, proc, file_node, net_node = make_graph()
        bbk = FakeBBK(
            {
                (proc, file_node, "Write"): 1e-9,
                (proc, net_node, "Send"): 1e-9,
            },
        )
        gmae = FakeGMAE({proc: 0.97}, threshold=0.95, threshold_source="calibration_policy")
        result = detect_two_stage_window(
            g,
            {"window_id": "window_0001"},
            bbk,
            gmae,
            TwoStageDetectionConfig(bbk_trigger_threshold=0.1, top_k=3, gmae_node_threshold=0.5, max_anomalous_nodes=5),
        )
        self.assertTrue(result["gmae_triggered"])
        self.assertEqual(1, len(result["anomalous_nodes"]))
        self.assertTrue(result["anomalous_nodes"][0]["is_anomalous"])
        self.assertEqual("process", result["anomalous_nodes"][0]["node_type"])
        self.assertEqual(0.95, result["gmae_node_threshold"])

    def test_default_threshold_warning_is_exposed(self):
        g, proc, file_node, net_node = make_graph()
        bbk = FakeBBK(
            {
                (proc, file_node, "Write"): 1e-9,
                (proc, net_node, "Send"): 1e-9,
            },
        )
        gmae = FakeGMAE({proc: 0.40}, threshold=0.5, warning="missing_gmae_calibration_threshold: using default node threshold")
        result = detect_two_stage_window(
            g,
            {"window_id": "window_0001"},
            bbk,
            gmae,
            TwoStageDetectionConfig(bbk_trigger_threshold=0.1, top_k=3, gmae_node_threshold=0.5, max_anomalous_nodes=5),
        )
        self.assertEqual([], result["anomalous_nodes"])
        self.assertIn("missing_gmae_calibration_threshold", result["gmae_warning"])

    def test_anomalous_subgraphs_are_exposed(self):
        g = nx.MultiDiGraph()
        g.graph.update(
            {
                "window_start": 0.0,
                "window_end": 1800.0,
                "window_mode": "sliding",
                "sliding_window_config": {"window_seconds": 1800, "stride_seconds": 600, "time_bin_seconds": 30},
                "reduction_config": {"window_seconds": 1800, "time_bin_seconds": 30},
            }
        )
        proc_a = "proc:container:abc:pid:1"
        proc_b = "proc:container:abc:pid:2"
        file_node = "file:/tmp/drop.sh"
        for node, meta in [
            (proc_a, {"pid": 1, "name": "curl", "pathname": "/usr/bin/curl", "container_id": "abcdef123456"}),
            (proc_b, {"pid": 2, "name": "bash", "pathname": "/usr/bin/bash", "container_id": "abcdef123456"}),
            (file_node, {"pathname": "/tmp/drop.sh"}),
        ]:
            g.add_node(node, meta=meta)
        g.add_edge(proc_a, file_node, type="Write", event_name="write", count=1, first_ts=10, last_ts=10, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=0)
        g.add_edge(file_node, proc_b, type="Read", event_name="read", count=1, first_ts=11, last_ts=11, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=0)
        bbk = FakeBBK(
            {
                (proc_a, file_node, "Write"): 1e-9,
                (file_node, proc_b, "Read"): 1e-9,
            },
        )
        gmae = FakeGMAE({proc_a: 12.0, proc_b: 11.0}, threshold=0.95)
        result = detect_two_stage_window(
            g,
            {"window_id": "window_0002"},
            bbk,
            gmae,
            TwoStageDetectionConfig(bbk_trigger_threshold=0.1, top_k=3, max_anomalous_nodes=5),
        )
        self.assertTrue(result["anomalous_nodes"])
        self.assertIn("anomalous_subgraphs", result)
        self.assertTrue(result["anomalous_subgraphs"])
        self.assertGreaterEqual(result["anomalous_subgraphs"][0]["edge_count"], 1)

    def test_summary_contains_gmae_reduction_ratio(self):
        summary = summarize_two_stage_results(
            [
                {"bbk_triggered": True, "gmae_triggered": True, "timing": {"bbk_time_ms": 1.0, "gmae_time_ms": 2.0, "total_window_time_ms": 3.0}},
                {"bbk_triggered": False, "gmae_triggered": False, "timing": {"bbk_time_ms": 1.0, "gmae_time_ms": 0.0, "total_window_time_ms": 1.0}},
            ],
            top_k=5,
            window_seconds=1800,
            stride_seconds=600,
            window_mode="sliding",
        )
        self.assertEqual(2, summary["total_windows"])
        self.assertEqual(1, summary["gmae_triggered_windows"])
        self.assertAlmostEqual(0.5, summary["gmae_reduction_ratio"])


if __name__ == "__main__":
    unittest.main()
