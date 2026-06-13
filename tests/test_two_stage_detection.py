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
    def __init__(self, scores):
        self.gmae_runtime = {"loaded": True}
        self.scores = dict(scores)
        self.calls = 0

    def score_process_nodes(self, graph):
        self.calls += 1
        return dict(self.scores)


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
        self.assertEqual("bbk_score_below_trigger_threshold", result["gmae_reason_if_skipped"])
        self.assertEqual(0, gmae.calls)
        self.assertEqual(0, result["candidate_process_count"])

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
        self.assertEqual("gmae_forced", result["stage"])
        self.assertEqual(1, len(result["top_processes"]))
        self.assertTrue(all(str(item["node"]).startswith("proc:") for item in result["top_processes"]))
        self.assertEqual(1, result["top_processes"][0]["rank"])
        self.assertIn("gmae_score", result["top_processes"][0])
        self.assertIn("supporting_rare_paths", result["top_processes"][0])

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
        self.assertEqual("gmae_disabled", result["gmae_reason_if_skipped"])
        self.assertEqual([], result["top_processes"])

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
