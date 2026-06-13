import unittest

import networkx as nx

from src.analysis.bbk_window_scorer import score_bbk_window


class FakeBBK:
    def __init__(self, support_map, *, seen=None, novelty_map=None, novelty_threshold=0.2):
        self.support_map = dict(support_map)
        self.seen = set(seen or [])
        self.novelty_map = dict(novelty_map or {})
        self.novelty_threshold = float(novelty_threshold)

    def canonical_signature(self, node, meta=None):
        meta = meta or {}
        if str(node).startswith("proc:"):
            if meta.get("pathname"):
                return f"proc:path:{meta['pathname']}"
            if meta.get("name"):
                return f"proc:name:{meta['name']}"
            return f"proc:name:{node}"
        if str(node).startswith("file:"):
            return f"file:path:{meta.get('pathname') or meta.get('name') or node}"
        if str(node).startswith("net:"):
            return f"net:name:{meta.get('name') or node}"
        return None

    def has_signature(self, signature, entity_type=None):
        return str(signature) in self.seen

    def novelty_score(self, node, meta=None):
        signature = self.canonical_signature(node, meta)
        return float(self.novelty_map.get(signature, 0.0 if signature in self.seen else 1.0))

    def get_process_novelty_threshold(self, default=0.15):
        return self.novelty_threshold

    def support(self, src, dst, edge_type, src_meta=None, dst_meta=None):
        return float(self.support_map.get((src, dst, edge_type), 1.0))


def make_graph():
    g = nx.MultiDiGraph()
    seen_proc = "proc:container:abc:pid:1"
    unseen_proc = "proc:container:abc:pid:2"
    file_node = "file:/tmp/a"
    net_node = "net:1.1.1.1:443"
    g.add_node(seen_proc, meta={"pid": 1, "name": "curl", "pathname": "/usr/bin/curl", "container_id": "abc"})
    g.add_node(unseen_proc, meta={"pid": 2, "name": "curl-helper", "pathname": "/usr/bin/curl-helper", "container_id": "abc"})
    g.add_node(file_node, meta={"pathname": "/tmp/a"})
    g.add_node(net_node, meta={"dst_ip": "1.1.1.1", "dst_port": 443})
    g.add_edge(seen_proc, file_node, type="Write", event_name="openat", count=1, first_ts=1, last_ts=1, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=0)
    g.add_edge(seen_proc, net_node, type="Send", event_name="connect", count=1, first_ts=1, last_ts=1, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=0)
    g.add_edge(unseen_proc, file_node, type="Write", event_name="openat", count=1, first_ts=1, last_ts=1, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=0)
    g.add_edge(unseen_proc, net_node, type="Send", event_name="connect", count=1, first_ts=1, last_ts=1, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=0)
    return g, seen_proc, unseen_proc, file_node, net_node


class BBKWindowScorerTest(unittest.TestCase):
    def test_empty_graph_returns_zero_with_reason(self):
        result = score_bbk_window(nx.MultiDiGraph(), FakeBBK({}))
        self.assertEqual(0.0, result["bbk_score"])
        self.assertEqual("empty_window_graph", result["reason"])

    def test_exact_seen_process_is_skipped_but_unseen_candidate_triggers(self):
        g, seen_proc, unseen_proc, file_node, net_node = make_graph()
        result = score_bbk_window(
            g,
            FakeBBK(
                {
                    (seen_proc, file_node, "Write"): 0.9,
                    (seen_proc, net_node, "Send"): 0.85,
                    (unseen_proc, file_node, "Write"): 1e-9,
                    (unseen_proc, net_node, "Send"): 1e-9,
                },
                seen={"proc:path:/usr/bin/curl"},
                novelty_map={"proc:path:/usr/bin/curl-helper": 0.33},
                novelty_threshold=0.2,
            ),
        )
        self.assertEqual(2, result["process_node_count"])
        self.assertEqual(1, result["candidate_process_count"])
        self.assertEqual(unseen_proc, result["top_candidate_processes"][0]["node"])
        self.assertEqual("exact_signature_unseen", result["top_candidate_processes"][0]["candidate_reason"])
        self.assertGreater(result["bbk_score"], 0.9)
        self.assertEqual(1, result["rare_edge_count"])
        self.assertTrue(result["top_rare_paths"])
        self.assertEqual(unseen_proc, result["top_rare_paths"][0]["process_node"])
        self.assertEqual(2, result["novelty_stats"]["count"])


if __name__ == "__main__":
    unittest.main()
