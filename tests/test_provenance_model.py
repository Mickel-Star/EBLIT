import unittest

import networkx as nx

from src.process.provenance_model import ProvenanceEventMapper, RarePathSelector


class ProvenanceModelTest(unittest.TestCase):
    def test_clone_ignores_pointer_like_child_tid_and_uses_ret_pid(self) -> None:
        mapper = ProvenanceEventMapper()
        edge = mapper.parse_log_event(
            {
                "event": "clone",
                "pid": 1234,
                "timestamp": 1.0,
                "ret": 4321,
                "comm": "python",
                "container_id": "abc123",
                "args": {
                    "child_tid": "0x736f09f12f90",
                },
            }
        )

        self.assertIsNotNone(edge)
        assert edge is not None
        self.assertEqual("Fork", edge.edge_type)
        self.assertEqual("proc:container:abc123:pid:1234", edge.src)
        self.assertEqual("proc:container:abc123:pid:4321", edge.dst)
        self.assertEqual(4321, edge.dst_meta["pid"])

    def test_rare_path_selector_enforces_monotonic_time_and_scores_sum_of_supports(self) -> None:
        selector = RarePathSelector(k1=2, k2=10)
        graph = nx.MultiDiGraph()
        seed = "proc:seed"
        middle = "file:/tmp/demo"
        older_proc = "proc:older"
        newer_proc = "proc:newer"
        graph.add_node(seed, meta={"name": "seed", "pathname": "/usr/bin/seed"})
        graph.add_node(middle, meta={"pathname": "/tmp/demo"})
        graph.add_node(older_proc, meta={"name": "older"})
        graph.add_node(newer_proc, meta={"name": "newer"})
        graph.add_edge(seed, middle, type="Write", event_name="write", count=1, first_ts=10, last_ts=10, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=0)
        graph.add_edge(middle, older_proc, type="Read", event_name="read", count=1, first_ts=5, last_ts=5, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=0)
        graph.add_edge(middle, newer_proc, type="Read", event_name="read", count=1, first_ts=20, last_ts=20, segments=[{"bin": 1, "count": 1}], bin_idx=1, source_semantic_version=1)

        calls = []

        def support(src, dst, edge_type, src_meta=None, dst_meta=None):
            calls.append((src, dst, edge_type, dict(src_meta or {}), dict(dst_meta or {})))
            return 0.5

        results = selector.select_with_chains(graph, seed, support)

        self.assertTrue(any("newer" in str(item.get("text") or "") for item in results))
        self.assertTrue(all("older" not in str(item.get("text") or "") for item in results))
        longer_paths = [item for item in results if len(item.get("chain") or []) == 2 and "newer" in str(item.get("text") or "")]
        self.assertTrue(longer_paths)
        self.assertAlmostEqual(2.0, float(longer_paths[0]["score"]))
        self.assertTrue(calls)
        self.assertIn("pathname", calls[0][3])


if __name__ == "__main__":
    unittest.main()
