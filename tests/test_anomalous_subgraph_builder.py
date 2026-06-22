import unittest

import networkx as nx

from src.analysis.anomalous_subgraph_builder import build_anomalous_subgraphs


def _graph() -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    proc_a = "proc:a"
    proc_b = "proc:b"
    proc_c = "proc:c"
    file_x = "file:/tmp/x"
    file_y = "file:/tmp/y"
    bridge = "proc:bridge"
    for node, name in [(proc_a, "a"), (proc_b, "b"), (proc_c, "c"), (bridge, "bridge"), (file_x, "/tmp/x"), (file_y, "/tmp/y")]:
        g.add_node(node, meta={"name": name, "pathname": name, "display_name": name})
    g.add_edge(proc_a, file_x, type="Write", event_name="openat", count=1, first_ts=1, last_ts=1, source_semantic_version=0)
    g.add_edge(file_x, proc_b, type="Read", event_name="read", count=1, first_ts=2, last_ts=2, source_semantic_version=0)
    g.add_edge(proc_b, file_y, type="Write", event_name="write", count=1, first_ts=3, last_ts=3, source_semantic_version=0)
    g.add_edge(proc_c, file_y, type="Write", event_name="write", count=1, first_ts=4, last_ts=4, source_semantic_version=0)
    g.add_edge(proc_a, bridge, type="Fork", event_name="clone", count=1, first_ts=5, last_ts=5, source_semantic_version=0)
    g.add_edge(bridge, proc_b, type="Execute", event_name="execve", count=1, first_ts=6, last_ts=6, source_semantic_version=0)
    return g


class AnomalousSubgraphBuilderTest(unittest.TestCase):
    def test_direct_and_bridge_paths_produce_subgraphs(self) -> None:
        g = _graph()
        anomalous_nodes = [
            {"node_id": "proc:a", "node_type": "process", "display_name": "a", "gmae_score": 12.0, "is_anomalous": True, "rank": 1},
            {"node_id": "proc:b", "node_type": "process", "display_name": "b", "gmae_score": 11.0, "is_anomalous": True, "rank": 2},
            {"node_id": "proc:c", "node_type": "process", "display_name": "c", "gmae_score": 9.0, "is_anomalous": True, "rank": 3},
        ]
        subgraphs = build_anomalous_subgraphs(g, anomalous_nodes, {"proc:a": 12.0, "proc:b": 11.0, "proc:c": 9.0}, nseed_per_type=2, max_edges=50)
        self.assertTrue(subgraphs)
        self.assertTrue(any("proc:a" in sg["anomalous_node_ids"] and "proc:b" in sg["anomalous_node_ids"] for sg in subgraphs))
        self.assertTrue(any("proc:bridge" in sg["normal_bridge_node_ids"] for sg in subgraphs))

    def test_minor_subgraphs_are_filtered(self) -> None:
        g = nx.MultiDiGraph()
        g.add_node("proc:a", meta={"name": "a"})
        g.add_node("proc:b", meta={"name": "b"})
        g.add_edge("proc:a", "proc:b", type="Write", event_name="write", count=1, first_ts=1, last_ts=1, source_semantic_version=0)
        subgraphs = build_anomalous_subgraphs(
            g,
            [{"node_id": "proc:a", "node_type": "process", "display_name": "a", "gmae_score": 1.0, "is_anomalous": True, "rank": 1}, {"node_id": "proc:b", "node_type": "process", "display_name": "b", "gmae_score": 1.0, "is_anomalous": True, "rank": 2}],
            {"proc:a": 1.0, "proc:b": 1.0},
            min_abnormality_level="moderate",
        )
        self.assertEqual([], subgraphs)


if __name__ == "__main__":
    unittest.main()
