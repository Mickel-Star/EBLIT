import json
import tempfile
import unittest
from pathlib import Path

from src.process.streaming_reduction import (
    SlidingWindowConfig,
    SlidingWindowReducer,
    StreamingReducer,
    StreamingReductionConfig,
)
from src.process.provenance_model import ProvenanceEdge
from src.process.window_io import dump_window_graph, load_window_graph


def synthetic_event(minute: int) -> dict:
    return {
        "timestamp": float(minute * 60),
        "uid": 0,
        "comm": f"proc_{minute}",
        "pid": 1000 + int(minute),
        "tid": 1000 + int(minute),
        "ret": 3,
        "event": "openat",
        "args": {
            "pathname": f"/tmp/sliding_window_file_{minute}",
            "inode": str(10_000 + int(minute)),
        },
        "container_id": "abcdef1234567890",
        "container_image": "synthetic:latest",
    }


def synthetic_events(minutes: int):
    return [synthetic_event(minute) for minute in range(minutes)]


class SlidingWindowReducerTest(unittest.TestCase):
    def test_sliding_window_defaults_are_1800_600(self):
        cfg = SlidingWindowConfig()
        self.assertEqual(1800, cfg.window_seconds)
        self.assertEqual(600, cfg.stride_seconds)

    def test_sliding_windows_emit_expected_boundaries(self):
        reducer = SlidingWindowReducer(
            config=SlidingWindowConfig(
                window_seconds=1800,
                stride_seconds=600,
                time_bin_seconds=30,
            )
        )

        windows = []
        for event in synthetic_events(51):
            windows.extend(reducer.add_event(event))

        self.assertEqual(3, len(windows))
        self.assertEqual(
            [(0.0, 1800.0), (600.0, 2400.0), (1200.0, 3000.0)],
            [(window.window_start, window.window_end) for window in windows],
        )
        self.assertTrue(all(window.complete for window in windows))
        self.assertEqual([30, 30, 30], [window.event_count for window in windows])
        self.assertTrue(all(window.graph.number_of_nodes() > 0 for window in windows))
        self.assertTrue(all(window.graph.number_of_edges() > 0 for window in windows))

        overlaps = [
            min(left.window_end, right.window_end) - max(left.window_start, right.window_start)
            for left, right in zip(windows, windows[1:])
        ]
        self.assertEqual([1200.0, 1200.0], overlaps)

    def test_finalize_can_emit_remaining_available_window(self):
        reducer = SlidingWindowReducer(
            config=SlidingWindowConfig(
                window_seconds=1800,
                stride_seconds=600,
                time_bin_seconds=30,
            )
        )

        windows = []
        for event in synthetic_events(50):
            windows.extend(reducer.add_event(event))
        windows.extend(reducer.finalize(emit_partial=True))

        self.assertEqual(3, len(windows))
        self.assertEqual((1200.0, 3000.0), (windows[-1].window_start, windows[-1].window_end))
        self.assertFalse(windows[-1].complete)
        self.assertEqual(30, windows[-1].event_count)
        self.assertEqual([], reducer.finalize(emit_partial=True))


    def test_sliding_window_metadata_roundtrip_through_window_io(self):
        reducer = SlidingWindowReducer(
            config=SlidingWindowConfig(
                window_seconds=1800,
                stride_seconds=600,
                time_bin_seconds=30,
            )
        )

        windows = []
        for event in synthetic_events(31):
            windows.extend(reducer.add_event(event))

        self.assertEqual(1, len(windows))
        result = windows[0]
        self.assertEqual("sliding", result.graph.graph.get("window_mode"))

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "window_000001.json"
            dump_window_graph(str(path), result.graph)
            loaded = load_window_graph(str(path))

        self.assertEqual("sliding", loaded.graph.get("window_mode"))
        self.assertEqual(
            {
                "window_seconds": 1800,
                "stride_seconds": 600,
                "time_bin_seconds": 30,
                "edge_key_mode": "event_time_bin",
            },
            loaded.graph.get("sliding_window_config"),
        )
        self.assertEqual(
            {
                "window_seconds": 1800,
                "time_bin_seconds": 30,
                "edge_key_mode": "event_time_bin",
            },
            loaded.graph.get("reduction_config"),
        )
        self.assertEqual(result.window_start_ns, loaded.graph.get("window_start_ns"))
        self.assertEqual(result.window_end_ns, loaded.graph.get("window_end_ns"))
        self.assertEqual(result.window_start, loaded.graph.get("window_start"))
        self.assertEqual(result.window_end, loaded.graph.get("window_end"))
        self.assertEqual(result.event_count, loaded.graph.get("event_count"))
        self.assertEqual(result.complete, loaded.graph.get("complete"))

    def test_legacy_fixed_window_file_with_only_reduction_config_still_loads(self):
        payload = {
            "metadata": {
                "reduction_config": {
                    "window_seconds": 1800,
                    "time_bin_seconds": 30,
                    "edge_key_mode": "event_time_bin",
                }
            },
            "nodes": [
                {"id": "proc:container:abc:pid:1", "meta": {"pid": 1, "name": "proc"}},
                {"id": "file:/tmp/example", "meta": {"pathname": "/tmp/example"}},
            ],
            "edges": [
                {
                    "src": "proc:container:abc:pid:1",
                    "dst": "file:/tmp/example",
                    "type": "Read",
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

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "legacy_window.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_window_graph(str(path))

        self.assertEqual(payload["metadata"]["reduction_config"], loaded.graph.get("reduction_config"))
        self.assertNotIn("sliding_window_config", loaded.graph)
        self.assertEqual(2, loaded.number_of_nodes())
        self.assertEqual(1, loaded.number_of_edges())

    def test_streaming_reducer_still_uses_tumbling_windows(self):
        reducer = StreamingReducer(
            config=StreamingReductionConfig(
                window_seconds=1800,
                time_bin_seconds=30,
            )
        )

        windows = list(reducer.ingest_logs(synthetic_events(51)))

        self.assertEqual(2, len(windows))
        first_graph, _first_metas = windows[0]
        second_graph, _second_metas = windows[1]
        self.assertGreater(first_graph.number_of_edges(), 0)
        self.assertGreater(second_graph.number_of_edges(), 0)
        self.assertNotIn("sliding_window_config", first_graph.graph)

    def test_streaming_reducer_splits_reads_after_write_version_change(self):
        reducer = StreamingReducer(
            config=StreamingReductionConfig(
                window_seconds=1800,
                time_bin_seconds=30,
            )
        )
        proc = "proc:container:abc:pid:1"
        file_node = "file:/tmp/demo"
        proc_meta = {"pid": 1, "name": "curl", "pathname": "/usr/bin/curl"}
        file_meta = {"pathname": "/tmp/demo"}
        edges = [
            ProvenanceEdge(src=file_node, dst=proc, edge_type="Read", event_name="read", timestamp_ns=1_000_000_000, src_meta=file_meta, dst_meta=proc_meta),
            ProvenanceEdge(src=file_node, dst=proc, edge_type="Read", event_name="read", timestamp_ns=2_000_000_000, src_meta=file_meta, dst_meta=proc_meta),
            ProvenanceEdge(src=proc, dst=file_node, edge_type="Write", event_name="write", timestamp_ns=3_000_000_000, src_meta=proc_meta, dst_meta=file_meta),
            ProvenanceEdge(src=file_node, dst=proc, edge_type="Read", event_name="read", timestamp_ns=4_000_000_000, src_meta=file_meta, dst_meta=proc_meta),
        ]

        for edge in edges:
            reducer.ingest_edge(edge)
        graph, _metas = reducer.flush()

        read_edges = sorted(
            [(u, v, data) for u, v, _k, data in graph.edges(keys=True, data=True) if data.get("type") == "Read"],
            key=lambda item: int(item[2].get("source_semantic_version", 0)),
        )
        write_edges = [(u, v, data) for u, v, _k, data in graph.edges(keys=True, data=True) if data.get("type") == "Write"]
        self.assertEqual(2, len(read_edges))
        self.assertEqual(1, len(write_edges))
        self.assertEqual(2, read_edges[0][2]["count"])
        self.assertEqual(0, read_edges[0][2]["source_semantic_version"])
        self.assertEqual(1, read_edges[1][2]["count"])
        self.assertEqual(1, read_edges[1][2]["source_semantic_version"])


if __name__ == "__main__":
    unittest.main()
