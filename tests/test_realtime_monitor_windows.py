import itertools
import json
import tempfile
import unittest
from pathlib import Path

from src.common.defaults import DEFAULT_DETECT_STRIDE_SECONDS
from src.process.realtime_monitor import RealtimeConfig, iter_realtime_windows
from src.process.window_io import dump_window_graph, load_window_graph


def tracee_openat_event(minute: int) -> dict:
    return {
        "timestamp": float(minute * 60),
        "userId": 0,
        "processName": f"proc_{minute}",
        "processId": 1000 + int(minute),
        "threadId": 1000 + int(minute),
        "hostProcessId": 2000 + int(minute),
        "hostThreadId": 2000 + int(minute),
        "returnValue": 3,
        "eventName": "openat",
        "containerId": "abcdef1234567890",
        "containerImage": "synthetic:latest",
        "args": [
            {"name": "pathname", "value": f"/tmp/realtime_window_file_{minute}"},
            {"name": "inode", "value": str(10_000 + int(minute))},
        ],
    }


def write_trace(path: Path, minutes: int) -> None:
    lines = [json.dumps(tracee_openat_event(minute)) for minute in range(minutes)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def edge_first_ts_bounds(graph):
    values = [int(data.get("first_ts", 0)) for _u, _v, _k, data in graph.edges(keys=True, data=True)]
    return min(values), max(values)


class RealtimeMonitorWindowTest(unittest.TestCase):
    def test_realtime_config_defaults_to_sliding(self):
        cfg = RealtimeConfig()

        self.assertEqual("sliding", cfg.window_mode)
        self.assertEqual(DEFAULT_DETECT_STRIDE_SECONDS, cfg.stride_seconds)
        self.assertFalse(cfg.emit_partial)

    def test_iter_realtime_windows_emits_sliding_boundaries_from_jsonl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "tracee.jsonl"
            write_trace(trace_path, minutes=51)

            cfg = RealtimeConfig(
                window_mode="sliding",
                window_seconds=1800,
                stride_seconds=600,
                time_bin_seconds=30,
                poll_interval_seconds=0.001,
                start_at_end=False,
            )
            stream = iter_realtime_windows(str(trace_path), cfg)
            try:
                windows = list(itertools.islice(stream, 3))
            finally:
                stream.close()
            persisted_path = Path(tmpdir) / "window_0001.json"
            dump_window_graph(str(persisted_path), windows[0][0])
            loaded = load_window_graph(str(persisted_path))

        self.assertEqual(3, len(windows))
        graphs = [graph for graph, _metas in windows]
        self.assertEqual(
            [(0.0, 1800.0), (600.0, 2400.0), (1200.0, 3000.0)],
            [(graph.graph.get("window_start"), graph.graph.get("window_end")) for graph in graphs],
        )
        self.assertTrue(all(graph.graph.get("complete") is True for graph in graphs))
        self.assertEqual([30, 30, 30], [graph.graph.get("event_count") for graph in graphs])
        self.assertEqual("sliding", graphs[0].graph.get("window_mode"))
        self.assertEqual(
            {
                "window_seconds": 1800,
                "stride_seconds": 600,
                "time_bin_seconds": 30,
                "edge_key_mode": "event_time_bin",
            },
            graphs[0].graph.get("sliding_window_config"),
        )
        self.assertEqual("sliding", loaded.graph.get("window_mode"))
        self.assertEqual(0.0, loaded.graph.get("window_start"))
        self.assertEqual(1800.0, loaded.graph.get("window_end"))
        self.assertEqual(graphs[0].graph.get("sliding_window_config"), loaded.graph.get("sliding_window_config"))

    def test_iter_realtime_windows_fixed_mode_stays_non_overlapping(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "tracee.jsonl"
            write_trace(trace_path, minutes=61)

            cfg = RealtimeConfig(
                window_mode="fixed",
                window_seconds=1800,
                stride_seconds=600,
                time_bin_seconds=30,
                poll_interval_seconds=0.001,
                start_at_end=False,
            )
            stream = iter_realtime_windows(str(trace_path), cfg)
            try:
                windows = list(itertools.islice(stream, 2))
            finally:
                stream.close()

        self.assertEqual(2, len(windows))
        first_graph, _first_metas = windows[0]
        second_graph, _second_metas = windows[1]
        self.assertNotIn("sliding_window_config", first_graph.graph)
        self.assertNotIn("sliding_window_config", second_graph.graph)
        self.assertEqual(0, edge_first_ts_bounds(first_graph)[0])
        self.assertEqual(1_800_000_000_000, edge_first_ts_bounds(second_graph)[0])
        self.assertLess(edge_first_ts_bounds(first_graph)[1], edge_first_ts_bounds(second_graph)[0])


if __name__ == "__main__":
    unittest.main()
