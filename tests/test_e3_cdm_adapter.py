import json
import tempfile
import unittest
from pathlib import Path

from src.process.e3_cdm_adapter import build_e3_windows


def write_jsonl(path: Path, rows) -> None:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


class E3CDMAdapterTest(unittest.TestCase):
    def test_mmap_event_builds_proc_to_file_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data_path = root / "ta1-cadets-e3-official.json"
            gt_path = root / "cadets.txt"
            gt_path.write_text("", encoding="utf-8")
            rows = [
                {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.Subject": {
                            "uuid": "SUBJECT-1",
                            "cid": 4242,
                            "hostId": "HOST-1",
                            "startTimestampNanos": 1,
                            "properties": {"map": {"exec": "vmstat", "ppid": "1"}},
                        }
                    }
                },
                {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.FileObject": {
                            "uuid": "FILE-1",
                            "type": "FILE_OBJECT_FILE",
                            "baseObject": {"properties": {"map": {}}},
                        }
                    }
                },
                {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.Event": {
                            "uuid": "EVENT-1",
                            "type": "EVENT_MMAP",
                            "subject": {"com.bbn.tc.schema.avro.cdm18.UUID": "SUBJECT-1"},
                            "predicateObject": {"com.bbn.tc.schema.avro.cdm18.UUID": "FILE-1"},
                            "predicateObjectPath": None,
                            "timestampNanos": 1_522_706_863_163_352_079,
                            "name": {"string": "aue_mmap"},
                            "size": {"long": 4096},
                            "properties": {
                                "map": {
                                    "partial_path": "/lib/libdevstat.so.7",
                                    "exec": "vmstat",
                                    "ppid": "2549",
                                    "fd": "3",
                                }
                            },
                        }
                    }
                },
            ]
            write_jsonl(data_path, rows)

            windows, summary = build_e3_windows(
                e3_dir=root,
                groundtruth_path=gt_path,
                window_seconds=1800,
                stride_seconds=600,
                time_bin_seconds=30,
                emit_partial=True,
            )

        self.assertEqual(1, len(windows))
        graph = windows[0].graph
        self.assertEqual(1, graph.number_of_edges())
        src, dst, _key, edge = next(iter(graph.edges(keys=True, data=True)))
        self.assertTrue(str(src).startswith("file:"))
        self.assertTrue(str(dst).startswith("proc:"))
        self.assertEqual("Mmap", edge["type"])
        self.assertEqual("aue_mmap", edge["event_name"])
        proc_meta = graph.nodes[dst]["meta"]
        file_meta = graph.nodes[src]["meta"]
        self.assertEqual("vmstat", proc_meta["name"])
        self.assertEqual("/lib/libdevstat.so.7", file_meta["pathname"])
        self.assertEqual(1, summary["events_supported"])

    def test_groundtruth_uuid_filters_malicious_windows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data_path = root / "ta1-cadets-e3-official.json"
            gt_path = root / "cadets.txt"
            gt_path.write_text("FILE-1\n", encoding="utf-8")
            rows = [
                {"datum": {"com.bbn.tc.schema.avro.cdm18.Subject": {"uuid": "SUBJECT-1", "cid": 1, "hostId": "HOST", "properties": {"map": {}}}}},
                {"datum": {"com.bbn.tc.schema.avro.cdm18.FileObject": {"uuid": "FILE-1", "type": "FILE_OBJECT_FILE", "baseObject": {"properties": {"map": {}}}}}},
                {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.Event": {
                            "uuid": "EVENT-1",
                            "type": "EVENT_READ",
                            "subject": {"com.bbn.tc.schema.avro.cdm18.UUID": "SUBJECT-1"},
                            "predicateObject": {"com.bbn.tc.schema.avro.cdm18.UUID": "FILE-1"},
                            "predicateObjectPath": {"string": "/tmp/secret"},
                            "timestampNanos": 100,
                            "name": {"string": "aue_read"},
                            "properties": {"map": {"exec": "cat"}},
                        }
                    }
                },
            ]
            write_jsonl(data_path, rows)

            windows, summary = build_e3_windows(
                e3_dir=root,
                groundtruth_path=gt_path,
                window_seconds=1800,
                stride_seconds=600,
                time_bin_seconds=30,
                emit_partial=True,
            )

        self.assertEqual([], windows)
        self.assertEqual(1, summary["events_malicious_filtered"])


if __name__ == "__main__":
    unittest.main()
