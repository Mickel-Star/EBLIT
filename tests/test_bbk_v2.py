import tempfile
import unittest
from pathlib import Path

from src.knowledge.benign_behavior_kb import BenignBehaviorKnowledgeBase, MIN_SUPPORT


class BBKV2Test(unittest.TestCase):
    def _make_store(self, tmpdir: str) -> BenignBehaviorKnowledgeBase:
        return BenignBehaviorKnowledgeBase(
            db_path=str(Path(tmpdir) / "bbk.sqlite"),
            model_path=str(Path(tmpdir) / "bbk_word2vec.model"),
            calibration_path=str(Path(tmpdir) / "bbk_calibration.json"),
            vector_dim=16,
            epochs=5,
            reset=True,
        )

    def test_canonical_signature_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            try:
                self.assertEqual(
                    "proc:path:/usr/bin/curl",
                    store.canonical_signature("proc:1", {"pathname": "/usr/bin/curl", "name": "curl"}),
                )
                self.assertEqual(
                    "proc:name:curl",
                    store.canonical_signature("proc:2", {"name": "curl"}),
                )
                self.assertEqual(
                    "file:path:/tmp/demo",
                    store.canonical_signature("file:1", {"pathname": "/tmp/demo"}),
                )
                self.assertEqual(
                    "net:tcp|1.2.3.4|443",
                    store.canonical_signature("net:1", {"protocol": "tcp", "dst_ip": "1.2.3.4", "dst_port": 443}),
                )
            finally:
                store.close()

    def test_support_and_novelty_cover_exact_backoff_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            try:
                seen_proc = {"pathname": "/usr/bin/curl", "name": "curl"}
                seen_file = {"pathname": "/tmp/seen", "name": "seen"}
                similar_proc = {"pathname": "/usr/bin/curl-helper", "name": "curl-helper"}
                novel_proc = {"name": "qzxqzx"}

                metas = {
                    "proc:seen": seen_proc,
                    "file:seen": seen_file,
                }
                store.update_from_edges([("proc:seen", "file:seen", "Write", 2)], metas)
                store.update_word2vec_from_metas(metas)

                exact_support = store.support("proc:seen", "file:seen", "Write", seen_proc, seen_file)
                backoff_support = store.support("proc:similar", "file:seen", "Write", similar_proc, seen_file)
                unknown_support = store.support("proc:novel", "file:novel", "Write", novel_proc, {"pathname": "/tmp/novel"})

                self.assertGreater(exact_support, MIN_SUPPORT)
                self.assertLessEqual(exact_support, 1.0)
                self.assertGreaterEqual(backoff_support, MIN_SUPPORT)
                self.assertEqual(MIN_SUPPORT, unknown_support)

                self.assertEqual(0.0, store.novelty_score("proc:seen", seen_proc))
                similar_novelty = store.novelty_score("proc:similar", similar_proc)
                self.assertGreater(similar_novelty, 0.0)
                self.assertLess(similar_novelty, 1.0)
                self.assertEqual(1.0, store.novelty_score("proc:novel", novel_proc))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
