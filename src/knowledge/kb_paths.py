import os
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class KnowledgeBasePaths:
    base_dir: str = "./data/kb"

    bbk_db_path: str = "./data/kb/bbk.sqlite"
    bbk_calibration_path: str = "./data/kb/bbk_calibration.json"
    tik_db_dir: str = "./data/kb/vector_db"
    ark_graph_path: str = "./data/kb/ark_logic_graph.json"
    gmae_baseline_path: str = "./data/kb/gmae_baseline.pt"
    gmae_baseline_meta_path: str = "./data/kb/gmae_baseline_meta.json"
    gmae_e3_pretrained_path: str = "./data/kb/gmae_e3_pretrained.pt"
    gmae_e3_pretrained_meta_path: str = "./data/kb/gmae_e3_pretrained_meta.json"
    gmae_calibration_path: str = "./data/kb/gmae_calibration.json"
    process_error_calibration_path: str = "./data/kb/process_error_calibration.json"
    sampled_train_windows_snapshot_path: str = "./data/kb/sampled_train_windows.jsonl"
    full_window_index_snapshot_path: str = "./data/kb/full_window_index.jsonl"

    bbk_word2vec_path: str = "./data/models/bbk_word2vec.model"
    tracee_word2vec_path: str = "./data/models/gensim/tracee_word2vec.model"
    tracee_doc2vec_path: str = "./data/models/gensim/tracee_doc2vec.model"

    def ensure_layout(self) -> None:
        os.makedirs(self.base_dir, exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.bbk_db_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.bbk_calibration_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.ark_graph_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.gmae_baseline_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.gmae_baseline_meta_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.gmae_e3_pretrained_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.gmae_e3_pretrained_meta_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.gmae_calibration_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.process_error_calibration_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.sampled_train_windows_snapshot_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.full_window_index_snapshot_path)), exist_ok=True)

        self._migrate_if_needed("./data/bbk.sqlite", self.bbk_db_path)
        self._migrate_vector_db("./data/vector_db", self.tik_db_dir)
        self._migrate_if_needed("./data/processed/ark_logic_graph.json", self.ark_graph_path)
        self._migrate_if_needed("./data/kb/gmae_baseline.pth", self.gmae_baseline_path)
        self._migrate_if_needed("./data/kb/gmae_baseline.meta.json", self.gmae_baseline_meta_path)
        os.makedirs(self.tik_db_dir, exist_ok=True)

    def _migrate_if_needed(self, old_path: str, new_path: str, is_dir: bool = False) -> None:
        if os.path.exists(new_path):
            return
        if not os.path.exists(old_path):
            return
        os.makedirs(os.path.dirname(os.path.abspath(new_path)), exist_ok=True)
        try:
            if is_dir:
                shutil.move(old_path, new_path)
            else:
                os.replace(old_path, new_path)
        except OSError:
            return

    def _migrate_vector_db(self, old_dir: str, new_dir: str) -> None:
        if not os.path.exists(old_dir):
            return
        if not os.path.exists(new_dir):
            os.makedirs(os.path.dirname(os.path.abspath(new_dir)), exist_ok=True)
            try:
                shutil.move(old_dir, new_dir)
            except OSError:
                return
            return
        try:
            entries = os.listdir(new_dir)
        except OSError:
            entries = []
        if entries:
            return
        try:
            for name in os.listdir(old_dir):
                shutil.move(os.path.join(old_dir, name), os.path.join(new_dir, name))
            try:
                os.rmdir(old_dir)
            except OSError:
                pass
        except OSError:
            return


KB_PATHS = KnowledgeBasePaths()
