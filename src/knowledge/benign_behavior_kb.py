#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import os
import pickle
import sqlite3
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:  # pragma: no cover - optional dependency
    from gensim.models import Word2Vec  # type: ignore
except Exception:  # pragma: no cover - fallback for environments without working gensim/scipy
    class _MiniKeyedVectors:
        def __init__(self, vector_size: int, seed: int = 13) -> None:
            self.vector_size = int(vector_size)
            self.seed = int(seed)
            self.key_to_index: Dict[str, int] = {}

        def _vector_for_token(self, token: str) -> List[float]:
            return _hashed_token_vector(str(token), self.vector_size, self.seed)

        def __contains__(self, token: str) -> bool:
            return str(token) in self.key_to_index

        def __getitem__(self, token: str) -> List[float]:
            if str(token) not in self.key_to_index:
                raise KeyError(token)
            return self._vector_for_token(str(token))

    class Word2Vec:  # type: ignore
        def __init__(self, vector_size: int = 64, window: int = 5, min_count: int = 1, workers: int = 1, seed: int = 13):
            self.vector_size = int(vector_size)
            self.window = int(window)
            self.min_count = int(min_count)
            self.workers = int(workers)
            self.seed = int(seed)
            self.wv = _MiniKeyedVectors(self.vector_size, self.seed)

        def build_vocab(self, sentences, update: bool = False):
            if not update:
                self.wv.key_to_index = {}
            for sentence in sentences or []:
                for token in sentence or []:
                    token_text = str(token)
                    if token_text not in self.wv.key_to_index:
                        self.wv.key_to_index[token_text] = len(self.wv.key_to_index)

        def train(self, sentences, total_examples: int | None = None, epochs: int = 1):
            return 0

        def save(self, path: str) -> None:
            payload = {
                "vector_size": int(self.vector_size),
                "window": int(self.window),
                "min_count": int(self.min_count),
                "workers": int(self.workers),
                "seed": int(self.seed),
                "tokens": list(self.wv.key_to_index.keys()),
            }
            with open(path, "wb") as fp:
                pickle.dump(payload, fp)

        @classmethod
        def load(cls, path: str):
            with open(path, "rb") as fp:
                payload = pickle.load(fp)
            model = cls(
                vector_size=int(payload.get("vector_size", 64)),
                window=int(payload.get("window", 5)),
                min_count=int(payload.get("min_count", 1)),
                workers=int(payload.get("workers", 1)),
                seed=int(payload.get("seed", 13)),
            )
            tokens = list(payload.get("tokens") or [])
            model.build_vocab([tokens], update=False)
            return model

from src.common.io import read_json, write_json
from src.process.provenance_model import tokenize_identifier


SCHEMA_VERSION = 2
MIN_SUPPORT = 1e-9
DEFAULT_PROCESS_NOVELTY_THRESHOLD = 0.15


def _clip_probability(value: float) -> float:
    return max(MIN_SUPPORT, min(1.0, float(value)))


def _hashed_token_vector(token: str, vector_size: int, seed: int = 13) -> List[float]:
    dims = max(int(vector_size), 1)
    vector = [0.0] * dims
    token_text = str(token or "")
    for gram_size in (1, 2, 3):
        if len(token_text) < gram_size:
            continue
        for idx in range(0, len(token_text) - gram_size + 1):
            gram = token_text[idx : idx + gram_size]
            digest = hashlib.blake2b(
                f"{seed}|{token_text}|{gram_size}|{gram}".encode("utf-8"),
                digest_size=16,
            ).digest()
            slot = int.from_bytes(digest[:4], "little") % dims
            magnitude = 1.0 + float(digest[5]) / 255.0
            vector[slot] += magnitude
    norm = math.sqrt(sum(value * value for value in vector))
    if norm <= 0.0:
        return vector
    return [value / norm for value in vector]


def _safe_json_loads(payload: str, default: Any) -> Any:
    text = str(payload or "").strip()
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def _vector_norm(values: Sequence[float]) -> float:
    total = 0.0
    for value in values:
        total += float(value) * float(value)
    return math.sqrt(total)


def _cosine_similarity(left: Sequence[float], right: Sequence[float], left_norm: float, right_norm: float) -> float:
    if left_norm <= 0.0 or right_norm <= 0.0:
        return 0.0
    dot = 0.0
    for lhs, rhs in zip(left, right):
        dot += float(lhs) * float(rhs)
    return max(0.0, min(1.0, dot / float(left_norm * right_norm)))


class BenignBehaviorKnowledgeBase:
    def __init__(
        self,
        db_path: str = "./data/kb/bbk.sqlite",
        model_path: str = "./data/models/bbk_word2vec.model",
        calibration_path: str = "./data/kb/bbk_calibration.json",
        vector_dim: int = 64,
        min_count: int = 1,
        epochs: int = 10,
        reset: bool = False,
    ):
        self.db_path = str(db_path)
        self.model_path = str(model_path)
        self.calibration_path = str(calibration_path)
        self.vector_dim = int(vector_dim)
        self.min_count = int(min_count)
        self.epochs = int(epochs)

        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.model_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.calibration_path)), exist_ok=True)

        if bool(reset):
            self._remove_if_exists(self.db_path)
            self._remove_if_exists(self.model_path)
            self._remove_if_exists(self.calibration_path)

        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        self.w2v: Optional[Word2Vec] = None
        self._load_or_init_model()
        self.calibration: Dict[str, Any] = self._load_calibration()

    def _remove_if_exists(self, path: str) -> None:
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

    def _existing_tables(self) -> set[str]:
        cur = self.conn.cursor()
        rows = cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        return {str(row[0]) for row in rows}

    def _init_schema(self) -> None:
        tables = self._existing_tables()
        old_tables = {"edge_freq", "node_degree", "node_meta"}
        if old_tables & tables:
            raise RuntimeError(
                "BBK schema v1 detected in bbk.sqlite; rebuild BBK with `build_bbk` before running detection."
            )

        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS signature_meta (
                signature TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                exemplar_pathname TEXT,
                exemplar_name TEXT,
                seen_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS edge_stats (
                src_signature TEXT NOT NULL,
                dst_signature TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                total_freq INTEGER NOT NULL,
                PRIMARY KEY (src_signature, dst_signature, edge_type)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS signature_degree (
                signature TEXT PRIMARY KEY,
                out_freq INTEGER NOT NULL,
                in_freq INTEGER NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS signature_embedding (
                signature TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                vector TEXT NOT NULL,
                norm REAL NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS global_stats (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                total_out_sum INTEGER NOT NULL DEFAULT 0,
                total_in_sum INTEGER NOT NULL DEFAULT 0,
                edge_type_priors TEXT NOT NULL DEFAULT '{}',
                schema_version INTEGER NOT NULL DEFAULT 2
            )
            """
        )
        cur.execute(
            """
            INSERT INTO global_stats(id, total_out_sum, total_in_sum, edge_type_priors, schema_version)
            VALUES(1, 0, 0, '{}', ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (SCHEMA_VERSION,),
        )
        row = cur.execute("SELECT schema_version FROM global_stats WHERE id=1").fetchone()
        schema_version = int(row[0]) if row else 0
        if schema_version != SCHEMA_VERSION:
            raise RuntimeError(
                f"Unsupported BBK schema version {schema_version}; expected {SCHEMA_VERSION}. Rebuild BBK first."
            )
        self.conn.commit()

    def _load_or_init_model(self) -> None:
        if os.path.exists(self.model_path):
            try:
                self.w2v = Word2Vec.load(self.model_path)
                self.vector_dim = int(self.w2v.vector_size)
                return
            except Exception:
                pass
        self.w2v = Word2Vec(vector_size=self.vector_dim, window=5, min_count=self.min_count, workers=1)

    def _load_calibration(self) -> Dict[str, Any]:
        if not self.calibration_path or not os.path.exists(self.calibration_path):
            return {}
        try:
            payload = read_json(self.calibration_path)
        except Exception:
            return {}
        return dict(payload or {}) if isinstance(payload, dict) else {}

    def save_calibration(self, payload: Dict[str, Any]) -> None:
        data = dict(payload or {})
        data.setdefault("schema_version", SCHEMA_VERSION)
        write_json(self.calibration_path, data)
        self.calibration = data

    def get_process_novelty_threshold(self, default: float = DEFAULT_PROCESS_NOVELTY_THRESHOLD) -> float:
        try:
            value = float(self.calibration.get("process_novelty_threshold", default))
        except (TypeError, ValueError):
            value = float(default)
        return max(0.0, min(1.0, value))

    def _entity_type(self, node_id: str, meta: Optional[Dict[str, Any]]) -> str:
        node = str(node_id or "")
        info = dict(meta or {})
        explicit = str(info.get("entity_type") or "").strip().lower()
        if explicit in {"proc", "process"}:
            return "proc"
        if explicit in {"file"}:
            return "file"
        if explicit in {"socket", "net", "network"}:
            return "net"
        if node.startswith("proc:"):
            return "proc"
        if node.startswith("file:"):
            return "file"
        if node.startswith("net:"):
            return "net"
        if info.get("dst_ip") or info.get("src_ip"):
            return "net"
        if info.get("pathname"):
            return "file"
        return "unknown"

    def canonical_signature(self, node_id: str, meta: Optional[Dict[str, Any]] = None) -> Optional[str]:
        info = dict(meta or {})
        node = str(node_id or "")
        if info.get("is_unspec_net"):
            return None

        entity_type = self._entity_type(node, info)
        pathname = str(info.get("pathname") or "").strip()
        name = str(info.get("name") or "").strip()

        if entity_type == "proc":
            if pathname:
                return f"proc:path:{pathname}"
            if name:
                return f"proc:name:{name}"
            return f"proc:name:{node}" if node else None

        if entity_type == "file":
            candidate = pathname or name
            if not candidate and node.startswith("file:"):
                candidate = node[len("file:") :]
            return f"file:path:{candidate}" if candidate else None

        if entity_type == "net":
            if "unknown_connected_socket" in node or name == "unknown_connected_socket":
                return None
            protocol = str(info.get("protocol") or info.get("proto") or "").strip().lower()
            dst_ip = str(info.get("dst_ip") or "").strip()
            dst_port = info.get("dst_port")
            if dst_ip and dst_port not in (None, ""):
                try:
                    return f"net:{protocol or 'tcp'}|{dst_ip}|{int(dst_port)}"
                except (TypeError, ValueError):
                    pass
            if name:
                return f"net:name:{name}"
            if node.startswith("net:"):
                return f"net:name:{node[len('net:') :]}"
        return None

    def _signature_text(self, signature: str, entity_type: str, meta: Optional[Dict[str, Any]]) -> str:
        info = dict(meta or {})
        if entity_type == "proc":
            if info.get("pathname") or info.get("name"):
                return str(info.get("pathname") or info.get("name") or signature)
            text = str(signature or "")
            if text.startswith("proc:path:"):
                return text[len("proc:path:") :]
            if text.startswith("proc:name:"):
                return text[len("proc:name:") :]
            return text
        if entity_type == "file":
            if info.get("pathname") or info.get("name"):
                return str(info.get("pathname") or info.get("name") or signature)
            text = str(signature or "")
            if text.startswith("file:path:"):
                return text[len("file:path:") :]
            return text
        if entity_type == "net":
            if info.get("name") or info.get("dst_ip"):
                return str(info.get("name") or info.get("dst_ip") or signature)
            text = str(signature or "")
            if text.startswith("net:"):
                return text[len("net:") :]
            return text
        return str(signature)

    def _signature_tokens(self, signature: str, entity_type: str, meta: Optional[Dict[str, Any]]) -> List[str]:
        text = self._signature_text(signature, entity_type, meta)
        tokens = tokenize_identifier(text)
        if tokens:
            return tokens
        return tokenize_identifier(signature)

    def _vector_from_tokens(self, tokens: Sequence[str]) -> Optional[List[float]]:
        if self.w2v is None or not getattr(self.w2v, "wv", None):
            return None
        keyed_vectors = self.w2v.wv
        vectors = [keyed_vectors[token] for token in tokens if token in keyed_vectors.key_to_index]
        if not vectors:
            return None
        for token in tokens:
            if token not in keyed_vectors.key_to_index:
                vectors.append([0.35 * value for value in _hashed_token_vector(token, len(vectors[0]))])
        dim = len(vectors[0])
        avg = [0.0] * dim
        for vector in vectors:
            for idx, value in enumerate(vector):
                avg[idx] += float(value)
        scale = float(len(vectors))
        return [value / scale for value in avg]

    def _signature_vector(self, signature: str, entity_type: str, meta: Optional[Dict[str, Any]] = None) -> Optional[List[float]]:
        tokens = self._signature_tokens(signature, entity_type, meta)
        if not tokens:
            return None
        return self._vector_from_tokens(tokens)

    def _upsert_signature_meta(
        self,
        cur: sqlite3.Cursor,
        signature: str,
        entity_type: str,
        meta: Optional[Dict[str, Any]],
        *,
        seen_increment: int,
    ) -> None:
        info = dict(meta or {})
        cur.execute(
            """
            INSERT INTO signature_meta(signature, entity_type, exemplar_pathname, exemplar_name, seen_count)
            VALUES(?,?,?,?,?)
            ON CONFLICT(signature) DO UPDATE SET
                entity_type=excluded.entity_type,
                exemplar_pathname=COALESCE(NULLIF(excluded.exemplar_pathname, ''), signature_meta.exemplar_pathname),
                exemplar_name=COALESCE(NULLIF(excluded.exemplar_name, ''), signature_meta.exemplar_name),
                seen_count=signature_meta.seen_count + excluded.seen_count
            """,
            (
                signature,
                entity_type,
                str(info.get("pathname") or ""),
                str(info.get("name") or ""),
                int(max(seen_increment, 0)),
            ),
        )

    def _store_signature_embedding(
        self,
        cur: sqlite3.Cursor,
        signature: str,
        entity_type: str,
        vector: Sequence[float],
    ) -> None:
        norm = _vector_norm(vector)
        if norm <= 0.0:
            return
        seen_count_row = cur.execute(
            "SELECT seen_count FROM signature_meta WHERE signature=?",
            (signature,),
        ).fetchone()
        seen_count = int(seen_count_row[0]) if seen_count_row else 0
        cur.execute(
            """
            INSERT INTO signature_embedding(signature, entity_type, vector, norm, seen_count)
            VALUES(?,?,?,?,?)
            ON CONFLICT(signature) DO UPDATE SET
                entity_type=excluded.entity_type,
                vector=excluded.vector,
                norm=excluded.norm,
                seen_count=excluded.seen_count
            """,
            (
                signature,
                entity_type,
                json.dumps([float(value) for value in vector]),
                float(norm),
                int(seen_count),
            ),
        )

    def update_from_edges(self, edges: Iterable[Tuple[str, str, str, int]], metas: Dict[str, Dict[str, Any]]) -> None:
        cur = self.conn.cursor()
        signature_cache: Dict[str, Tuple[str, str, Dict[str, Any]]] = {}

        for node_id, meta in (metas or {}).items():
            info = dict(meta or {})
            signature = self.canonical_signature(str(node_id), info)
            if not signature:
                continue
            entity_type = self._entity_type(str(node_id), info)
            signature_cache[str(node_id)] = (signature, entity_type, info)
            self._upsert_signature_meta(cur, signature, entity_type, info, seen_increment=1)

        global_row = cur.execute(
            "SELECT total_out_sum, total_in_sum, edge_type_priors FROM global_stats WHERE id=1"
        ).fetchone()
        edge_type_counts = _safe_json_loads(global_row[2] if global_row else "{}", {})
        if not isinstance(edge_type_counts, dict):
            edge_type_counts = {}
        total_out_sum = int(global_row[0]) if global_row else 0
        total_in_sum = int(global_row[1]) if global_row else 0

        for raw_edge in edges:
            if len(raw_edge) < 4:
                continue
            src, dst, edge_type, count = raw_edge[:4]
            src_key = str(src)
            dst_key = str(dst)
            src_signature = signature_cache.get(src_key)
            if src_signature is None:
                src_meta = dict((metas or {}).get(src_key) or {})
                src_sig = self.canonical_signature(src_key, src_meta)
                if src_sig:
                    src_signature = (src_sig, self._entity_type(src_key, src_meta), src_meta)
            dst_signature = signature_cache.get(dst_key)
            if dst_signature is None:
                dst_meta = dict((metas or {}).get(dst_key) or {})
                dst_sig = self.canonical_signature(dst_key, dst_meta)
                if dst_sig:
                    dst_signature = (dst_sig, self._entity_type(dst_key, dst_meta), dst_meta)
            if src_signature is None or dst_signature is None:
                continue

            src_sig, src_entity_type, src_meta = src_signature
            dst_sig, dst_entity_type, dst_meta = dst_signature
            edge_count = max(int(count), 0)
            if edge_count <= 0:
                continue

            self._upsert_signature_meta(cur, src_sig, src_entity_type, src_meta, seen_increment=0)
            self._upsert_signature_meta(cur, dst_sig, dst_entity_type, dst_meta, seen_increment=0)

            cur.execute(
                """
                INSERT INTO edge_stats(src_signature, dst_signature, edge_type, total_freq)
                VALUES(?,?,?,?)
                ON CONFLICT(src_signature, dst_signature, edge_type) DO UPDATE SET
                    total_freq = edge_stats.total_freq + excluded.total_freq
                """,
                (src_sig, dst_sig, str(edge_type), edge_count),
            )
            cur.execute(
                """
                INSERT INTO signature_degree(signature, out_freq, in_freq)
                VALUES(?,?,?)
                ON CONFLICT(signature) DO UPDATE SET
                    out_freq = signature_degree.out_freq + excluded.out_freq,
                    in_freq = signature_degree.in_freq + excluded.in_freq
                """,
                (src_sig, edge_count, 0),
            )
            cur.execute(
                """
                INSERT INTO signature_degree(signature, out_freq, in_freq)
                VALUES(?,?,?)
                ON CONFLICT(signature) DO UPDATE SET
                    out_freq = signature_degree.out_freq + excluded.out_freq,
                    in_freq = signature_degree.in_freq + excluded.in_freq
                """,
                (dst_sig, 0, edge_count),
            )

            total_out_sum += edge_count
            total_in_sum += edge_count
            edge_name = str(edge_type or "")
            edge_type_counts[edge_name] = int(edge_type_counts.get(edge_name, 0) or 0) + edge_count

        cur.execute(
            """
            UPDATE global_stats
            SET total_out_sum=?, total_in_sum=?, edge_type_priors=?, schema_version=?
            WHERE id=1
            """,
            (
                int(total_out_sum),
                int(total_in_sum),
                json.dumps(edge_type_counts, sort_keys=True),
                SCHEMA_VERSION,
            ),
        )
        self.conn.commit()

    def update_word2vec_from_metas(self, metas: Dict[str, Dict[str, Any]]) -> None:
        if self.w2v is None:
            self._load_or_init_model()
        assert self.w2v is not None

        signature_rows: List[Tuple[str, str, Dict[str, Any]]] = []
        sentences: List[List[str]] = []
        for node_id, meta in (metas or {}).items():
            info = dict(meta or {})
            signature = self.canonical_signature(str(node_id), info)
            if not signature:
                continue
            entity_type = self._entity_type(str(node_id), info)
            tokens = self._signature_tokens(signature, entity_type, info)
            if tokens:
                signature_rows.append((signature, entity_type, info))
                sentences.append(tokens)

        if not sentences:
            return

        if not self.w2v.wv.key_to_index:
            self.w2v.build_vocab(sentences)
        else:
            self.w2v.build_vocab(sentences, update=True)

        self.w2v.train(sentences, total_examples=len(sentences), epochs=self.epochs)
        self.w2v.save(self.model_path)

        cur = self.conn.cursor()
        seen_signatures = set()
        for signature, entity_type, info in signature_rows:
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            vector = self._signature_vector(signature, entity_type, info)
            if vector is None:
                continue
            self._store_signature_embedding(cur, signature, entity_type, vector)
        self.conn.commit()

    def get_total_freq(self, src_signature: str, dst_signature: str, edge_type: str) -> int:
        row = self.conn.execute(
            """
            SELECT total_freq FROM edge_stats
            WHERE src_signature=? AND dst_signature=? AND edge_type=?
            """,
            (str(src_signature), str(dst_signature), str(edge_type)),
        ).fetchone()
        return int(row[0]) if row else 0

    def get_out_in(self, signature: str) -> Tuple[int, int]:
        row = self.conn.execute(
            "SELECT out_freq, in_freq FROM signature_degree WHERE signature=?",
            (str(signature),),
        ).fetchone()
        if not row:
            return (0, 0)
        return (int(row[0]), int(row[1]))

    def get_global_stats(self) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT total_out_sum, total_in_sum, edge_type_priors, schema_version FROM global_stats WHERE id=1"
        ).fetchone()
        priors = _safe_json_loads(row[2] if row else "{}", {})
        if not isinstance(priors, dict):
            priors = {}
        return {
            "total_out_sum": int(row[0]) if row else 0,
            "total_in_sum": int(row[1]) if row else 0,
            "edge_type_priors": {str(k): int(v) for k, v in priors.items()},
            "schema_version": int(row[3]) if row else SCHEMA_VERSION,
        }

    def has_signature(self, signature: Optional[str], entity_type: Optional[str] = None) -> bool:
        if not signature:
            return False
        if entity_type:
            row = self.conn.execute(
                "SELECT 1 FROM signature_meta WHERE signature=? AND entity_type=?",
                (str(signature), str(entity_type)),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT 1 FROM signature_meta WHERE signature=?",
                (str(signature),),
            ).fetchone()
        return row is not None

    def _embedding_rows(self, entity_type: str) -> List[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT signature, vector, norm FROM signature_embedding WHERE entity_type=?",
                (str(entity_type),),
            ).fetchall()
        )

    def max_similarity(self, signature: Optional[str], entity_type: str) -> float:
        if not signature or entity_type not in {"proc", "file", "net"}:
            return 0.0
        if self.has_signature(signature, entity_type):
            return 1.0
        candidate = self._signature_vector(str(signature), str(entity_type))
        if candidate is None:
            return 0.0
        candidate_norm = _vector_norm(candidate)
        if candidate_norm <= 0.0:
            return 0.0
        best = 0.0
        for row in self._embedding_rows(str(entity_type)):
            vector = _safe_json_loads(str(row["vector"]), [])
            if not isinstance(vector, list):
                continue
            best = max(best, _cosine_similarity(candidate, vector, candidate_norm, float(row["norm"] or 0.0)))
        return max(0.0, min(1.0, best))

    def novelty_score(self, node_id: str, meta: Optional[Dict[str, Any]] = None) -> float:
        signature = self.canonical_signature(str(node_id), meta)
        if not signature:
            return 1.0
        entity_type = self._entity_type(str(node_id), meta)
        if entity_type != "proc":
            return 1.0
        if self.has_signature(signature, entity_type):
            return 0.0
        if not self._embedding_rows(entity_type):
            return 1.0
        similarity = self.max_similarity(signature, entity_type)
        return max(0.0, min(1.0, 1.0 - similarity))

    def _edge_type_prior(self, edge_type: str) -> float:
        stats = self.get_global_stats()
        priors = dict(stats.get("edge_type_priors") or {})
        total = float(sum(int(value) for value in priors.values()))
        if total <= 0.0:
            return MIN_SUPPORT
        value = float(priors.get(str(edge_type), 0) or 0.0) / total
        return _clip_probability(value)

    def support(
        self,
        src: str,
        dst: str,
        edge_type: str,
        src_meta: Optional[Dict[str, Any]] = None,
        dst_meta: Optional[Dict[str, Any]] = None,
    ) -> float:
        src_signature = self.canonical_signature(str(src), src_meta)
        dst_signature = self.canonical_signature(str(dst), dst_meta)
        if not src_signature or not dst_signature:
            return MIN_SUPPORT

        out_freq, _ = self.get_out_in(src_signature)
        _, in_freq = self.get_out_in(dst_signature)
        stats = self.get_global_stats()
        total_out_sum = max(int(stats.get("total_out_sum") or 0), 1)
        total_in_sum = max(int(stats.get("total_in_sum") or 0), 1)
        dout = float(out_freq) / float(total_out_sum)
        din = float(in_freq) / float(total_in_sum)
        tf = self.get_total_freq(src_signature, dst_signature, str(edge_type))
        if tf > 0 and out_freq > 0 and in_freq > 0:
            support_value = (float(tf) / float(max(out_freq, 1))) * dout * din
            return _clip_probability(support_value)

        src_entity_type = self._entity_type(str(src), src_meta)
        dst_entity_type = self._entity_type(str(dst), dst_meta)
        src_sim = self.max_similarity(src_signature, src_entity_type)
        dst_sim = self.max_similarity(dst_signature, dst_entity_type)
        if src_sim <= 0.0 or dst_sim <= 0.0:
            return MIN_SUPPORT
        support_backoff = src_sim * dst_sim * self._edge_type_prior(str(edge_type)) * max(dout, MIN_SUPPORT) * max(din, MIN_SUPPORT)
        return _clip_probability(support_backoff)

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass
