#!/usr/bin/env python3
"""
向量化器
将提取的Tracee特征转换为向量嵌入
"""

import os
import hashlib
import numpy as np
from typing import List, Dict, Any, Tuple
from gensim.models import Word2Vec, Doc2Vec
from gensim.models.doc2vec import TaggedDocument
from src.common.text import tokenize_identifier

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '../../'))

class TraceeVectorizer:
    """Tracee特征向量化器"""
    
    def __init__(
        self,
        w2v_dim: int = 64,
        d2v_dim: int = 64,
        model_dir: str = "./data/models/gensim",
        min_count: int = 1,
        epochs: int = 20
    ):
        """初始化向量化器"""
        self.offline_mode = False
        self.w2v_dim = int(w2v_dim)
        self.d2v_dim = int(d2v_dim)
        self.vector_dim = self.w2v_dim + self.d2v_dim
        self.min_count = int(min_count)
        self.epochs = int(epochs)

        if model_dir.startswith("./"):
            model_dir = os.path.join(project_root, model_dir[2:])
        self.model_dir = model_dir
        os.makedirs(self.model_dir, exist_ok=True)

        self.word2vec_path = os.path.join(self.model_dir, "tracee_word2vec.model")
        self.doc2vec_path = os.path.join(self.model_dir, "tracee_doc2vec.model")

        self.word2vec: Word2Vec | None = None
        self.doc2vec: Doc2Vec | None = None

        try:
            self._load_or_train_models()
        except Exception as e:
            print(f"警告: 无法初始化 Word2Vec/Doc2Vec 模型，将切换到离线Mock模式。错误: {str(e)[:120]}...")
            print("正在切换到【离线Mock模式】...")
            print("注意：在离线模式下，向量化将基于文本哈希生成，仅用于测试流程连通性，不具备真实语义搜索能力。")
            self.offline_mode = True
            self.word2vec = None
            self.doc2vec = None

    def _tokenize(self, text: str) -> List[str]:
        return tokenize_identifier(text or "")

    def _build_bootstrap_corpus(self) -> List[str]:
        corpus: List[str] = []
        stix_cache = os.path.join(project_root, "data/knowledge/enterprise-attack.json")
        if os.path.exists(stix_cache):
            try:
                import json
                with open(stix_cache, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for obj in data.get("objects", []):
                    if obj.get("type") != "attack-pattern":
                        continue
                    name = obj.get("name") or ""
                    desc = obj.get("description") or ""
                    corpus.append(f"{name} {desc}")
            except Exception:
                pass
        corpus.extend(
            [
                "execve bash sh python curl wget",
                "openat /etc/passwd /etc/shadow /var/run/secrets/kubernetes.io/serviceaccount/token",
                "connect 10.96.0.1:443 kubernetes api server",
                "kubectl exec container pod host escape privilege escalation",
            ]
        )
        return [c for c in corpus if c]

    def _load_or_train_models(self) -> None:
        if os.path.exists(self.word2vec_path):
            try:
                self.word2vec = Word2Vec.load(self.word2vec_path)
                self.w2v_dim = int(self.word2vec.vector_size)
            except Exception as e:
                print(f"警告: 现有 Word2Vec 模型不可用，将重建。错误: {str(e)[:120]}...")
                self.word2vec = None
        if os.path.exists(self.doc2vec_path):
            try:
                self.doc2vec = Doc2Vec.load(self.doc2vec_path)
                self.d2v_dim = int(self.doc2vec.vector_size)
            except Exception as e:
                print(f"警告: 现有 Doc2Vec 模型不可用，将重建。错误: {str(e)[:120]}...")
                self.doc2vec = None

        self.vector_dim = self.w2v_dim + self.d2v_dim

        if self.word2vec is not None and self.doc2vec is not None:
            return

        corpus_texts = self._build_bootstrap_corpus()
        tokenized = [self._tokenize(t) for t in corpus_texts]
        tokenized = [t for t in tokenized if t]
        if not tokenized:
            raise RuntimeError("缺少可用于训练 embedding 的语料")

        if self.word2vec is None:
            self.word2vec = Word2Vec(
                sentences=tokenized,
                vector_size=self.w2v_dim,
                window=5,
                min_count=self.min_count,
                workers=4,
                epochs=self.epochs,
            )
            self.word2vec.save(self.word2vec_path)

        if self.doc2vec is None:
            documents = [TaggedDocument(words=toks, tags=[str(i)]) for i, toks in enumerate(tokenized)]
            self.doc2vec = Doc2Vec(
                documents=documents,
                vector_size=self.d2v_dim,
                window=5,
                min_count=self.min_count,
                workers=4,
                epochs=self.epochs,
                dm=1,
            )
            self.doc2vec.save(self.doc2vec_path)

    def vectorize_process_graph(self, graph_context: str) -> np.ndarray:
        """
        将图上下文（线性化后的文本）转换为向量
        对应论文中的 Semantic Embedding 步骤
        """
        return self.vectorize_text(graph_context)

    def vectorize_text(self, text: str) -> np.ndarray:
        """将文本转换为向量"""
        if self.offline_mode:
            seed = int(hashlib.sha256((text or "").encode('utf-8')).hexdigest(), 16) % (2**32)
            np.random.seed(seed)
            vec = np.random.rand(self.vector_dim)
            norm = np.linalg.norm(vec)
            return vec if norm == 0 else vec / norm

        if self.word2vec is None or self.doc2vec is None:
            self._load_or_train_models()

        tokens = self._tokenize(text)
        w2v_vec = np.zeros(self.w2v_dim, dtype=np.float32)
        if tokens and self.word2vec is not None:
            valid = [t for t in tokens if t in self.word2vec.wv]
            if valid:
                w2v_vec = np.mean([self.word2vec.wv[t] for t in valid], axis=0).astype(np.float32)

        d2v_vec = np.zeros(self.d2v_dim, dtype=np.float32)
        if tokens and self.doc2vec is not None:
            d2v_vec = np.array(self.doc2vec.infer_vector(tokens, epochs=20), dtype=np.float32)

        vec = np.concatenate([w2v_vec, d2v_vec], axis=0)
        norm = np.linalg.norm(vec)
        return vec if norm == 0 else vec / norm

    def vectorize_node_path_word2vec(self, text: str) -> np.ndarray:
        if self.offline_mode:
            seed = int(hashlib.sha256((text or "").encode("utf-8")).hexdigest(), 16) % (2**32)
            np.random.seed(seed)
            vec = np.random.rand(self.w2v_dim)
            norm = np.linalg.norm(vec)
            return vec if norm == 0 else vec / norm

        if self.word2vec is None:
            self._load_or_train_models()
        tokens = self._tokenize(text)
        vec = np.zeros(self.w2v_dim, dtype=np.float32)
        if tokens and self.word2vec is not None:
            valid = [t for t in tokens if t in self.word2vec.wv]
            if valid:
                vec = np.mean([self.word2vec.wv[t] for t in valid], axis=0).astype(np.float32)
        norm = np.linalg.norm(vec)
        return vec if norm == 0 else vec / norm

    def vectorize_path_doc2vec(self, text: str) -> np.ndarray:
        if self.offline_mode:
            seed = int(hashlib.sha256((text or "").encode("utf-8")).hexdigest(), 16) % (2**32)
            np.random.seed(seed)
            vec = np.random.rand(self.d2v_dim)
            norm = np.linalg.norm(vec)
            return vec if norm == 0 else vec / norm

        if self.doc2vec is None:
            self._load_or_train_models()
        tokens = self._tokenize(text)
        vec = np.zeros(self.d2v_dim, dtype=np.float32)
        if tokens and self.doc2vec is not None:
            vec = np.array(self.doc2vec.infer_vector(tokens, epochs=20), dtype=np.float32)
        norm = np.linalg.norm(vec)
        return vec if norm == 0 else vec / norm
    
    def batch_vectorize(self, texts: List[str]) -> np.ndarray:
        """批量向量化文本列表"""
        if self.offline_mode:
            vectors = []
            for text in texts:
                vectors.append(self.vectorize_text(text))
            return np.array(vectors)

        return np.array([self.vectorize_text(t) for t in texts], dtype=np.float32)

    def calculate_similarity(self, vector1: np.ndarray, vector2: np.ndarray) -> float:
        denom = (np.linalg.norm(vector1) * np.linalg.norm(vector2))
        if denom == 0:
            return 0.0
        return float(np.dot(vector1, vector2) / denom)
