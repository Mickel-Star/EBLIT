#!/usr/bin/env python3
import os
from typing import Any, Dict, List, Optional

import chromadb
import numpy as np


class VectorDatabase:
    def __init__(self, db_path: str = "./data/vector_db", collection_name: str = "tracee_features"):
        os.makedirs(db_path, exist_ok=True)
        self.client = chromadb.PersistentClient(path=db_path)
        self.collection_name = collection_name
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"description": "Vector collection"}
        )

    def add_vectors(self, documents: List[Dict[str, Any]]) -> List[str]:
        if not documents:
            return []

        ids = [doc["id"] for doc in documents]
        vectors = [doc["vector"] for doc in documents]
        metadatas = [doc.get("metadata", {}) for doc in documents]
        texts = [doc.get("feature_string", "") for doc in documents]

        try:
            self.collection.add(ids=ids, embeddings=vectors, metadatas=metadatas, documents=texts)
        except Exception:
            self.clear_collection()
            self.collection.add(ids=ids, embeddings=vectors, metadatas=metadatas, documents=texts)

        return ids

    def query_vectors(self, query_vector: np.ndarray, n_results: int = 5, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        results = self.collection.query(
            query_embeddings=[query_vector.tolist()],
            n_results=n_results,
            where=filters,
        )
        return {
            "ids": results["ids"][0],
            "distances": results["distances"][0],
            "metadatas": results["metadatas"][0],
            "documents": results["documents"][0],
        }

    def clear_collection(self) -> None:
        self.client.delete_collection(name=self.collection_name)
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"description": "Vector collection"},
        )
