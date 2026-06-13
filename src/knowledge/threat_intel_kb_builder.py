#!/usr/bin/env python3
import os
from typing import Any, Dict, List

from src.knowledge.asg_transformer import ASGTransformer
from src.knowledge.stix_loader import MitreStixLoader
from src.process.vector_db import VectorDatabase
from src.process.vectorizer import TraceeVectorizer


class ThreatIntelligenceKnowledgeBuilder:
    def __init__(self, db_path: str = "./data/vector_db"):
        self.asg_transformer = ASGTransformer()
        self.vectorizer = TraceeVectorizer()
        self.db = VectorDatabase(db_path=db_path, collection_name="tik_knowledge")
        self.stix_loader = MitreStixLoader()

    def build(self) -> None:
        self.db.clear_collection()
        techniques = self.stix_loader.load_data()
        if not techniques:
            raise RuntimeError("无法加载 STIX 数据")

        documents: List[Dict[str, Any]] = []
        for tech in techniques:
            asg_result = self.asg_transformer.transform_technique(tech)
            paths = asg_result.get("paths", []) or []
            if not paths:
                continue
            for i, path in enumerate(paths):
                vec = self.vectorizer.vectorize_path_doc2vec(path)
                documents.append(
                    {
                        "id": f"{tech['id']}_path_{i}",
                        "vector": vec.tolist(),
                        "metadata": {
                            "type": "tik_path",
                            "technique_id": tech["id"],
                            "name": tech.get("name", ""),
                            "tactic": tech.get("tactic", ""),
                        },
                        "feature_string": path,
                    }
                )

        self.db.add_vectors(documents)
        print(f"✅ tik_knowledge ingested: {len(documents)} vectors")


if __name__ == "__main__":
    ThreatIntelligenceKnowledgeBuilder().build()
