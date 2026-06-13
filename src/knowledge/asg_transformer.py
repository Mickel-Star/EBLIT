#!/usr/bin/env python3
"""
ASG (Attack Scene Graph) Transformer
Converts MITRE ATT&CK techniques and procedures into structured Attack Scene Graphs.
"""

import re
import networkx as nx
from typing import Dict, List, Any, Tuple

class ASGTransformer:
    def __init__(self):
        # Define common entities and actions for extraction
        self.entities = {
            'Subject': ['attacker', 'adversary', 'user', 'process', 'script'],
            'Object': ['container', 'pod', 'node', 'host', 'api server', 'kubelet', 'file', 'socket', 'token', 'secret'],
            'Tool': ['kubectl', 'docker', 'curl', 'wget', 'bash', 'sh', 'ssh', 'exec']
        }
        
        # Simple rule-based extraction patterns (can be enhanced with NLP)
        self.action_patterns = [
            (r'use (\w+) to (\w+) (\w+)', 'Tool-Action-Object'),
            (r'run (\w+) in (\w+)', 'Action-Object'),
            (r'execute (\w+) on (\w+)', 'Action-Object'),
            (r'access (\w+)', 'Action-Object'),
            (r'connect to (\w+)', 'Action-Object'),
        ]

    def transform_technique(self, technique: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms a MITRE technique into an ASG structure.
        Returns a dict containing the graph data and serialized paths.
        """
        graph = nx.DiGraph()
        technique_id = technique['id']
        name = technique['name']
        
        # Root node: The Technique itself
        graph.add_node(technique_id, type='Technique', name=name, tactic=technique.get('tactic'))
        
        # Process description to extract high-level ASG paths
        description_paths = self._extract_paths_from_text(technique['description'])
        for i, path in enumerate(description_paths):
            self._add_path_to_graph(graph, technique_id, path, f"desc_path_{i}")
            
        # Process procedure examples (if available)
        # Assuming input might have a 'procedures' list, or we extract from description
        # For now, we simulate extraction from description as "procedures"
        
        # Serialize paths for embedding
        paths = self._get_all_paths_as_text(graph, technique_id)
        
        return {
            'technique_id': technique_id,
            'graph': nx.node_link_data(graph),
            'paths': paths,
            'original_text': technique['description']
        }

    def _extract_paths_from_text(self, text: str) -> List[List[Tuple[str, str, str]]]:
        """
        Extracts Entity-Relation-Entity triplets from text.
        Returns a list of paths, where each path is a list of triplets.
        """
        paths = []
        sentences = re.split(r'[.!?]', text)
        
        for sentence in sentences:
            sentence = sentence.strip().lower()
            if not sentence:
                continue
                
            # Heuristic extraction based on keywords
            # Subject is usually "Adversary" implicitly
            subject = "Adversary"
            
            # Find tools
            tools = [t for t in self.entities['Tool'] if t in sentence]
            # Find objects
            objects = [o for o in self.entities['Object'] if o in sentence]
            
            if tools and objects:
                # Construct path: Adversary -> uses -> Tool -> targets -> Object
                for tool in tools:
                    for obj in objects:
                        path = [
                            (subject, 'uses', tool),
                            (tool, 'targets', obj)
                        ]
                        paths.append(path)
            elif objects:
                 # Construct path: Adversary -> targets -> Object
                 for obj in objects:
                     path = [
                         (subject, 'targets', obj)
                     ]
                     paths.append(path)
                     
        return paths

    def _add_path_to_graph(self, graph: nx.DiGraph, root_id: str, path: List[Tuple[str, str, str]], path_id: str):
        """Adds a path of triplets to the NetworkX graph"""
        prev_node = root_id
        
        for i, (subj, rel, obj) in enumerate(path):
            # Create nodes if they don't exist
            # We suffix with path_id to keep paths distinct but rooted at technique
            # Or we can merge entities. Let's merge common entities for a connected graph.
            
            subj_node = f"{subj}"
            obj_node = f"{obj}"
            
            if i == 0 and subj == "Adversary":
                # Connect root technique to the start of the chain
                graph.add_edge(root_id, subj_node, relation="initiated_by")
            
            graph.add_node(subj_node, type='Entity', name=subj)
            graph.add_node(obj_node, type='Entity', name=obj)
            
            graph.add_edge(subj_node, obj_node, relation=rel)
            
            prev_node = obj_node

    def _get_all_paths_as_text(self, graph: nx.DiGraph, root_id: str) -> List[str]:
        """
        Traverses the graph to generate "Path Sentences" for embedding.
        Format: Subject action Object action Object...
        """
        text_paths = []
        root_name = graph.nodes.get(root_id, {}).get("name", root_id)
        
        # Simple DFS to find all paths from root
        # Limiting depth to avoid infinite loops if cycles exist (though ASG is usually DAG)
        try:
            # Find all simple paths from root to leaves
            leaves = [x for x in graph.nodes() if graph.out_degree(x) == 0 and graph.in_degree(x) > 0]
            for leaf in leaves:
                for path in nx.all_simple_paths(graph, root_id, leaf):
                    # Convert path nodes to string
                    path_str = ""
                    for i in range(len(path) - 1):
                        u, v = path[i], path[i+1]
                        edge_data = graph.get_edge_data(u, v)
                        relation = edge_data.get('relation', 'related_to')
                        
                        u_name = graph.nodes[u].get('name', u)
                        v_name = graph.nodes[v].get('name', v)

                        if u == root_id and relation == "initiated_by":
                            continue

                        if not path_str:
                            path_str += f"{u_name} {relation} {v_name}"
                        else:
                            path_str += f" {relation} {v_name}"

                    if path_str:
                        text_paths.append(f"{root_name} | {path_str}")
        except Exception as e:
            print(f"Error generating paths: {e}")
            
        return text_paths

if __name__ == "__main__":
    # Test
    transformer = ASGTransformer()
    mock_tech = {
        "id": "T1609",
        "name": "Container Administration Command",
        "tactic": "Execution",
        "description": "Adversaries may use kubectl exec to run commands in a container."
    }
    
    result = transformer.transform_technique(mock_tech)
    print("ASG Paths:")
    for p in result['paths']:
        print(f"- {p}")
