#!/usr/bin/env python3
"""
Logic Graph Builder
Builds a structural Logic Graph of MITRE Tactics and Techniques to support Attack Graph Reconstruction.
Uses NetworkX to model the 'Stage' relationships (Initial Access -> Execution -> ...).
"""

import networkx as nx
import json
import os

class LogicGraphBuilder:
    def __init__(self):
        self.logic_graph = nx.DiGraph()
        # Define the standard kill chain order for Containers
        self.tactic_order = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Impact"
        ]
        
    def build_graph(self, techniques: list):
        """
        Builds the logic graph where:
        - Nodes are Techniques
        - Edges represent logical progression between Tactics
        """
        self.logic_graph.clear()
        
        # 1. Add Technique Nodes
        tech_by_tactic = {t: [] for t in self.tactic_order}
        
        for tech in techniques:
            self.logic_graph.add_node(
                tech['id'], 
                name=tech['name'], 
                tactic=tech['tactic'],
                type='Technique'
            )
            if tech['tactic'] in tech_by_tactic:
                tech_by_tactic[tech['tactic']].append(tech['id'])
                
        # 2. Add Logic Edges (Tactic Flow)
        # Connect every technique in Tactic N to every technique in Tactic N+1
        # This creates a 'Reachability Graph' representing possible attack paths
        for i in range(len(self.tactic_order) - 1):
            current_tactic = self.tactic_order[i]
            next_tactic = self.tactic_order[i+1]
            
            current_techs = tech_by_tactic[current_tactic]
            next_techs = tech_by_tactic[next_tactic]
            
            for src in current_techs:
                for dst in next_techs:
                    self.logic_graph.add_edge(src, dst, type='logical_flow')
                    
        print(f"✅ Built Logic Graph with {self.logic_graph.number_of_nodes()} nodes and {self.logic_graph.number_of_edges()} edges.")
        return self.logic_graph

    def check_attack_plausibility(self, tech_id_1: str, tech_id_2: str) -> bool:
        """
        Checks if a transition from tech_1 to tech_2 is logical.
        Returns True if tech_2 is reachable from tech_1 in the logic graph.
        """
        if not self.logic_graph.has_node(tech_id_1) or not self.logic_graph.has_node(tech_id_2):
            return False
        return nx.has_path(self.logic_graph, tech_id_1, tech_id_2)

    def reconstruct_attack_chain(self, detected_technique_ids: list) -> list:
        """
        Given a set of detected disparate techniques, sort them into a logical kill chain.
        """
        # Filter valid IDs
        valid_ids = [tid for tid in detected_technique_ids if self.logic_graph.has_node(tid)]
        
        # Sort based on topological sort of Tactic order
        # Since our graph is fully connected between stages, we can just sort by Tactic index
        
        def get_tactic_index(tid):
            tactic = self.logic_graph.nodes[tid]['tactic']
            return self.tactic_order.index(tactic) if tactic in self.tactic_order else 999
            
        sorted_chain = sorted(valid_ids, key=get_tactic_index)
        return sorted_chain

if __name__ == "__main__":
    # Test with dummy data
    builder = LogicGraphBuilder()
    dummy_techs = [
        {'id': 'T1190', 'name': 'Exploit', 'tactic': 'Initial Access'},
        {'id': 'T1609', 'name': 'Exec', 'tactic': 'Execution'},
        {'id': 'T1611', 'name': 'Escape', 'tactic': 'Persistence'}
    ]
    g = builder.build_graph(dummy_techs)
    
    chain = builder.reconstruct_attack_chain(['T1611', 'T1190'])
    print(f"Reconstructed Chain: {chain}")  # Should be T1190 -> T1611
