#!/usr/bin/env python3
"""
MITRE STIX Loader
Loads MITRE ATT&CK data from the official STIX 2.1 repository on GitHub.
Filters for Container-related techniques.
"""

import requests
import json
import os
from stix2 import MemoryStore, Filter
from typing import List, Dict, Any
from src.knowledge.kb_paths import KB_PATHS

class MitreStixLoader:
    def __init__(self):
        # Official MITRE Enterprise ATT&CK STIX URL
        self.stix_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.cache_file = "data/kb/stix/enterprise-attack.json"
        try:
            KB_PATHS.ensure_layout()
        except Exception:
            pass
        
    def load_data(self) -> List[Dict[str, Any]]:
        """
        Loads STIX data, filters for Container techniques, and returns structured data.
        """
        stix_data = self._get_stix_content()
        if not stix_data:
            print("Failed to load STIX data.")
            return []
            
        print("Parsing STIX data...")
        src = MemoryStore(stix_data)
        
        # Filter for Attack Patterns (Techniques)
        techniques = src.query([Filter("type", "=", "attack-pattern")])
        
        container_techniques = []
        
        for tech in techniques:
            # Check if it applies to Containers
            # MITRE STIX 2.1 uses 'x_mitre_platforms' to denote platforms
            platforms = getattr(tech, 'x_mitre_platforms', [])
            # Case-insensitive check for 'containers'
            if platforms and any("container" in p.lower() for p in platforms):
                
                # Extract Tactics
                kill_chain_phases = getattr(tech, 'kill_chain_phases', [])
                tactics = [phase.phase_name for phase in kill_chain_phases if phase.kill_chain_name == 'mitre-attack']
                
                # Use the first tactic for primary classification, or join them
                primary_tactic = tactics[0].replace('-', ' ').title() if tactics else "Unknown"
                
                # Extract external ID (e.g., T1609)
                ext_refs = getattr(tech, 'external_references', [])
                mitre_id = next((ref.external_id for ref in ext_refs if ref.source_name == 'mitre-attack'), None)
                
                if mitre_id:
                    container_techniques.append({
                        "id": mitre_id,
                        "name": tech.name,
                        "description": tech.description,
                        "tactic": primary_tactic,
                        "platforms": platforms,
                        "url": next((ref.url for ref in ext_refs if ref.source_name == 'mitre-attack'), "")
                    })
                    
        print(f"✅ Found {len(container_techniques)} Container-related techniques from official STIX data.")
        return container_techniques

    def _get_stix_content(self):
        """Fetches STIX JSON from URL or local cache."""
        if os.path.exists(self.cache_file):
            print(f"Loading cached STIX data from {self.cache_file}...")
            with open(self.cache_file, 'r') as f:
                return json.load(f)
                
        print(f"Downloading STIX data from {self.stix_url}...")
        try:
            response = requests.get(self.stix_url)
            response.raise_for_status()
            data = response.json()
            
            # Cache it
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(data, f)
                
            return data
        except Exception as e:
            print(f"Error downloading STIX data: {e}")
            return None

if __name__ == "__main__":
    loader = MitreStixLoader()
    data = loader.load_data()
    # Print sample
    if data:
        print(json.dumps(data[0], indent=2))
