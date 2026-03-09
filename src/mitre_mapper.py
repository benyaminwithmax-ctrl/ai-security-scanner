import logging
logger = logging.getLogger("mitre_mapper")

MITRE_ATLAS = {
    "AML.T0051": {
        "name": "LLM Prompt Injection",
        "tactic": "ML Attack Staging",
        "description": "Adversaries may craft inputs to manipulate LLM behavior",
        "url": "https://atlas.mitre.org/techniques/AML.T0051"
    },
    "AML.T0054": {
        "name": "LLM Jailbreak",
        "tactic": "ML Attack Staging",
        "description": "Adversaries may attempt to bypass LLM safety filters",
        "url": "https://atlas.mitre.org/techniques/AML.T0054"
    },
    "AML.T0048": {
        "name": "Exfiltration via ML Inference API",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data through AI model responses",
        "url": "https://atlas.mitre.org/techniques/AML.T0048"
    },
    "AML.T0050": {
        "name": "ML Supply Chain Compromise",
        "tactic": "Impact",
        "description": "Adversaries may abuse AI tools to cause unintended actions",
        "url": "https://atlas.mitre.org/techniques/AML.T0050"
    },
    "AML.T0057": {
        "name": "LLM Indirect Prompt Injection",
        "tactic": "ML Attack Staging",
        "description": "Adversaries hide instructions inside data processed by LLMs",
        "url": "https://atlas.mitre.org/techniques/AML.T0057"
    },
}

class MitreMapper:
    def map(self, result):
        return MITRE_ATLAS.get(result.mitre_atlas, {
            "name": "Unknown Technique",
            "tactic": result.tactic,
            "description": "No mapping found",
            "url": "https://atlas.mitre.org"
        })

    def map_all(self, results):
        mappings = {}
        for r in results:
            mappings[r.attack_id] = self.map(r)
        return mappings
