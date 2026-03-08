import json, os, logging, random
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("attack_generator")

@dataclass
class Attack:
    id: str
    name: str
    payload: str
    category: str
    mitre_atlas: str
    tactic: str
    severity: str
    detection_keywords: list
    mutated: bool = False
    parent_id: Optional[str] = None

class AttackGenerator:
    def __init__(self, library_dir=None):
        if library_dir is None:
            base = Path(__file__).parent.parent
            library_dir = str(base / "attack_library")
        self.library_dir = Path(library_dir)
        self.attacks = []
        if not self.library_dir.exists():
            raise FileNotFoundError(f"Attack library not found at: {self.library_dir}")
        self._load_all()
        logger.info(f"AttackGenerator ready: {len(self.attacks)} attacks loaded")

    def _load_all(self):
        for json_file in sorted(self.library_dir.glob("*.json")):
            self._load_file(json_file)

    def _load_file(self, json_file):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            category = data.get("category", json_file.stem)
            mitre_atlas = data.get("mitre_atlas", "UNKNOWN")
            tactic = data.get("tactic", "Unknown")
            for raw in data.get("attacks", []):
                self.attacks.append(Attack(
                    id=raw["id"], name=raw["name"], payload=raw["payload"],
                    category=category, mitre_atlas=mitre_atlas, tactic=tactic,
                    severity=raw.get("severity", "MEDIUM"),
                    detection_keywords=raw.get("detection_keywords", []),
                ))
        except Exception as e:
            logger.error(f"Failed to load {json_file.name}: {e}")

    def get_all(self): return list(self.attacks)
    def get_by_category(self, category): return [a for a in self.attacks if a.category == category]
    def get_by_severity(self, severity): return [a for a in self.attacks if a.severity == severity.upper()]
    def get_critical_and_high(self): return [a for a in self.attacks if a.severity in ("CRITICAL", "HIGH")]
    def get_random_sample(self, n=10): return random.sample(self.attacks, min(n, len(self.attacks)))

    def stats(self):
        by_cat, by_sev = {}, {}
        for a in self.attacks:
            by_cat[a.category] = by_cat.get(a.category, 0) + 1
            by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
        return {"total": len(self.attacks), "by_category": by_cat, "by_severity": by_sev}

    def summary(self):
        s = self.stats()
        print("\n" + "="*50)
        print("  ATTACK LIBRARY SUMMARY")
        print("="*50)
        print(f"  Total: {s['total']} attacks")
        for cat, count in sorted(s["by_category"].items()):
            print(f"  • {cat:<25} {count}")
        print("="*50 + "\n")
