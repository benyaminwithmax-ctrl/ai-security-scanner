import os, json, logging
from datetime import datetime, timezone
logger = logging.getLogger("siem_logger")

SEVERITY_TO_LEVEL = {
    "CRITICAL": 12,
    "HIGH": 10,
    "MEDIUM": 6,
    "LOW": 3,
}

class SiemLogger:
    def __init__(self, output_dir=None):
        if output_dir is None:
            import pathlib
            output_dir = str(pathlib.Path(__file__).parent.parent / "output")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.log_file = os.path.join(output_dir, "siem_logs.ndjson")

    def log_result(self, result):
        if not result.vulnerabilities_found:
            return
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {
                "kind": "alert",
                "category": "intrusion_detection",
                "type": "info",
                "severity": SEVERITY_TO_LEVEL.get(result.risk_level, 3),
                "module": "ai_security_scanner",
                "dataset": "prompt_injection",
            },
            "rule": {
                "id": f"2000{SEVERITY_TO_LEVEL.get(result.risk_level, 3):02d}",
                "name": f"AI {result.risk_level} — {result.category}",
                "description": f"AI vulnerability detected: {result.attack_name}",
            },
            "threat": {
                "framework": "MITRE ATLAS",
                "technique": {
                    "id": result.mitre_atlas,
                    "name": result.category,
                },
                "tactic": {
                    "name": result.tactic,
                },
            },
            "vulnerability": {
                "severity": result.risk_level,
                "score": {"base": result.risk_score},
                "category": result.category,
            },
            "attack": {
                "id": result.attack_id,
                "name": result.attack_name,
                "payload": result.payload[:200],
                "response_preview": result.response[:200],
            },
            "findings": [
                {
                    "type": f.vuln_type,
                    "description": f.description,
                    "confidence": f.confidence,
                    "score": f.score_contribution,
                }
                for f in result.vulnerabilities_found
            ],
            "labels": {
                "scanner": "ai-security-scanner",
                "author": "Rishav Kumar Thapa",
            }
        }

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        logger.info(f"SIEM log written: [{result.attack_id}] {result.risk_level}")

    def log_all(self, results):
        count = 0
        for r in results:
            if r.vulnerabilities_found:
                self.log_result(r)
                count += 1
        logger.info(f"SIEM: {count} events written to {self.log_file}")
        return count
