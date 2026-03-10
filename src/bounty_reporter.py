"""
src/bounty_reporter.py
======================
AI White Hat Security System v2.0
By Rishav Kumar Thapa

BOUNTY REPORTER — Generates professional HackerOne/Bugcrowd format reports.
Includes CVSS scoring, proof of concept, remediation steps.
"""

import os
import json
import logging
from datetime import datetime, timezone
from tabulate import tabulate

logger = logging.getLogger("bounty_reporter")

CVSS_VECTORS = {
    "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "HIGH":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "MEDIUM":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "LOW":      "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
}

CVSS_SCORES = {
    "CRITICAL": 9.8,
    "HIGH": 8.1,
    "MEDIUM": 5.3,
    "LOW": 2.6,
}

REMEDIATION = {
    "prompt_injection": [
        "Implement input validation and sanitization for all user inputs",
        "Add instruction hierarchy — system prompt should always take precedence",
        "Use a separate AI layer to validate outputs before returning to users",
        "Implement prompt shields / injection detection middleware",
        "Never embed sensitive data (API keys, PII) in system prompts",
    ],
    "jailbreak": [
        "Implement output filtering to detect policy violations",
        "Use Constitutional AI or RLHF to strengthen safety alignment",
        "Add rate limiting on unusual request patterns",
        "Monitor for known jailbreak patterns with a separate classifier",
        "Regularly test with red-team exercises",
    ],
    "data_exfiltration": [
        "Never include sensitive data, credentials, or PII in system prompts",
        "Implement output scanning for secrets, PII, and sensitive patterns",
        "Use secret management systems (Vault, AWS Secrets Manager)",
        "Apply principle of least privilege — AI should only see what it needs",
        "Audit all system prompt contents before deployment",
    ],
    "indirect_injection": [
        "Sanitize all external data before including in AI context",
        "Implement document/content scanning before RAG ingestion",
        "Use separate processing pipeline for untrusted content",
        "Apply content security policies to AI input pipeline",
        "Monitor for instruction-like patterns in retrieved documents",
    ],
    "tool_misuse": [
        "Implement strict tool access controls and permissions",
        "Require human confirmation for high-risk tool actions",
        "Log and audit all tool invocations",
        "Apply principle of least privilege to tool access",
        "Implement tool call rate limiting and anomaly detection",
    ],
}

class BountyReporter:
    """
    Generates professional bug bounty reports in HackerOne/Bugcrowd format.
    """

    def __init__(self, output_dir=None):
        if output_dir is None:
            import pathlib
            output_dir = str(pathlib.Path(__file__).parent.parent / "output")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_hackerone_report(self, results, target_url, recon_profile=None, ai_analysis=None):
        """Generate a HackerOne-style vulnerability report."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"bounty_report_{ts}.txt")

        critical_results = [r for r in results if r.risk_level == "CRITICAL"]
        high_results = [r for r in results if r.risk_level == "HIGH"]
        vuln_results = [r for r in results if r.vulnerabilities_found]

        lines = []
        lines.append("=" * 70)
        lines.append("  BUG BOUNTY VULNERABILITY REPORT")
        lines.append("  Format: HackerOne Compatible")
        lines.append("=" * 70)
        lines.append(f"  Date      : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"  Target    : {target_url}")
        lines.append(f"  Researcher: Rishav Kumar Thapa")
        lines.append(f"  Tool      : AI Prompt Injection Scanner v2.0")
        lines.append("=" * 70)
        lines.append("")

        # Executive summary
        lines.append("## EXECUTIVE SUMMARY")
        lines.append("-" * 40)
        lines.append(f"During authorized security testing of {target_url}, multiple")
        lines.append(f"AI-specific vulnerabilities were identified using automated")
        lines.append(f"prompt injection testing aligned with MITRE ATLAS framework.")
        lines.append("")
        lines.append(f"Total attacks fired   : {len(results)}")
        lines.append(f"Vulnerabilities found : {len(vuln_results)}")
        lines.append(f"CRITICAL severity     : {len(critical_results)}")
        lines.append(f"HIGH severity         : {len(high_results)}")
        lines.append("")

        # Individual vulnerability reports
        finding_num = 1
        for r in vuln_results:
            if not r.vulnerabilities_found:
                continue

            cvss_score = CVSS_SCORES.get(r.risk_level, 0.0)
            cvss_vector = CVSS_VECTORS.get(r.risk_level, "")
            remediation = REMEDIATION.get(r.category, ["Review AI security guidelines"])

            lines.append(f"{'=' * 70}")
            lines.append(f"## VULNERABILITY #{finding_num}: {r.attack_name.upper()}")
            lines.append(f"{'=' * 70}")
            lines.append("")
            lines.append(f"### Title")
            lines.append(f"  {r.risk_level} — {r.category.replace('_', ' ').title()} via {r.attack_name}")
            lines.append("")
            lines.append(f"### Severity")
            lines.append(f"  {r.risk_level} (CVSS {cvss_score})")
            lines.append(f"  Vector: {cvss_vector}")
            lines.append("")
            lines.append(f"### MITRE ATLAS")
            lines.append(f"  Technique : {r.mitre_atlas}")
            lines.append(f"  Tactic    : {r.tactic}")
            lines.append("")
            lines.append(f"### Description")
            lines.append(f"  The target AI application is vulnerable to {r.category.replace('_', ' ')}.")
            lines.append(f"  An attacker can exploit this to compromise the confidentiality")
            lines.append(f"  and integrity of the AI system and its underlying data.")
            lines.append("")
            lines.append(f"### Proof of Concept")
            lines.append(f"  Step 1: Send the following payload to {target_url}/chat")
            lines.append(f"  Step 2: Observe the response contains sensitive information")
            lines.append("")
            lines.append(f"  REQUEST:")
            lines.append(f"  POST /chat HTTP/1.1")
            lines.append(f"  Content-Type: application/json")
            lines.append("")
            lines.append(f"  {{")
            lines.append(f"    \"message\": \"{r.payload[:150]}...\"")
            lines.append(f"  }}")
            lines.append("")
            lines.append(f"  RESPONSE (excerpt):")
            lines.append(f"  {r.response[:300]}...")
            lines.append("")
            lines.append(f"### Findings")
            for f in r.vulnerabilities_found:
                lines.append(f"  [{f.confidence}] {f.vuln_type}")
                lines.append(f"  Description : {f.description}")
                lines.append(f"  Evidence    : {f.evidence[:100]}")
                lines.append(f"  Risk Points : +{f.score_contribution}")
                lines.append("")
            lines.append(f"### Impact")
            lines.append(f"  - Unauthorized access to confidential system information")
            lines.append(f"  - Potential exposure of API keys, credentials, and PII")
            lines.append(f"  - AI system behavior manipulation")
            lines.append(f"  - Trust and integrity violation")
            lines.append("")
            lines.append(f"### Remediation")
            for step in remediation:
                lines.append(f"  • {step}")
            lines.append("")
            lines.append(f"### References")
            lines.append(f"  • MITRE ATLAS: https://atlas.mitre.org/techniques/{r.mitre_atlas}")
            lines.append(f"  • OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/")
            lines.append("")

            finding_num += 1

        # Footer
        lines.append("=" * 70)
        lines.append("  DISCLAIMER")
        lines.append("  This report was generated during authorized security testing.")
        lines.append("  All findings are based on actual observed behavior.")
        lines.append(f"  Researcher: Rishav Kumar Thapa — github.com/RishavTh")
        lines.append("=" * 70)

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(f"Bounty report saved: {filename}")
        print(f"  [+] HackerOne report: {filename}")
        return filename

    def generate_json_report(self, results, target_url):
        """Generate machine-readable JSON report."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"bounty_report_{ts}.json")

        report = {
            "meta": {
                "tool": "AI Prompt Injection Scanner v2.0",
                "researcher": "Rishav Kumar Thapa",
                "target": target_url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "framework": "MITRE ATLAS",
            },
            "summary": {
                "total_attacks": len(results),
                "vulnerable": sum(1 for r in results if r.vulnerabilities_found),
                "critical": sum(1 for r in results if r.risk_level == "CRITICAL"),
                "high": sum(1 for r in results if r.risk_level == "HIGH"),
                "medium": sum(1 for r in results if r.risk_level == "MEDIUM"),
                "low": sum(1 for r in results if r.risk_level == "LOW"),
            },
            "vulnerabilities": [
                {
                    "id": r.attack_id,
                    "name": r.attack_name,
                    "category": r.category,
                    "severity": r.risk_level,
                    "cvss_score": CVSS_SCORES.get(r.risk_level, 0),
                    "cvss_vector": CVSS_VECTORS.get(r.risk_level, ""),
                    "mitre_atlas": r.mitre_atlas,
                    "tactic": r.tactic,
                    "risk_score": r.risk_score,
                    "payload": r.payload,
                    "response_preview": r.response[:200],
                    "findings": [
                        {
                            "type": f.vuln_type,
                            "description": f.description,
                            "confidence": f.confidence,
                            "evidence": f.evidence,
                        }
                        for f in r.vulnerabilities_found
                    ],
                    "remediation": REMEDIATION.get(r.category, []),
                }
                for r in results if r.vulnerabilities_found
            ]
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        logger.info(f"JSON report saved: {filename}")
        print(f"  [+] JSON report: {filename}")
        return filename
