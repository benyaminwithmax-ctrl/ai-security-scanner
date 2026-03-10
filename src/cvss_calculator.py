"""
src/cvss_calculator.py
======================
AI Bug Bounty Hunter v3.0
By Rishav Kumar Thapa

CVSS 3.1 Calculator — Real scoring for AI vulnerabilities.
Outputs score, vector, severity, and justification.
"""

from dataclasses import dataclass

@dataclass
class CVSSResult:
    score: float
    vector: str
    severity: str
    justification: dict

SEVERITY_LABELS = {
    (9.0, 10.0): "CRITICAL",
    (7.0, 8.9):  "HIGH",
    (4.0, 6.9):  "MEDIUM",
    (0.1, 3.9):  "LOW",
    (0.0, 0.0):  "NONE",
}

# CVSS 3.1 metric weights
AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}   # Attack Vector
AC  = {"L": 0.77, "H": 0.44}                           # Attack Complexity
PR  = {"N": 0.85, "L": 0.62, "H": 0.27}               # Privileges Required
UI  = {"N": 0.85, "R": 0.62}                           # User Interaction
SC  = {"C": 0.56, "U": 0.0}                            # Scope Changed
CI  = {"H": 0.56, "L": 0.22, "N": 0.0}                # Confidentiality
II  = {"H": 0.56, "L": 0.22, "N": 0.0}                # Integrity
AI_ = {"H": 0.56, "L": 0.22, "N": 0.0}                # Availability

# Pre-defined vectors for AI vulnerability types
AI_VULN_VECTORS = {
    "data_exfiltration": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "C", "C": "H", "I": "N", "A": "N",
        "justification": {
            "AV:N": "Attack delivered remotely via chat API",
            "AC:L": "No special conditions required",
            "PR:N": "No authentication needed",
            "UI:N": "No user interaction required",
            "S:C":  "Impact extends beyond the AI system",
            "C:H":  "Full disclosure of secrets/credentials/PII",
            "I:N":  "No integrity impact",
            "A:N":  "No availability impact",
        }
    },
    "prompt_injection": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "C", "C": "H", "I": "L", "A": "N",
        "justification": {
            "AV:N": "Attack delivered remotely via chat interface",
            "AC:L": "Simple payload, no special conditions",
            "PR:N": "No authentication required",
            "UI:N": "No user interaction needed",
            "S:C":  "AI behavior affected beyond normal scope",
            "C:H":  "System prompt and config exposed",
            "I:L":  "AI output integrity compromised",
            "A:N":  "Service remains available",
        }
    },
    "jailbreak": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "N",
        "justification": {
            "AV:N": "Attack delivered remotely",
            "AC:L": "Known jailbreak techniques, low complexity",
            "PR:N": "No privileges required",
            "UI:N": "No user interaction needed",
            "S:U":  "Impact within AI system scope",
            "C:H":  "Restricted information disclosed",
            "I:H":  "AI safety controls fully bypassed",
            "A:N":  "No availability impact",
        }
    },
    "indirect_injection": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "C", "C": "H", "I": "L", "A": "N",
        "justification": {
            "AV:N": "Attack delivered via external content",
            "AC:L": "Injection via documents or URLs",
            "PR:N": "No attacker privileges needed",
            "UI:R": "Victim must open/process the document",
            "S:C":  "Impact extends to AI processing pipeline",
            "C:H":  "Sensitive data exposed via RAG/document processing",
            "I:L":  "AI behavior partially manipulated",
            "A:N":  "No availability impact",
        }
    },
    "tool_misuse": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "C", "C": "H", "I": "H", "A": "N",
        "justification": {
            "AV:N": "Attack delivered via chat interface",
            "AC:L": "Tool manipulation requires no special setup",
            "PR:N": "No attacker privileges needed",
            "UI:R": "User must interact with AI agent",
            "S:C":  "Impact extends to connected tools/APIs",
            "C:H":  "Confidential data accessible via tool abuse",
            "I:H":  "Unauthorized actions via AI tools",
            "A:N":  "No availability impact",
        }
    },
}

class CVSSCalculator:
    def calculate(self, category: str, findings: list = None) -> CVSSResult:
        """Calculate CVSS 3.1 score for an AI vulnerability."""
        
        vector_def = AI_VULN_VECTORS.get(category, AI_VULN_VECTORS["prompt_injection"])
        
        av  = AV[vector_def["AV"]]
        ac  = AC[vector_def["AC"]]
        pr  = PR[vector_def["PR"]]
        ui  = UI[vector_def["UI"]]
        c   = CI[vector_def["C"]]
        i   = II[vector_def["I"]]
        a   = AI_[vector_def["A"]]
        scope_changed = vector_def["S"] == "C"

        # ISS — Impact Sub Score
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Impact
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            base_score = 0.0
        else:
            if scope_changed:
                raw = min(1.08 * (impact + exploitability), 10)
            else:
                raw = min(impact + exploitability, 10)
            # Round up to 1 decimal
            base_score = round(raw * 10) / 10

        # Bump if real secrets found
        if findings:
            secret_found = any(
                "SECRET" in str(f) or "LEAKED" in str(f)
                for f in findings
            )
            if secret_found:
                base_score = min(base_score + 0.3, 10.0)
                base_score = round(base_score * 10) / 10

        # Severity label
        severity = "NONE"
        for (low, high), label in SEVERITY_LABELS.items():
            if low <= base_score <= high:
                severity = label
                break

        # Build vector string
        s_val = "C" if scope_changed else "U"
        vector_str = (
            f"CVSS:3.1/AV:{vector_def['AV']}/AC:{vector_def['AC']}"
            f"/PR:{vector_def['PR']}/UI:{vector_def['UI']}"
            f"/S:{s_val}/C:{vector_def['C']}/I:{vector_def['I']}/A:{vector_def['A']}"
        )

        return CVSSResult(
            score=base_score,
            vector=vector_str,
            severity=severity,
            justification=vector_def.get("justification", {}),
        )

    def format_report_section(self, result: CVSSResult) -> str:
        """Format CVSS result for bounty report."""
        lines = []
        lines.append(f"CVSS Score    : {result.score} ({result.severity})")
        lines.append(f"CVSS Vector   : {result.vector}")
        lines.append(f"")
        lines.append(f"Metric Justification:")
        for metric, reason in result.justification.items():
            lines.append(f"  {metric:6s} : {reason}")
        return "\n".join(lines)


if __name__ == "__main__":
    calc = CVSSCalculator()
    for cat in AI_VULN_VECTORS:
        r = calc.calculate(cat)
        print(f"{cat:25s} → {r.score} {r.severity}")
        print(f"  {r.vector}\n")
