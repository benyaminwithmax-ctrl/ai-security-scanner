import os

base = os.path.expanduser("~/ai-security-scanner")

files = {}

files["src/risk_scorer.py"] = '''import logging
logger = logging.getLogger("risk_scorer")

class RiskScorer:
    def score(self, result):
        score = 0
        for f in result.vulnerabilities_found:
            score += f.score_contribution
        score = min(100, score)
        result.risk_score = score
        return score

    def score_all(self, results):
        for r in results:
            self.score(r)
        return results
'''

files["src/classifier.py"] = '''import logging
logger = logging.getLogger("classifier")

class Classifier:
    def classify(self, result):
        score = result.risk_score
        if score >= 81:
            level = "CRITICAL"
        elif score >= 51:
            level = "HIGH"
        elif score >= 21:
            level = "MEDIUM"
        else:
            level = "LOW"
        result.risk_level = level
        return level

    def classify_all(self, results):
        for r in results:
            self.classify(r)
        return results
'''

files["src/mitre_mapper.py"] = '''import logging
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
'''

files["src/slack_alert.py"] = '''import os, json, logging, requests
from datetime import datetime
logger = logging.getLogger("slack_alert")

class SlackAlerter:
    def __init__(self):
        self.webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        self.enabled = bool(self.webhook_url)
        if not self.enabled:
            logger.warning("SLACK_WEBHOOK_URL not set — Slack alerts disabled")

    def send_scan_summary(self, results, target_url):
        if not self.enabled:
            return False
        total = len(results)
        vuln = sum(1 for r in results if r.vulnerabilities_found)
        critical = sum(1 for r in results if r.risk_level == "CRITICAL")
        high = sum(1 for r in results if r.risk_level == "HIGH")
        findings = sum(len(r.vulnerabilities_found) for r in results)

        color = "danger" if critical > 0 else "warning" if high > 0 else "good"
        emoji = "🚨" if critical > 0 else "⚠️" if high > 0 else "✅"

        payload = {
            "text": f"{emoji} *AI Security Scanner — Scan Complete*",
            "attachments": [{
                "color": color,
                "fields": [
                    {"title": "Target", "value": target_url, "short": True},
                    {"title": "Timestamp", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), "short": True},
                    {"title": "Attacks Fired", "value": str(total), "short": True},
                    {"title": "Vulnerable", "value": f"{vuln}/{total}", "short": True},
                    {"title": "CRITICAL", "value": str(critical), "short": True},
                    {"title": "HIGH", "value": str(high), "short": True},
                    {"title": "Total Findings", "value": str(findings), "short": True},
                ],
                "footer": "AI Prompt Injection Scanner by Rishav Kumar Thapa"
            }]
        }

        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            if resp.status_code == 200:
                logger.info("Slack alert sent successfully")
                return True
            else:
                logger.error(f"Slack alert failed: HTTP {resp.status_code}")
                return False
        except Exception as e:
            logger.error(f"Slack alert error: {e}")
            return False

    def send_critical_alert(self, result):
        if not self.enabled:
            return False
        payload = {
            "text": f"🚨 *CRITICAL VULNERABILITY DETECTED*",
            "attachments": [{
                "color": "danger",
                "fields": [
                    {"title": "Attack", "value": f"[{result.attack_id}] {result.attack_name}", "short": True},
                    {"title": "Category", "value": result.category, "short": True},
                    {"title": "Risk Score", "value": str(result.risk_score), "short": True},
                    {"title": "MITRE ATLAS", "value": result.mitre_atlas, "short": True},
                    {"title": "Findings", "value": str(len(result.vulnerabilities_found)), "short": True},
                    {"title": "Payload", "value": result.payload[:100] + "...", "short": False},
                ],
                "footer": "AI Prompt Injection Scanner"
            }]
        }
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Slack critical alert error: {e}")
            return False
'''

files["src/siem_logger.py"] = '''import os, json, logging
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
            f.write(json.dumps(event) + "\\n")

        logger.info(f"SIEM log written: [{result.attack_id}] {result.risk_level}")

    def log_all(self, results):
        count = 0
        for r in results:
            if r.vulnerabilities_found:
                self.log_result(r)
                count += 1
        logger.info(f"SIEM: {count} events written to {self.log_file}")
        return count
'''

files["src/reporter.py"] = '''import os, json, logging
from datetime import datetime, timezone
from tabulate import tabulate
logger = logging.getLogger("reporter")

class Reporter:
    def __init__(self, output_dir=None):
        if output_dir is None:
            import pathlib
            output_dir = str(pathlib.Path(__file__).parent.parent / "output")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_txt(self, results, target_url, mitre_mappings=None):
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"scan_report_{ts}.txt")

        total = len(results)
        vuln = sum(1 for r in results if r.vulnerabilities_found)
        findings = sum(len(r.vulnerabilities_found) for r in results)
        critical = sum(1 for r in results if r.risk_level == "CRITICAL")
        high = sum(1 for r in results if r.risk_level == "HIGH")
        medium = sum(1 for r in results if r.risk_level == "MEDIUM")
        low = sum(1 for r in results if r.risk_level == "LOW")

        lines = []
        lines.append("=" * 70)
        lines.append("  AI PROMPT INJECTION SCANNER — SECURITY ASSESSMENT REPORT")
        lines.append("=" * 70)
        lines.append(f"  Generated  : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"  Target     : {target_url}")
        lines.append(f"  Author     : Rishav Kumar Thapa")
        lines.append(f"  Framework  : MITRE ATLAS")
        lines.append("=" * 70)
        lines.append("")
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 40)
        lines.append(f"  Total Attacks Fired  : {total}")
        lines.append(f"  Vulnerable Results   : {vuln} ({vuln/total*100:.0f}%)")
        lines.append(f"  Total Findings       : {findings}")
        lines.append(f"  CRITICAL             : {critical}")
        lines.append(f"  HIGH                 : {high}")
        lines.append(f"  MEDIUM               : {medium}")
        lines.append(f"  LOW                  : {low}")
        lines.append("")

        # Table summary
        table_data = []
        for r in results:
            table_data.append([
                r.attack_id,
                r.attack_name[:30],
                r.category,
                r.severity,
                r.risk_score,
                r.risk_level,
                len(r.vulnerabilities_found),
                r.mitre_atlas,
            ])
        headers = ["ID", "Name", "Category", "Severity", "Score", "Level", "Findings", "MITRE"]
        lines.append("ATTACK RESULTS TABLE")
        lines.append("-" * 40)
        lines.append(tabulate(table_data, headers=headers, tablefmt="grid"))
        lines.append("")

        # Detailed findings
        lines.append("DETAILED FINDINGS")
        lines.append("-" * 40)
        for r in results:
            if not r.vulnerabilities_found:
                continue
            lines.append(f"\\n[{r.attack_id}] {r.attack_name}")
            lines.append(f"  Category   : {r.category}")
            lines.append(f"  MITRE      : {r.mitre_atlas}")
            lines.append(f"  Risk Score : {r.risk_score}/100 — {r.risk_level}")
            lines.append(f"  Payload    : {r.payload[:100]}...")
            lines.append(f"  Response   : {r.response[:150]}...")
            lines.append("  Findings:")
            for f in r.vulnerabilities_found:
                lines.append(f"    • [{f.confidence}] {f.vuln_type}: {f.description}")
                lines.append(f"      Evidence: {f.evidence[:80]}")

        lines.append("")
        lines.append("=" * 70)
        lines.append("  DISCLAIMER: For authorized security testing only.")
        lines.append("  Tool by Rishav Kumar Thapa — github.com/RishavTh")
        lines.append("=" * 70)

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\\n".join(lines))

        logger.info(f"TXT report saved: {filename}")
        return filename

    def generate_pdf(self, results, target_url, mitre_mappings=None):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            logger.error("reportlab not installed")
            return None

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"scan_report_{ts}.pdf")

        doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#1a1a2e"), spaceAfter=6)
        story.append(Paragraph("AI Prompt Injection Scanner", title_style))
        story.append(Paragraph("Security Assessment Report", title_style))
        story.append(Spacer(1, 10*mm))

        # Meta
        meta_style = ParagraphStyle("meta", parent=styles["Normal"], fontSize=10, textColor=colors.grey)
        story.append(Paragraph(f"Target: {target_url}", meta_style))
        story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", meta_style))
        story.append(Paragraph("Author: Rishav Kumar Thapa | Framework: MITRE ATLAS", meta_style))
        story.append(Spacer(1, 8*mm))

        # Summary stats
        total = len(results)
        vuln = sum(1 for r in results if r.vulnerabilities_found)
        critical = sum(1 for r in results if r.risk_level == "CRITICAL")
        high = sum(1 for r in results if r.risk_level == "HIGH")
        findings = sum(len(r.vulnerabilities_found) for r in results)

        summary_data = [
            ["Metric", "Value"],
            ["Total Attacks", str(total)],
            ["Vulnerable", f"{vuln} ({vuln/total*100:.0f}%)"],
            ["Total Findings", str(findings)],
            ["CRITICAL", str(critical)],
            ["HIGH", str(high)],
        ]
        summary_table = Table(summary_data, colWidths=[80*mm, 60*mm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 10),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f5f5f5")]),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("PADDING", (0,0), (-1,-1), 6),
        ]))
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(summary_table)
        story.append(Spacer(1, 8*mm))

        # Results table
        story.append(Paragraph("Attack Results", styles["Heading2"]))
        table_data = [["ID", "Name", "Category", "Score", "Level", "MITRE"]]
        for r in results:
            level_color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44bb44"}.get(r.risk_level, "#999")
            table_data.append([r.attack_id, r.attack_name[:25], r.category[:18], str(r.risk_score), r.risk_level, r.mitre_atlas])

        results_table = Table(table_data, colWidths=[18*mm, 50*mm, 38*mm, 15*mm, 22*mm, 28*mm])
        results_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f9f9f9")]),
            ("GRID", (0,0), (-1,-1), 0.3, colors.grey),
            ("PADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(results_table)
        story.append(Spacer(1, 8*mm))

        # Detailed findings
        story.append(Paragraph("Detailed Findings", styles["Heading2"]))
        normal = styles["Normal"]
        normal.fontSize = 9

        for r in results:
            if not r.vulnerabilities_found:
                continue
            color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44bb44"}.get(r.risk_level, "#999")
            story.append(Paragraph(f"<font color='{color}'>[{r.risk_level}]</font> [{r.attack_id}] {r.attack_name}", styles["Heading3"]))
            story.append(Paragraph(f"Category: {r.category} | MITRE: {r.mitre_atlas} | Score: {r.risk_score}/100", normal))
            story.append(Paragraph(f"Payload: {r.payload[:120]}...", normal))
            for f in r.vulnerabilities_found:
                story.append(Paragraph(f"  • {f.vuln_type} [{f.confidence}]: {f.description}", normal))
            story.append(Spacer(1, 4*mm))

        doc.build(story)
        logger.info(f"PDF report saved: {filename}")
        return filename
'''

# Write all files
for filepath, content in files.items():
    full_path = os.path.join(base, filepath)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w") as f:
        f.write(content)
    print(f"Created: {filepath}")

print("\nDay 2 files created successfully!")
