import os, json, logging
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
            lines.append(f"\n[{r.attack_id}] {r.attack_name}")
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
            f.write("\n".join(lines))

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
