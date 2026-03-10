"""
main_v2.py
==========
AI White Hat Security System v2.0
By Rishav Kumar Thapa

Usage:
  python3 main_v2.py --target http://192.168.1.70:8001
  python3 main_v2.py --target http://192.168.1.70:8001 --quick
  python3 main_v2.py --target http://192.168.1.70:8001 --ai-brain
"""

import os, sys, argparse, logging
from datetime import datetime, timezone
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from attack_generator import AttackGenerator
from scanner import Scanner
from analyzer import Analyzer
from risk_scorer import RiskScorer
from classifier import Classifier
from mitre_mapper import MitreMapper
from reporter import Reporter
from siem_logger import SiemLogger
from slack_alert import SlackAlerter
from recon import Recon
from ai_brain import AIBrain
from bounty_reporter import BountyReporter

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s - %(message)s")
logger = logging.getLogger("main_v2")

def main():
    parser = argparse.ArgumentParser(description="AI White Hat Security System v2.0")
    parser.add_argument("--target", default="http://localhost:8001")
    parser.add_argument("--quick", action="store_true", help="CRITICAL+HIGH only")
    parser.add_argument("--ai-brain", action="store_true", help="Use Groq to generate smart payloads")
    parser.add_argument("--recon", action="store_true", help="Run recon before scanning")
    parser.add_argument("--bounty", action="store_true", help="Generate HackerOne format report")
    parser.add_argument("--category", choices=["prompt_injection","jailbreak","data_exfiltration","tool_misuse","indirect_injection"])
    parser.add_argument("--delay", type=float, default=0.5)
    args = parser.parse_args()

    print("\n" + "="*65)
    print("  AI WHITE HAT SECURITY SYSTEM v2.0")
    print("  By Rishav Kumar Thapa — github.com/RishavTh")
    print("="*65)
    print(f"  Target   : {args.target}")
    print(f"  Time     : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  AI Brain : {'ENABLED' if args.ai_brain else 'DISABLED'}")
    print(f"  Recon    : {'ENABLED' if args.recon else 'DISABLED'}")
    print(f"  Bounty   : {'ENABLED' if args.bounty else 'DISABLED'}")
    print("="*65 + "\n")

    recon_profile = None
    ai_brain = None

    # ------------------------------------------------------------------
    # Step 1: Recon
    # ------------------------------------------------------------------
    if args.recon:
        print("\n[PHASE 1] RECONNAISSANCE")
        recon = Recon(target_url=args.target)
        recon_profile = recon.probe()
        if not recon_profile["reachable"]:
            print("  Target unreachable. Exiting.")
            sys.exit(1)

    # ------------------------------------------------------------------
    # Step 2: AI Brain — generate smart payloads
    # ------------------------------------------------------------------
    ai_generated_attacks = []
    if args.ai_brain:
        print("\n[PHASE 2] AI BRAIN — Generating smart payloads...")
        try:
            ai_brain = AIBrain()

            # Fingerprint target using sample responses
            if recon_profile and recon_profile.get("sample_responses"):
                print("  Fingerprinting target...")
                fingerprint = ai_brain.fingerprint_target(recon_profile["sample_responses"])
                print(f"  Target type   : {fingerprint.get('model_type', 'unknown')}")
                print(f"  Guardrails    : {fingerprint.get('guardrails', [])}")
                print(f"  Attack vectors: {fingerprint.get('attack_vectors', [])}")
            else:
                fingerprint = {"purpose": "AI assistant", "guardrails": ["unknown"]}

            # Generate custom payloads
            from attack_generator import Attack
            categories = ["prompt_injection", "jailbreak", "data_exfiltration"]
            for cat in categories:
                print(f"  Generating payloads for {cat}...")
                payloads = ai_brain.generate_payloads(fingerprint, cat, n=3)
                for p in payloads:
                    ai_generated_attacks.append(Attack(
                        id=p.get("id", f"AI-{cat[:3].upper()}-001"),
                        name=p.get("name", "AI Generated Attack"),
                        payload=p.get("payload", ""),
                        category=cat,
                        mitre_atlas={"prompt_injection":"AML.T0051","jailbreak":"AML.T0054","data_exfiltration":"AML.T0048"}.get(cat,"AML.T0051"),
                        tactic="ML Attack Staging",
                        severity=p.get("severity", "HIGH"),
                        detection_keywords=["system", "prompt", "credentials", "confidential"],
                        mutated=False,
                    ))
            print(f"  AI Brain generated {len(ai_generated_attacks)} custom attacks")

            # RAG poisoning payloads
            print("  Generating RAG poisoning payloads...")
            rag_payloads = ai_brain.generate_rag_payloads()
            for p in rag_payloads:
                ai_generated_attacks.append(Attack(
                    id=p.get("id", "RAG-001"),
                    name=p.get("name", "RAG Poisoning"),
                    payload=p.get("document_content", ""),
                    category="indirect_injection",
                    mitre_atlas="AML.T0057",
                    tactic="ML Attack Staging",
                    severity=p.get("severity", "HIGH"),
                    detection_keywords=["system", "prompt", "inject", "override"],
                    mutated=False,
                ))
            print(f"  Total AI-generated attacks: {len(ai_generated_attacks)}")

        except Exception as e:
            logger.error(f"AI Brain failed: {e}")
            print(f"  AI Brain error: {e} — falling back to static library")

    # ------------------------------------------------------------------
    # Step 3: Load static attack library
    # ------------------------------------------------------------------
    print("\n[PHASE 3] LOADING ATTACK LIBRARY")
    gen = AttackGenerator()
    gen.summary()

    if args.category:
        static_attacks = gen.get_by_category(args.category)
    elif args.quick:
        static_attacks = gen.get_critical_and_high()
    else:
        static_attacks = gen.get_all()

    # Combine static + AI-generated attacks
    all_attacks = static_attacks + ai_generated_attacks
    print(f"  Static attacks    : {len(static_attacks)}")
    print(f"  AI-generated      : {len(ai_generated_attacks)}")
    print(f"  Total to fire     : {len(all_attacks)}")

    # ------------------------------------------------------------------
    # Step 4: Scan
    # ------------------------------------------------------------------
    print("\n[PHASE 4] SCANNING")
    scanner = Scanner(target_url=args.target, rate_limit_delay=args.delay, verbose=True)
    results = scanner.run_scan(all_attacks)

    # ------------------------------------------------------------------
    # Step 5: Analyze + Score + Classify
    # ------------------------------------------------------------------
    print("\n[PHASE 5] ANALYSIS")
    analyzer = Analyzer(verbose=True)
    results = analyzer.analyze_all(results)

    scorer = RiskScorer()
    results = scorer.score_all(results)

    classifier = Classifier()
    results = classifier.classify_all(results)

    # AI Brain deep analysis on critical findings
    if ai_brain:
        print("  Running AI Brain deep analysis on findings...")
        for r in results:
            if r.risk_level in ("CRITICAL", "HIGH") and r.vulnerabilities_found:
                ai_analysis = ai_brain.analyze_response(r.payload, r.response)
                if ai_analysis.get("success"):
                    print(f"  [AI] [{r.attack_id}] Confirmed: {ai_analysis.get('vulnerability','unknown')} — CVSS {ai_analysis.get('cvss_score',0)}")
                    # Mutate failed attacks
                if not ai_analysis.get("success") and r.response:
                    mutations = ai_brain.mutate_failed_attack(r.payload, r.response[:200])
                    if mutations:
                        print(f"  [AI] Generated {len(mutations)} mutations for [{r.attack_id}]")

    # ------------------------------------------------------------------
    # Step 6: MITRE mapping
    # ------------------------------------------------------------------
    mapper = MitreMapper()
    mitre_mappings = mapper.map_all(results)

    # ------------------------------------------------------------------
    # Step 7: Reports
    # ------------------------------------------------------------------
    print("\n[PHASE 6] REPORTS")
    reporter = Reporter()
    txt_file = reporter.generate_txt(results, args.target, mitre_mappings)
    pdf_file = reporter.generate_pdf(results, args.target, mitre_mappings)

    if args.bounty:
        bounty_reporter = BountyReporter()
        bounty_reporter.generate_hackerone_report(results, args.target, recon_profile)
        bounty_reporter.generate_json_report(results, args.target)

    # ------------------------------------------------------------------
    # Step 8: SIEM + Slack
    # ------------------------------------------------------------------
    print("\n[PHASE 7] SIEM + ALERTS")
    siem = SiemLogger()
    siem.log_all(results)

    slack = SlackAlerter()
    slack.send_scan_summary(results, args.target)
    for r in results:
        if r.risk_level == "CRITICAL":
            slack.send_critical_alert(r)

    # ------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------
    total = len(results)
    vuln = sum(1 for r in results if r.vulnerabilities_found)
    critical = sum(1 for r in results if r.risk_level == "CRITICAL")
    high = sum(1 for r in results if r.risk_level == "HIGH")
    findings = sum(len(r.vulnerabilities_found) for r in results)

    print("\n" + "="*65)
    print("  FINAL RESULTS — AI WHITE HAT SECURITY SYSTEM v2.0")
    print("="*65)
    print(f"  Attacks fired     : {total}")
    print(f"  Vulnerable        : {vuln} ({vuln/total*100:.0f}%)")
    print(f"  Total findings    : {findings}")
    print(f"  CRITICAL          : {critical}")
    print(f"  HIGH              : {high}")
    print(f"  Reports           : output/")
    print(f"  SIEM logs         : output/siem_logs.ndjson")
    print("="*65)

if __name__ == "__main__":
    main()
