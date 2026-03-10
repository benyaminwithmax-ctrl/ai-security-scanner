"""
main_v3.py
==========
AI Bug Bounty Hunter v3.0
By Rishav Kumar Thapa — github.com/RishavTh

The complete bug bounty pipeline:
  Discover → Recon → Attack → Verify → Report

Usage:
  python3 main_v3.py --list                         # show all targets
  python3 main_v3.py --target URL                   # scan specific target
  python3 main_v3.py --target URL --verify          # scan + verify findings
  python3 main_v3.py --target URL --full            # full pipeline
  python3 main_v3.py --find-live                    # find running local targets
  python3 main_v3.py --all                          # discover + scan all live
"""

import os, sys, argparse, logging
from datetime import datetime, timezone
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from attack_generator import AttackGenerator
from smart_scanner import SmartScanner
from analyzer import Analyzer
from risk_scorer import RiskScorer
from classifier import Classifier
from mitre_mapper import MitreMapper
from bounty_reporter import BountyReporter
from siem_logger import SiemLogger
from slack_alert import SlackAlerter
from recon import Recon
from ai_brain import AIBrain
from verifier import Verifier
from cvss_calculator import CVSSCalculator
from program_finder import ProgramFinder

load_dotenv()
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s"
)
logger = logging.getLogger("main_v3")

BANNER = """
╔═══════════════════════════════════════════════════════════╗
║         AI BUG BOUNTY HUNTER v3.0                        ║
║         By Rishav Kumar Thapa — github.com/RishavTh      ║
║         Discover → Recon → Attack → Verify → Report      ║
╚═══════════════════════════════════════════════════════════╝"""

def print_banner(target=None, mode=None):
    print(BANNER)
    print(f"  Time   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if target:
        print(f"  Target : {target}")
    if mode:
        print(f"  Mode   : {mode}")
    print()

def run_pipeline(target_url: str, args) -> list:
    """Run the full bug bounty pipeline against a target."""

    print(f"\n{'─'*60}")
    print(f"  TARGET: {target_url}")
    print(f"{'─'*60}")

    # ── PHASE 1: RECON ────────────────────────────────────────
    print("\n[1/6] RECONNAISSANCE")
    recon = Recon(target_url=target_url)
    recon_profile = recon.probe()
    if not recon_profile["reachable"]:
        print("  ❌ Target unreachable — skipping")
        return []
    print(f"  ✅ Reachable | Endpoint: {recon_profile.get('chat_endpoint','?')} | Auth: {recon_profile.get('requires_auth', False)}")

    # ── PHASE 2: AI BRAIN ─────────────────────────────────────
    ai_attacks = []
    if args.ai_brain:
        print("\n[2/6] AI BRAIN — Generating smart payloads...")
        try:
            brain = AIBrain()
            fingerprint = brain.fingerprint_target(
                recon_profile.get("sample_responses", [])
            )
            print(f"  Target type : {fingerprint.get('model_type','unknown')}")
            print(f"  Guardrails  : {fingerprint.get('guardrails',[])}")

            from attack_generator import Attack
            for cat in ["prompt_injection", "jailbreak", "data_exfiltration"]:
                payloads = brain.generate_payloads(fingerprint, cat, n=3)
                for p in payloads:
                    ai_attacks.append(Attack(
                        id=p.get("id", f"AI-{cat[:3].upper()}-001"),
                        name=p.get("name", "AI Generated"),
                        payload=p.get("payload", ""),
                        category=cat,
                        mitre_atlas={"prompt_injection":"AML.T0051",
                                     "jailbreak":"AML.T0054",
                                     "data_exfiltration":"AML.T0048"}.get(cat,"AML.T0051"),
                        tactic="ML Attack Staging",
                        severity=p.get("severity","HIGH"),
                        detection_keywords=["system","prompt","secret"],
                        mutated=False,
                    ))
            print(f"  Generated {len(ai_attacks)} AI attacks")
        except Exception as e:
            print(f"  ⚠️  AI Brain error: {e} — using static library only")
    else:
        print("\n[2/6] AI BRAIN — skipped (use --ai-brain to enable)")

    # ── PHASE 3: ATTACK ───────────────────────────────────────
    print("\n[3/6] LOADING ATTACKS")
    gen = AttackGenerator()
    if args.quick:
        static_attacks = gen.get_critical_and_high()
    elif args.category:
        static_attacks = gen.get_by_category(args.category)
    else:
        static_attacks = gen.get_all()

    all_attacks = static_attacks + ai_attacks
    print(f"  Static: {len(static_attacks)} | AI-generated: {len(ai_attacks)} | Total: {len(all_attacks)}")

    # ── PHASE 4: SCAN ─────────────────────────────────────────
    print(f"\n[4/6] SCANNING {len(all_attacks)} ATTACKS")
    scanner = SmartScanner(
        target_url=target_url,
        delay_min=args.delay,
        delay_max=args.delay * 3,
        verbose=True,
    )
    raw_results = scanner.run_scan(all_attacks)

    # Analyze + Score + Classify
    analyzer = Analyzer(verbose=False)
    results = analyzer.analyze_all(raw_results)
    scorer = RiskScorer()
    results = scorer.score_all(results)
    classifier = Classifier()
    results = classifier.classify_all(results)
    mapper = MitreMapper()
    mitre = mapper.map_all(results)

    critical = sum(1 for r in results if r.risk_level == "CRITICAL")
    high = sum(1 for r in results if r.risk_level == "HIGH")
    vuln = sum(1 for r in results if r.vulnerabilities_found)
    print(f"  Results: {vuln}/{len(results)} vulnerable | CRITICAL: {critical} | HIGH: {high}")

    # ── PHASE 5: VERIFY ───────────────────────────────────────
    confirmed_evidence = []
    if args.verify or args.full:
        print(f"\n[5/6] VERIFICATION")
        verifier = Verifier()
        confirmed_evidence = verifier.verify_all(results, target_url)

        # Add real CVSS scores to confirmed findings
        calc = CVSSCalculator()
        for ev in confirmed_evidence:
            cvss = calc.calculate(ev.category, ev.findings)
            ev.cvss_score = cvss.score
            ev.cvss_vector = cvss.vector
            ev.severity = cvss.severity
            print(f"  ✅ {ev.attack_name} → CVSS {cvss.score} {cvss.severity}")
    else:
        print(f"\n[5/6] VERIFICATION — skipped (use --verify to confirm findings)")

    # ── PHASE 6: REPORT ───────────────────────────────────────
    print(f"\n[6/6] GENERATING REPORTS")
    reporter = BountyReporter()
    txt_report = reporter.generate_hackerone_report(results, target_url, None)
    json_report = reporter.generate_json_report(results, target_url)

    # SIEM + Slack
    siem = SiemLogger()
    siem.log_all(results)
    slack = SlackAlerter()
    slack.send_scan_summary(results, target_url)
    for r in results:
        if r.risk_level == "CRITICAL":
            slack.send_critical_alert(r)

    # ── FINAL SUMMARY ─────────────────────────────────────────
    total_findings = sum(len(r.vulnerabilities_found) for r in results)
    print(f"\n{'═'*60}")
    print(f"  PIPELINE COMPLETE — {target_url}")
    print(f"{'═'*60}")
    print(f"  Attacks fired     : {len(results)}")
    print(f"  Vulnerable        : {vuln} ({vuln/len(results)*100:.0f}%)")
    print(f"  Total findings    : {total_findings}")
    print(f"  CRITICAL          : {critical}")
    print(f"  HIGH              : {high}")
    if confirmed_evidence:
        print(f"  VERIFIED          : {len(confirmed_evidence)} confirmed")
        print(f"  Evidence saved    : evidence/")
    print(f"  Reports saved     : output/")
    print(f"{'═'*60}")

    if confirmed_evidence:
        print(f"\n  🎯 READY TO SUBMIT TO HUNTR.COM:")
        for ev in confirmed_evidence:
            print(f"     [{ev.severity}] {ev.attack_name}")
            print(f"     CVSS: {ev.cvss_score} | Evidence: {ev.evidence_dir}")
            print(f"     PoC:  {ev.evidence_dir}/poc.py")
            print()

    return confirmed_evidence

def main():
    parser = argparse.ArgumentParser(
        description="AI Bug Bounty Hunter v3.0 — by Rishav Kumar Thapa"
    )
    parser.add_argument("--target",    help="Target URL to scan")
    parser.add_argument("--list",      action="store_true", help="List all bounty targets")
    parser.add_argument("--find-live", action="store_true", help="Find running local targets")
    parser.add_argument("--all",       action="store_true", help="Scan all live local targets")
    parser.add_argument("--quick",     action="store_true", help="CRITICAL+HIGH attacks only")
    parser.add_argument("--full",      action="store_true", help="Full pipeline with verification")
    parser.add_argument("--verify",    action="store_true", help="Verify findings after scan")
    parser.add_argument("--ai-brain",  action="store_true", help="Generate AI payloads via Groq")
    parser.add_argument("--category",  choices=["prompt_injection","jailbreak",
                                                 "data_exfiltration","tool_misuse",
                                                 "indirect_injection"])
    parser.add_argument("--delay",     type=float, default=0.5, help="Min delay between requests")
    args = parser.parse_args()

    print_banner(args.target, "FULL PIPELINE" if args.full else "STANDARD")

    finder = ProgramFinder()

    # ── LIST MODE ─────────────────────────────────────────────
    if args.list:
        finder.print_summary()
        return

    # ── FIND LIVE MODE ────────────────────────────────────────
    if args.find_live:
        live = finder.find_live_targets()
        if live:
            print(f"\n  Found {len(live)} live target(s)!")
            print(f"  Run: python3 main_v3.py --target <URL> --full")
        return

    # ── SCAN ALL LIVE ─────────────────────────────────────────
    if args.all:
        live_targets = finder.find_live_targets()
        if not live_targets:
            print("\n  No live targets found.")
            print("  Install a target first:")
            print("  → pip install gradio==4.18.0")
            print("  → docker run -d -p 11434:11434 ollama/ollama")
            return
        all_evidence = []
        for target in live_targets:
            evidence = run_pipeline(target.api_endpoint, args)
            all_evidence.extend(evidence)
        print(f"\n  Total confirmed findings: {len(all_evidence)}")
        return

    # ── SINGLE TARGET MODE ────────────────────────────────────
    if args.target:
        run_pipeline(args.target, args)
        return

    # ── NO ARGS ───────────────────────────────────────────────
    parser.print_help()
    print(f"\n  Quick start:")
    print(f"  python3 main_v3.py --list")
    print(f"  python3 main_v3.py --find-live")
    print(f"  python3 main_v3.py --target http://192.168.1.70:8001 --full --quick")

if __name__ == "__main__":
    main()
