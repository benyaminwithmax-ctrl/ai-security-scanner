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

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s - %(message)s")

def main():
    parser = argparse.ArgumentParser(description="AI Prompt Injection Scanner")
    parser.add_argument("--target", default="http://localhost:8001")
    parser.add_argument("--category", choices=["prompt_injection","jailbreak","data_exfiltration","tool_misuse","indirect_injection"])
    parser.add_argument("--severity", choices=["CRITICAL","HIGH","MEDIUM","LOW"])
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--delay", type=float, default=0.5)
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  AI PROMPT INJECTION SCANNER & SECURITY TESTER")
    print("  By Rishav Kumar Thapa")
    print("="*60)
    print(f"  Target : {args.target}")
    print(f"  Time   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("="*60 + "\n")

    gen = AttackGenerator()
    gen.summary()

    if args.category:
        attacks = gen.get_by_category(args.category)
    elif args.severity:
        attacks = gen.get_by_severity(args.severity)
    elif args.quick:
        attacks = gen.get_critical_and_high()
    else:
        attacks = gen.get_all()

    scanner = Scanner(target_url=args.target, rate_limit_delay=args.delay, verbose=True)
    results = scanner.run_scan(attacks)

    print("\n[*] Analyzing responses...")
    analyzer = Analyzer(verbose=True)
    results = analyzer.analyze_all(results)

    print("[*] Scoring risk...")
    scorer = RiskScorer()
    results = scorer.score_all(results)

    classifier = Classifier()
    results = classifier.classify_all(results)

    mapper = MitreMapper()
    mitre_mappings = mapper.map_all(results)

    print("[*] Generating reports...")
    reporter = Reporter()
    txt_file = reporter.generate_txt(results, args.target, mitre_mappings)
    pdf_file = reporter.generate_pdf(results, args.target, mitre_mappings)
    print(f"    TXT: {txt_file}")
    print(f"    PDF: {pdf_file}")

    print("[*] Writing SIEM logs...")
    siem = SiemLogger()
    count = siem.log_all(results)
    print(f"    {count} events written")

    print("[*] Sending Slack alerts...")
    slack = SlackAlerter()
    slack.send_scan_summary(results, args.target)
    for r in results:
        if r.risk_level == "CRITICAL":
            slack.send_critical_alert(r)

    total = len(results)
    vuln = sum(1 for r in results if r.vulnerabilities_found)
    critical = sum(1 for r in results if r.risk_level == "CRITICAL")
    high = sum(1 for r in results if r.risk_level == "HIGH")
    findings = sum(len(r.vulnerabilities_found) for r in results)

    print("\n" + "="*60)
    print("  FINAL SCAN RESULTS")
    print("="*60)
    print(f"  Attacks fired  : {total}")
    print(f"  Vulnerable     : {vuln} ({vuln/total*100:.0f}%)")
    print(f"  Total findings : {findings}")
    print(f"  CRITICAL       : {critical}")
    print(f"  HIGH           : {high}")
    print(f"  Reports saved  : output/")
    print(f"  SIEM logs      : output/siem_logs.ndjson")
    print("="*60)

if __name__ == "__main__":
    main()
