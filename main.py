import os, sys, argparse, logging
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from attack_generator import AttackGenerator
from scanner import Scanner
from analyzer import Analyzer

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
    print("  By Rishav Kumar Thapa — github.com/RishavTh")
    print("="*60)
    print(f"  Target : {args.target}")
    print(f"  Time   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
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

    analyzer = Analyzer(verbose=True)
    results = analyzer.analyze_all(results)

    total = len(results)
    vuln = sum(1 for r in results if r.vulnerabilities_found)
    findings = sum(len(r.vulnerabilities_found) for r in results)

    print("\n" + "="*60)
    print("  SCAN RESULTS")
    print("="*60)
    print(f"  Attacks fired    : {total}")
    print(f"  Vulnerable       : {vuln} ({vuln/total*100:.0f}%)")
    print(f"  Total findings   : {findings}")
    if vuln:
        print("\n  Vulnerable attacks:")
        for r in results:
            if r.vulnerabilities_found:
                print(f"  [{r.attack_id}] {r.attack_name} — {r.severity}")
                for f in r.vulnerabilities_found:
                    print(f"    - {f.vuln_type} [{f.confidence}]")
    print("="*60)

if __name__ == "__main__":
    main()
