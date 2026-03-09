import os, json, logging, requests
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
