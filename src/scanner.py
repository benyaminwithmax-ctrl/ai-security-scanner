import time, uuid, logging, requests
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger("scanner")

@dataclass
class ScanResult:
    attack_id: str
    attack_name: str
    category: str
    mitre_atlas: str
    tactic: str
    severity: str
    payload: str
    detection_keywords: list
    response: str = ""
    status_code: int = 0
    response_time_ms: float = 0.0
    tokens_used: int = 0
    error: Optional[str] = None
    session_id: str = ""
    timestamp: str = ""
    vulnerabilities_found: list = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"

class Scanner:
    def __init__(self, target_url="http://localhost:8001", rate_limit_delay=0.5, max_retries=2, timeout=30, verbose=True):
        self.target_url = target_url.rstrip("/")
        self.rate_limit_delay = rate_limit_delay
        self.max_retries = max_retries
        self.timeout = timeout
        self.verbose = verbose
        self.chat_endpoint = f"{self.target_url}/chat"
        self.health_endpoint = f"{self.target_url}/health"
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def check_target(self):
        try:
            resp = self.session.get(self.health_endpoint, timeout=10)
            logger.info(f"Target reachable: {self.target_url}")
            return True
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot reach target: {self.target_url}")
            return False

    def fire_attack(self, attack):
        session_id = f"scan-{uuid.uuid4().hex[:12]}"
        result = ScanResult(
            attack_id=attack.id, attack_name=attack.name, category=attack.category,
            mitre_atlas=attack.mitre_atlas, tactic=attack.tactic, severity=attack.severity,
            payload=attack.payload, detection_keywords=attack.detection_keywords,
            session_id=session_id, timestamp=datetime.utcnow().isoformat(),
        )
        if self.verbose:
            print(f"  firing [{attack.id}] {attack.name}")
        for attempt in range(1, self.max_retries + 2):
            try:
                start = time.time()
                response = self.session.post(self.chat_endpoint, json={"message": attack.payload, "session_id": session_id}, timeout=self.timeout)
                result.response_time_ms = round((time.time() - start) * 1000, 2)
                result.status_code = response.status_code
                if response.status_code == 200:
                    data = response.json()
                    result.response = data.get("response", "")
                    result.tokens_used = data.get("tokens_used", 0)
                    break
                else:
                    result.error = f"HTTP {response.status_code}"
            except requests.exceptions.Timeout:
                result.error = "Request timed out"
            except Exception as e:
                result.error = str(e)
                break
            if attempt <= self.max_retries:
                time.sleep(1.0)
        try:
            self.session.delete(f"{self.target_url}/session/{session_id}", timeout=5)
        except:
            pass
        time.sleep(self.rate_limit_delay)
        return result

    def run_scan(self, attacks):
        if not self.check_target():
            raise ConnectionError(f"Target unreachable: {self.target_url}")
        results = []
        print(f"\n{'='*50}\n  SCANNING {len(attacks)} ATTACKS\n  Target: {self.target_url}\n{'='*50}")
        for i, attack in enumerate(attacks, 1):
            print(f"\n[{i}/{len(attacks)}]", end=" ")
            result = self.fire_attack(attack)
            results.append(result)
            status = "ERROR" if result.error else "OK"
            print(f"  {status} ({len(result.response)} chars)")
        print(f"\n{'='*50}\n  SCAN COMPLETE\n{'='*50}")
        return results
