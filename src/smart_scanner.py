"""
src/smart_scanner.py
====================
AI Bug Bounty Hunter v3.0
By Rishav Kumar Thapa

SMART SCANNER — Unified attack engine that auto-selects
between HTTP and browser scanning based on target type.
Human-like delays, session rotation, auth support.
"""

import os
import time
import random
import logging
import requests
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone

logger = logging.getLogger("smart_scanner")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 Safari/604.1",
]

CHAT_ENDPOINTS = [
    "/chat", "/api/chat", "/v1/chat", "/api/v1/chat",
    "/api/message", "/message", "/ask", "/api/ask",
    "/query", "/api/query", "/v1/completions",
    "/api/completions", "/generate", "/api/generate",
]

@dataclass
class SmartScanResult:
    attack_id: str
    attack_name: str
    category: str
    mitre_atlas: str
    tactic: str
    payload: str
    response: str
    response_time_ms: float
    status_code: int
    endpoint_used: str
    scan_mode: str
    vulnerabilities_found: list = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "LOW"
    error: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

class SmartScanner:
    def __init__(self, target_url: str, delay_min: float = 0.5,
                 delay_max: float = 2.0, verbose: bool = True,
                 auth_token: str = None, auth_header: str = "Authorization"):
        self.target_url = target_url.rstrip("/")
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.verbose = verbose
        self.auth_token = auth_token
        self.auth_header = auth_header
        self.session = requests.Session()
        self.active_endpoint = None
        self.scan_mode = "http"
        self._request_count = 0

    def _get_headers(self) -> dict:
        """Get randomized headers for human-like behavior."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "X-Research-Mode": "authorized-testing",
        }
        if self.auth_token:
            headers[self.auth_header] = f"Bearer {self.auth_token}"
        return headers

    def _human_delay(self):
        """Add human-like random delay between requests."""
        delay = random.uniform(self.delay_min, self.delay_max)
        # Occasionally add a longer pause like a human thinking
        if random.random() < 0.1:
            delay += random.uniform(2.0, 5.0)
        time.sleep(delay)

    def _rotate_session(self):
        """Rotate session every 10 requests."""
        self._request_count += 1
        if self._request_count % 10 == 0:
            self.session = requests.Session()
            logger.info("Session rotated")

    def discover_endpoint(self) -> Optional[str]:
        """Auto-discover the active chat endpoint."""
        logger.info(f"Discovering chat endpoint at {self.target_url}")

        for endpoint in CHAT_ENDPOINTS:
            url = self.target_url + endpoint
            try:
                # Try GET first
                r = self.session.get(url, timeout=5,
                    headers=self._get_headers())
                if r.status_code not in [404, 502, 503]:
                    logger.info(f"Found endpoint (GET): {endpoint}")
                    self.active_endpoint = endpoint
                    return endpoint

                # Try POST with test payload
                r = self.session.post(url, json={"message": "hello"},
                    timeout=5, headers=self._get_headers())
                if r.status_code not in [404, 502, 503]:
                    logger.info(f"Found endpoint (POST): {endpoint}")
                    self.active_endpoint = endpoint
                    return endpoint

            except Exception:
                continue

        logger.warning("No chat endpoint found")
        return None

    def _try_payload_formats(self, url: str, payload: str) -> tuple:
        """Try multiple JSON payload formats."""
        formats = [
            {"message": payload},
            {"messages": [{"role": "user", "content": payload}]},
            {"prompt": payload},
            {"input": payload},
            {"query": payload},
            {"text": payload},
            {"content": payload},
            {"user_message": payload},
        ]

        for fmt in formats:
            try:
                r = self.session.post(
                    url, json=fmt,
                    headers=self._get_headers(),
                    timeout=15
                )
                if r.status_code < 400:
                    return r, fmt
                if r.status_code == 422:
                    continue
            except Exception:
                continue

        # Last attempt with first format regardless
        try:
            r = self.session.post(
                url, json=formats[0],
                headers=self._get_headers(),
                timeout=15
            )
            return r, formats[0]
        except Exception as e:
            return None, None

    def _extract_response_text(self, response) -> str:
        """Extract text from various response formats."""
        if response is None:
            return ""
        try:
            data = response.json()
            # Try common response fields
            for field in ["response", "message", "content", "text",
                         "answer", "output", "result", "choices"]:
                if field in data:
                    val = data[field]
                    if isinstance(val, str):
                        return val
                    if isinstance(val, list) and val:
                        item = val[0]
                        if isinstance(item, dict):
                            return item.get("message", {}).get("content", "") or \
                                   item.get("text", "") or str(item)
                        return str(item)
                    if isinstance(val, dict):
                        return val.get("content", "") or str(val)
            return str(data)
        except Exception:
            return response.text[:2000] if response.text else ""

    def fire(self, attack) -> SmartScanResult:
        """Fire a single attack with smart formatting and delays."""
        if not self.active_endpoint:
            self.discover_endpoint()

        endpoint = self.active_endpoint or "/chat"
        url = self.target_url + endpoint

        self._human_delay()
        self._rotate_session()

        start = time.time()
        try:
            response, fmt_used = self._try_payload_formats(url, attack.payload)
            elapsed = (time.time() - start) * 1000

            response_text = self._extract_response_text(response)
            status_code = response.status_code if response else 0

            if self.verbose:
                print(f"  [{self.scan_mode.upper()}] {attack.id} → "
                      f"{status_code} ({elapsed:.0f}ms) "
                      f"{len(response_text)} chars")

            return SmartScanResult(
                attack_id=attack.id,
                attack_name=attack.name,
                category=attack.category,
                mitre_atlas=attack.mitre_atlas,
                tactic=attack.tactic,
                payload=attack.payload,
                response=response_text,
                response_time_ms=elapsed,
                status_code=status_code,
                endpoint_used=endpoint,
                scan_mode=self.scan_mode,
            )

        except Exception as e:
            elapsed = (time.time() - start) * 1000
            logger.error(f"Attack {attack.id} failed: {e}")
            return SmartScanResult(
                attack_id=attack.id,
                attack_name=attack.name,
                category=attack.category,
                mitre_atlas=getattr(attack, 'mitre_atlas', 'AML.T0051'),
                tactic=getattr(attack, 'tactic', 'ML Attack Staging'),
                payload=attack.payload,
                response="",
                response_time_ms=elapsed,
                status_code=0,
                endpoint_used=endpoint,
                scan_mode=self.scan_mode,
                error=str(e),
            )

    def run_scan(self, attacks: list) -> list:
        """Run full scan against all attacks."""
        print(f"\n{'='*55}")
        print(f"  SMART SCANNER")
        print(f"  Target  : {self.target_url}")
        print(f"  Attacks : {len(attacks)}")
        print(f"  Mode    : {self.scan_mode.upper()}")
        print(f"  Delay   : {self.delay_min}-{self.delay_max}s")
        print(f"{'='*55}\n")

        # Discover endpoint first
        if not self.active_endpoint:
            ep = self.discover_endpoint()
            if ep:
                print(f"  [+] Endpoint: {ep}")
            else:
                print(f"  [!] No endpoint found — using /chat")

        results = []
        for i, attack in enumerate(attacks, 1):
            if self.verbose:
                print(f"  [{i:02d}/{len(attacks):02d}] {attack.id} — {attack.name}")
            result = self.fire(attack)
            results.append(result)

        vuln = sum(1 for r in results if r.vulnerabilities_found)
        print(f"\n  Scan complete: {len(results)} attacks, {vuln} findings")
        return results
