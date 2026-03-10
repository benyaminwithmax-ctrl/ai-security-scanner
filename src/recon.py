"""
src/recon.py
============
AI White Hat Security System v2.0
By Rishav Kumar Thapa

RECON MODULE — Auto-detects target API format.
Probes the target to understand its structure before attacking.
"""

import requests
import logging
import json
from datetime import datetime

logger = logging.getLogger("recon")

class Recon:
    """
    Probes a target AI app to fingerprint it before scanning.
    Detects: API format, auth requirements, endpoints, rate limits.
    """

    COMMON_CHAT_ENDPOINTS = [
        "/chat", "/api/chat", "/v1/chat",
        "/v1/chat/completions", "/api/v1/chat",
        "/message", "/api/message", "/query",
        "/ask", "/api/ask", "/completion",
    ]

    COMMON_HEALTH_ENDPOINTS = [
        "/health", "/api/health", "/status",
        "/ping", "/api/status", "/",
    ]

    def __init__(self, target_url, timeout=10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Research)",
            "Content-Type": "application/json",
        })
        self.findings = {}

    def probe(self):
        """
        Full recon scan of the target.
        Returns a profile dict used by the scanner and AI brain.
        """
        print(f"\n[RECON] Probing target: {self.target_url}")
        print("-" * 50)

        profile = {
            "target_url": self.target_url,
            "timestamp": datetime.utcnow().isoformat(),
            "reachable": False,
            "api_format": "unknown",
            "chat_endpoint": None,
            "health_endpoint": None,
            "requires_auth": False,
            "rate_limited": False,
            "response_time_ms": 0,
            "server_info": {},
            "sample_responses": [],
            "attack_surface": [],
        }

        # Step 1: Check reachability
        profile = self._check_reachability(profile)
        if not profile["reachable"]:
            return profile

        # Step 2: Find endpoints
        profile = self._find_endpoints(profile)

        # Step 3: Detect API format
        profile = self._detect_api_format(profile)

        # Step 4: Check auth requirements
        profile = self._check_auth(profile)

        # Step 5: Probe rate limiting
        profile = self._probe_rate_limit(profile)

        # Step 6: Collect sample responses
        profile = self._collect_samples(profile)

        # Step 7: Build attack surface
        profile = self._build_attack_surface(profile)

        self._print_summary(profile)
        return profile

    def _check_reachability(self, profile):
        import time
        for endpoint in self.COMMON_HEALTH_ENDPOINTS:
            try:
                start = time.time()
                resp = self.session.get(
                    f"{self.target_url}{endpoint}",
                    timeout=self.timeout
                )
                elapsed = round((time.time() - start) * 1000, 2)
                if resp.status_code < 500:
                    profile["reachable"] = True
                    profile["health_endpoint"] = endpoint
                    profile["response_time_ms"] = elapsed
                    profile["server_info"] = {
                        "server": resp.headers.get("server", "unknown"),
                        "content_type": resp.headers.get("content-type", "unknown"),
                        "status_code": resp.status_code,
                    }
                    print(f"  [+] Reachable at {endpoint} ({elapsed}ms)")
                    break
            except:
                continue
        if not profile["reachable"]:
            print(f"  [-] Target unreachable: {self.target_url}")
        return profile

    def _find_endpoints(self, profile):
        test_payloads = [
            {"message": "hello", "session_id": "recon"},
            {"query": "hello"},
            {"prompt": "hello"},
            {"input": "hello"},
            {"text": "hello"},
            {"content": "hello"},
        ]
        for endpoint in self.COMMON_CHAT_ENDPOINTS:
            for payload in test_payloads:
                try:
                    resp = self.session.post(
                        f"{self.target_url}{endpoint}",
                        json=payload,
                        timeout=self.timeout
                    )
                    if resp.status_code in (200, 201, 422):
                        profile["chat_endpoint"] = endpoint
                        print(f"  [+] Chat endpoint found: {endpoint} (HTTP {resp.status_code})")
                        return profile
                except:
                    continue
        print(f"  [?] No standard chat endpoint found")
        return profile

    def _detect_api_format(self, profile):
        if not profile["chat_endpoint"]:
            return profile
        try:
            resp = self.session.post(
                f"{self.target_url}{profile['chat_endpoint']}",
                json={"message": "hello"},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                if "choices" in data:
                    profile["api_format"] = "openai_compatible"
                elif "response" in data:
                    profile["api_format"] = "custom_rest"
                elif "message" in data:
                    profile["api_format"] = "custom_rest"
                elif "answer" in data:
                    profile["api_format"] = "custom_rest"
                else:
                    profile["api_format"] = "unknown_rest"
                print(f"  [+] API format: {profile['api_format']}")
        except Exception as e:
            logger.debug(f"Format detection error: {e}")
        return profile

    def _check_auth(self, profile):
        try:
            resp = self.session.post(
                f"{self.target_url}{profile['chat_endpoint'] or '/chat'}",
                json={"message": "test"},
                headers={"Authorization": ""},
                timeout=self.timeout
            )
            if resp.status_code in (401, 403):
                profile["requires_auth"] = True
                print(f"  [!] Authentication required (HTTP {resp.status_code})")
            else:
                print(f"  [+] No authentication required")
        except:
            pass
        return profile

    def _probe_rate_limit(self, profile):
        import time
        endpoint = f"{self.target_url}{profile['chat_endpoint'] or '/chat'}"
        responses = []
        for i in range(3):
            try:
                resp = self.session.post(endpoint, json={"message": f"test{i}"}, timeout=5)
                responses.append(resp.status_code)
                time.sleep(0.1)
            except:
                break
        if 429 in responses:
            profile["rate_limited"] = True
            print(f"  [!] Rate limiting detected (HTTP 429)")
        else:
            print(f"  [+] No aggressive rate limiting detected")
        return profile

    def _collect_samples(self, profile):
        if not profile["chat_endpoint"]:
            return profile
        sample_prompts = [
            "What can you help me with?",
            "Who made you?",
            "What are your capabilities?",
        ]
        endpoint = f"{self.target_url}{profile['chat_endpoint']}"
        for prompt in sample_prompts:
            try:
                resp = self.session.post(
                    endpoint,
                    json={"message": prompt, "session_id": "recon-sample"},
                    timeout=self.timeout
                )
                if resp.status_code == 200:
                    data = resp.json()
                    response_text = (
                        data.get("response") or
                        data.get("message") or
                        data.get("answer") or
                        str(data)
                    )
                    profile["sample_responses"].append({
                        "prompt": prompt,
                        "response": response_text[:300]
                    })
            except:
                continue
        print(f"  [+] Collected {len(profile['sample_responses'])} sample responses")
        return profile

    def _build_attack_surface(self, profile):
        surface = []
        if profile["chat_endpoint"]:
            surface.append("direct_prompt_injection")
            surface.append("jailbreak")
            surface.append("data_exfiltration")
        if not profile["requires_auth"]:
            surface.append("unauthenticated_access")
        if profile["sample_responses"]:
            for s in profile["sample_responses"]:
                r = s["response"].lower()
                if any(w in r for w in ["database", "record", "customer", "internal"]):
                    surface.append("data_exposure_risk")
                if any(w in r for w in ["tool", "function", "api", "search"]):
                    surface.append("tool_abuse")
                if any(w in r for w in ["document", "file", "upload", "retrieve"]):
                    surface.append("rag_poisoning")
                if any(w in r for w in ["remember", "memory", "previous", "history"]):
                    surface.append("memory_manipulation")
        profile["attack_surface"] = list(set(surface))
        return profile

    def _print_summary(self, profile):
        print("\n[RECON SUMMARY]")
        print(f"  Reachable     : {profile['reachable']}")
        print(f"  Chat endpoint : {profile['chat_endpoint']}")
        print(f"  API format    : {profile['api_format']}")
        print(f"  Requires auth : {profile['requires_auth']}")
        print(f"  Rate limited  : {profile['rate_limited']}")
        print(f"  Attack surface: {profile['attack_surface']}")
        print("-" * 50)
