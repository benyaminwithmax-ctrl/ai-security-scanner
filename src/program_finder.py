"""
src/program_finder.py
=====================
AI Bug Bounty Hunter v3.0
By Rishav Kumar Thapa

PROGRAM FINDER — Discovers AI bug bounty targets from
huntr.com and HackerOne. Filters for AI/LLM programs
that allow automated testing and have API endpoints.
"""

import json
import logging
import os
import requests
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("program_finder")

@dataclass
class BountyTarget:
    name: str
    platform: str
    url: str
    api_endpoint: str
    scope: list
    max_bounty: int
    allows_automation: bool
    has_ai_features: bool
    notes: str
    category: str
    github_repo: str = ""

# Manually curated AI bounty targets from huntr.com
# These are confirmed AI/ML programs that accept security reports
HUNTR_TARGETS = [
    BountyTarget(
        name="Gradio",
        platform="huntr.com",
        url="https://huntr.com/repos/gradio-app/gradio",
        api_endpoint="http://localhost:7860",
        scope=["File upload handling", "API endpoints", "Input validation",
               "Authentication bypass", "SSRF", "Path traversal"],
        max_bounty=1500,
        allows_automation=True,
        has_ai_features=True,
        notes="Python AI UI framework. Run locally. Test /upload, /queue, /component_server endpoints.",
        category="ml_framework",
        github_repo="gradio-app/gradio",
    ),
    BountyTarget(
        name="LlamaIndex",
        platform="huntr.com",
        url="https://huntr.com/repos/run-llama/llama_index",
        api_endpoint="http://localhost:8000",
        scope=["RAG pipeline injection", "Document loader exploits",
               "Prompt injection via documents", "Tool misuse"],
        max_bounty=1500,
        allows_automation=True,
        has_ai_features=True,
        notes="RAG framework. Test document loaders, query engines, tool integrations.",
        category="ml_framework",
        github_repo="run-llama/llama_index",
    ),
    BountyTarget(
        name="LibreChat",
        platform="huntr.com",
        url="https://huntr.com/repos/danny-avila/LibreChat",
        api_endpoint="http://localhost:3080",
        scope=["Prompt injection", "Jailbreak", "Data exfiltration",
               "API key exposure", "Authentication bypass"],
        max_bounty=1500,
        allows_automation=True,
        has_ai_features=True,
        notes="Open source ChatGPT UI. Run via Docker. Has raw API at /api/ask.",
        category="ai_chatbot",
        github_repo="danny-avila/LibreChat",
    ),
    BountyTarget(
        name="Dify",
        platform="huntr.com",
        url="https://huntr.com/repos/langgenius/dify",
        api_endpoint="http://localhost/v1",
        scope=["Prompt injection", "RAG poisoning", "Tool misuse",
               "API key exposure", "Indirect injection"],
        max_bounty=1500,
        allows_automation=True,
        has_ai_features=True,
        notes="AI app builder. Has full REST API. Test /v1/chat-messages endpoint.",
        category="ai_platform",
        github_repo="langgenius/dify",
    ),
    BountyTarget(
        name="Ollama",
        platform="huntr.com",
        url="https://huntr.com/repos/ollama/ollama",
        api_endpoint="http://localhost:11434",
        scope=["API endpoint security", "Model file parsing",
               "SSRF via model pull", "Path traversal", "RCE"],
        max_bounty=1500,
        allows_automation=True,
        has_ai_features=True,
        notes="Local LLM runner. Lightweight. Test /api/chat, /api/pull, /api/show.",
        category="inference",
        github_repo="ollama/ollama",
    ),
    BountyTarget(
        name="Open WebUI",
        platform="huntr.com",
        url="https://huntr.com/repos/open-webui/open-webui",
        api_endpoint="http://localhost:3000",
        scope=["Prompt injection", "File upload", "API exposure",
               "Authentication bypass", "XSS via AI output"],
        max_bounty=1500,
        allows_automation=True,
        has_ai_features=True,
        notes="Web UI for Ollama. Has REST API. Test /api/chat and /api/models.",
        category="ai_chatbot",
        github_repo="open-webui/open-webui",
    ),
    BountyTarget(
        name="Anything LLM",
        platform="huntr.com",
        url="https://huntr.com/repos/mintplex-labs/anything-llm",
        api_endpoint="http://localhost:3001/api",
        scope=["RAG poisoning", "Document injection", "API key exposure",
               "Prompt injection", "Indirect injection"],
        max_bounty=1500,
        allows_automation=True,
        has_ai_features=True,
        notes="All-in-one local AI. Has /api/chat endpoint. Test RAG pipeline.",
        category="ai_platform",
        github_repo="mintplex-labs/anything-llm",
    ),
    BountyTarget(
        name="LiteLLM",
        platform="huntr.com",
        url="https://huntr.com/repos/berriai/litellm",
        api_endpoint="http://localhost:4000",
        scope=["API key exposure", "Proxy bypass", "Model routing abuse",
               "Authentication bypass", "SSRF"],
        max_bounty=1500,
        allows_automation=True,
        has_ai_features=True,
        notes="LLM proxy. OpenAI-compatible API. Test /chat/completions endpoint.",
        category="inference",
        github_repo="berriai/litellm",
    ),
]

class ProgramFinder:
    def __init__(self, output_dir=None):
        if output_dir is None:
            import pathlib
            output_dir = str(pathlib.Path(__file__).parent.parent / "output")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def get_all_targets(self) -> list:
        """Return all curated bounty targets."""
        return HUNTR_TARGETS

    def get_by_category(self, category: str) -> list:
        """Filter targets by category."""
        return [t for t in HUNTR_TARGETS if t.category == category]

    def get_lightweight(self) -> list:
        """Return targets that can run on low-resource machines."""
        lightweight = ["ollama", "litellm", "gradio"]
        return [t for t in HUNTR_TARGETS
                if t.name.lower() in lightweight]

    def get_api_first(self) -> list:
        """Return targets with the best raw API support."""
        api_first = ["ollama", "litellm", "dify", "librechat", "anything llm"]
        return [t for t in HUNTR_TARGETS
                if t.name.lower() in api_first]

    def check_target_live(self, target: BountyTarget) -> bool:
        """Check if a locally running target is accessible."""
        try:
            r = requests.get(target.api_endpoint, timeout=3)
            return r.status_code < 500
        except Exception:
            return False

    def find_live_targets(self) -> list:
        """Find which targets are currently running locally."""
        live = []
        print("\n  Checking for live local targets...")
        for target in HUNTR_TARGETS:
            is_live = self.check_target_live(target)
            status = "✅ LIVE" if is_live else "❌ offline"
            print(f"  {target.name:20s} {target.api_endpoint:35s} {status}")
            if is_live:
                live.append(target)
        return live

    def print_summary(self):
        """Print a summary of all available targets."""
        print(f"\n{'='*65}")
        print(f"  AI BUG BOUNTY TARGETS — huntr.com")
        print(f"{'='*65}")
        print(f"  {'Name':20s} {'Bounty':8s} {'Category':15s} Notes")
        print(f"  {'-'*60}")
        for t in HUNTR_TARGETS:
            print(f"  {t.name:20s} ${t.max_bounty:<7d} {t.category:15s} {t.notes[:40]}")
        print(f"{'='*65}")
        print(f"  Total: {len(HUNTR_TARGETS)} targets | "
              f"Max bounty: ${max(t.max_bounty for t in HUNTR_TARGETS):,}")
        print(f"{'='*65}\n")

    def save_targets(self, targets: list = None) -> str:
        """Save targets to JSON for dashboard."""
        if targets is None:
            targets = HUNTR_TARGETS
        data = [
            {
                "name": t.name,
                "platform": t.platform,
                "url": t.url,
                "api_endpoint": t.api_endpoint,
                "max_bounty": t.max_bounty,
                "category": t.category,
                "github_repo": t.github_repo,
                "notes": t.notes,
                "scope": t.scope,
            }
            for t in targets
        ]
        path = os.path.join(self.output_dir, "targets.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved {len(data)} targets to {path}")
        return path


if __name__ == "__main__":
    finder = ProgramFinder()
    finder.print_summary()
    finder.find_live_targets()
