"""Runtime configuration for the security agent.

All values are overridable via environment variables so the agent can run
the same way locally, in Docker, or in a GitHub Actions job with secrets
injected as env vars.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_FILE = REPO_ROOT / "scope.yaml"
KNOWLEDGE_DIR = REPO_ROOT / "knowledge"
REPORTS_DIR = REPO_ROOT / "reports"
EVALS_DIR = REPO_ROOT / "evals"
AUDIT_LOG_PATH = REPO_ROOT / "reports" / "audit.jsonl"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class ProviderConfig:
    """Which LLM backend drives the agent loop. Model-agnostic by design:
    the agent "brain" can be swapped without touching the loop or tools.
    """

    # "ollama" | "groq" | "openai_compatible" | "anthropic"
    kind: str = field(default_factory=lambda: os.environ.get("AGENT_LLM_PROVIDER", "ollama"))
    model: str = field(default_factory=lambda: os.environ.get("AGENT_LLM_MODEL", "qwen2.5:14b"))
    base_url: str = field(
        default_factory=lambda: os.environ.get("AGENT_LLM_BASE_URL", "http://localhost:11434")
    )
    api_key: str = field(default_factory=lambda: os.environ.get("AGENT_LLM_API_KEY", ""))
    temperature: float = field(
        default_factory=lambda: float(os.environ.get("AGENT_LLM_TEMPERATURE", "0.2"))
    )
    max_tokens: int = field(default_factory=lambda: _env_int("AGENT_LLM_MAX_TOKENS", 4096))


@dataclass
class AgentConfig:
    provider: ProviderConfig = field(default_factory=ProviderConfig)
    dry_run: bool = field(default_factory=lambda: _env_bool("AGENT_DRY_RUN", True))
    max_iterations: int = field(default_factory=lambda: _env_int("AGENT_MAX_ITERATIONS", 25))
    require_human_approval_default: bool = field(
        default_factory=lambda: _env_bool("AGENT_REQUIRE_APPROVAL", True)
    )


def load_config() -> AgentConfig:
    return AgentConfig()
