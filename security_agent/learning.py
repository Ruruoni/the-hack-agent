"""Self-learn: read a new repo or document, decide whether it's a fit,
and draft a tool/playbook proposal for human review. Never executes
anything from what it reads, never registers a draft into the live
tool registry, never touches a network target.

This is deliberately the one autonomous-sounding piece of this repo
that's actually safe to let run with no approval gate: reading text and
writing a draft file changes nothing real. The line stays exactly where
it's been all session -- *acting* (running a tool against a target,
applying a fix, sending a report) is gated; *learning* (reading,
reasoning, drafting) is not, because it can't touch anything.

Promotion of a draft into security_agent/tools/ is always a separate,
deliberate human step -- the same PR + CODEOWNERS + eval-gate review
every other tool in this repo went through. Nothing here shortcuts
that.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import config as cfg
from .config import AgentConfig
from .guardrails import AuditLog
from .memory import KnowledgeBase
from .providers import LLMProvider, build_provider

# Mirrors security_agent/README.md's "Deliberately not wrapped" section
# so the same judgment this session applied by hand gets applied
# consistently to anything learn_from_repo looks at. Kept here as a
# prompt fragment, not a strict allow/deny list -- the model still has
# to reason about the specific repo, not just pattern-match a name.
RISK_CRITERIA = """\
Decline (do not draft a tool) if the repository is, or primarily bundles:
- A denial-of-service / stress-testing / flooding tool.
- A phishing-attack kit (as opposed to an authorized phishing-SIMULATION
  platform like GoPhish, which only launches pre-reviewed campaigns).
- A "menu"/aggregator that installs/launches dozens of other tools
  under one umbrella, especially if any of its own categories are
  DoS, phishing, or indiscriminate brute-forcing.
- A full exploitation framework (Metasploit-like: goes from "confirm a
  bug" to "I have a shell" and keeps going on its own).
- A post-compromise lateral-movement/credential-dumping toolkit that
  assumes an existing foothold (Mimikatz/Rubeus/Certipy/NetExec-like).
- Anything requiring hooking a real, unwitting person's browser/device
  (BeEF-like), or live tracking of a real person's physical location.
- A shared-medium/broadcast attack (ARP spoofing, wireless deauth) that
  can affect devices beyond a single named target.
- Anything whose own documentation describes mass-targeting, scanning
  the whole internet, or attacking targets without per-target
  authorization.

Accept (draft a tool) if it's a single-purpose, scopeable tool --
recon, a specific vulnerability class scanner, a local
analysis/decoding utility, a credentialed audit of an account/asset you
already control, or a narrowly-bounded confirmation step (like this
repo's existing credential_test, capped at 25 candidates against one
account) -- the same shape as every tool already in
security_agent/tools/.
"""

DRAFT_PROMPT_TEMPLATE = """You are evaluating a GitHub repository for inclusion as a new tool \
in an authorization-gated security agent. Every existing tool in this \
agent goes through guardrails.py before doing anything: a network-target \
tool calls `guardrails.authorize_tool_call(name, target, category, \
description)` with category one of passive_recon/active_scanning/ \
exploitation; a tool with no network target (local file/credentialed \
audit) calls `guardrails.authorize_local_action(name, path, \
description)` instead.

{risk_criteria}

Repository: {repo_url}

README and file listing (truncated):
---
{repo_summary}
---

Respond with ONLY a JSON object, no markdown fences, no commentary:
{{
  "decision": "accept" or "decline",
  "reasoning": "<2-4 sentences explaining the decision, citing the specific repo content you saw>",
  "tool_name": "<snake_case tool name, only if accept>",
  "action_category": "<passive_recon|active_scanning|exploitation|local, only if accept>",
  "tool_code": "<complete Python source for a Tool subclass in this repo's style, only if accept -- see existing files in security_agent/tools/ for the exact pattern>",
  "playbook_markdown": "<a short playbook section in this repo's existing playbook style, only if accept>"
}}
"""


@dataclass
class LearningReport:
    source: str
    decision: str  # "accept" | "decline" | "error"
    reasoning: str
    staged_tool_path: Path | None = None
    staged_playbook_path: Path | None = None
    knowledge_note_path: Path | None = None


def _slugify(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower())
    return text.strip("-")[:60] or "learned"


def _clone_readonly(repo_url: str, timeout: int = 120) -> Path:
    """Shallow, read-only clone to a throwaway temp dir. Never installs
    or executes anything from the repo -- only used for reading text.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="agent-learn-"))
    cmd = ["git", "clone", "--depth", "1", repo_url, str(tmp_dir)]
    env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}
    subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    return tmp_dir


def _summarize_repo(repo_dir: Path, max_chars: int = 15000) -> str:
    """README + top-level file tree + a peek at a couple of likely-main
    source files -- bounded, read-only, never executed.
    """
    parts: list[str] = []
    total = 0

    for name in ("README.md", "README.rst", "README.txt", "README"):
        readme = repo_dir / name
        if readme.exists():
            text = readme.read_text(encoding="utf-8", errors="replace")
            parts.append(f"## {name}\n{text[:5000]}")
            total += len(parts[-1])
            break

    tree_lines = []
    for p in sorted(repo_dir.rglob("*")):
        if ".git" in p.parts:
            continue
        tree_lines.append(str(p.relative_to(repo_dir)))
        if len(tree_lines) > 200:
            break
    tree_text = "## File tree\n" + "\n".join(tree_lines)
    parts.append(tree_text)
    total += len(tree_text)

    joined = "\n\n".join(parts)
    return joined[:max_chars]


class LearningAgent:
    """Separate from SecurityAgent on purpose -- this never touches a
    target, so it doesn't need (and doesn't accept) a Guardrails
    instance the way every action-taking tool does. It still writes to
    the same audit log, for a complete record of everything the agent
    has ever done, learning included.
    """

    def __init__(
        self,
        config: AgentConfig | None = None,
        provider: LLMProvider | None = None,
        audit: AuditLog | None = None,
        knowledge: KnowledgeBase | None = None,
    ):
        self.config = config or AgentConfig()
        self.provider = provider or build_provider(self.config.provider)
        # audit/knowledge are injectable so tests don't write into the
        # real reports/audit.jsonl or knowledge/ -- same pattern as
        # Guardrails(scope=..., audit=...) and SecurityAgent(knowledge=...).
        self.audit = audit or AuditLog()
        self.knowledge = knowledge or KnowledgeBase()
        cfg.TOOLS_STAGING_DIR.mkdir(parents=True, exist_ok=True)
        cfg.PLAYBOOKS_STAGING_DIR.mkdir(parents=True, exist_ok=True)

    def learn_from_repo(self, repo_url: str) -> LearningReport:
        self.audit.record("learning_action_started", source=repo_url, kind="repo")
        try:
            repo_dir = _clone_readonly(repo_url)
        except Exception as exc:  # noqa: BLE001
            return self._finish(LearningReport(source=repo_url, decision="error", reasoning=str(exc)))

        try:
            summary = _summarize_repo(repo_dir)
        except Exception as exc:  # noqa: BLE001
            return self._finish(LearningReport(source=repo_url, decision="error", reasoning=str(exc)))

        prompt = DRAFT_PROMPT_TEMPLATE.format(
            risk_criteria=RISK_CRITERIA, repo_url=repo_url, repo_summary=summary
        )
        response = self.provider.chat(
            [
                {"role": "system", "content": "You evaluate and draft security tool integrations. Output JSON only."},
                {"role": "user", "content": prompt},
            ],
            tools=[],
        )

        parsed = self._parse_json(response.content or "")
        if parsed is None:
            return self._finish(
                LearningReport(source=repo_url, decision="error", reasoning="Could not parse model output as JSON.")
            )

        decision = parsed.get("decision", "decline")
        reasoning = parsed.get("reasoning", "(no reasoning given)")
        report = LearningReport(source=repo_url, decision=decision, reasoning=reasoning)

        if decision == "accept" and parsed.get("tool_code"):
            name = _slugify(parsed.get("tool_name", repo_url))
            tool_path = cfg.TOOLS_STAGING_DIR / f"{name}.py.draft"
            tool_path.write_text(parsed["tool_code"], encoding="utf-8")
            report.staged_tool_path = tool_path

            if parsed.get("playbook_markdown"):
                pb_path = cfg.PLAYBOOKS_STAGING_DIR / f"{name}.md.draft"
                pb_path.write_text(parsed["playbook_markdown"], encoding="utf-8")
                report.staged_playbook_path = pb_path

        return self._finish(report)

    def learn_from_document(self, path: str) -> LearningReport:
        """Text documents only in this version -- .md/.txt/.py/.json/
        .yaml/etc. Image/video analysis would need multimodal support
        in providers.py, which this does not add; it refuses cleanly
        for a binary/non-text file rather than pretending to read it.
        """
        self.audit.record("learning_action_started", source=path, kind="document")
        p = Path(path)
        if not p.is_file():
            return self._finish(LearningReport(source=path, decision="error", reasoning=f"{path} does not exist."))

        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return self._finish(
                LearningReport(
                    source=path, decision="error",
                    reasoning=(
                        "Not a text file (binary content, or an image/video/PDF). "
                        "This version of learn_from_document only reads plain text -- "
                        "image/video analysis needs multimodal provider support that "
                        "hasn't been added yet."
                    ),
                )
            )

        response = self.provider.chat(
            [
                {"role": "system", "content": "Summarize this document's content and anything security-relevant in it, concisely."},
                {"role": "user", "content": text[:20000]},
            ],
            tools=[],
        )
        summary = response.content or "(no summary produced)"
        return self._finish(LearningReport(source=path, decision="summarized", reasoning=summary))

    def _finish(self, report: LearningReport) -> LearningReport:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        note_body = f"Source: {report.source}\nDecision: {report.decision}\n\n{report.reasoning}"
        if report.staged_tool_path:
            note_body += f"\n\nDraft tool staged at: {report.staged_tool_path}"
        if report.staged_playbook_path:
            note_body += f"\nDraft playbook staged at: {report.staged_playbook_path}"
        report.knowledge_note_path = self.knowledge.write_note(f"learned-{ts}", note_body)

        self.audit.record(
            "learning_action_finished",
            source=report.source,
            decision=report.decision,
            staged_tool=str(report.staged_tool_path) if report.staged_tool_path else None,
        )
        return report

    @staticmethod
    def _parse_json(text: str) -> dict | None:
        import json

        text = text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            return None
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
