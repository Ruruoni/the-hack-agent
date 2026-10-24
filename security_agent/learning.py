"""Self-learn: read a repo, a document, a URL, or raw pasted text,
decide whether/what it's worth drafting, and stage a proposal for human
review. Never executes anything from what it reads, never registers a
draft into the live tool registry, never touches a network target.

This is deliberately the one autonomous-sounding piece of this repo
that's actually safe to let run with no approval gate: reading text and
writing a draft file changes nothing real. The line stays exactly where
it's been all session -- *acting* (running a tool against a target,
applying a fix, sending a report) is gated; *learning* (reading,
reasoning, drafting) is not, because it can't touch anything.

Promotion of a draft into security_agent/tools/ or knowledge/playbooks/
is always a separate, deliberate human step -- the same PR + CODEOWNERS
+ eval-gate review every other tool/playbook in this repo went through.
Nothing here shortcuts that -- including `consolidate()`, which only
ever *drafts* a suggested playbook update, never edits a live playbook
file directly.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

from . import config as cfg
from .config import AgentConfig
from .doc_extract import OcrUnavailable, extract_document_text
from .guardrails import AuditLog
from .memory import KnowledgeBase
from .providers import LLMProvider, build_provider

# Mirrors security_agent/README.md's "Deliberately not wrapped" section
# so the same judgment this session applied by hand gets applied
# consistently to anything learned from. Kept here as a prompt
# fragment, not a strict allow/deny list -- the model still has to
# reason about the specific source, not just pattern-match a name.
RISK_CRITERIA = """\
Decline (do not draft a tool) if the source describes, or primarily is:
- A denial-of-service / stress-testing / flooding tool or technique.
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

Accept (draft a tool, or a playbook note) if it's a single-purpose,
scopeable technique or tool -- recon, a specific vulnerability class,
a local analysis/decoding utility, a credentialed audit of an
account/asset you already control, or a narrowly-bounded confirmation
step (like this repo's existing credential_test, capped at 25
candidates against one account) -- the same shape as every tool
already in security_agent/tools/.
"""

REPO_PROMPT_TEMPLATE = """You are evaluating a GitHub repository for inclusion as a new tool \
in an authorization-gated security agent. Every existing tool in this \
agent goes through guardrails.py before doing anything: a network-target \
tool calls `guardrails.authorize_tool_call(name, target, category, \
description)` with category one of passive_recon/active_scanning/ \
exploitation; a tool with no network target (local file/credentialed \
audit) calls `guardrails.authorize_local_action(name, path, \
description)` instead.

{risk_criteria}

Repository: {source}

README and file listing (truncated):
---
{content}
---

Respond with ONLY a JSON object, no markdown fences, no commentary:
{{
  "decision": "accept" or "decline",
  "reasoning": "<2-4 sentences explaining the decision, citing the specific content you saw>",
  "tool_name": "<snake_case tool name, only if accept>",
  "action_category": "<passive_recon|active_scanning|exploitation|local, only if accept>",
  "tool_code": "<complete Python source for a Tool subclass in this repo's style, only if accept -- see existing files in security_agent/tools/ for the exact pattern>",
  "playbook_markdown": "<a short playbook section in this repo's existing playbook style, only if accept>"
}}
"""

# Used for anything that's informational rather than code to wrap: a
# document, a URL (an article, write-up, advisory, CTF solution), or
# raw pasted text describing a hack pattern. Unlike the repo flow, this
# never drafts executable tool code -- at most a playbook addendum
# (text describing a technique and how to test/report it), since the
# source itself usually isn't a tool to wrap, just knowledge to record.
INFO_PROMPT_TEMPLATE = """Summarize the security-relevant content below concisely: what \
technique, vulnerability pattern, or finding does it describe, and is \
it the kind of reusable pattern worth adding a note to this security \
agent's testing methodology (knowledge/playbooks/)?

{risk_criteria}

Source: {source}

Content (truncated):
---
{content}
---

Respond with ONLY a JSON object, no markdown fences, no commentary:
{{
  "summary": "<2-5 sentence summary of what this source actually says>",
  "worth_a_playbook_note": true or false,
  "playbook_addendum": "<a short markdown section describing the pattern/technique and how to test for or recognize it, only if worth_a_playbook_note is true -- in the style of knowledge/playbooks/*.md>",
  "suggested_playbook": "<which existing playbook file this would extend, e.g. 'a03-injection.md', or 'new' if it doesn't fit any existing one, only if worth_a_playbook_note is true>"
}}
"""

CONSOLIDATE_PROMPT_TEMPLATE = """Below are recent growth notes this security agent has written to \
itself -- summaries of past runs and past learn_from_* calls. Look \
for recurring patterns, gaps, or concrete improvements worth making \
to the testing methodology, not a restatement of each note individually.

Notes:
---
{notes}
---

Respond with ONLY a JSON object, no markdown fences, no commentary:
{{
  "digest": "<a concise synthesis: what patterns recur, what gaps show up repeatedly, what would meaningfully improve future runs>",
  "worth_a_playbook_update": true or false,
  "playbook_addendum": "<a concrete, specific markdown addition to an existing playbook, only if worth_a_playbook_update is true -- not a generic restatement>",
  "suggested_playbook": "<which existing playbook file this would extend, only if worth_a_playbook_update is true>"
}}
"""


@dataclass
class LearningReport:
    source: str
    decision: str  # "accept" | "decline" | "summarized" | "error"
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
    """README + top-level file tree -- bounded, read-only, never executed."""
    parts: list[str] = []

    for name in ("README.md", "README.rst", "README.txt", "README"):
        readme = repo_dir / name
        if readme.exists():
            text = readme.read_text(encoding="utf-8", errors="replace")
            parts.append(f"## {name}\n{text[:5000]}")
            break

    tree_lines = []
    for p in sorted(repo_dir.rglob("*")):
        if ".git" in p.parts:
            continue
        tree_lines.append(str(p.relative_to(repo_dir)))
        if len(tree_lines) > 200:
            break
    parts.append("## File tree\n" + "\n".join(tree_lines))

    return "\n\n".join(parts)[:max_chars]


def _strip_html(html: str) -> str:
    """Minimal, dependency-free HTML-to-text: drop script/style blocks
    and tags, collapse whitespace. Imperfect but good enough for
    extracting readable article/write-up text -- no rendering, no JS
    execution, just text extraction from the fetched response body.
    """
    text = re.sub(r"<script.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _fetch_url_text(url: str, timeout: int = 30, max_bytes: int = 2_000_000) -> str:
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers={"User-Agent": "the-hack-agent/learning"})
        resp.raise_for_status()
        raw = resp.text[:max_bytes]
    if "html" in resp.headers.get("content-type", "").lower() or "<html" in raw[:1000].lower():
        return _strip_html(raw)
    return raw


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

    # ---------------------------------------------------------------- repo

    def learn_from_repo(self, repo_url: str) -> LearningReport:
        self.audit.record("learning_action_started", source=repo_url, kind="repo")
        try:
            repo_dir = _clone_readonly(repo_url)
            summary = _summarize_repo(repo_dir)
        except Exception as exc:  # noqa: BLE001
            return self._finish(LearningReport(source=repo_url, decision="error", reasoning=str(exc)))

        prompt = REPO_PROMPT_TEMPLATE.format(risk_criteria=RISK_CRITERIA, source=repo_url, content=summary)
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

    # ----------------------------------------------------- document / url / text

    def learn_from_document(self, path: str) -> LearningReport:
        """Plain text (.md/.txt/.py/.json/.yaml/etc.), PDF (text or
        scanned -- scanned/image-only pages fall back to OCR), and
        common image formats (.png/.jpg/.tiff/etc., always OCR'd).
        Video analysis would need multimodal provider support, which
        this does not add; it refuses cleanly for anything else rather
        than pretending to read it.
        """
        self.audit.record("learning_action_started", source=path, kind="document")
        p = Path(path)
        if not p.is_file():
            return self._finish(LearningReport(source=path, decision="error", reasoning=f"{path} does not exist."))

        try:
            text, info = extract_document_text(p)
        except OcrUnavailable as exc:
            return self._finish(LearningReport(source=path, decision="error", reasoning=str(exc)))
        except UnicodeDecodeError:
            return self._finish(
                LearningReport(
                    source=path, decision="error",
                    reasoning=(
                        "Not a recognized text, PDF, or image file (unsupported binary "
                        "content). Supported: plain text (.md/.txt/.py/.json/.yaml/"
                        "etc.), PDF (text or scanned, via OCR), and common image "
                        "formats (.png/.jpg/.tiff/etc.). Video analysis isn't "
                        "supported."
                    ),
                )
            )
        except Exception as exc:  # noqa: BLE001
            return self._finish(LearningReport(source=path, decision="error", reasoning=f"Could not extract text: {exc}"))

        if not text.strip():
            return self._finish(
                LearningReport(source=path, decision="error", reasoning=f"No extractable text found in {path}.")
            )

        content = text
        if info.ocr_pages:
            content = (
                f"[Note: {info.ocr_pages} of {info.total_pages} page(s) of this "
                f"document were extracted via OCR -- verify accuracy on anything "
                f"safety-critical.]\n\n{text}"
            )
        return self._learn_from_informational_text(path, content, kind="document")

    def learn_from_url(self, url: str) -> LearningReport:
        """Any fetchable web page -- an article, write-up, advisory,
        CTF solution, CVE page. Fetches and extracts readable text
        only; never executes any script on the page, never follows the
        page's own links further.
        """
        self.audit.record("learning_action_started", source=url, kind="url")
        try:
            text = _fetch_url_text(url)
        except Exception as exc:  # noqa: BLE001
            return self._finish(LearningReport(source=url, decision="error", reasoning=str(exc)))

        if not text.strip():
            return self._finish(
                LearningReport(source=url, decision="error", reasoning="Fetched page had no readable text content.")
            )
        return self._learn_from_informational_text(url, text, kind="url")

    def learn_from_text(self, content: str, label: str = "pasted-text") -> LearningReport:
        """Raw text handed directly to the agent -- a pasted attack-
        pattern description, a snippet from a conversation, anything
        that isn't a file path or a URL. No fetching, no file I/O for
        the source itself.
        """
        self.audit.record("learning_action_started", source=label, kind="text")
        return self._learn_from_informational_text(label, content, kind="text")

    def _learn_from_informational_text(self, source: str, content: str, kind: str) -> LearningReport:
        prompt = INFO_PROMPT_TEMPLATE.format(risk_criteria=RISK_CRITERIA, source=source, content=content[:20000])
        response = self.provider.chat(
            [
                {"role": "system", "content": "You summarize security-relevant content and judge whether it's worth a methodology note. Output JSON only."},
                {"role": "user", "content": prompt},
            ],
            tools=[],
        )
        parsed = self._parse_json(response.content or "")
        if parsed is None:
            # Fall back to treating the raw response as a plain summary
            # rather than erroring outright -- a model that ignores the
            # JSON instruction still usually produces a useful answer.
            return self._finish(
                LearningReport(source=source, decision="summarized", reasoning=response.content or "(no summary produced)")
            )

        summary = parsed.get("summary", "(no summary given)")
        report = LearningReport(source=source, decision="summarized", reasoning=summary)

        if parsed.get("worth_a_playbook_note") and parsed.get("playbook_addendum"):
            target_playbook = parsed.get("suggested_playbook", "new")
            name = _slugify(f"{target_playbook}-{source}")
            pb_path = cfg.PLAYBOOKS_STAGING_DIR / f"{name}.md.draft"
            pb_path.write_text(
                f"<!-- Suggested addition to knowledge/playbooks/{target_playbook} -->\n\n"
                + parsed["playbook_addendum"],
                encoding="utf-8",
            )
            report.staged_playbook_path = pb_path

        return self._finish(report)

    # ------------------------------------------------------------ consolidate

    def consolidate(self, max_chars: int = 60000) -> LearningReport:
        """The "digest everything learnt and improve" pass: reads the
        accumulated growth notes (past run summaries + past learn_from_*
        calls) and asks the model to synthesize recurring patterns or
        concrete improvements, staging a playbook addendum if it finds
        one worth proposing. Never edits a live playbook directly.
        """
        self.audit.record("learning_action_started", source="knowledge/*.md", kind="consolidate")
        notes = self.knowledge.load_growth_notes(max_chars=max_chars)
        if not notes.strip():
            return self._finish(
                LearningReport(source="knowledge/*.md", decision="error", reasoning="No growth notes to consolidate yet.")
            )

        prompt = CONSOLIDATE_PROMPT_TEMPLATE.format(notes=notes)
        response = self.provider.chat(
            [
                {"role": "system", "content": "You synthesize recurring patterns from an agent's own run history. Output JSON only."},
                {"role": "user", "content": prompt},
            ],
            tools=[],
        )
        parsed = self._parse_json(response.content or "")
        if parsed is None:
            return self._finish(
                LearningReport(source="knowledge/*.md", decision="error", reasoning="Could not parse model output as JSON.")
            )

        digest = parsed.get("digest", "(no digest produced)")
        report = LearningReport(source="knowledge/*.md", decision="summarized", reasoning=digest)

        if parsed.get("worth_a_playbook_update") and parsed.get("playbook_addendum"):
            target_playbook = parsed.get("suggested_playbook", "new")
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            pb_path = cfg.PLAYBOOKS_STAGING_DIR / f"consolidated-{ts}.md.draft"
            pb_path.write_text(
                f"<!-- Suggested addition to knowledge/playbooks/{target_playbook}, "
                f"synthesized from accumulated growth notes -->\n\n" + parsed["playbook_addendum"],
                encoding="utf-8",
            )
            report.staged_playbook_path = pb_path

        return self._finish(report)

    # --------------------------------------------------------------- shared

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
            staged_playbook=str(report.staged_playbook_path) if report.staged_playbook_path else None,
        )
        return report

    @staticmethod
    def _parse_json(text: str) -> dict | None:
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
