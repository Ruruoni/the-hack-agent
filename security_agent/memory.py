"""Growth memory: durable, human-reviewable notes the agent writes after
each run, read back in on the next run. This is how the agent "grows"
without self-modifying code outside of normal, reviewed PRs — knowledge
lives in plain markdown files in `knowledge/`, committed to git like
anything else.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from . import config as cfg


def _slugify(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower())
    return text.strip("-")[:60] or "note"


class KnowledgeBase:
    def __init__(self, root: Path = cfg.KNOWLEDGE_DIR):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def load_all(self, max_chars: int = 20000) -> str:
        """Concatenate existing knowledge notes (most recent first) up to a
        budget, for injection into the agent's system prompt.
        """
        files = sorted(self.root.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        chunks: list[str] = []
        total = 0
        for f in files:
            text = f.read_text(encoding="utf-8")
            if total + len(text) > max_chars:
                break
            chunks.append(f"## {f.name}\n{text}")
            total += len(text)
        return "\n\n".join(chunks)

    def write_note(self, title: str, body: str) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = self.root / f"{ts}-{_slugify(title)}.md"
        content = f"# {title}\n\n_Recorded {ts} UTC_\n\n{body}\n"
        path.write_text(content, encoding="utf-8")
        return path
