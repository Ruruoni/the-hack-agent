"""Two kinds of memory, both plain markdown in git:

- `knowledge/playbooks/*.md` — curated, human-written OWASP Top 10
  methodology, loaded in full every run (this is the "comes ready
  equipped out of the box" knowledge: swap/add a model and it already
  knows how to run a basic-to-advanced OWASP engagement without having
  learned anything yet).
- `knowledge/*.md` (everything else, flat in the root) — short notes the
  agent itself writes after each run, read back in up to a size budget.
  This is the "growth" memory: accumulated, reviewable, but never a
  replacement for the curated playbooks.
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
        self.playbooks_dir = root / "playbooks"
        self.root.mkdir(parents=True, exist_ok=True)
        self.playbooks_dir.mkdir(parents=True, exist_ok=True)

    def load_playbooks(self) -> str:
        """Curated methodology — always loaded in full, in a stable order
        (00-methodology first, then alphabetical) so the model sees the
        ground rules before the per-category detail.
        """
        files = sorted(self.playbooks_dir.glob("*.md"))
        chunks = [f"## playbooks/{f.name}\n{f.read_text(encoding='utf-8')}" for f in files]
        return "\n\n".join(chunks)

    def load_growth_notes(self, max_chars: int = 12000) -> str:
        """Agent-written run notes (most recent first) up to a budget."""
        files = sorted(
            (f for f in self.root.glob("*.md") if f.name.lower() != "readme.md"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        chunks: list[str] = []
        total = 0
        for f in files:
            text = f.read_text(encoding="utf-8")
            if total + len(text) > max_chars:
                break
            chunks.append(f"## {f.name}\n{text}")
            total += len(text)
        return "\n\n".join(chunks)

    def load_all(self, max_growth_chars: int = 12000) -> str:
        """Everything to inject into the system prompt: full playbooks plus
        a budgeted slice of growth notes.
        """
        playbooks = self.load_playbooks()
        growth = self.load_growth_notes(max_growth_chars)
        parts = []
        if playbooks:
            parts.append("# OWASP methodology playbooks (curated, always loaded)\n\n" + playbooks)
        if growth:
            parts.append("# Notes from previous runs (growth memory)\n\n" + growth)
        return "\n\n".join(parts)

    def write_note(self, title: str, body: str) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = self.root / f"{ts}-{_slugify(title)}.md"
        content = f"# {title}\n\n_Recorded {ts} UTC_\n\n{body}\n"
        path.write_text(content, encoding="utf-8")
        return path
