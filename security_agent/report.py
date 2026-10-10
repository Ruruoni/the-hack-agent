"""Writes a human-readable markdown report for each run to `reports/`."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from . import config as cfg


class RunReport:
    def __init__(self, objective: str):
        self.objective = objective
        self.started_at = datetime.now(timezone.utc)
        self.steps: list[dict] = []
        self.findings: list[str] = []

    def log_step(self, tool: str, target: str, summary: str, ok: bool) -> None:
        self.steps.append({"tool": tool, "target": target, "summary": summary, "ok": ok})

    def add_finding(self, text: str) -> None:
        self.findings.append(text)

    def render(self) -> str:
        lines = [
            f"# Security Agent Run Report",
            "",
            f"**Objective:** {self.objective}",
            f"**Started:** {self.started_at.isoformat()}",
            "",
            "## Findings",
            "",
        ]
        if self.findings:
            lines += [f"- {f}" for f in self.findings]
        else:
            lines.append("_No findings recorded this run._")

        lines += ["", "## Steps", ""]
        for i, s in enumerate(self.steps, 1):
            status = "OK" if s["ok"] else "FAILED/REFUSED"
            lines.append(f"### {i}. `{s['tool']}` → `{s['target']}` [{status}]")
            lines.append("")
            lines.append("```")
            lines.append(s["summary"][:2000])
            lines.append("```")
            lines.append("")
        return "\n".join(lines)

    def save(self, reports_dir: Path | None = None) -> Path:
        target_dir = reports_dir or cfg.REPORTS_DIR
        target_dir.mkdir(parents=True, exist_ok=True)
        ts = self.started_at.strftime("%Y%m%d-%H%M%S")
        path = target_dir / f"run-{ts}.md"
        path.write_text(self.render(), encoding="utf-8")
        return path
