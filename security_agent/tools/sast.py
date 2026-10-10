"""Static analysis and secret-scanning tools.

These operate on *local source code* only (this repo, or a cloned repo you
point at explicitly) — never against a live network target — so they go
through `authorize_local_action` rather than the domain/CIDR scope check.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class SastScanTool(Tool):
    """Wraps semgrep for static analysis of a local codebase."""

    name = "sast_scan"
    description = "Run semgrep static analysis against a local directory path."
    action_category = "passive_recon"
    binary = "semgrep"
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Local directory to scan."},
            "config": {
                "type": "string",
                "description": "Semgrep ruleset, default 'p/security-audit'.",
            },
        },
        "required": ["path"],
    }

    def run(self, guardrails: Guardrails, path: str, config: str = "p/security-audit", **_: Any) -> ToolResult:
        guardrails.authorize_local_action(self.name, path, f"semgrep scan of {path}")
        if not self.available():
            msg = "semgrep is not installed on this runner."
            guardrails.record_refusal(self.name, path, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["semgrep", "--config", config, "--json", "--quiet", path]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=600)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, path, (out or err)[:500])
        return ToolResult(ok=rc in (0, 1), summary=out or err, data={"returncode": rc})


class SecretScanTool(Tool):
    """Wraps gitleaks to find committed secrets in a local git repo."""

    name = "secret_scan"
    description = "Run gitleaks against a local git repository path to find committed secrets."
    action_category = "passive_recon"
    binary = "gitleaks"
    parameters = {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "Local git repo path."}},
        "required": ["path"],
    }

    def run(self, guardrails: Guardrails, path: str, **_: Any) -> ToolResult:
        guardrails.authorize_local_action(self.name, path, f"gitleaks scan of {path}")
        if not self.available():
            msg = "gitleaks is not installed on this runner."
            guardrails.record_refusal(self.name, path, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["gitleaks", "detect", "--source", path, "--no-banner", "-v"]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=300)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, path, (out or err)[:500])
        return ToolResult(ok=rc in (0, 1), summary=out or err, data={"returncode": rc})
