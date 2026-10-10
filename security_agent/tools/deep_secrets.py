"""Deeper secret scanning -- wraps TruffleHog
(https://github.com/trufflesecurity/trufflehog, AGPL-3.0).

Complements `secret_scan` (gitleaks): TruffleHog supports many more
detectors and can optionally live-verify a found secret against its
actual provider API (`--only-verified`) rather than just pattern-match,
which cuts false positives sharply. Local filesystem/git-history
analysis only -- `authorize_local_action`, like secret_scan/sast_scan.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class DeepSecretScanTool(Tool):
    name = "deep_secret_scan"
    description = (
        "Scan a local filesystem path or git repository (including full "
        "history) for secrets using TruffleHog, with optional live "
        "verification against the provider API to cut false positives. "
        "Local analysis only, like secret_scan -- not a network target."
    )
    action_category = "passive_recon"
    binary = "trufflehog"
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Local path, or a git repo URL to scan its full history."},
            "mode": {
                "type": "string",
                "description": "'filesystem' (default, local path) or 'git' (repo URL, scans full history).",
                "default": "filesystem",
            },
            "only_verified": {
                "type": "boolean",
                "default": True,
                "description": "Live-verify each candidate secret against its provider API before reporting it.",
            },
        },
        "required": ["target"],
    }

    def run(
        self,
        guardrails: Guardrails,
        target: str,
        mode: str = "filesystem",
        only_verified: bool = True,
        **_: Any,
    ) -> ToolResult:
        guardrails.authorize_local_action(self.name, target, f"TruffleHog {mode} scan of {target}")
        if not self.available():
            msg = "trufflehog is not installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["trufflehog", mode, target, "--json"]
        if only_verified:
            cmd.append("--only-verified")
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=600)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, (out or err)[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
