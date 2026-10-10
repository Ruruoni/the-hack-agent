"""Active vulnerability scanning — flagged as `active_scanning`, which
scope.yaml must explicitly allow, separate from passive recon.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class WebVulnScanTool(Tool):
    """Wraps nuclei. Template-based, non-destructive-by-default vulnerability
    scanning (misconfig, known-CVE detection templates, exposed panels,
    etc.). Does not include exploit/fuzzing templates that could disrupt
    a target — those are a separate, approval-gated tool.
    """

    name = "web_vuln_scan"
    description = (
        "Run a nuclei scan with safe, non-destructive templates (misconfig, "
        "exposure, known-CVE detection) against an in-scope URL or host."
    )
    action_category = "active_scanning"
    binary = "nuclei"
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL or host to scan."},
            "severity": {
                "type": "string",
                "description": "Comma-separated severities, e.g. 'medium,high,critical'.",
            },
        },
        "required": ["target"],
    }

    def run(
        self, guardrails: Guardrails, target: str, severity: str | None = None, **_: Any
    ) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, target, self.action_category, f"nuclei scan of {target}"
        )
        if not self.available():
            msg = "nuclei is not installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["nuclei", "-u", target, "-silent", "-exclude-tags", "dos,fuzz,intrusive"]
        if severity:
            cmd += ["-severity", severity]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=900)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, out[:500] or err[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
