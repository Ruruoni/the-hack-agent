"""TLS/certificate configuration scanning — wraps testssl.sh, falling back
to sslscan if that's what's installed.
"""
from __future__ import annotations

import shutil
from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class TlsScanTool(Tool):
    name = "tls_scan"
    description = (
        "Check an in-scope host's TLS configuration: protocol versions, "
        "cipher suites, certificate validity, and common misconfigurations. "
        "Read-only — no payloads sent to the application layer."
    )
    action_category = "passive_recon"
    binary = "testssl.sh"
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host or host:port to check."},
        },
        "required": ["target"],
    }

    def available(self) -> bool:
        return shutil.which("testssl.sh") is not None or shutil.which("sslscan") is not None

    def run(self, guardrails: Guardrails, target: str, **_: Any) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, target, self.action_category, f"TLS configuration scan of {target}"
        )
        if shutil.which("testssl.sh"):
            cmd = ["testssl.sh", "--quiet", "--color", "0", target]
        elif shutil.which("sslscan"):
            cmd = ["sslscan", target]
        else:
            msg = "Neither testssl.sh nor sslscan is installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        try:
            rc, out, err = self._run_subprocess(cmd, timeout=300)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, (out or err)[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
