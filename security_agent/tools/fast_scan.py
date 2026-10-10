"""Fast port scanning -- wraps RustScan
(https://github.com/RustScan/RustScan, MIT), which scans the full port
range quickly and hands results to nmap for service detection. A
faster alternative to `port_scan` (nmap directly) for large port
ranges; still goes through the same scope check and uses nmap's
conservative-by-default timing for the service-detection phase, unlike
Masscan which has a well-known flooding failure mode at high packet
rates and is deliberately not wrapped here (see security_agent/README.md).
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class FastPortScanTool(Tool):
    name = "fast_port_scan"
    description = (
        "Scan all 65535 ports of an in-scope host quickly with RustScan "
        "(which hands matches to nmap for service detection). Prefer "
        "this over port_scan when you need full-range coverage, not just "
        "the top-1000 ports."
    )
    action_category = "passive_recon"
    binary = "rustscan"
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host to scan."},
        },
        "required": ["target"],
    }

    def run(self, guardrails: Guardrails, target: str, **_: Any) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, target, self.action_category, f"RustScan full-range scan of {target}"
        )
        if not self.available():
            msg = "rustscan is not installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["rustscan", "-a", target, "--", "-sV"]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=600)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, (out or err)[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
