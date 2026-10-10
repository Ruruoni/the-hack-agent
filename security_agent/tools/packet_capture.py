"""Passive packet capture -- wraps tcpdump for a bounded capture window
on a local network interface the operator already has legitimate
access to (e.g. running this agent inside the client's own network
during an on-site engagement). Complements `traffic_capture`
(mitmproxy), which works by reverse-proxying a specific HTTP(S) target
rather than capturing raw traffic on an interface.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class PacketCaptureTool(Tool):
    name = "packet_capture"
    description = (
        "Passively capture traffic on a local network interface for a "
        "bounded duration using tcpdump, optionally filtered to an "
        "in-scope host/subnet with a BPF filter. For engagements run "
        "inside the client's own network."
    )
    action_category = "passive_recon"
    binary = "tcpdump"
    parameters = {
        "type": "object",
        "properties": {
            "interface": {"type": "string", "description": "Network interface to capture on, e.g. 'eth0'."},
            "target": {
                "type": "string",
                "description": "The in-scope host or CIDR to restrict capture to (checked against scope.yaml).",
            },
            "duration_seconds": {"type": "integer", "default": 30},
        },
        "required": ["interface", "target"],
    }

    def run(
        self,
        guardrails: Guardrails,
        interface: str,
        target: str,
        duration_seconds: int = 30,
        **_: Any,
    ) -> ToolResult:
        # `target` is what's scope-checked; the BPF filter syntax is built
        # from it afterward, so a model can never smuggle an out-of-scope
        # host into the filter string itself.
        guardrails.authorize_tool_call(
            self.name, target, self.action_category,
            f"tcpdump on {interface} filtered to host/net {target} for {duration_seconds}s",
        )
        if not self.available():
            msg = "tcpdump is not installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        duration_seconds = max(5, min(duration_seconds, 300))  # hard ceiling
        bpf_filter = f"net {target}" if "/" in target else f"host {target}"
        cmd = [
            "timeout", str(duration_seconds),
            "tcpdump", "-i", interface, "-n", "-c", "500",  # cap packet count too
            bpf_filter,
        ]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=duration_seconds + 30)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, (out or err)[:500])
        return ToolResult(ok=True, summary=out or err, data={"returncode": rc})
