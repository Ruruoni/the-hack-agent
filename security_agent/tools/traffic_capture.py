"""Traffic interception -- wraps mitmproxy's headless `mitmdump`
(https://github.com/mitmproxy/mitmproxy, MIT) for a time-bounded
capture of traffic reverse-proxied to an in-scope target.

Note on realistic use: mitmproxy is normally an interactive, long-running
proxy you route a browser/app through -- this wrapper runs it headless
for a strictly bounded duration via `timeout`, which covers automated
capture-and-summarize use cases but not interactive manual testing.
Exact flags may need adjusting to your installed mitmproxy version.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class TrafficCaptureTool(Tool):
    name = "traffic_capture"
    description = (
        "Reverse-proxy traffic to an in-scope target through mitmdump for "
        "a bounded duration and summarize the captured flows (requests/"
        "responses, headers, status codes). Useful for inspecting what a "
        "client (browser, mobile app) actually sends -- tokens in URLs, "
        "unexpected plaintext calls, etc."
    )
    action_category = "active_scanning"
    binary = "mitmdump"
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Upstream host to reverse-proxy to, e.g. https://app.example-lab.local"},
            "listen_port": {"type": "integer", "default": 8080},
            "duration_seconds": {"type": "integer", "default": 30, "description": "Capture window, kept short."},
        },
        "required": ["target"],
    }

    def run(
        self,
        guardrails: Guardrails,
        target: str,
        listen_port: int = 8080,
        duration_seconds: int = 30,
        **_: Any,
    ) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, target, self.action_category,
            f"mitmdump reverse-proxy capture of {target} for {duration_seconds}s",
        )
        if not self.available():
            msg = "mitmdump is not installed on this runner (pip install mitmproxy)."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        duration_seconds = max(5, min(duration_seconds, 300))  # hard ceiling regardless of input
        flow_file = Path(tempfile.mkdtemp()) / "capture.flow"
        cmd = [
            "timeout", str(duration_seconds),
            "mitmdump", "--mode", f"reverse:{target}", "-p", str(listen_port),
            "-q", "-w", str(flow_file),
        ]
        try:
            self._run_subprocess(cmd, timeout=duration_seconds + 30)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        if not flow_file.exists():
            msg = "No flows captured (nothing was routed through the proxy during the window)."
            guardrails.record_result(self.name, target, msg)
            return ToolResult(ok=True, summary=msg, data={})

        try:
            rc, out, err = self._run_subprocess(
                ["mitmdump", "-n", "-r", str(flow_file), "--flow-detail", "2"], timeout=60
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, (out or err)[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
