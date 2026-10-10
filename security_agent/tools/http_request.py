"""A single, guarded, manual HTTP request tool.

This is the escape hatch for anything the dedicated scanners don't cover
(header/CORS checks, verb testing, IDOR probing, SSRF callback testing,
auth flow steps) — but it's still a single request per call, still goes
through the same scope/target check as everything else, and never
follows the model's instructions about *which* host to hit without that
check running first.
"""
from __future__ import annotations

from typing import Any

import httpx

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class HttpRequestTool(Tool):
    name = "http_request"
    description = (
        "Send a single HTTP request to an in-scope URL with a chosen method, "
        "headers, and body. Use for header/CORS checks, HTTP verb testing, "
        "IDOR probing (swap an ID/session and compare responses), and "
        "configuring SSRF-test features to point at an in-scope callback "
        "host. One request per call — for anything needing many requests, "
        "use a dedicated scanner tool instead."
    )
    action_category = "active_scanning"
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Full URL to request."},
            "method": {
                "type": "string",
                "description": "HTTP method, e.g. GET, POST, PUT, DELETE, OPTIONS.",
                "default": "GET",
            },
            "headers": {
                "type": "object",
                "description": "Optional request headers as key/value pairs.",
            },
            "body": {"type": "string", "description": "Optional raw request body."},
            "follow_redirects": {"type": "boolean", "default": False},
        },
        "required": ["target"],
    }

    def run(
        self,
        guardrails: Guardrails,
        target: str,
        method: str = "GET",
        headers: dict | None = None,
        body: str | None = None,
        follow_redirects: bool = False,
        **_: Any,
    ) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, target, self.action_category, f"{method} {target}"
        )
        try:
            with httpx.Client(follow_redirects=follow_redirects, timeout=30.0) as client:
                resp = client.request(method.upper(), target, headers=headers or {}, content=body)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        summary_lines = [
            f"{resp.status_code} {resp.reason_phrase}",
            "-- headers --",
            "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
            "-- body (first 2000 chars) --",
            resp.text[:2000],
        ]
        summary = "\n".join(summary_lines)
        guardrails.record_result(self.name, target, f"{resp.status_code} {method}")
        return ToolResult(
            ok=True,
            summary=summary,
            data={"status_code": resp.status_code, "headers": dict(resp.headers)},
        )
