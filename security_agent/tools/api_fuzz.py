"""API schema-based fuzz testing -- wraps Schemathesis
(https://github.com/schemathesis/schemathesis, MIT).

Important limitation to flag honestly: guardrails.py's rate limiting
and budget tracking operate per *tool call*, not per individual HTTP
request schemathesis makes internally -- a single authorized call to
this tool can generate many requests against the target in one go.
Keep `max_examples` low, and prefer this tool only against targets
whose rules_of_engagement comfortably tolerate a short burst of
automated requests.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class ApiFuzzTool(Tool):
    name = "api_fuzz_test"
    description = (
        "Property-based fuzz test a REST/GraphQL API against its OpenAPI/"
        "GraphQL schema using Schemathesis -- checks for schema "
        "conformance violations, unhandled server errors (5xx), and "
        "other spec-deviation bugs. Read-oriented by default (GET-heavy "
        "schemas are safest); restricts volume via max_examples. Does "
        "not attempt destructive/stateful mutation beyond what the "
        "schema itself defines as valid requests."
    )
    action_category = "active_scanning"
    binary = "schemathesis"
    parameters = {
        "type": "object",
        "properties": {
            "schema_url": {
                "type": "string",
                "description": "URL to the OpenAPI/Swagger or GraphQL schema (e.g. https://api.example-lab.local/openapi.json).",
            },
            "base_url": {
                "type": "string",
                "description": "Base URL to send generated requests to, if different from the schema's own server entry.",
            },
            "max_examples": {
                "type": "integer",
                "default": 20,
                "description": "Cap on generated test cases per endpoint -- keep this low.",
            },
        },
        "required": ["schema_url"],
    }

    def run(
        self,
        guardrails: Guardrails,
        schema_url: str,
        base_url: str | None = None,
        max_examples: int = 20,
        **_: Any,
    ) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, schema_url, self.action_category,
            f"schemathesis fuzz of {schema_url} (max_examples={max_examples})",
        )
        if not self.available():
            msg = "schemathesis is not installed on this runner (pip install schemathesis)."
            guardrails.record_refusal(self.name, schema_url, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = [
            "schemathesis", "run", schema_url,
            "--max-examples", str(max(1, min(max_examples, 200))),  # hard ceiling regardless of input
            "--checks", "not_a_server_error,status_code_conformance,response_schema_conformance",
        ]
        if base_url:
            cmd += ["--base-url", base_url]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=600)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, schema_url, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, schema_url, (out or err)[-500:])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
