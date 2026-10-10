"""SQL injection testing — wraps sqlmap.

Detection (the default) is `active_scanning`: low `--level`/`--risk`,
no data extraction. Setting `dump=True` switches the action category to
`exploitation`, which `scope.yaml` must separately allow *and* which
`guardrails.py` will block on human approval regardless — this file
cannot bypass that by itself.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class SqlInjectionTestTool(Tool):
    name = "sql_injection_test"
    description = (
        "Test an in-scope URL/parameter for SQL injection using sqlmap. "
        "Default mode only detects (--level 1 --risk 1, no data access). "
        "Set dump=True ONLY to extract a minimal proof-of-concept once a "
        "human has approved exploitation for this target — this flips the "
        "action into the exploitation category and will prompt for "
        "approval."
    )
    action_category = "active_scanning"  # overridden to 'exploitation' when dump=True
    binary = "sqlmap"
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Full URL containing the parameter to test."},
            "data": {
                "type": "string",
                "description": "Optional POST body (sqlmap --data) if the parameter is in a POST request.",
            },
            "dump": {
                "type": "boolean",
                "default": False,
                "description": "Extract a minimal PoC row instead of just detecting. Requires approval.",
            },
        },
        "required": ["target"],
    }

    def run(
        self,
        guardrails: Guardrails,
        target: str,
        data: str | None = None,
        dump: bool = False,
        **_: Any,
    ) -> ToolResult:
        category = "exploitation" if dump else "active_scanning"
        description = (
            f"sqlmap {'DATA EXTRACTION (--dump, minimal)' if dump else 'detection-only'} against {target}"
        )
        guardrails.authorize_tool_call(self.name, target, category, description)

        if not self.available():
            msg = "sqlmap is not installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["sqlmap", "-u", target, "--batch", "--level", "1", "--risk", "1"]
        if data:
            cmd += ["--data", data]
        if dump:
            # Minimal PoC only: first table/row sqlmap finds, never --dump-all.
            cmd += ["--dump", "--stop", "1"]

        try:
            rc, out, err = self._run_subprocess(cmd, timeout=900)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, (out or err)[-500:])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc, "dumped": dump})
