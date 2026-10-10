"""Directory/file discovery — wraps ffuf."""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class DirectoryBruteforceTool(Tool):
    name = "directory_bruteforce"
    description = (
        "Discover hidden directories/files on an in-scope URL using ffuf "
        "with a wordlist. Use for finding admin panels, backup files, old "
        "API versions, exposed config files."
    )
    action_category = "active_scanning"
    binary = "ffuf"
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Base URL with FUZZ placeholder, e.g. https://host/FUZZ",
            },
            "wordlist": {"type": "string", "description": "Path to wordlist file on disk."},
            "extensions": {
                "type": "string",
                "description": "Comma-separated extensions to append, e.g. '.php,.bak,.env'.",
            },
        },
        "required": ["target"],
    }

    def run(
        self,
        guardrails: Guardrails,
        target: str,
        wordlist: str | None = None,
        extensions: str | None = None,
        **_: Any,
    ) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, target, self.action_category, f"ffuf directory discovery on {target}"
        )
        if not self.available():
            msg = "ffuf is not installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        wl = wordlist or DEFAULT_WORDLIST
        cmd = ["ffuf", "-u", target, "-w", wl, "-mc", "200,204,301,302,307,401,403", "-s"]
        if extensions:
            cmd += ["-e", extensions]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=600)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, out[:500] or err[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
