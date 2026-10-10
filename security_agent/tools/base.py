"""Tool base class + registry.

Every tool:
  1. Declares an OpenAI-style function schema (so any provider can call it).
  2. Declares its `action_category` (passive_recon / active_scanning / ...)
     which guardrails.py checks against scope.yaml.
  3. Goes through `Guardrails.authorize_tool_call()` before doing anything,
     and never receives raw, unchecked model output as a shell command.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Callable

from ..guardrails import Guardrails


@dataclass
class ToolResult:
    ok: bool
    summary: str
    data: dict[str, Any]


class Tool:
    name: str = "tool"
    description: str = ""
    action_category: str = "passive_recon"
    parameters: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
    binary: str | None = None  # external CLI binary this tool shells out to

    def available(self) -> bool:
        return self.binary is None or shutil.which(self.binary) is not None

    def schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def run(self, guardrails: Guardrails, **kwargs: Any) -> ToolResult:
        raise NotImplementedError

    def _run_subprocess(self, cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def schemas(self) -> list[dict[str, Any]]:
        return [t.schema() for t in self._tools.values()]

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return list(self._tools.keys())
