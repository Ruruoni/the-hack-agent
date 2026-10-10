"""Binary/reverse-engineering analysis -- wraps Ghidra's headless
analyzer (https://github.com/NationalSecurityAgency/ghidra, Apache-2.0).

Operates on a local binary file -- local analysis, like sast_scan, not
a network target. Ghidra's full power is its interactive GUI; this
wrapper covers automated headless import+analysis only (default
analysis passes: strings, function identification, basic
decompilation signals), which is enough to triage a binary (e.g. a
firmware blob, a suspicious executable found during an engagement)
before deciding whether deeper manual RE in the GUI is warranted.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


def _find_analyze_headless() -> str | None:
    # analyzeHeadless is a shell script, typically on PATH after install,
    # or under $GHIDRA_INSTALL_DIR/support/.
    found = shutil.which("analyzeHeadless")
    if found:
        return found
    import os

    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_dir:
        candidate = Path(ghidra_dir) / "support" / "analyzeHeadless"
        if candidate.exists():
            return str(candidate)
    return None


class BinaryAnalysisTool(Tool):
    name = "binary_analysis"
    description = (
        "Run Ghidra's headless analyzer against a local binary (firmware "
        "blob, executable) to triage it: imports, strings, function "
        "identification. Local file analysis only, no network target."
    )
    action_category = "passive_recon"
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Local path to the binary to analyze."},
        },
        "required": ["path"],
    }

    def available(self) -> bool:
        return _find_analyze_headless() is not None

    def run(self, guardrails: Guardrails, path: str, **_: Any) -> ToolResult:
        guardrails.authorize_local_action(self.name, path, f"Ghidra headless analysis of {path}")
        analyze_headless = _find_analyze_headless()
        if not analyze_headless:
            msg = (
                "Ghidra's analyzeHeadless is not installed/on PATH "
                "(set GHIDRA_INSTALL_DIR or add support/ to PATH)."
            )
            guardrails.record_refusal(self.name, path, msg)
            return ToolResult(ok=False, summary=msg, data={})

        project_dir = tempfile.mkdtemp()
        cmd = [
            analyze_headless, project_dir, "tmp_project",
            "-import", path, "-deleteProject",
        ]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=900)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, path, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, path, (out or err)[-500:])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
