"""Smart contract static analysis — wraps Slither
(https://github.com/crytic/slither, AGPL-3.0, Trail of Bits).

Operates on local Solidity source (a repo checkout or single file) --
local source analysis, like sast_scan, not a network target.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class SmartContractScanTool(Tool):
    name = "smart_contract_scan"
    description = (
        "Run Slither static analysis on local Solidity source code "
        "(a repo path or single .sol file) to find reentrancy, "
        "access-control, integer-overflow, and other common smart "
        "contract vulnerability classes."
    )
    action_category = "passive_recon"
    binary = "slither"
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Local path to Solidity source or a Hardhat/Foundry project root."},
        },
        "required": ["path"],
    }

    def run(self, guardrails: Guardrails, path: str, **_: Any) -> ToolResult:
        guardrails.authorize_local_action(self.name, path, f"Slither scan of {path}")
        if not self.available():
            msg = "slither is not installed on this runner (pip install slither-analyzer)."
            guardrails.record_refusal(self.name, path, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["slither", path, "--json", "-"]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=600)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, path, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        # Slither exits non-zero when it finds issues -- that's success for
        # our purposes (findings exist), not a tool failure.
        guardrails.record_result(self.name, path, (out or err)[:500])
        return ToolResult(ok=True, summary=out or err, data={"returncode": rc})
