"""Active Directory relationship mapping -- wraps the BloodHound
collector (bloodhound-python,
https://github.com/dirkjanm/BloodHound.py, MIT; or SharpHound,
https://github.com/SpecterOps/BloodHound, part of the BloodHound
project).

This is the *collector* only -- it enumerates AD relationships (group
memberships, ACLs, session data) via standard LDAP/SMB queries, the
same kind of read that any domain-authenticated user can already
perform. It does not exploit anything. The resulting attack-path
analysis is informational, same category as nmap finding open ports --
but because a single collection run queries many hosts across the
whole domain at once, it stays in `active_scanning` rather than
`passive_recon` so it's easy to gate separately via scope.yaml if you
want tighter control over it specifically.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class ActiveDirectoryReconTool(Tool):
    name = "active_directory_recon"
    description = (
        "Enumerate Active Directory relationships (group memberships, "
        "ACLs, sessions) for attack-path analysis using the BloodHound "
        "collector. Read-only LDAP/SMB queries, same as what any "
        "domain-authenticated user can already see -- does not exploit "
        "anything, just maps what's there."
    )
    action_category = "active_scanning"
    binary = "bloodhound-python"
    parameters = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "In-scope AD domain, e.g. corp.example-lab.local"},
            "domain_controller": {"type": "string", "description": "DC hostname/IP to query."},
            "username": {"type": "string", "description": "Authenticated domain account to collect as."},
        },
        "required": ["domain", "domain_controller", "username"],
    }

    def run(
        self,
        guardrails: Guardrails,
        domain: str,
        domain_controller: str,
        username: str,
        **_: Any,
    ) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, domain_controller, self.action_category,
            f"BloodHound collection against {domain} via {domain_controller} as {username}",
        )
        if not self.available():
            msg = "bloodhound-python is not installed on this runner (pip install bloodhound)."
            guardrails.record_refusal(self.name, domain_controller, msg)
            return ToolResult(ok=False, summary=msg, data={})

        # Password/Kerberos ticket is read from the environment
        # (BHP_PASSWORD) rather than ever appearing in a tool-call
        # argument or the model's plan text.
        import os

        cmd = [
            "bloodhound-python", "-d", domain, "-dc", domain_controller,
            "-u", username, "-c", "All",
        ]
        if os.environ.get("BHP_PASSWORD"):
            cmd += ["-p", os.environ["BHP_PASSWORD"]]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=900)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, domain_controller, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, domain_controller, (out or err)[-500:])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
