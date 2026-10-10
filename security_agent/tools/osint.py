"""OSINT reconnaissance -- Sherlock
(https://github.com/sherlock-project/sherlock, MIT) for username
enumeration across social platforms, and theHarvester
(https://github.com/laramies/theHarvester, GPL-3.0) for email/subdomain
harvesting from public sources.

Important scope note for UsernameOsintTool specifically: it queries
hundreds of third-party sites (github.com, twitter.com, etc.) that are
never going to be individually listed in scope.yaml's allowed_domains --
that's expected, this is public-information lookup akin to a search
engine, not an attack against those sites. What DOES need authorization
is the *subject* -- the username/person being investigated must be
in scope for this engagement (e.g. an employee for an authorized social-
engineering-readiness assessment, or the organization's own public
accounts), never an arbitrary third party picked on a whim. Enforced via
`authorize_local_action` keyed on the username, since there's no single
network host to check against allowed_domains/allowed_cidrs here.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class UsernameOsintTool(Tool):
    name = "username_osint"
    description = (
        "Check which platforms a given username appears on, using "
        "Sherlock. The username/subject must be in scope for this "
        "engagement (an employee, or the organization's own accounts) -- "
        "never an arbitrary third party."
    )
    action_category = "passive_recon"
    binary = "sherlock"
    parameters = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "description": "Username to search for."},
        },
        "required": ["username"],
    }

    def run(self, guardrails: Guardrails, username: str, **_: Any) -> ToolResult:
        guardrails.authorize_local_action(
            self.name, username, f"Sherlock username OSINT lookup for '{username}'"
        )
        if not self.available():
            msg = "sherlock is not installed on this runner (pip install sherlock-project)."
            guardrails.record_refusal(self.name, username, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["sherlock", username, "--timeout", "10", "--print-found"]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=180)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, username, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, username, (out or err)[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})


class EmailHarvestTool(Tool):
    name = "email_harvest"
    description = (
        "Harvest email addresses, subdomains, and employee names "
        "associated with an in-scope domain from public sources "
        "(certificate transparency logs, search engines) using "
        "theHarvester. Passive -- no direct contact with the domain's "
        "own infrastructure, only third-party public-data sources."
    )
    action_category = "passive_recon"
    binary = "theHarvester"
    parameters = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "In-scope domain to harvest data about."},
            "sources": {
                "type": "string",
                "description": "Comma-separated sources, e.g. 'crtsh,bing'. Default is key-free sources.",
                "default": "crtsh,bing",
            },
        },
        "required": ["domain"],
    }

    def run(
        self, guardrails: Guardrails, domain: str, sources: str = "crtsh,bing", **_: Any
    ) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, domain, self.action_category, f"theHarvester OSINT sweep of {domain}"
        )
        if not self.available():
            msg = "theHarvester is not installed on this runner."
            guardrails.record_refusal(self.name, domain, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["theHarvester", "-d", domain, "-b", sources]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=300)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, domain, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, domain, (out or err)[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
