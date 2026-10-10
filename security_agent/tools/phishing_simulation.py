"""Phishing-susceptibility simulation -- wraps GoPhish's REST API
(https://github.com/gophish/gophish, MIT), the standard open-source
platform purpose-built for *authorized internal security-awareness
testing* -- not an attack tool. This is the responsible substitute for
the "phishing attack tools" bucket this agent declines to wrap (see
security_agent/README.md's "deliberately not wrapped" section).

Deliberately narrow by design, on top of the category gate:
  - This tool only LAUNCHES a campaign that a human has already built
    and reviewed in GoPhish itself (template, landing page, sending
    profile) -- it never authors phishing content, and campaign_id must
    already exist.
  - Every recipient email's domain is checked against scope.yaml's
    allowed_domains, same as any other target -- a campaign can only be
    launched against the organization's own people, never an arbitrary
    external list.
  - Always in the `exploitation` category, so it always blocks on
    explicit human approval regardless of what scope.yaml otherwise
    allows.
"""
from __future__ import annotations

from typing import Any

import httpx

from ..guardrails import Guardrails, ScopeViolation
from .base import Tool, ToolResult


class PhishingSimulationTool(Tool):
    name = "phishing_simulation_launch"
    description = (
        "Launch an already-built, human-reviewed GoPhish campaign "
        "(by campaign_id) against a specific list of recipient emails, "
        "each of which must belong to an in-scope domain. Does not "
        "create or author any phishing content -- only triggers a "
        "campaign someone already built and reviewed in GoPhish."
    )
    action_category = "exploitation"
    parameters = {
        "type": "object",
        "properties": {
            "gophish_api_url": {"type": "string", "description": "Base URL of your GoPhish instance's API."},
            "gophish_api_key": {"type": "string", "description": "GoPhish API key (from your own GoPhish admin panel)."},
            "campaign_id": {"type": "integer", "description": "ID of an existing, already-reviewed campaign."},
            "recipient_emails": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Recipients -- each email's domain must be in scope.yaml's allowed_domains.",
            },
        },
        "required": ["gophish_api_url", "gophish_api_key", "campaign_id", "recipient_emails"],
    }

    def available(self) -> bool:
        return True  # HTTP API, no local binary to check

    def run(
        self,
        guardrails: Guardrails,
        gophish_api_url: str,
        gophish_api_key: str,
        campaign_id: int,
        recipient_emails: list[str],
        **_: Any,
    ) -> ToolResult:
        # Validate every recipient's domain before anything else -- a
        # single out-of-scope recipient refuses the whole call rather
        # than silently dropping them.
        for email in recipient_emails:
            domain = email.split("@")[-1] if "@" in email else email
            try:
                guardrails.scope.check_target(domain)
            except ScopeViolation as exc:
                guardrails.record_refusal(self.name, email, str(exc))
                raise

        guardrails.authorize_tool_call(
            self.name,
            ",".join(recipient_emails),
            self.action_category,
            f"Launch GoPhish campaign {campaign_id} against {len(recipient_emails)} in-scope recipient(s)",
        )

        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(
                    f"{gophish_api_url.rstrip('/')}/api/campaigns/{campaign_id}/launch",
                    headers={"Authorization": f"Bearer {gophish_api_key}"},
                )
                resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, str(campaign_id), f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        summary = f"Launched GoPhish campaign {campaign_id}: {resp.status_code} {resp.text[:300]}"
        guardrails.record_result(self.name, str(campaign_id), summary)
        return ToolResult(ok=True, summary=summary, data={"status_code": resp.status_code})
