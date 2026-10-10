"""Cloud posture auditing — wraps Prowler
(https://github.com/prowler-cloud/prowler, Apache-2.0).

Prowler audits an AWS/Azure/GCP/Kubernetes account's OWN configuration
using credentials for that account — there is no "network target" to
scope-check in the domain/CIDR sense (you cannot audit a cloud account
you don't hold credentials for), so this goes through
`authorize_local_action` the same way sast_scan/secret_scan do, keyed on
the account/profile identifier rather than a host.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class CloudPostureScanTool(Tool):
    name = "cloud_posture_scan"
    description = (
        "Audit an AWS/Azure/GCP/Kubernetes account's configuration for "
        "misconfigurations using Prowler, against credentials already "
        "configured in this environment (e.g. an AWS CLI profile). Never "
        "audits an account you don't hold credentials for -- there's no "
        "network target here, only your own cloud configuration."
    )
    action_category = "passive_recon"
    binary = "prowler"
    parameters = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "description": "Cloud provider: 'aws', 'azure', 'gcp', or 'kubernetes'.",
            },
            "profile_or_account": {
                "type": "string",
                "description": "Credential profile name or account identifier already configured locally.",
            },
            "checks": {
                "type": "string",
                "description": "Optional comma-separated Prowler check IDs to limit scope, e.g. 's3_bucket_public_access'.",
            },
        },
        "required": ["provider", "profile_or_account"],
    }

    def run(
        self,
        guardrails: Guardrails,
        provider: str,
        profile_or_account: str,
        checks: str | None = None,
        **_: Any,
    ) -> ToolResult:
        guardrails.authorize_local_action(
            self.name,
            f"{provider}:{profile_or_account}",
            f"Prowler {provider} posture audit of {profile_or_account}",
        )
        if not self.available():
            msg = "prowler is not installed on this runner (pip install prowler)."
            guardrails.record_refusal(self.name, profile_or_account, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["prowler", provider, "--profile", profile_or_account, "--output-formats", "json-ocsf"]
        if checks:
            cmd += ["--checks", checks]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=1800)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, profile_or_account, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, profile_or_account, (out or err)[-500:])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
