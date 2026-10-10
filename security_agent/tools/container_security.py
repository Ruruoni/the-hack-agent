"""Container and Kubernetes security — Trivy for image/IaC scanning
(https://github.com/aquasecurity/trivy, Apache-2.0, local/no network
target) and kube-hunter for live cluster testing
(https://github.com/aquasecurity/kube-hunter, Apache-2.0, network
target -- an in-scope cluster API endpoint).
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class ContainerImageScanTool(Tool):
    name = "container_image_scan"
    description = (
        "Scan a container image (by name:tag) or a local IaC/Dockerfile "
        "path with Trivy for known-CVE vulnerable packages and "
        "misconfigurations. Read-only inspection, no network target."
    )
    action_category = "passive_recon"
    binary = "trivy"
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Image reference (e.g. 'myapp:1.2.3') or local path to scan.",
            },
            "scan_type": {
                "type": "string",
                "description": "'image' (default) or 'config'/'fs' for IaC/Dockerfile scanning.",
                "default": "image",
            },
        },
        "required": ["target"],
    }

    def run(self, guardrails: Guardrails, target: str, scan_type: str = "image", **_: Any) -> ToolResult:
        guardrails.authorize_local_action(self.name, target, f"trivy {scan_type} scan of {target}")
        if not self.available():
            msg = "trivy is not installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["trivy", scan_type, "--severity", "MEDIUM,HIGH,CRITICAL", "--format", "json", target]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=600)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, (out or err)[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})


class K8sLiveScanTool(Tool):
    name = "k8s_live_scan"
    description = (
        "Run kube-hunter against an in-scope, live Kubernetes cluster "
        "network/API endpoint to find exposed/misconfigured cluster "
        "components. Active, network-facing -- unlike container_image_scan."
    )
    action_category = "active_scanning"
    binary = "kube-hunter"
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Cluster API endpoint/host or CIDR to probe.",
            },
        },
        "required": ["target"],
    }

    def run(self, guardrails: Guardrails, target: str, **_: Any) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, target, self.action_category, f"kube-hunter scan of {target}"
        )
        if not self.available():
            msg = "kube-hunter is not installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["kube-hunter", "--remote", target, "--report", "json"]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=900)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, (out or err)[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
