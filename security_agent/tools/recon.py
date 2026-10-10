"""Passive/light-active reconnaissance tools."""
from __future__ import annotations

import shlex
import socket
from typing import Any

import httpx

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class PortScanTool(Tool):
    """Wraps nmap. Passive-ish service discovery — no exploit scripts."""

    name = "port_scan"
    description = (
        "Run an nmap service/version scan against a single in-scope host or "
        "CIDR. Use for discovering open ports and running services before "
        "deeper analysis. Does not run exploit scripts."
    )
    action_category = "passive_recon"
    binary = "nmap"
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host, domain, or CIDR to scan."},
            "ports": {
                "type": "string",
                "description": "Port spec, e.g. '1-1000' or '80,443,8080'. Default top-1000.",
            },
        },
        "required": ["target"],
    }

    def run(self, guardrails: Guardrails, target: str, ports: str | None = None, **_: Any) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, target, self.action_category, f"nmap service scan of {target}"
        )
        if not self.available():
            msg = "nmap is not installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["nmap", "-sV", "-T3", "--open"]
        cmd += ["-p", ports] if ports else []
        cmd += [target]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=600)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        summary = out[-4000:] if out else err[-2000:]
        guardrails.record_result(self.name, target, summary[:500])
        return ToolResult(ok=rc == 0, summary=summary, data={"returncode": rc, "cmd": shlex.join(cmd)})


class SubdomainEnumTool(Tool):
    """Wraps subfinder (passive subdomain enumeration)."""

    name = "subdomain_enum"
    description = "Passively enumerate subdomains of an in-scope domain using subfinder."
    action_category = "passive_recon"
    binary = "subfinder"
    parameters = {
        "type": "object",
        "properties": {"domain": {"type": "string", "description": "Root domain, e.g. example.com"}},
        "required": ["domain"],
    }

    def run(self, guardrails: Guardrails, domain: str, **_: Any) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, domain, self.action_category, f"passive subdomain enum of {domain}"
        )
        if not self.available():
            msg = "subfinder is not installed on this runner."
            guardrails.record_refusal(self.name, domain, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["subfinder", "-d", domain, "-silent"]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=300)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, domain, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        subs = [s for s in out.splitlines() if s.strip()]
        guardrails.record_result(self.name, domain, f"{len(subs)} subdomains found")
        return ToolResult(ok=rc == 0, summary="\n".join(subs), data={"subdomains": subs})


class HttpProbeTool(Tool):
    """Wraps httpx (projectdiscovery) to check which hosts are alive and
    fingerprint them. Cheap, low-noise, good first step before scanning.
    """

    name = "http_probe"
    description = "Probe a list of in-scope hosts/URLs to see which are alive and fingerprint tech."
    action_category = "passive_recon"
    binary = "httpx"
    parameters = {
        "type": "object",
        "properties": {
            "targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Hosts or URLs to probe.",
            }
        },
        "required": ["targets"],
    }

    def run(self, guardrails: Guardrails, targets: list[str], **_: Any) -> ToolResult:
        for t in targets:
            guardrails.authorize_tool_call(self.name, t, self.action_category, f"http probe {t}")
        if not self.available():
            msg = "httpx (projectdiscovery) is not installed on this runner."
            guardrails.record_refusal(self.name, ",".join(targets), msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["httpx", "-silent", "-tech-detect", "-status-code"]
        try:
            proc = self._run_subprocess_with_stdin(cmd, "\n".join(targets))
        except Exception as exc:  # noqa: BLE001
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, ",".join(targets), proc[:500])
        return ToolResult(ok=True, summary=proc, data={})

    def _run_subprocess_with_stdin(self, cmd: list[str], stdin_data: str, timeout: int = 180) -> str:
        import subprocess

        proc = subprocess.run(
            cmd, input=stdin_data, capture_output=True, text=True, timeout=timeout
        )
        return proc.stdout or proc.stderr


class IpGeolocationTool(Tool):
    """One-time, non-live network-metadata lookup: which registered
    region/organization an IP block belongs to, per public IP-to-ASN/
    geolocation registries -- the same class of information as a WHOIS
    lookup, not tracking a person. This resolves a static database
    entry for the IP *block*, not a live position: a cloud/VPN/CDN IP
    typically resolves to the provider's registered address, which is
    routinely nowhere near any actual person using that IP, and the
    city-level field in particular is frequently wrong by design (many
    providers register blocks at a single national office).
    """

    name = "ip_geolocation"
    description = (
        "Look up which country/region/organization an IP address (or a "
        "resolved hostname) is registered to, using public IP-geolocation "
        "data -- ordinary network metadata (same idea as WHOIS), not live "
        "or person-tracking. Useful for recon context (e.g. 'is this "
        "in-scope host actually hosted where the organization claims')."
    )
    action_category = "passive_recon"

    def available(self) -> bool:
        return True  # HTTP API call, no local binary to check

    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "In-scope IP address or hostname."},
        },
        "required": ["target"],
    }

    def run(self, guardrails: Guardrails, target: str, **_: Any) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name, target, self.action_category, f"IP geolocation/ASN lookup for {target}"
        )

        ip = target
        try:
            socket.inet_aton(target)
        except OSError:
            try:
                ip = socket.gethostbyname(target)
            except OSError as exc:
                msg = f"Could not resolve '{target}' to an IP: {exc}"
                guardrails.record_result(self.name, target, msg)
                return ToolResult(ok=False, summary=msg, data={})

        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "status,message,country,countryCode,regionName,city,isp,org,as,query"},
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        if data.get("status") != "success":
            msg = f"Lookup failed: {data.get('message', 'unknown error')}"
            guardrails.record_result(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data=data)

        summary = (
            f"{ip} is registered to: {data.get('org') or data.get('isp')}\n"
            f"ASN: {data.get('as')}\n"
            f"Location on file: {data.get('city')}, {data.get('regionName')}, {data.get('country')}\n"
            f"(static registry entry for this IP block -- not a live position, and frequently "
            f"reflects the provider's registered address rather than any end user's location)"
        )
        guardrails.record_result(self.name, target, summary[:500])
        return ToolResult(ok=True, summary=summary, data=data)
